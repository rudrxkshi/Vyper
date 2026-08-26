from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 2
ACTIVE_STATES = (
	"PENDING",
	"PROFILING",
	"POLICY_SELECTED",
	"AWAITING_AUTHORIZATION",
	"RUNNING",
	"VERIFYING",
)
TERMINAL_STATES = {"VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"}


def utc_now() -> str:
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_target(target: str) -> str:
	cleaned = str(target or "").strip().rstrip("/")
	if cleaned and os.path.exists(cleaned):
		return os.path.realpath(cleaned)
	return cleaned


class DuplicateActiveTargetError(RuntimeError):
	pass


class RemoteCommandReplayError(RuntimeError):
	pass


class LocalJobStore:
	"""Versioned SQLite storage for local jobs and immutable lifecycle events."""

	_JSON_COLUMNS = {
		"authorization_metadata_json",
		"progress_json",
		"profile_json",
		"policy_json",
		"execution_json",
		"verification_json",
		"evidence_json",
		"certificate_json",
		"error_json",
	}

	def __init__(self, database_path: str | Path) -> None:
		self.database_path = str(database_path)
		Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
		self._initialize()

	@contextmanager
	def _connect(self) -> Iterator[sqlite3.Connection]:
		connection = sqlite3.connect(self.database_path, timeout=30, check_same_thread=False)
		connection.row_factory = sqlite3.Row
		try:
			connection.execute("PRAGMA foreign_keys = ON")
			yield connection
			connection.commit()
		finally:
			connection.close()

	def _initialize(self) -> None:
		with self._connect() as connection:
			connection.executescript(
				"""
				CREATE TABLE IF NOT EXISTS schema_metadata (
					key TEXT PRIMARY KEY,
					value TEXT NOT NULL
				);
				CREATE TABLE IF NOT EXISTS local_jobs (
					local_job_id TEXT PRIMARY KEY,
					api_version TEXT NOT NULL,
					target TEXT NOT NULL,
					normalized_target TEXT NOT NULL,
					dry_run INTEGER NOT NULL,
					authorization_metadata_json TEXT NOT NULL,
					job_state TEXT NOT NULL,
					final_status TEXT,
					created_at TEXT NOT NULL,
					started_at TEXT,
					finished_at TEXT,
					updated_at TEXT NOT NULL,
					message TEXT NOT NULL,
					progress_json TEXT,
					profile_json TEXT,
					policy_json TEXT,
					execution_json TEXT,
					verification_json TEXT,
					evidence_json TEXT,
					certificate_json TEXT,
					error_json TEXT,
					worker_pid INTEGER
				);
				CREATE TABLE IF NOT EXISTS local_job_events (
					local_job_id TEXT NOT NULL,
					sequence INTEGER NOT NULL,
					state TEXT NOT NULL,
					timestamp TEXT NOT NULL,
					message TEXT NOT NULL,
					progress_json TEXT,
					PRIMARY KEY (local_job_id, sequence),
					FOREIGN KEY (local_job_id) REFERENCES local_jobs(local_job_id) ON DELETE CASCADE
				);
				CREATE UNIQUE INDEX IF NOT EXISTS uq_active_destructive_target
				ON local_jobs(normalized_target)
				WHERE dry_run = 0 AND job_state IN (
					'PENDING', 'PROFILING', 'POLICY_SELECTED',
					'AWAITING_AUTHORIZATION', 'RUNNING', 'VERIFYING'
				);
				CREATE TABLE IF NOT EXISTS remote_job_requests (
					central_job_id TEXT PRIMARY KEY,
					target_identity TEXT NOT NULL,
					requested_target TEXT NOT NULL,
					dry_run INTEGER NOT NULL,
					central_approved INTEGER NOT NULL,
					local_approved INTEGER NOT NULL DEFAULT 0,
					status TEXT NOT NULL,
					expires_at TEXT NOT NULL,
					idempotency_key TEXT NOT NULL UNIQUE,
					nonce TEXT NOT NULL,
					payload_json TEXT NOT NULL,
					local_job_id TEXT UNIQUE,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL
				);
				CREATE TABLE IF NOT EXISTS outbox (
					outbox_id TEXT PRIMARY KEY,
					kind TEXT NOT NULL,
					central_job_id TEXT,
					local_job_id TEXT,
					sequence INTEGER,
					idempotency_key TEXT NOT NULL UNIQUE,
					payload_json TEXT NOT NULL,
					created_at TEXT NOT NULL,
					attempt_count INTEGER NOT NULL DEFAULT 0,
					last_attempt_at TEXT,
					next_attempt_at TEXT NOT NULL,
					delivered_at TEXT,
					last_error TEXT
				);
				CREATE TABLE IF NOT EXISTS remote_command_receipts (
					nonce TEXT PRIMARY KEY,
					command_id TEXT NOT NULL UNIQUE,
					command_hash TEXT NOT NULL,
					received_at TEXT NOT NULL
				);
				"""
			)
			connection.execute(
				"INSERT OR REPLACE INTO schema_metadata(key, value) VALUES('schema_version', ?)",
				(str(SCHEMA_VERSION),),
			)

	def create_job(
		self,
		*,
		local_job_id: str,
		api_version: str,
		target: str,
		dry_run: bool,
		authorization_metadata: dict[str, Any],
	) -> dict[str, Any]:
		now = utc_now()
		try:
			with self._connect() as connection:
				connection.execute(
					"""
					INSERT INTO local_jobs (
						local_job_id, api_version, target, normalized_target, dry_run,
						authorization_metadata_json, job_state, created_at, updated_at, message
					) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, 'Job accepted.')
					""",
					(
						local_job_id,
						api_version,
						target,
						normalize_target(target),
						int(dry_run),
						json.dumps(authorization_metadata, sort_keys=True),
						now,
						now,
					),
				)
				self._append_event(connection, local_job_id, "PENDING", "Job accepted.", None, now)
		except sqlite3.IntegrityError as exc:
			if "uq_active_destructive_target" in str(exc) or "normalized_target" in str(exc):
				raise DuplicateActiveTargetError(target) from exc
			raise
		return self.get_job(local_job_id)

	def transition(
		self,
		local_job_id: str,
		state: str,
		message: str,
		*,
		progress: dict[str, Any] | None = None,
	) -> dict[str, Any] | None:
		now = utc_now()
		with self._connect() as connection:
			row = connection.execute(
				"SELECT job_state, started_at FROM local_jobs WHERE local_job_id = ?",
				(local_job_id,),
			).fetchone()
			if row is None:
				return None
			started_at = row["started_at"] or (now if state != "PENDING" else None)
			finished_at = now if state in TERMINAL_STATES else None
			final_status = state if state in TERMINAL_STATES else None
			connection.execute(
				"""
				UPDATE local_jobs SET job_state = ?, updated_at = ?, started_at = ?,
				finished_at = COALESCE(?, finished_at), final_status = COALESCE(?, final_status),
				message = ?, progress_json = ?
				WHERE local_job_id = ?
				""",
				(state, now, started_at, finished_at, final_status, message, self._dump(progress), local_job_id),
			)
			self._append_event(connection, local_job_id, state, message, progress, now)
		return self.get_job(local_job_id)

	def update_progress(self, local_job_id: str, progress: dict[str, Any]) -> None:
		job = self.get_job(local_job_id)
		if job is None or job["job_state"] in TERMINAL_STATES:
			return
		self.transition(local_job_id, job["job_state"], "Measured progress update.", progress=progress)

	def complete(self, local_job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
		state = str(payload["job_state"])
		final_status = payload.get("final_status")
		now = utc_now()
		with self._connect() as connection:
			connection.execute(
				"""
				UPDATE local_jobs SET job_state = ?, final_status = ?, updated_at = ?,
				finished_at = ?, message = ?, progress_json = ?, profile_json = ?,
				policy_json = ?, execution_json = ?, verification_json = ?,
				evidence_json = ?, certificate_json = ?, error_json = ?
				WHERE local_job_id = ?
				""",
				(
					state,
					final_status,
					now,
					now,
					str(payload.get("message") or ""),
					self._dump(payload.get("progress")),
					self._dump(payload.get("profile")),
					self._dump(payload.get("policy")),
					self._dump(payload.get("execution")),
					self._dump(payload.get("verification")),
					self._dump(payload.get("evidence")),
					self._dump(payload.get("certificate")),
					self._dump(payload.get("error")),
					local_job_id,
				),
			)
			current = connection.execute(
				"SELECT state FROM local_job_events WHERE local_job_id = ? ORDER BY sequence DESC LIMIT 1",
				(local_job_id,),
			).fetchone()
			if current is None or current["state"] != state:
				self._append_event(
					connection,
					local_job_id,
					state,
					str(payload.get("message") or "Workflow completed."),
					payload.get("progress"),
					now,
				)
		return self.get_job(local_job_id)

	def set_worker_pid(self, local_job_id: str, worker_pid: int) -> None:
		with self._connect() as connection:
			connection.execute(
				"UPDATE local_jobs SET worker_pid = ?, updated_at = ? WHERE local_job_id = ?",
				(worker_pid, utc_now(), local_job_id),
			)

	def start_job(self, local_job_id: str, worker_pid: int) -> bool:
		now = utc_now()
		with self._connect() as connection:
			connection.execute("BEGIN IMMEDIATE")
			row = connection.execute(
				"SELECT job_state FROM local_jobs WHERE local_job_id = ?",
				(local_job_id,),
			).fetchone()
			if row is None or row["job_state"] != "PENDING":
				return False
			connection.execute(
				"""
				UPDATE local_jobs SET job_state = 'PROFILING', worker_pid = ?,
				started_at = ?, updated_at = ?, message = 'Profiling target device.'
				WHERE local_job_id = ? AND job_state = 'PENDING'
				""",
				(worker_pid, now, now, local_job_id),
			)
			self._append_event(connection, local_job_id, "PROFILING", "Profiling target device.", None, now)
			return True

	def cancel_pending(self, local_job_id: str) -> str:
		with self._connect() as connection:
			connection.execute("BEGIN IMMEDIATE")
			row = connection.execute(
				"SELECT job_state FROM local_jobs WHERE local_job_id = ?",
				(local_job_id,),
			).fetchone()
			if row is None:
				return "missing"
			if row["job_state"] != "PENDING":
				return "unsafe"
			now = utc_now()
			connection.execute(
				"""
				UPDATE local_jobs SET job_state = 'CANCELLED', final_status = 'CANCELLED',
				finished_at = ?, updated_at = ?, message = ? WHERE local_job_id = ?
				""",
				(now, now, "Pending job cancelled before execution.", local_job_id),
			)
			self._append_event(
				connection,
				local_job_id,
				"CANCELLED",
				"Pending job cancelled before execution.",
				None,
				now,
			)
		return "cancelled"

	def recover_interrupted(self) -> int:
		recovered = 0
		with self._connect() as connection:
			rows = connection.execute(
				f"SELECT local_job_id, job_state FROM local_jobs WHERE job_state IN ({','.join('?' for _ in ACTIVE_STATES)})",
				ACTIVE_STATES,
			).fetchall()
		for row in rows:
			state = "CANCELLED" if row["job_state"] == "PENDING" else "INCONCLUSIVE"
			self.transition(
				row["local_job_id"],
				state,
				"Local agent restarted before terminal verification could be confirmed.",
			)
			recovered += 1
		return recovered

	def get_job(self, local_job_id: str) -> dict[str, Any] | None:
		with self._connect() as connection:
			row = connection.execute(
				"SELECT * FROM local_jobs WHERE local_job_id = ?",
				(local_job_id,),
			).fetchone()
			if row is None:
				return None
			events = connection.execute(
				"SELECT sequence, state, timestamp, message, progress_json FROM local_job_events WHERE local_job_id = ? ORDER BY sequence",
				(local_job_id,),
			).fetchall()
		return self._row_to_job(row, events)

	def list_jobs(self, *, state: str | None = None, target: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
		clauses: list[str] = []
		parameters: list[Any] = []
		if state:
			clauses.append("job_state = ?")
			parameters.append(state)
		if target:
			clauses.append("normalized_target = ?")
			parameters.append(normalize_target(target))
		where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
		parameters.append(max(1, min(int(limit), 500)))
		with self._connect() as connection:
			rows = connection.execute(
				f"SELECT local_job_id FROM local_jobs{where} ORDER BY created_at DESC LIMIT ?",
				parameters,
			).fetchall()
		return [job for row in rows if (job := self.get_job(row["local_job_id"])) is not None]

	def save_remote_request(self, payload: dict[str, Any]) -> dict[str, Any]:
		now = utc_now()
		central_job_id = str(payload["central_job_id"])
		with self._connect() as connection:
			connection.execute(
				"""
				INSERT OR IGNORE INTO remote_job_requests (
					central_job_id, target_identity, requested_target, dry_run,
					central_approved, local_approved, status, expires_at,
					idempotency_key, nonce, payload_json, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					central_job_id, payload["target_identity"], payload["requested_target"],
					int(bool(payload["dry_run"])), int(bool((payload.get("authorization_policy") or {}).get("central_approved"))),
					"READY" if payload["dry_run"] else "WAITING_LOCAL_APPROVAL", payload["expires_at"],
					payload["idempotency_key"], payload["nonce"], self._dump(payload), now, now,
				),
			)
		return self.get_remote_request(central_job_id)

	def record_remote_command(self, *, command_id: str, nonce: str, command_hash: str) -> bool:
		"""Persist a signed-command receipt before it can reach local approval.

		A byte-identical re-delivery is safe and returns ``False``. Any reuse of a
		nonce or command id with a different signed envelope is rejected locally.
		"""
		with self._connect() as connection:
			existing = connection.execute(
				"SELECT command_id, command_hash FROM remote_command_receipts WHERE nonce = ? OR command_id = ?",
				(nonce, command_id),
			).fetchone()
			if existing is not None:
				if existing["command_id"] == command_id and existing["command_hash"] == command_hash:
					return False
				raise RemoteCommandReplayError("Remote command nonce or command ID was already used by another command.")
			connection.execute(
				"INSERT INTO remote_command_receipts(nonce, command_id, command_hash, received_at) VALUES (?, ?, ?, ?)",
				(nonce, command_id, command_hash, utc_now()),
			)
		return True

	def get_remote_request(self, central_job_id: str) -> dict[str, Any] | None:
		with self._connect() as connection:
			row = connection.execute("SELECT * FROM remote_job_requests WHERE central_job_id = ?", (central_job_id,)).fetchone()
		if row is None:
			return None
		payload = dict(row)
		payload["dry_run"] = bool(payload["dry_run"])
		payload["central_approved"] = bool(payload["central_approved"])
		payload["local_approved"] = bool(payload["local_approved"])
		payload["payload"] = self._load(payload.pop("payload_json"))
		return payload

	def list_remote_requests(self) -> list[dict[str, Any]]:
		with self._connect() as connection:
			rows = connection.execute("SELECT central_job_id FROM remote_job_requests ORDER BY created_at DESC").fetchall()
		return [request for row in rows if (request := self.get_remote_request(row["central_job_id"])) is not None]

	def map_remote_job(self, central_job_id: str, local_job_id: str, *, local_approved: bool) -> bool:
		with self._connect() as connection:
			updated = connection.execute(
				"""
				UPDATE remote_job_requests SET local_job_id = ?, local_approved = ?, status = 'SUBMITTED', updated_at = ?
				WHERE central_job_id = ? AND local_job_id IS NULL
				""",
				(local_job_id, int(local_approved), utc_now(), central_job_id),
			)
		return updated.rowcount == 1

	def enqueue_outbox(
		self,
		*,
		outbox_id: str,
		kind: str,
		idempotency_key: str,
		payload: dict[str, Any],
		central_job_id: str | None = None,
		local_job_id: str | None = None,
		sequence: int | None = None,
	) -> bool:
		if self._contains_secret(payload):
			raise ValueError("Secret-bearing payload cannot be stored in the outbox.")
		now = utc_now()
		with self._connect() as connection:
			inserted = connection.execute(
				"""
				INSERT OR IGNORE INTO outbox (
					outbox_id, kind, central_job_id, local_job_id, sequence,
					idempotency_key, payload_json, created_at, next_attempt_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(outbox_id, kind, central_job_id, local_job_id, sequence, idempotency_key, self._dump(payload), now, now),
			)
		return inserted.rowcount == 1

	def due_outbox(self, *, now: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
		with self._connect() as connection:
			rows = connection.execute(
				"""
				SELECT * FROM outbox WHERE delivered_at IS NULL AND next_attempt_at <= ?
				ORDER BY created_at LIMIT ?
				""",
				(now or utc_now(), max(1, min(limit, 100))),
			).fetchall()
		return [{**dict(row), "payload": self._load(row["payload_json"])} for row in rows]

	def mark_outbox_delivered(self, outbox_id: str) -> None:
		with self._connect() as connection:
			connection.execute(
				"UPDATE outbox SET delivered_at = ?, last_attempt_at = ?, last_error = NULL WHERE outbox_id = ?",
				(utc_now(), utc_now(), outbox_id),
			)

	def mark_outbox_failed(self, outbox_id: str, error: str) -> None:
		now_dt = datetime.now(timezone.utc)
		with self._connect() as connection:
			row = connection.execute("SELECT attempt_count FROM outbox WHERE outbox_id = ?", (outbox_id,)).fetchone()
			if row is None:
				return
			attempt = int(row["attempt_count"]) + 1
			delay = min(300, 2 ** min(attempt, 8))
			next_attempt = (now_dt.timestamp() + delay)
			next_iso = datetime.fromtimestamp(next_attempt, tz=timezone.utc).isoformat().replace("+00:00", "Z")
			connection.execute(
				"""
				UPDATE outbox SET attempt_count = ?, last_attempt_at = ?, next_attempt_at = ?, last_error = ?
				WHERE outbox_id = ?
				""",
				(attempt, utc_now(), next_iso, str(error)[:500], outbox_id),
			)

	def outbox_summary(self) -> dict[str, Any]:
		with self._connect() as connection:
			row = connection.execute(
				"""
				SELECT sum(CASE WHEN delivered_at IS NULL THEN 1 ELSE 0 END) AS pending,
				max(CASE WHEN kind = 'heartbeat' THEN delivered_at END) AS last_heartbeat
				FROM outbox
				"""
			).fetchone()
		return {"pending": int(row["pending"] or 0), "last_heartbeat": row["last_heartbeat"]}

	def _contains_secret(self, value: Any) -> bool:
		markers = ("password", "secret", "token", "credential", "passphrase")
		if isinstance(value, dict):
			for key, item in value.items():
				if any(marker in str(key).lower() for marker in markers) and item not in (None, "", "<redacted>", False):
					return True
				if self._contains_secret(item):
					return True
		elif isinstance(value, (list, tuple)):
			return any(self._contains_secret(item) for item in value)
		return False

	def _append_event(
		self,
		connection: sqlite3.Connection,
		local_job_id: str,
		state: str,
		message: str,
		progress: dict[str, Any] | None,
		timestamp: str,
	) -> None:
		row = connection.execute(
			"SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM local_job_events WHERE local_job_id = ?",
			(local_job_id,),
		).fetchone()
		connection.execute(
			"INSERT INTO local_job_events(local_job_id, sequence, state, timestamp, message, progress_json) VALUES (?, ?, ?, ?, ?, ?)",
			(local_job_id, int(row["next_sequence"]), state, timestamp, message, self._dump(progress)),
		)

	def _row_to_job(self, row: sqlite3.Row, events: list[sqlite3.Row]) -> dict[str, Any]:
		payload = dict(row)
		payload["dry_run"] = bool(payload["dry_run"])
		for column in self._JSON_COLUMNS:
			payload[column.removesuffix("_json")] = self._load(payload.pop(column))
		payload.pop("normalized_target", None)
		payload.pop("authorization_metadata", None)
		payload["state_history"] = [
			{
				"sequence": int(event["sequence"]),
				"state": event["state"],
				"timestamp": event["timestamp"],
				"message": event["message"],
				"progress": self._load(event["progress_json"]),
			}
			for event in events
		]
		return payload

	def _dump(self, value: Any) -> str | None:
		return None if value is None else json.dumps(value, sort_keys=True, separators=(",", ":"))

	def _load(self, value: str | None) -> Any:
		return None if value is None else json.loads(value)
