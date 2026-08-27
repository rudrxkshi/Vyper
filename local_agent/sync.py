from __future__ import annotations

import hashlib
import json
import logging
import os
import platform as platform_module
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid4, uuid5

from vyper_version import __version__

import httpx

from agent.discovery import DeviceDiscovery

from .storage import LocalJobStore, TERMINAL_STATES, utc_now
from .identity import Ed25519IdentityStore, endpoint_identity_fingerprint
from .command_verifier import canonical_command, verify_remote_command


AGENT_PROTOCOL_VERSION = "1"
ORPHANED_CENTRAL_JOB_DETAIL = "Central job not found for authenticated agent."
logger = logging.getLogger(__name__)


def _normalize_inventory_value(value: Any) -> Any:
	"""Return a deterministic inventory representation without volatile data."""
	if isinstance(value, dict):
		return {key: _normalize_inventory_value(value[key]) for key in sorted(value)}
	if isinstance(value, list):
		normalized = [_normalize_inventory_value(item) for item in value]
		return sorted(
			normalized,
			key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
		)
	return value


def _safe_sync_error(exc: Exception) -> str:
	if isinstance(exc, httpx.HTTPStatusError):
		return f"Central returned HTTP {exc.response.status_code}."
	if isinstance(exc, httpx.TimeoutException):
		return "Central request timed out."
	if isinstance(exc, httpx.RequestError):
		return "Central request failed."
	message = " ".join(str(exc).split()).strip()
	if message.startswith("Remote command validation failed:"):
		return "Remote command validation failed."
	if message in {
		"Local agent is not enrolled.",
		"Central returned an incompatible agent protocol version.",
		"Central job assignment did not contain a signed command.",
		"Remote command identity does not match its job reference.",
	}:
		return message
	if message.startswith("Remote command is missing required "):
		return "Remote command is missing a required field."
	return "Operation failed; exception detail omitted."


class AgentCredentialStore:
	def __init__(self, path: str | Path) -> None:
		self.path = Path(path)

	def save(self, credential: dict[str, str]) -> None:
		self.path.parent.mkdir(parents=True, exist_ok=True)
		payload = json.dumps(credential, sort_keys=True, separators=(",", ":")).encode("utf-8")
		flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
		fd = os.open(self.path, flags, 0o600)
		try:
			view = memoryview(payload)
			while view:
				written = os.write(fd, view)
				if written <= 0:
					raise OSError("Credential write did not make progress.")
				view = view[written:]
			os.fsync(fd)
		finally:
			os.close(fd)
			try:
				os.chmod(self.path, 0o600)
			except OSError:
				pass

	def load(self) -> dict[str, str] | None:
		try:
			payload = json.loads(self.path.read_text(encoding="utf-8"))
		except (OSError, ValueError):
			return None
		if not isinstance(payload, dict) or not payload.get("agent_id") or not payload.get("agent_token"):
			return None
		return {str(key): str(value) for key, value in payload.items()}


def hardware_identity(device: dict[str, Any], agent_id: str) -> str:
	capabilities = device.get("capabilities") if isinstance(device.get("capabilities"), dict) else {}
	for key in ("nvme_nguid", "nvme_eui64", "wwn"):
		value = str(device.get(key) or capabilities.get(key) or "").strip().lower()
		if value:
			return hashlib.sha256(f"{key}:{value}".encode("utf-8")).hexdigest()
	serial = str(device.get("serial_number") or "").strip().lower()
	model = str(device.get("model") or "").strip().lower()
	size = str(device.get("size_bytes") or "")
	stable = f"serial:{serial}|model:{model}|size:{size}" if serial else (
		f"fallback:{agent_id}|model:{model}|size:{size}|type:{device.get('device_type') or ''}|path:{device.get('device_path') or ''}"
	)
	return hashlib.sha256(stable.encode("utf-8")).hexdigest()


class CentralSyncClient:
	"""Outbound-only central protocol client with a durable SQLite outbox."""

	def __init__(
		self,
		*,
		central_url: str,
		credential_store: AgentCredentialStore,
		identity_store: Ed25519IdentityStore | None = None,
		job_store: LocalJobStore,
		discovery: DeviceDiscovery,
		submit_local_job: Callable[..., str],
		transport: httpx.BaseTransport | None = None,
		timeout: float = 10.0,
		auto_run_dry_run: bool = True,
	) -> None:
		self.central_url = central_url.rstrip("/")
		self.credential_store = credential_store
		self.identity_store = identity_store or Ed25519IdentityStore(credential_store.path.with_name("agent_identity.pem"))
		self.job_store = job_store
		self.discovery = discovery
		self.submit_local_job = submit_local_job
		self.transport = transport
		self.timeout = timeout
		self.auto_run_dry_run = auto_run_dry_run
		self._approval_lock = threading.Lock()

	def enroll(self, enrollment_token: str, *, display_name: str | None = None) -> dict[str, Any]:
		identity = self.identity_store.load_or_create()
		payload = {
			"enrollment_token": enrollment_token,
			"display_name": display_name,
			"hostname": socket.gethostname(),
			"platform": platform_module.system(),
			"architecture": platform_module.machine(),
			"agent_version": os.getenv("VYPER_AGENT_VERSION", __version__),
			"api_version": "2",
			"agent_protocol_version": AGENT_PROTOCOL_VERSION,
			"device_public_key_pem": identity.public_key_pem,
			"device_public_key_id": identity.public_key_id,
			"identity_fingerprint": endpoint_identity_fingerprint(identity),
		}
		with self._client(authenticated=False) as client:
			response = client.post("/agents/enroll", json=payload)
			response.raise_for_status()
			credential = response.json()
		if not credential.get("command_verification_key_pem") or not credential.get("command_verification_key_id"):
			raise RuntimeError("Central enrollment response did not include a command verification key.")
		self.credential_store.save(credential)
		return {"agent_id": credential["agent_id"], "agent_protocol_version": credential["agent_protocol_version"]}

	def status(self) -> dict[str, Any]:
		credential = self.credential_store.load()
		outbox = self.job_store.outbox_summary()
		return {
			"configured": True,
			"enrolled": credential is not None,
			"agent_id": credential.get("agent_id") if credential else None,
			"central_url": self.central_url,
			"outbox_pending": outbox["pending"],
			"outbox_abandoned": outbox["abandoned"],
			"last_heartbeat": outbox["last_heartbeat"],
			"agent_protocol_version": AGENT_PROTOCOL_VERSION,
		}

	def queue_heartbeat(self) -> bool:
		credential = self._credential()
		active = len([job for job in self.job_store.list_jobs(limit=500) if job["job_state"] not in TERMINAL_STATES])
		payload = {
			"agent_version": os.getenv("VYPER_AGENT_VERSION", __version__),
			"api_version": "2",
			"agent_protocol_version": AGENT_PROTOCOL_VERSION,
			"hostname": socket.gethostname(),
			"platform": platform_module.system(),
			"architecture": platform_module.machine(),
			"local_status": "READY",
			"active_job_count": active,
		}
		bucket = int(time.time() // 30)
		return self.job_store.enqueue_outbox(
			outbox_id=str(uuid4()), kind="heartbeat", idempotency_key=f"heartbeat:{credential['agent_id']}:{bucket}", payload=payload,
		)

	def queue_inventory(self) -> bool:
		credential = self._credential()
		devices = _normalize_inventory_value([device.to_dict() for device in self.discovery.discover()])
		canonical = json.dumps(devices, sort_keys=True, separators=(",", ":"))
		version = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
		payload = {
			"agent_protocol_version": AGENT_PROTOCOL_VERSION,
			"inventory_version": version,
			"observed_at": utc_now(),
			"devices": devices,
		}
		return self.job_store.enqueue_inventory_snapshot(
			outbox_id=str(uuid4()), agent_id=credential["agent_id"], inventory_version=version, payload=payload,
		)

	def poll_job(self) -> dict[str, Any] | None:
		with self._client() as client:
			response = client.get("/agent/jobs/next")
			if response.status_code == 204:
				return None
			response.raise_for_status()
			payload = response.json()
			if payload.get("agent_protocol_version") != AGENT_PROTOCOL_VERSION:
				raise RuntimeError("Central returned an incompatible agent protocol version.")
			request = self._verify_and_record_command(payload)
			# Acknowledge only after the signed assignment is durably committed locally.
			acknowledgement = client.post(f"/agent/jobs/{payload['central_job_id']}/delivery-ack")
			acknowledgement.raise_for_status()
		if payload.get("execution_mode", "normal_local") == "normal_local" and request["dry_run"] and self.auto_run_dry_run and request["local_job_id"] is None:
			self.approve_remote_job(request["central_job_id"], local_approved=False)
		return self.job_store.get_remote_request(payload["central_job_id"])

	def _verify_and_record_command(self, payload: dict[str, Any]) -> dict[str, Any]:
		credential = self._credential()
		command = payload.get("command")
		if not isinstance(command, dict):
			raise RuntimeError("Central job assignment did not contain a signed command.")
		try:
			verify_remote_command(
				command, agent_id=credential["agent_id"],
				public_key_pem=credential["command_verification_key_pem"],
			)
		except Exception as exc:
			raise RuntimeError(f"Remote command validation failed: {exc}") from exc
		parameters = command["parameters"]
		if str(parameters.get("central_job_id") or "") != str(command["command_id"]):
			raise RuntimeError("Remote command identity does not match its job reference.")
		assignment = {
			"central_job_id": command["command_id"], "target_identity": parameters.get("target_identity"),
			"requested_target": parameters.get("requested_target"), "dry_run": parameters.get("dry_run"),
			"authorization_policy": command.get("authorization") or {}, "expires_at": command["expires_at"],
			"idempotency_key": parameters.get("idempotency_key"), "nonce": command["nonce"],
			"status": payload.get("status"), "execution_mode": parameters.get("execution_mode", "normal_local"),
			"command": command,
		}
		for field in ("target_identity", "requested_target", "idempotency_key"):
			if not assignment[field]:
				raise RuntimeError(f"Remote command is missing required {field}.")
		self.job_store.record_remote_command(
			command_id=str(command["command_id"]), nonce=str(command["nonce"]),
			command_hash=hashlib.sha256(canonical_command(command)).hexdigest(),
		)
		return self.job_store.save_remote_request(assignment)

	def approve_remote_job(self, central_job_id: str, *, local_approved: bool, ata_password: str | None = None) -> str:
		with self._approval_lock:
			return self._approve_remote_job(
				central_job_id, local_approved=local_approved, ata_password=ata_password,
			)

	def _approve_remote_job(self, central_job_id: str, *, local_approved: bool, ata_password: str | None = None) -> str:
		request = self.job_store.get_remote_request(central_job_id)
		if request is None:
			raise KeyError("Remote job request not found.")
		if request["local_job_id"]:
			return str(request["local_job_id"])
		if (request.get("payload") or {}).get("execution_mode") == "boot_sanitize":
			raise RuntimeError(
				"System-disk boot jobs cannot enter the normal local worker. Prepare the authenticated "
				"one-shot boot handoff with 'vyper system-disk prepare --central-job-id <id>'."
			)
		if not request["dry_run"] and (not request["central_approved"] or not local_approved):
			raise PermissionError("Destructive remote jobs require separate central and local approval.")
		if request["expires_at"] <= utc_now():
			raise RuntimeError("Remote job request has expired.")
		credential = self._credential()
		devices = [device.to_dict() for device in self.discovery.discover()]
		device = next((item for item in devices if item["device_path"] == request["requested_target"]), None)
		if device is None:
			raise RuntimeError("Remote target no longer exists.")
		if hardware_identity(device, credential["agent_id"]) != request["target_identity"]:
			raise RuntimeError("Remote target identity no longer matches current discovery.")
		if device.get("is_system_device") is not False or device.get("profile_error"):
			raise RuntimeError("Remote target safety state changed; execution is blocked.")
		if not request["dry_run"] and (device.get("mounted") is not False or device.get("eligible_for_sanitization") is not True):
			raise RuntimeError("Remote target is mounted or its sanitization eligibility is unknown; execution is blocked.")
		deterministic_local_job_id = str(uuid5(NAMESPACE_URL, f"vyper:{credential['agent_id']}:{central_job_id}"))
		local_job_id = self.submit_local_job(
			local_job_id=deterministic_local_job_id,
			target=request["requested_target"],
			dry_run=request["dry_run"],
			authorized=request["dry_run"] or local_approved,
			ata_password=ata_password,
		)
		if not self.job_store.map_remote_job(central_job_id, local_job_id, local_approved=local_approved):
			mapped = self.job_store.get_remote_request(central_job_id)
			return str(mapped["local_job_id"])
		return local_job_id

	def queue_job_updates(self) -> int:
		queued = 0
		for request in self.job_store.list_remote_requests():
			local_job_id = request.get("local_job_id")
			if not local_job_id:
				continue
			job = self.job_store.get_job(local_job_id)
			if job is None:
				continue
			for event in job["state_history"]:
				payload = {"agent_protocol_version": AGENT_PROTOCOL_VERSION, "local_job_id": local_job_id, **event}
				queued += int(self.job_store.enqueue_outbox(
					outbox_id=str(uuid4()), kind="job_event", central_job_id=request["central_job_id"],
					local_job_id=local_job_id, sequence=event["sequence"],
					idempotency_key=f"event:{request['central_job_id']}:{event['sequence']}", payload=payload,
				))
			if job["final_status"] is not None:
				result_payload = {
					"agent_protocol_version": AGENT_PROTOCOL_VERSION,
					"idempotency_key": f"result:{request['central_job_id']}",
					"local_job_id": local_job_id,
					"job_state": job["job_state"], "final_status": job["final_status"],
					"created_at": job["created_at"], "started_at": job["started_at"], "finished_at": job["finished_at"],
					"profile": job["profile"], "policy": job["policy"], "execution": job["execution"],
					"verification": job["verification"], "evidence": job["evidence"], "certificate": job["certificate"],
					"state_history": job["state_history"], "error": job["error"],
				}
				queued += int(self.job_store.enqueue_outbox(
					outbox_id=str(uuid4()), kind="job_result", central_job_id=request["central_job_id"],
					local_job_id=local_job_id, idempotency_key=f"result:{request['central_job_id']}", payload=result_payload,
				))
		return queued

	def flush_outbox(self) -> int:
		delivered = 0
		for message in self.job_store.due_outbox():
			try:
				method, path = self._outbox_destination(message)
				with self._client() as client:
					response = client.request(method, path, json=message["payload"])
					if self._is_orphaned_central_job(message, response):
						self.job_store.mark_outbox_abandoned(
							message["outbox_id"], reason=ORPHANED_CENTRAL_JOB_DETAIL, http_status=404,
						)
						logger.warning(
							"Outbox delivery abandoned kind=%s central_job_id=%s http_status=404 "
							"retryable=false detail=%s",
							message["kind"], message.get("central_job_id"), ORPHANED_CENTRAL_JOB_DETAIL,
						)
						continue
					response.raise_for_status()
				self.job_store.mark_outbox_delivered(message["outbox_id"])
				delivered += 1
			except Exception as exc:
				status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
				detail = self._safe_central_detail(exc.response) if isinstance(exc, httpx.HTTPStatusError) else None
				diagnostic = type(exc).__name__
				if status_code is not None:
					diagnostic += f" HTTP {status_code}"
				if detail:
					diagnostic += f": {detail}"
				self.job_store.mark_outbox_failed(message["outbox_id"], diagnostic)
				logger.warning(
					"Outbox delivery failed kind=%s central_job_id=%s http_status=%s retryable=true detail=%s",
					message["kind"], message.get("central_job_id"), status_code, detail or type(exc).__name__,
				)
		return delivered

	@staticmethod
	def _safe_central_detail(response: httpx.Response) -> str | None:
		try:
			payload = response.json()
		except (ValueError, json.JSONDecodeError):
			return None
		detail = payload.get("detail") if isinstance(payload, dict) else None
		if not isinstance(detail, str):
			return None
		if any(marker in detail.lower() for marker in ("password", "secret", "token", "credential", "authorization")):
			return "<redacted>"
		return detail[:300]

	@classmethod
	def _is_orphaned_central_job(cls, message: dict[str, Any], response: httpx.Response) -> bool:
		return (
			message.get("kind") in {"job_event", "job_result"}
			and response.status_code == 404
			and cls._safe_central_detail(response) == ORPHANED_CENTRAL_JOB_DETAIL
		)

	def run_once(self) -> None:
		for operation, callback in (
			("queue_heartbeat", self.queue_heartbeat),
			("queue_inventory", self.queue_inventory),
			("poll_job", self.poll_job),
			("queue_job_updates", self.queue_job_updates),
			("flush_outbox", self.flush_outbox),
		):
			try:
				callback()
			except Exception as exc:
				logger.warning(
					"Central sync operation failed operation=%s exception=%s detail=%s",
					operation, type(exc).__name__, _safe_sync_error(exc),
				)

	def _outbox_destination(self, message: dict[str, Any]) -> tuple[str, str]:
		if message["kind"] == "heartbeat":
			return "POST", "/agent/heartbeat"
		if message["kind"] == "inventory":
			return "PUT", "/agent/inventory"
		if message["kind"] == "job_event":
			return "POST", f"/agent/jobs/{message['central_job_id']}/events"
		if message["kind"] == "job_result":
			return "POST", f"/agent/jobs/{message['central_job_id']}/result"
		raise ValueError("Unknown outbox message kind.")

	def _credential(self) -> dict[str, str]:
		credential = self.credential_store.load()
		if credential is None:
			raise RuntimeError("Local agent is not enrolled.")
		return credential

	def _client(self, *, authenticated: bool = True) -> httpx.Client:
		headers = {"User-Agent": "vyper-local-sync"}
		if authenticated:
			headers["Authorization"] = f"Bearer {self._credential()['agent_token']}"
		return httpx.Client(base_url=self.central_url, headers=headers, timeout=self.timeout, transport=self.transport)


class SyncLoop:
	def __init__(
		self,
		client: CentralSyncClient,
		*,
		interval_seconds: float = 5.0,
		heartbeat_interval_seconds: float = 30.0,
		inventory_interval_seconds: float = 60.0,
	) -> None:
		self.client = client
		self.interval_seconds = max(2.0, interval_seconds)
		self.heartbeat_interval_seconds = max(self.interval_seconds, heartbeat_interval_seconds)
		self.inventory_interval_seconds = max(self.interval_seconds, inventory_interval_seconds)
		self.stop_event = threading.Event()
		self.thread: threading.Thread | None = None
		self._failure_log_times: dict[tuple[str, str, str], float] = {}
		self.failure_log_interval_seconds = 60.0

	def start(self) -> None:
		if self.thread and self.thread.is_alive():
			return
		self.thread = threading.Thread(target=self._run, name="vyper-central-sync", daemon=True)
		self.thread.start()

	def stop(self) -> None:
		self.stop_event.set()
		if self.thread:
			self.thread.join(timeout=2)

	def _attempt(self, operation: str, callback: Callable[[], Any], *, now: float) -> bool:
		try:
			callback()
			return True
		except Exception as exc:
			detail = _safe_sync_error(exc)
			key = (operation, type(exc).__name__, detail)
			last_logged = self._failure_log_times.get(key)
			if last_logged is None or now - last_logged >= self.failure_log_interval_seconds:
				logger.warning(
					"Central sync operation failed operation=%s exception=%s detail=%s",
					operation, type(exc).__name__, detail,
				)
				self._failure_log_times[key] = now
			return False

	def _run_iteration(self, *, now: float, next_heartbeat: float, next_inventory: float) -> tuple[float, float]:
		if now >= next_heartbeat and self._attempt("queue_heartbeat", self.client.queue_heartbeat, now=now):
			next_heartbeat = now + self.heartbeat_interval_seconds
		if now >= next_inventory and self._attempt("queue_inventory", self.client.queue_inventory, now=now):
			next_inventory = now + self.inventory_interval_seconds
		self._attempt("poll_job", self.client.poll_job, now=now)
		self._attempt("queue_job_updates", self.client.queue_job_updates, now=now)
		self._attempt("flush_outbox", self.client.flush_outbox, now=now)
		return next_heartbeat, next_inventory

	def _run(self) -> None:
		next_heartbeat = 0.0
		next_inventory = 0.0
		while not self.stop_event.is_set():
			now = time.monotonic()
			next_heartbeat, next_inventory = self._run_iteration(
				now=now, next_heartbeat=next_heartbeat, next_inventory=next_inventory,
			)
			self.stop_event.wait(self.interval_seconds)
