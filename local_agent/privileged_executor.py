from __future__ import annotations

import errno
import json
import logging
import os
import re
import socket
import struct
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

from fastapi.encoders import jsonable_encoder

from agent.agent import VYPERAgent
from agent.discovery import DeviceDiscovery
from agent.profiler import DeviceProfiler

from .jobs import redact, result_payload


PROTOCOL_VERSION = "1"
MAX_REQUEST_BYTES = 64 * 1024
ALLOWED_OPERATIONS = {"discover", "profile", "sanitize"}
TARGET_PATTERN = re.compile(r"^/dev/[A-Za-z0-9._/+:-]+$")
logger = logging.getLogger("vyper.privileged_executor")


class ExecutorProtocolError(ValueError):
	pass


def _target(value: Any) -> str:
	target = str(value or "")
	if not TARGET_PATTERN.fullmatch(target) or (os.name != "nt" and not os.path.realpath(target).startswith("/dev/")):
		raise ExecutorProtocolError("Target must be an absolute block-device path under /dev.")
	return target


def validate_request(payload: Any) -> dict[str, Any]:
	if not isinstance(payload, dict) or set(payload) - {"version", "request_id", "operation", "target", "dry_run", "authorization", "execution_mode"}:
		raise ExecutorProtocolError("Malformed executor request schema.")
	if payload.get("version") != PROTOCOL_VERSION:
		raise ExecutorProtocolError("Unsupported executor protocol version.")
	try:
		UUID(str(payload.get("request_id")))
	except ValueError as exc:
		raise ExecutorProtocolError("request_id must be a UUID.") from exc
	operation = str(payload.get("operation") or "")
	if operation not in ALLOWED_OPERATIONS:
		raise ExecutorProtocolError("Unknown privileged operation.")
	if operation in {"profile", "sanitize"}:
		payload["target"] = _target(payload.get("target"))
	mode = str(payload.get("execution_mode") or "normal_local")
	if mode not in {"normal_local", "boot_sanitize"}:
		raise ExecutorProtocolError("Unknown execution mode.")
	if operation == "sanitize":
		if not isinstance(payload.get("dry_run"), bool):
			raise ExecutorProtocolError("sanitize requires a boolean dry_run field.")
		authorization = payload.get("authorization")
		if not isinstance(authorization, dict) or set(authorization) - {"approved", "ata_password"}:
			raise ExecutorProtocolError("Malformed sanitization authorization.")
		if authorization.get("approved") is not True and payload["dry_run"] is not True:
			raise ExecutorProtocolError("Destructive execution requires explicit authorization.")
	return payload


@dataclass
class PrivilegedExecutor:
	dry_run_only: bool = False
	execution_mode: str = "normal_local"

	def __post_init__(self) -> None:
		self._targets: set[str] = set()
		self._lock = threading.Lock()

	def dispatch(
		self,
		raw: bytes,
		*,
		peer_uid: int | None = None,
		peer_gid: int | None = None,
		event_callback: Callable[[Any], None] | None = None,
		stage_callback: Callable[[str], None] | None = None,
		progress_callback: Callable[[Any], None] | None = None,
	) -> dict[str, Any]:
		if len(raw) > MAX_REQUEST_BYTES:
			raise ExecutorProtocolError("Executor request exceeds the size limit.")
		try:
			request = validate_request(json.loads(raw.decode("utf-8")))
		except (UnicodeDecodeError, json.JSONDecodeError) as exc:
			raise ExecutorProtocolError("Executor request is not valid JSON.") from exc
		if request.get("execution_mode", "normal_local") != self.execution_mode:
			raise ExecutorProtocolError("Execution mode does not match the privileged helper mode.")
		operation = request["operation"]
		target = request.get("target")
		log = {"timestamp": datetime.now(timezone.utc).isoformat(), "request_id": request["request_id"],
			"operation": operation, "target": target, "peer_uid": peer_uid, "peer_gid": peer_gid}
		logger.info(json.dumps(redact(log), sort_keys=True))
		if operation == "discover":
			return {"version": PROTOCOL_VERSION, "request_id": request["request_id"],
				"result": [item.to_dict() for item in DeviceDiscovery().discover()]}
		if operation == "profile":
			return {"version": PROTOCOL_VERSION, "request_id": request["request_id"],
				"result": result_payload(DeviceProfiler(dry_run=True).profile(target))}
		with self._lock:
			if target in self._targets:
				raise ExecutorProtocolError("The target already has an active privileged operation.")
			self._targets.add(target)
		try:
			effective_dry_run = bool(request["dry_run"]) or self.dry_run_only
			result = VYPERAgent(dry_run=effective_dry_run).sanitize_device(
				target,
				authorization=request["authorization"],
				dry_run=effective_dry_run,
				event_callback=event_callback,
				stage_callback=stage_callback,
				progress_callback=progress_callback,
			)
			payload = result_payload(result)
			execution = payload.get("execution") if isinstance(payload, dict) else None
			policy = payload.get("policy") if isinstance(payload, dict) else None
			completion = {
				"timestamp": datetime.now(timezone.utc).isoformat(),
				"request_id": request["request_id"],
				"operation": operation,
				"target": target,
				"peer_uid": peer_uid,
				"peer_gid": peer_gid,
				"selected_pathway": policy.get("selected_pathway") if isinstance(policy, dict) else None,
				"controller_target": execution.get("controller_target") if isinstance(execution, dict) else None,
				"command": execution.get("command") if isinstance(execution, dict) else None,
				"result_status": payload.get("final_status") if isinstance(payload, dict) else None,
			}
			logger.info(json.dumps(redact(completion), sort_keys=True))
			return {"version": PROTOCOL_VERSION, "request_id": request["request_id"], "result": payload}
		finally:
			request["authorization"].clear()
			with self._lock:
				self._targets.discard(target)


class PrivilegedExecutorClient:
	def __init__(self, socket_path: str | Path, *, timeout: float = 30.0, execution_mode: str = "normal_local") -> None:
		self.socket_path = str(socket_path); self.timeout = timeout; self.execution_mode = execution_mode

	def sanitize_device(
		self,
		target: str,
		authorization: dict[str, Any],
		dry_run: bool = False,
		*,
		event_callback: Callable[[Any], None] | None = None,
		stage_callback: Callable[[str], None] | None = None,
		progress_callback: Callable[[Any], None] | None = None,
	) -> dict[str, Any]:
		return self.request(
			"sanitize",
			target=target,
			dry_run=bool(dry_run),
			authorization=dict(authorization),
			event_callback=event_callback,
			stage_callback=stage_callback,
			progress_callback=progress_callback,
		)

	def request(
		self,
		operation: str,
		*,
		event_callback: Callable[[Any], None] | None = None,
		stage_callback: Callable[[str], None] | None = None,
		progress_callback: Callable[[Any], None] | None = None,
		**fields: Any,
	) -> Any:
		payload = {"version": PROTOCOL_VERSION, "request_id": str(uuid4()), "operation": operation,
			"execution_mode": self.execution_mode, **fields}
		data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
		if len(data) > MAX_REQUEST_BYTES:
			raise ExecutorProtocolError("Executor request exceeds the size limit.")
		with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
			client.settimeout(self.timeout); client.connect(self.socket_path); client.sendall(data)
			if operation == "sanitize":
				client.settimeout(None)
			response = bytearray()
			while True:
				chunk = client.recv(8192)
				if not chunk or len(response) + len(chunk) > MAX_REQUEST_BYTES:
					raise ExecutorProtocolError("Invalid executor response.")
				response.extend(chunk)
				while b"\n" in response:
					line, remainder = bytes(response).split(b"\n", 1)
					response = bytearray(remainder)
					decoded = json.loads(line)
					if "event" in decoded:
						self._deliver_event(
							decoded["event"],
							event_callback=event_callback,
							stage_callback=stage_callback,
							progress_callback=progress_callback,
						)
						continue
					if decoded.get("error"):
						raise ExecutorProtocolError(str(decoded["error"]))
					return decoded.get("result")

	@staticmethod
	def _deliver_event(
		event: Any,
		*,
		event_callback: Callable[[Any], None] | None,
		stage_callback: Callable[[str], None] | None,
		progress_callback: Callable[[Any], None] | None,
	) -> None:
		if not isinstance(event, dict):
			raise ExecutorProtocolError("Malformed executor event frame.")
		kind = event.get("kind")
		value = event.get("value")
		callback = {"state": event_callback, "stage": stage_callback, "progress": progress_callback}.get(kind)
		if kind not in {"state", "stage", "progress"}:
			raise ExecutorProtocolError("Unknown executor event frame.")
		if callback is not None:
			try:
				callback(value)
			except Exception as exc:
				logger.warning("Executor event callback failed kind=%s exception=%s", kind, type(exc).__name__)


def peer_credentials(connection: socket.socket) -> tuple[int | None, int | None]:
	if not hasattr(socket, "SO_PEERCRED"):
		return None, None
	pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
	return uid, gid


def _send_response(connection: socket.socket, response: dict[str, Any]) -> bool:
	data = json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
	try:
		connection.sendall(data)
	except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
		logger.warning("Executor client disconnected before response delivery: %s", type(exc).__name__)
		return False
	except OSError as exc:
		if exc.errno not in {errno.EPIPE, errno.ECONNRESET, errno.ECONNABORTED}:
			raise
		logger.warning("Executor client disconnected before response delivery: %s", type(exc).__name__)
		return False
	return True


def _send_event(connection: socket.socket, kind: str, value: Any) -> None:
	_send_response(connection, {"version": PROTOCOL_VERSION, "event": {"kind": kind, "value": jsonable_encoder(value)}})


def serve(socket_path: str | Path, *, group_gid: int | None = None, dry_run_only: bool = False) -> None:
	path = Path(socket_path)
	path.parent.mkdir(parents=True, exist_ok=True); os.chmod(path.parent, 0o750)
	if path.exists(): path.unlink()
	executor = PrivilegedExecutor(dry_run_only=dry_run_only,
		execution_mode=os.getenv("VYPER_EXECUTION_MODE", "normal_local"))
	with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
		server.bind(str(path)); os.chmod(path, 0o660)
		if group_gid is not None: os.chown(path, 0, group_gid)
		server.listen(16)
		while True:
			connection, _ = server.accept()
			with connection:
				uid, gid = peer_credentials(connection)
				raw = bytearray()
				while b"\n" not in raw and len(raw) <= MAX_REQUEST_BYTES:
					chunk = connection.recv(8192)
					if not chunk: break
					raw.extend(chunk)
				try:
					response = executor.dispatch(
						bytes(raw).split(b"\n", 1)[0],
						peer_uid=uid,
						peer_gid=gid,
						event_callback=lambda state: _send_event(connection, "state", getattr(state, "value", state)),
						stage_callback=lambda event: _send_event(connection, "stage", event),
						progress_callback=lambda progress: _send_event(connection, "progress", progress),
					)
				except Exception as exc:
					response = {"version": PROTOCOL_VERSION, "error": f"{type(exc).__name__}: {exc}"}
				_send_response(connection, response)


def main() -> None:
	import grp
	path = os.getenv("VYPER_EXECUTOR_SOCKET", "/run/vyper/executor.sock")
	group = os.getenv("VYPER_EXECUTOR_GROUP", "vyper-executor")
	gid = grp.getgrnam(group).gr_gid
	serve(path, group_gid=gid, dry_run_only=os.getenv("VYPER_EXECUTOR_DRY_RUN", "false").lower() in {"1", "true", "yes"})


if __name__ == "__main__":
	main()
