from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

from fastapi.encoders import jsonable_encoder

from agent.agent import VYPERAgent
from agent.command_runner import CommandExecutor, SubprocessCommandExecutor
from agent.discovery import DeviceDiscovery
from agent.policy import PolicyEngine

from .jobs import redact, result_payload


BOOT_JOB_VERSION = "1"
BOOT_ENVIRONMENT_VERSION = "0.8.0-rc1"
TERMINAL_BOOT_STATES = {"VERIFIED", "FAILED", "INCONCLUSIVE", "CANCELLED", "EXPIRED"}


class ExecutionMode(str, Enum):
	NORMAL_LOCAL_MODE = "normal_local"
	BOOT_SANITIZE_MODE = "boot_sanitize"


class BootJobError(RuntimeError):
	pass


class BootIntegrityError(BootJobError):
	pass


class BootTargetValidationError(BootJobError):
	pass


def utc_now() -> datetime:
	return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
	return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
	return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
	return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_file(path: str | Path) -> str:
	digest = hashlib.sha256()
	with Path(path).open("rb") as handle:
		for chunk in iter(lambda: handle.read(1024 * 1024), b""):
			digest.update(chunk)
	return digest.hexdigest()


def _text(value: Any) -> str | None:
	text = str(value or "").strip()
	return text or None


def device_identifiers(device: dict[str, Any]) -> dict[str, Any]:
	capabilities = device.get("capabilities") if isinstance(device.get("capabilities"), dict) else {}
	def value(*names: str):
		for name in names:
			candidate = _text(device.get(name) or capabilities.get(name))
			if candidate:
				return candidate.lower()
		return None
	return {
		"nvme_nguid": value("nvme_nguid", "nguid"),
		"nvme_eui64": value("nvme_eui64", "eui64", "eui"),
		"wwn": value("wwn"),
		"serial_number": value("serial_number", "serial"),
		"model": value("model"),
		"size_bytes": int(device["size_bytes"]) if device.get("size_bytes") is not None else None,
		"device_type": _text(device.get("device_type")),
	}


def identity_confidence(identifiers: dict[str, Any]) -> str:
	if any(identifiers.get(key) for key in ("nvme_nguid", "nvme_eui64", "wwn")):
		return "HIGH"
	if identifiers.get("serial_number") and identifiers.get("model") and identifiers.get("size_bytes"):
		return "MEDIUM"
	return "LOW"


def identity_matches(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
	for key in ("size_bytes", "device_type"):
		if expected.get(key) is not None and expected.get(key) != observed.get(key):
			return False
	for key in ("nvme_nguid", "nvme_eui64", "wwn"):
		if expected.get(key):
			return expected.get(key) == observed.get(key)
	keys = ("serial_number", "model", "size_bytes")
	return all(expected.get(key) is not None and expected.get(key) == observed.get(key) for key in keys)


@dataclass(frozen=True)
class BootTarget:
	device_path: str
	device: dict[str, Any]
	identifiers: dict[str, Any]
	confidence: str


class SafetyInspector(Protocol):
	def inspect(self, target: str) -> dict[str, Any]: ...


class LinuxSafetyInspector:
	"""Read-only boot-mode topology checks. Missing/ambiguous data stays unknown."""
	def __init__(self, command_executor: CommandExecutor | None = None, *, sysfs_root: str | Path = "/sys") -> None:
		self.command_executor = command_executor or SubprocessCommandExecutor()
		self.sysfs_root = Path(sysfs_root)

	def inspect(self, target: str) -> dict[str, Any]:
		lsblk = self._run(["lsblk", "--json", "--output", "PATH,TYPE,FSTYPE,MOUNTPOINTS", target])
		swap = self._run(["swapon", "--show", "--noheadings", "--raw", "--output", "NAME"])
		root = self._run(["findmnt", "--json", "--target", "/", "--output", "SOURCE,TARGET,FSTYPE"])
		lvm = self._run(["pvs", "--reportformat", "json", "--options", "pv_name"])
		name = Path(target).name
		holders_path = self.sysfs_root / "class" / "block" / name / "holders"
		try:
			holders = sorted(item.name for item in holders_path.iterdir()) if holders_path.exists() else []
		except OSError:
			holders = None
		return {
			"lsblk": self._json(lsblk), "swap_devices": self._lines(swap), "root": self._json(root),
			"lvm": self._json(lvm), "holders": holders,
			"commands_known": all(item is not None for item in (lsblk, swap, root, lvm)),
		}

	def _run(self, command: list[str]):
		try:
			result = self.command_executor.run(command, timeout=15)
		except (OSError, FileNotFoundError):
			return None
		return result.stdout if result.success and result.exit_code == 0 else None

	def _json(self, value: str | None):
		try:
			return json.loads(value) if value is not None else None
		except (TypeError, json.JSONDecodeError):
			return None

	def _lines(self, value: str | None):
		return None if value is None else [line.strip() for line in value.splitlines() if line.strip()]


def validate_safety(target: BootTarget, safety: dict[str, Any]) -> list[str]:
	if not safety.get("commands_known"):
		raise BootTargetValidationError("Required boot safety state is unknown.")
	lsblk = safety.get("lsblk")
	if not isinstance(lsblk, dict):
		raise BootTargetValidationError("Target block topology could not be parsed.")
	nodes = lsblk.get("blockdevices")
	if not isinstance(nodes, list) or not nodes:
		raise BootTargetValidationError("Target was absent from boot block topology.")

	warnings: list[str] = []
	stack = list(nodes)
	while stack:
		node = stack.pop()
		stack.extend(node.get("children") or [])
		mounts = node.get("mountpoints") or ([] if node.get("mountpoint") is None else [node.get("mountpoint")])
		if any(_text(item) for item in mounts):
			raise BootTargetValidationError("Target or a child partition is mounted.")
		node_type = str(node.get("type") or "").lower()
		if node_type in {"raid", "md", "lvm", "crypt", "mpath", "dm"}:
			raise BootTargetValidationError(f"Unsupported active storage topology detected: {node_type}.")
		fstype = str(node.get("fstype") or "").lower()
		if fstype in {"linux_raid_member", "lvm2_member"}:
			raise BootTargetValidationError(f"Unsupported storage membership detected: {fstype}.")
		if fstype == "crypto_luks" or "bitlocker" in fstype:
			warnings.append(f"Encrypted data signature detected ({fstype}); data will not be unlocked.")

	swap_devices = safety.get("swap_devices")
	if swap_devices is None:
		raise BootTargetValidationError("Swap state is unknown.")
	if any(item == target.device_path or item.startswith(target.device_path) for item in swap_devices):
		raise BootTargetValidationError("Target backs active swap.")
	root = safety.get("root")
	if not isinstance(root, dict):
		raise BootTargetValidationError("Temporary root backing state is unknown.")
	for filesystem in root.get("filesystems") or []:
		source = str(filesystem.get("source") or "")
		if source == target.device_path or source.startswith(target.device_path):
			raise BootTargetValidationError("Target backs the active boot environment.")
	if safety.get("holders") is None:
		raise BootTargetValidationError("Open block-device holder state is unknown.")
	if safety.get("holders"):
		raise BootTargetValidationError("Target has active device-mapper, RAID, or other block holders.")
	lvm = safety.get("lvm")
	if not isinstance(lvm, dict):
		raise BootTargetValidationError("LVM membership state is unknown.")
	for report in lvm.get("report") or []:
		for pv in report.get("pv") or []:
			pv_name = str(pv.get("pv_name") or "")
			if pv_name == target.device_path or pv_name.startswith(target.device_path):
				raise BootTargetValidationError("Target participates in LVM and is unsupported by default.")
	return warnings


class BootJobStore:
	def __init__(self, root: str | Path, *, key_path: str | Path | None = None) -> None:
		self.root = Path(root)
		self.root.mkdir(parents=True, exist_ok=True)
		self.key_path = Path(key_path) if key_path else self.root / "job-mac.key"
		if not self.key_path.exists():
			self.key_path.write_bytes(secrets.token_bytes(32))
			os.chmod(self.key_path, 0o600)

	def create(self, *, device: dict[str, Any], boot_image_path: str | Path, central_job_id: str | None = None,
		agent_id: str | None = None, central_api_url: str | None = None, requested_method: str = "POLICY", dry_run: bool = False,
		expires_in_seconds: int = 3600) -> dict[str, Any]:
		identifiers = device_identifiers(device)
		confidence = identity_confidence(identifiers)
		if confidence == "LOW":
			raise BootJobError("System disk has no sufficiently stable identity; boot sanitization preparation stopped.")
		now = utc_now()
		boot_image_path = Path(boot_image_path)
		if not boot_image_path.is_file():
			raise BootJobError("Boot image is unavailable.")
		payload = {
			"schema_version": BOOT_JOB_VERSION, "boot_job_id": str(uuid4()), "central_job_id": central_job_id,
			"agent_id": agent_id, "central_api_url": central_api_url,
			"requested_asset_identity": hashlib.sha256(canonical_json(identifiers)).hexdigest(),
			"expected_device_identifiers": identifiers, "requested_method": requested_method, "dry_run": bool(dry_run),
			"created_at": iso(now), "expires_at": iso(now + timedelta(seconds=expires_in_seconds)),
			"authorization_state": "CENTRAL_APPROVED" if central_job_id else "LOCAL_PREPARED",
			"local_confirmation_state": "REQUIRED_IN_BOOT_ENVIRONMENT",
			"boot_image_version": BOOT_ENVIRONMENT_VERSION, "boot_image_sha256": sha256_file(boot_image_path),
			"job_nonce": secrets.token_urlsafe(32), "execution_mode": ExecutionMode.BOOT_SANITIZE_MODE.value,
			"ata_password_transfer": "NOT_STORED_REENTER_IN_BOOT_ENVIRONMENT",
		}
		document = self._sign(payload)
		job_dir = self.root / payload["boot_job_id"]
		job_dir.mkdir(mode=0o700)
		self._write(job_dir / "manifest.json", document, 0o600)
		state = {"status": "PREPARING_BOOT", "execution_attempted": False,
			"updated_at": iso(now), "events": [{"state": "PREPARING_BOOT", "timestamp": iso(now)}]}
		self._write(job_dir / "state.json", self._sign_state(payload["boot_job_id"], state), 0o600)
		return document

	def validate(self, boot_job_id: str, *, now: datetime | None = None) -> dict[str, Any]:
		document = json.loads((self.root / boot_job_id / "manifest.json").read_text(encoding="utf-8"))
		payload = document.get("payload")
		integrity = document.get("integrity")
		if not isinstance(payload, dict) or not isinstance(integrity, dict):
			raise BootIntegrityError("Boot job manifest shape is invalid.")
		expected = self._mac(payload)
		if integrity.get("algorithm") != "HMAC-SHA256" or not hmac.compare_digest(str(integrity.get("mac") or ""), expected):
			raise BootIntegrityError("Boot job manifest authentication failed.")
		if payload.get("boot_job_id") != boot_job_id or payload.get("execution_mode") != ExecutionMode.BOOT_SANITIZE_MODE.value:
			raise BootIntegrityError("Boot job identity or execution mode is invalid.")
		if parse_time(payload["expires_at"]) <= (now or utc_now()):
			self.transition(boot_job_id, "EXPIRED")
			raise BootJobError("Boot job has expired.")
		return document

	def state(self, boot_job_id: str) -> dict[str, Any]:
		document = json.loads((self.root / boot_job_id / "state.json").read_text(encoding="utf-8"))
		state = document.get("state")
		integrity = document.get("integrity")
		if not isinstance(state, dict) or not isinstance(integrity, dict):
			raise BootIntegrityError("Boot job state shape is invalid.")
		expected = self._state_mac(boot_job_id, state)
		if integrity.get("algorithm") != "HMAC-SHA256" or not hmac.compare_digest(str(integrity.get("mac") or ""), expected):
			raise BootIntegrityError("Boot job state authentication failed.")
		return state

	def transition(self, boot_job_id: str, status: str, **fields: Any) -> dict[str, Any]:
		state = self.state(boot_job_id)
		now = iso(utc_now())
		state.update(redact(fields))
		state["status"] = status
		state["updated_at"] = now
		state.setdefault("events", []).append({"state": status, "timestamp": now})
		self._write(self.root / boot_job_id / "state.json", self._sign_state(boot_job_id, state), 0o600)
		return state

	def begin_execution(self, boot_job_id: str) -> None:
		state = self.state(boot_job_id)
		if state.get("execution_attempted"):
			if state.get("status") not in TERMINAL_BOOT_STATES:
				self.transition(boot_job_id, "INCONCLUSIVE", error="Boot environment restarted after execution began; automatic replay refused.")
			raise BootJobError("Boot job nonce was already consumed; automatic replay is forbidden.")
		self.transition(boot_job_id, "RUNNING", execution_attempted=True, execution_started_at=iso(utc_now()))

	def cancel(self, boot_job_id: str) -> dict[str, Any]:
		state = self.state(boot_job_id)
		if state.get("execution_attempted"):
			raise BootJobError("A boot job cannot be cancelled after execution was attempted.")
		return self.transition(boot_job_id, "CANCELLED")

	def _sign(self, payload: dict[str, Any]) -> dict[str, Any]:
		return {"payload": payload, "integrity": {"algorithm": "HMAC-SHA256", "key_id": "local-boot-job-v1", "mac": self._mac(payload)}}

	def _mac(self, payload: dict[str, Any]) -> str:
		return hmac.new(self.key_path.read_bytes(), canonical_json(payload), hashlib.sha256).hexdigest()

	def _sign_state(self, boot_job_id: str, state: dict[str, Any]) -> dict[str, Any]:
		return {"state": state, "integrity": {"algorithm": "HMAC-SHA256", "key_id": "local-boot-job-v1",
			"mac": self._state_mac(boot_job_id, state)}}

	def _state_mac(self, boot_job_id: str, state: dict[str, Any]) -> str:
		payload = {"boot_job_id": boot_job_id, "state": state}
		return hmac.new(self.key_path.read_bytes(), canonical_json(payload), hashlib.sha256).hexdigest()

	def _write(self, path: Path, value: dict[str, Any], mode: int) -> None:
		temporary = path.with_suffix(path.suffix + ".tmp")
		temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
		os.chmod(temporary, mode)
		temporary.replace(path)


class BootSanitizeRuntime:
	def __init__(self, *, store: BootJobStore, discovery: DeviceDiscovery | Any,
		safety_inspector: SafetyInspector, agent: VYPERAgent | Any,
		result_directory: str | Path, upload_result: Callable[[dict[str, Any]], bool] | None = None,
		report_event: Callable[[str, int], None] | None = None,
		durable_result_storage: bool = False) -> None:
		self.store = store
		self.discovery = discovery
		self.safety_inspector = safety_inspector
		self.agent = agent
		self.result_directory = Path(result_directory)
		self.upload_result = upload_result
		self.report_event = report_event
		self.durable_result_storage = durable_result_storage

	def _transition(self, boot_job_id: str, status: str, **fields: Any) -> dict[str, Any]:
		state = self.store.transition(boot_job_id, status, **fields)
		if self.report_event:
			self.report_event(status, len(state.get("events") or []))
		return state

	def identify_target(self, document: dict[str, Any]) -> BootTarget:
		expected = document["payload"]["expected_device_identifiers"]
		matches = []
		for item in self.discovery.discover():
			device = item.to_dict() if hasattr(item, "to_dict") else dict(item)
			observed = device_identifiers(device)
			if identity_matches(expected, observed):
				matches.append(BootTarget(str(device["device_path"]), device, observed, identity_confidence(observed)))
		if not matches:
			raise BootTargetValidationError("No disk exactly matches the prepared stable identity.")
		if len(matches) != 1:
			raise BootTargetValidationError("Multiple disks match the prepared identity; execution stopped.")
		if matches[0].confidence == "LOW":
			raise BootTargetValidationError("Matched disk identity confidence is too low.")
		return matches[0]

	def validate_target(self, target: BootTarget) -> list[str]:
		if target.device.get("mounted") is not False:
			raise BootTargetValidationError("Target is mounted or mount state is unknown.")
		if target.device.get("is_system_device") is not False:
			raise BootTargetValidationError("Target backs the active boot environment or system association is unknown.")
		return validate_safety(target, self.safety_inspector.inspect(target.device_path))

	def confirmation_text(self, document: dict[str, Any], target: BootTarget) -> str:
		identifier = next((target.identifiers.get(key) for key in ("nvme_nguid", "nvme_eui64", "wwn", "serial_number") if target.identifiers.get(key)), "unavailable")
		return "\n".join([
			"SYSTEM DISK SANITIZATION", "", f"Device: {target.device_path}", f"Model: {target.identifiers.get('model') or 'Unknown'}",
			f"Serial/NGUID/WWN: {identifier}", f"Capacity: {target.identifiers.get('size_bytes') or 'Unknown'} bytes",
			f"Detected interface: {target.device.get('interface') or target.device.get('transport') or 'Unknown'}",
			f"Selected sanitization method: {document['payload']['requested_method']}", "",
			"WARNING: This operation will permanently destroy the operating system and all data on this disk.",
			f"Type ERASE {document['payload']['boot_job_id'][-8:]} to continue:",
		])

	def run(self, boot_job_id: str, *, confirmation: str, ata_password: str | None = None) -> dict[str, Any]:
		document = self.store.validate(boot_job_id)
		self._transition(boot_job_id, "BOOT_ENVIRONMENT_STARTED")
		target = self.identify_target(document)
		self._transition(boot_job_id, "VALIDATING_TARGET", observed_target=target.device_path,
			observed_identifiers=target.identifiers, identity_confidence=target.confidence)
		warnings = self.validate_target(target)
		self._transition(boot_job_id, "WAITING_LOCAL_APPROVAL", warnings=warnings)
		expected_confirmation = f"ERASE {boot_job_id[-8:]}"
		if confirmation != expected_confirmation:
			raise BootJobError("Fresh local boot-environment confirmation is required.")
		requested_method = str(document["payload"].get("requested_method") or "POLICY")
		if requested_method != "POLICY" and hasattr(self.agent, "profiler") and hasattr(self.agent, "policy_engine"):
			preflight_profile = self.agent.profiler.profile(target.device_path)
			requested_policy = PolicyEngine(dry_run=bool(document["payload"]["dry_run"]), policy=requested_method)
			decision = requested_policy.decide(preflight_profile)
			if decision.selected_pathway != requested_method:
				raise BootJobError(
					f"Prepared method {requested_method} does not match capability policy selection "
					f"{decision.selected_pathway or 'UNSUPPORTED'}; no substitution is allowed."
				)
			self.agent.policy_engine = requested_policy
		self.store.begin_execution(boot_job_id)
		if self.report_event:
			self.report_event("RUNNING", len(self.store.state(boot_job_id).get("events") or []))
		authorization = {"approved": True}
		if ata_password:
			authorization["ata_password"] = ata_password
		try:
			try:
				result = self.agent.sanitize_device(target.device_path, authorization=authorization,
					dry_run=bool(document["payload"]["dry_run"]))
				payload = result_payload(result, secrets=(ata_password or "",))
			except Exception as exc:
				self._transition(boot_job_id, "INCONCLUSIVE", error="Native engine exited without terminal evidence.")
				raise BootJobError("Native engine exited without terminal evidence; outcome is INCONCLUSIVE.") from exc
		finally:
			authorization.clear()
		status = str((payload.get("evidence") or {}).get("final_status") or payload.get("final_status") or payload.get("job_state") or "INCONCLUSIVE")
		if status not in {"VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"}:
			status = "INCONCLUSIVE"
		evidence = {
			"execution_environment": "boot_sanitize", "boot_job_id": boot_job_id,
			"central_job_id": document["payload"].get("central_job_id"),
			"boot_environment_version": BOOT_ENVIRONMENT_VERSION,
			"boot_image_sha256": document["payload"]["boot_image_sha256"],
			"target_identifiers_before": target.identifiers,
			"target_identifiers_after": device_identifiers(payload.get("profile") or target.device),
			"selected_pathway": (payload.get("policy") or {}).get("selected_pathway"),
			"execution": payload.get("execution"), "verification": payload.get("verification"),
			"engine_evidence": payload.get("evidence"), "certificate": payload.get("certificate"),
			"warnings": warnings, "final_status": status, "completed_at": iso(utc_now()),
		}
		uploaded = bool(self.upload_result and self.upload_result(evidence))
		evidence["upload_status"] = (
			"UPLOADED" if uploaded else
			"RETAINED_OFFLINE" if self.durable_result_storage else
			"RETAINED_IN_BOOT_MEMORY"
		)
		self.result_directory.mkdir(parents=True, exist_ok=True)
		result_path = self.result_directory / f"{boot_job_id}.result.json"
		evidence["result_path"] = str(result_path)
		result_path.write_text(json.dumps(redact(evidence), indent=2, sort_keys=True) + "\n", encoding="utf-8")
		os.chmod(result_path, 0o600)
		self._transition(boot_job_id, status, result=redact(evidence), local_confirmation_state="CONFIRMED_IN_BOOT_ENVIRONMENT")
		return evidence
