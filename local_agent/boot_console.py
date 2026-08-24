from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from agent.agent import VYPERAgent
from agent.discovery import DeviceDiscovery

from .boot_sanitize import BootJobError, BootJobStore, BootSanitizeRuntime, LinuxSafetyInspector, iso, utc_now


def _active_job_id() -> str:
	configured = os.getenv("VYPER_BOOT_JOB_ID")
	if configured:
		return configured.strip()
	path = Path("/etc/vyper/active-boot-job")
	if path.is_file():
		return path.read_text(encoding="utf-8").strip()
	for item in Path("/proc/cmdline").read_text(encoding="utf-8").split():
		if item.startswith("vyper.boot_job="):
			return item.split("=", 1)[1]
	raise BootJobError("No active boot job was supplied.")


def _attempt_wired_dhcp() -> str:
	tool = "/sbin/dhclient"
	if not Path(tool).is_file():
		return "UNAVAILABLE"
	result = subprocess.run([tool, "-1", "-v"], check=False, timeout=60)
	return "CONNECTED" if result.returncode == 0 else "OFFLINE"


def _write_refusal(store: BootJobStore, job_id: str, result_dir: Path, message: str) -> None:
	result_dir.mkdir(parents=True, exist_ok=True)
	payload = {"execution_environment": "boot_sanitize", "boot_job_id": job_id,
		"final_status": "FAILED", "successful_sanitization_claim": False,
		"refusal_reason": message, "timestamp": iso(utc_now())}
	(result_dir / f"{job_id}.refusal.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
	try:
		state = store.state(job_id)
		status = "INCONCLUSIVE" if state.get("execution_attempted") else "FAILED"
		store.transition(job_id, status, error=message, result=payload)
	except Exception:
		pass


def _uploader(store: BootJobStore, job_id: str):
	def upload(evidence: dict) -> bool:
		document = store.validate(job_id)["payload"]
		central_job_id = document.get("central_job_id")
		central_url = str(document.get("central_api_url") or "").rstrip("/")
		credential_path = Path("/etc/vyper/boot-agent-identity.json")
		if not central_job_id or not central_url or not credential_path.is_file():
			return False
		if not central_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
			return False
		credential = json.loads(credential_path.read_text(encoding="utf-8"))
		status = str(evidence.get("final_status") or "INCONCLUSIVE")
		payload = {
			"agent_protocol_version": "1", "idempotency_key": f"boot-result:{job_id}",
			"local_job_id": job_id, "job_state": status, "final_status": status,
			"finished_at": evidence.get("completed_at"), "execution": evidence.get("execution"),
			"verification": evidence.get("verification"), "evidence": evidence.get("engine_evidence"),
			"certificate": evidence.get("certificate"), "state_history": [], "error": None,
			"boot_context": {key: value for key, value in evidence.items() if key not in {"execution", "verification", "engine_evidence", "certificate"}},
		}
		request = urllib.request.Request(
			f"{central_url}/agent/jobs/{central_job_id}/result", data=json.dumps(payload).encode("utf-8"), method="POST",
			headers={"Authorization": f"Bearer {credential['agent_token']}", "Content-Type": "application/json"},
		)
		try:
			with urllib.request.urlopen(request, timeout=20) as response:
				return 200 <= response.status < 300
		except (OSError, ValueError, urllib.error.URLError):
			return False
	return upload


def _event_reporter(store: BootJobStore, job_id: str):
	def report(state: str, local_sequence: int) -> None:
		document = store.validate(job_id)["payload"]
		central_job_id = document.get("central_job_id")
		central_url = str(document.get("central_api_url") or "").rstrip("/")
		credential_path = Path("/etc/vyper/boot-agent-identity.json")
		if not central_job_id or not central_url or not credential_path.is_file():
			return
		try:
			credential = json.loads(credential_path.read_text(encoding="utf-8"))
			payload = {"agent_protocol_version": "1", "local_job_id": job_id, "sequence": local_sequence,
				"state": state, "timestamp": iso(utc_now()), "message": f"Boot sanitize state: {state}.", "progress": None}
			request = urllib.request.Request(f"{central_url}/agent/jobs/{central_job_id}/events",
				data=json.dumps(payload).encode("utf-8"), method="POST",
				headers={"Authorization": f"Bearer {credential['agent_token']}", "Content-Type": "application/json"})
			with urllib.request.urlopen(request, timeout=10):
				pass
		except (OSError, ValueError, KeyError, urllib.error.URLError):
			return
	return report


def main() -> int:
	store_root = Path(os.getenv("VYPER_BOOT_JOB_ROOT", "/var/lib/vyper/boot-jobs"))
	result_dir = Path(os.getenv("VYPER_BOOT_RESULT_DIR", "/var/lib/vyper/boot-results"))
	job_id = _active_job_id()
	store = BootJobStore(store_root)
	runtime = BootSanitizeRuntime(store=store, discovery=DeviceDiscovery(), safety_inspector=LinuxSafetyInspector(),
		agent=VYPERAgent(dry_run=False), result_directory=result_dir, upload_result=_uploader(store, job_id),
		report_event=_event_reporter(store, job_id),
		durable_result_storage=os.getenv("VYPER_BOOT_RESULT_DURABLE", "").lower() in {"1", "true", "yes"})
	print("VYPER temporary boot environment")
	print("Preparing wired network:", _attempt_wired_dhcp())
	try:
		document = store.validate(job_id)
		target = runtime.identify_target(document)
		runtime.validate_target(target)
		print(runtime.confirmation_text(document, target))
		confirmation = input().strip()
		ata_password = None
		if str(document["payload"].get("requested_method")) == "ATA_ERASE":
			ata_password = getpass.getpass("ATA password (entered only in boot environment): ")
		result = runtime.run(job_id, confirmation=confirmation, ata_password=ata_password)
		print(json.dumps({"state": result["final_status"], "upload_status": result["upload_status"],
			"result_path": result["result_path"]}, indent=2))
		print("Sanitization workflow is terminal. The machine will shut down; it will not boot the destroyed OS.")
		if os.getenv("VYPER_BOOT_NO_SHUTDOWN", "").lower() not in {"1", "true", "yes"}:
			subprocess.run(["poweroff", "-f"], check=False, timeout=30)
		return 0 if result["final_status"] == "VERIFIED" else 1
	except (BootJobError, OSError, ValueError) as exc:
		message = str(exc)
		_write_refusal(store, job_id, result_dir, message)
		print(f"BOOT SANITIZATION STOPPED: {message}", file=sys.stderr)
		print("No success is claimed. Use a safe shutdown after recording this status.", file=sys.stderr)
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
