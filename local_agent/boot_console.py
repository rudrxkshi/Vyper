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

from .boot_sanitize import (
	BootJobError, BootJobStore, BootSanitizeRuntime, LinuxSafetyInspector,
	durable_write_text, iso, utc_now,
)
from .boot_shutdown import BootShutdownCoordinator
from .jobs import redact
from .vm_validation import (
	BootSelfTest, BootValidationLogger, EvidenceDiskManager, VMValidationGate, VirtualizationInspector,
	build_vm_validation_report,
)


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
	try:
		result = subprocess.run([tool, "-1", "-d", "-v"], check=False, timeout=60)
	except (OSError, subprocess.TimeoutExpired):
		return "OFFLINE"
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
	result_dir.mkdir(parents=True, exist_ok=True)
	job_id = _active_job_id()
	store = BootJobStore(store_root)
	discovery = DeviceDiscovery()
	validation_log = BootValidationLogger(result_dir / f"{job_id}.validation.jsonl")
	validation_log.write("boot_environment_startup", kernel=os.uname().release if hasattr(os, "uname") else "unknown")
	def validation_guard(document, target):
		manifest = document["payload"].get("vm_validation")
		if not manifest:
			return None
		gate = VMValidationGate(virtualization_inspector=VirtualizationInspector(), discovery=discovery).evaluate(
			manifest, target.device, allow_destructive=manifest.get("allow_destructive_vm_test") is True,
			boot_environment_independent=target.device.get("is_system_device") is False)
		validation_log.write("vm_validation_guard", target=target.device_path,
			virtualization=gate.get("host_virtualization"), blockers=gate.get("blockers"),
			destructive_eligible=gate.get("destructive_eligible"))
		if gate.get("host_virtualization", {}).get("virtualbox_proven") is not True or gate.get("blockers"):
			raise BootJobError("VM validation environment or disposable target identity could not be proven.")
		mount_result = EvidenceDiskManager().mount(gate)
		gate["evidence_mount"] = mount_result
		if mount_result.get("mounted"):
			runtime.result_directory = Path(mount_result["result_directory"])
			runtime.durable_result_storage = True
			validation_log.path = runtime.result_directory / f"{job_id}.validation.jsonl"
		if not document["payload"].get("dry_run") and gate.get("destructive_eligible") is not True:
			raise BootJobError("Destructive VM validation gates are incomplete.")
		if not document["payload"].get("dry_run") and mount_result.get("mounted") is not True:
			raise BootJobError("Destructive VM validation requires mounted separate evidence storage.")
		return gate
	runtime = BootSanitizeRuntime(store=store, discovery=DeviceDiscovery(), safety_inspector=LinuxSafetyInspector(),
		agent=VYPERAgent(dry_run=False), result_directory=result_dir, upload_result=_uploader(store, job_id),
		report_event=_event_reporter(store, job_id),
		durable_result_storage=os.getenv("VYPER_BOOT_RESULT_DURABLE", "").lower() in {"1", "true", "yes"},
		validation_guard=validation_guard)
	print("VYPER temporary boot environment")
	self_test = BootSelfTest(result_directory=result_dir).run()
	print(json.dumps(self_test, indent=2, sort_keys=True))
	validation_log.write("boot_self_test", status=self_test["boot_self_test"], checks=self_test["checks"])
	if self_test["boot_self_test"] != "PASS":
		_write_refusal(store, job_id, result_dir, "Boot environment self-test failed.")
		return 2
	print("Preparing wired network:", _attempt_wired_dhcp())
	try:
		document = store.validate(job_id)
		validation_log.write("manifest_validated", boot_job_id=job_id, dry_run=document["payload"].get("dry_run"))
		target = runtime.identify_target(document)
		validation_log.write("target_discovered", target=target.device_path, identity=target.identifiers)
		runtime.validate_target(target)
		validation_log.write("safety_checks_passed", target=target.device_path)
		print(runtime.confirmation_text(document, target))
		confirmation = input().strip()
		ata_password = None
		if str(document["payload"].get("requested_method")) == "ATA_ERASE":
			ata_password = getpass.getpass("ATA password (entered only in boot environment): ")
		result = runtime.run(job_id, confirmation=confirmation, ata_password=ata_password)
		vm_context = document["payload"].get("vm_validation")
		state = store.state(job_id)
		def record_shutdown(shutdown: dict) -> None:
			result["shutdown"] = redact(shutdown)
			durable_write_text(result["result_path"], json.dumps(redact(result), indent=2, sort_keys=True) + "\n")
			if vm_context:
				report = build_vm_validation_report(output_directory=runtime.result_directory,
					boot_job=document["payload"], state=state, gate=result.get("vm_validation") or {},
					boot_artifact=vm_context.get("boot_artifact_validation") or {"status": "FAIL"},
					grub_handoff=state.get("handoff") or {}, result=result)
				validation_log.write("vm_validation_report", final_conclusion=report["final_conclusion"],
					shutdown_status=shutdown.get("shutdown_status"), report_files=report["report_files"])
		validation_log.write("job_terminal", state=result.get("final_status"), upload_status=result.get("upload_status"))
		print(json.dumps({"state": result["final_status"], "upload_status": result["upload_status"],
			"result_path": result["result_path"]}, indent=2))
		print("Sanitization workflow is terminal. The machine will shut down; it will not boot the destroyed OS.")
		if os.getenv("VYPER_BOOT_NO_SHUTDOWN", "").lower() not in {"1", "true", "yes"}:
			evidence_mount = ((result.get("vm_validation") or {}).get("evidence_mount") or {})
			unmounted = False
			def durability() -> dict:
				nonlocal unmounted
				try:
					sync_result = subprocess.run(["sync"], check=False, timeout=30, capture_output=True, text=True)
					sync_returncode = sync_result.returncode
				except (OSError, subprocess.TimeoutExpired):
					sync_returncode = None
				unmount_result = None
				unmount_error = None
				device = evidence_mount.get("device")
				mountpoint = str(Path(runtime.result_directory).parent)
				if evidence_mount.get("mounted") and device:
					try:
						unmount_result = subprocess.run(["umount", mountpoint], check=False, timeout=30,
							capture_output=True, text=True)
						unmounted = unmount_result.returncode == 0
					except (OSError, subprocess.TimeoutExpired) as exc:
						unmount_error = type(exc).__name__
				return {"sync_returncode": sync_returncode,
					"evidence_unmount_attempted": bool(evidence_mount.get("mounted") and device),
					"evidence_unmount_returncode": unmount_result.returncode if unmount_result else None,
					"evidence_unmount_error": unmount_error}
			def recover_durability() -> None:
				if not unmounted:
					return
				device = str(evidence_mount.get("device"))
				mountpoint = str(Path(runtime.result_directory).parent)
				subprocess.run(["mount", "-o", "rw,nodev,nosuid,noexec", device, mountpoint],
					check=False, timeout=30, capture_output=True, text=True)
			try:
				BootShutdownCoordinator().attempt(durability=durability, record=record_shutdown,
					recover_durability=recover_durability)
			except Exception as exc:
				shutdown_failure = {"shutdown_status": "FAILED", "shutdown_method": None,
					"shutdown_warning": f"Shutdown coordination failed ({type(exc).__name__}); sanitization outcome is unchanged."}
				try:
					recover_durability()
					record_shutdown(shutdown_failure)
				except Exception:
					pass
				print(shutdown_failure["shutdown_warning"], file=sys.stderr)
		elif vm_context:
			record_shutdown({"shutdown_status": "SUPPRESSED", "shutdown_method": None,
				"shutdown_warning": "Shutdown was suppressed by VYPER_BOOT_NO_SHUTDOWN."})
		return 0 if result["final_status"] == "VERIFIED" else 1
	except (BootJobError, OSError, ValueError) as exc:
		message = str(exc)
		validation_log.write("job_refused", error=message,
			execution_attempted=bool(store.state(job_id).get("execution_attempted")))
		_write_refusal(store, job_id, runtime.result_directory, message)
		print(f"BOOT SANITIZATION STOPPED: {message}", file=sys.stderr)
		print("No success is claimed. Use a safe shutdown after recording this status.", file=sys.stderr)
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
