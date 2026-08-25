from __future__ import annotations

import argparse
import hashlib
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import replace

from vyper_version import __version__

from .config import load_config, write_config
from .diagnostics import collect_diagnostics


def _system_disk_service():
	from agent.discovery import DeviceDiscovery
	from .boot_handoff import GrubOneShotHandoff
	from .boot_sanitize import BootJobStore
	from .system_disk import SystemDiskService
	store_root = Path(os.getenv("VYPER_BOOT_JOB_ROOT", "/var/lib/vyper/boot-jobs"))
	return SystemDiskService(
		discovery=DeviceDiscovery(), store=BootJobStore(store_root), handoff=GrubOneShotHandoff(),
		boot_image_manifest=Path(os.getenv("VYPER_BOOT_IMAGE_MANIFEST", "/opt/vyper/boot/manifest.json")),
		boot_directory=Path(os.getenv("VYPER_BOOT_DIRECTORY", "/boot/vyper")),
	)


def _hardware_validation_harness(args):
	from agent.command_runner import SubprocessCommandExecutor
	from agent.profiler import DeviceProfiler
	from .hardware_validation import HardwareValidationHarness, LocalValidationClient
	settings = load_config()
	executor = SubprocessCommandExecutor()
	client = LocalValidationClient(
		f"http://127.0.0.1:{settings.local_agent_port}",
		api_key=os.getenv("VYPER_LOCAL_AGENT_API_KEY"),
	)
	return HardwareValidationHarness(
		profiler=DeviceProfiler(command_executor=executor),
		command_executor=executor,
		local_client=client,
		output_directory=args.output_dir,
	)


def _systemctl(action: str) -> int:
	result = subprocess.run(["systemctl", action, "vyper-agent.service", "vyper-console.service"], check=False)
	return int(result.returncode)


def _post_json(url: str, payload: dict) -> dict:
	request = urllib.request.Request(
		url,
		data=json.dumps(payload).encode("utf-8"),
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	with urllib.request.urlopen(request, timeout=15) as response:
		return json.loads(response.read().decode("utf-8"))


def _report_prepared_boot_events(*, central_url: str, central_job_id: str, boot_job_id: str,
	credential: dict, events: list[dict]) -> None:
	central_url = central_url.rstrip("/")
	if not central_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
		return
	for sequence, event in enumerate(events, start=1):
		payload = {
			"agent_protocol_version": "1", "local_job_id": boot_job_id, "sequence": sequence,
			"state": event["state"], "timestamp": event["timestamp"],
			"message": f"Boot sanitize state: {event['state']}.", "progress": None,
		}
		request = urllib.request.Request(
			f"{central_url}/agent/jobs/{central_job_id}/events",
			data=json.dumps(payload).encode("utf-8"), method="POST",
			headers={"Authorization": f"Bearer {credential['agent_token']}", "Content-Type": "application/json"},
		)
		try:
			with urllib.request.urlopen(request, timeout=10):
				pass
		except (OSError, ValueError, KeyError, urllib.error.URLError):
			# Preparation and the one-shot local safety flow do not depend on cloud reachability.
			return


def _wait_for_local_api(url: str, attempts: int = 20) -> bool:
	for _ in range(attempts):
		try:
			with urllib.request.urlopen(url, timeout=1) as response:
				if response.status == 200:
					return True
		except (OSError, urllib.error.URLError):
			pass
		time.sleep(0.25)
	return False


def enroll(args) -> int:
	config = load_config()
	central_url = (args.central_url or config.central_api_url or input("Central API URL: ")).strip().rstrip("/")
	if not central_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
		print("Enrollment requires HTTPS, except for explicit loopback development URLs.", file=sys.stderr)
		return 2
	updated = replace(config, central_api_url=central_url, sync_enabled=True)
	write_config(updated)
	if not args.no_restart:
		subprocess.run(["systemctl", "restart", "vyper-agent.service"], check=False)
		if not _wait_for_local_api(f"http://{updated.local_agent_bind}:{updated.local_agent_port}/health"):
			print("Enrollment failed: local agent did not become ready.", file=sys.stderr)
			return 1
	token = args.token or getpass.getpass("One-time enrollment token: ")
	try:
		result = _post_json(
			f"http://{updated.local_agent_bind}:{updated.local_agent_port}/sync/enroll",
			{"enrollment_token": token, "display_name": args.display_name},
		)
	except (OSError, ValueError, urllib.error.URLError) as exc:
		print(f"Enrollment failed: {type(exc).__name__}", file=sys.stderr)
		return 1
	print(f"Enrollment successful. Agent ID: {result['agent_id']}")
	return 0


def status() -> int:
	data = collect_diagnostics()
	print(f"VYPER {data['version']}")
	print(f"Agent service: {data['services']['vyper-agent.service']}")
	print(f"Console service: {data['services']['vyper-console.service']}")
	print(f"Local API: {data['local_api_health']}")
	print(f"Enrollment: {data['enrollment_status']}")
	print(f"Central sync: {data['central_sync']}")
	print(f"Outbox pending: {data['outbox_pending']}")
	return 0


def diagnose(json_output: bool = False) -> int:
	data = collect_diagnostics()
	if json_output:
		print(json.dumps(data, indent=2, sort_keys=True))
	else:
		for key, value in data.items():
			print(f"{key}: {json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value}")
	return 0


def verify_package(artifact_value: str, manifest_value: str | None = None, trust_store_value: str | None = None) -> int:
	artifact = Path(artifact_value).resolve()
	manifest_path = Path(manifest_value).resolve() if manifest_value else artifact.with_name("manifest.json")
	try:
		manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
	except (OSError, ValueError) as exc:
		print(json.dumps({"verified": False, "error": f"Manifest unavailable or invalid: {type(exc).__name__}"}))
		return 2
	digest = hashlib.sha256()
	try:
		with artifact.open("rb") as handle:
			for chunk in iter(lambda: handle.read(1024 * 1024), b""):
				digest.update(chunk)
	except OSError as exc:
		print(json.dumps({"verified": False, "error": f"Artifact unavailable: {type(exc).__name__}"}))
		return 2
	checksum_ok = digest.hexdigest() == manifest.get("sha256") and artifact.name == manifest.get("filename")
	signed = False; signature_verified = False; signature_result = "UNSIGNED / CHECKSUM_ONLY"
	if str(manifest.get("signature_status", "")).upper() == "SIGNED":
		try:
			from .release_signing import signature_bytes, trusted_public_key, verify_detached
			if manifest.get("signature_type") != "ed25519": raise ValueError("Unsupported signature type.")
			trust_store = Path(trust_store_value or os.getenv("VYPER_RELEASE_TRUST_STORE", "/opt/vyper/trust/trusted-release-keys.json"))
			public_pem = trusted_public_key(trust_store, str(manifest.get("signature_key_id") or ""))
			signature = signature_bytes(artifact.with_name(str(manifest.get("signature_file") or "")))
			verify_detached(artifact, signature, public_pem)
			signed = signature_verified = True; signature_result = "VERIFIED"
		except Exception as exc:
			signature_result = f"REJECTED: {type(exc).__name__}"
	report = {"verified": bool(checksum_ok and (signature_verified or str(manifest.get("signature_status", "")).upper() != "SIGNED")),
		"checksum_verified": checksum_ok, "signed": signed, "signature_verified": signature_verified,
		"signature_result": signature_result, "signature_status": manifest.get("signature_status", "unknown"),
		"signature_key_id": manifest.get("signature_key_id"), "sha256": digest.hexdigest()}
	print(json.dumps(report, sort_keys=True))
	return 0 if report["verified"] else 1


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(prog="vyper")
	subparsers = parser.add_subparsers(dest="command", required=True)
	for command in ("start", "stop", "restart", "status", "open", "diagnose", "version"):
		sub = subparsers.add_parser(command)
		if command == "diagnose":
			sub.add_argument("--json", action="store_true")
	enroll_parser = subparsers.add_parser("enroll")
	enroll_parser.add_argument("--central-url")
	enroll_parser.add_argument("--token", help=argparse.SUPPRESS)
	enroll_parser.add_argument("--display-name")
	enroll_parser.add_argument("--no-restart", action="store_true", help=argparse.SUPPRESS)
	verify_parser = subparsers.add_parser("verify-package")
	verify_parser.add_argument("artifact")
	verify_parser.add_argument("--manifest")
	verify_parser.add_argument("--trust-store")
	validation = subparsers.add_parser("validate-hardware")
	validation_classes = validation.add_subparsers(dest="validation_class", required=True)
	hdd_validation = validation_classes.add_parser("hdd")
	hdd_validation.add_argument("operation", nargs="?", choices=["prepare"], default="validate")
	hdd_validation.add_argument("--device", required=True)
	hdd_validation.add_argument("--execute", action="store_true")
	hdd_validation.add_argument("--output-dir", default="hardware-validation")
	hdd_validation.add_argument("--poll-seconds", type=float, default=1.0)
	hdd_validation.add_argument("--timeout-seconds", type=float, default=172800.0)
	sata_validation = validation_classes.add_parser("sata-ssd")
	sata_validation.add_argument("operation", nargs="?", choices=["prepare"], default="validate")
	sata_validation.add_argument("--device", required=True)
	sata_validation.add_argument("--execute", action="store_true")
	sata_validation.add_argument("--output-dir", default="hardware-validation")
	sata_validation.add_argument("--poll-seconds", type=float, default=1.0)
	sata_validation.add_argument("--timeout-seconds", type=float, default=172800.0)
	nvme_validation = validation_classes.add_parser("nvme")
	nvme_validation.add_argument("operation", nargs="?", choices=["prepare"], default="validate")
	nvme_validation.add_argument("--device", required=True)
	nvme_validation.add_argument("--execute", action="store_true")
	nvme_validation.add_argument("--output-dir", default="hardware-validation")
	nvme_validation.add_argument("--poll-seconds", type=float, default=1.0)
	nvme_validation.add_argument("--timeout-seconds", type=float, default=172800.0)
	system_disk = subparsers.add_parser("system-disk")
	system_commands = system_disk.add_subparsers(dest="system_disk_command", required=True)
	prepare_parser = system_commands.add_parser("prepare")
	prepare_parser.add_argument("--dry-run", action="store_true")
	prepare_parser.add_argument("--authorize-system-disk", action="store_true")
	prepare_parser.add_argument("--method", default="POLICY", choices=["POLICY", "HDD_OVERWRITE", "ATA_ERASE", "CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"])
	prepare_parser.add_argument("--central-job-id")
	prepare_parser.add_argument("--expires-in-seconds", type=int, default=3600)
	prepare_parser.add_argument("--no-apply", action="store_true", help=argparse.SUPPRESS)
	prepare_parser.add_argument("--vm-validation-manifest")
	prepare_parser.add_argument("--allow-destructive-vm-test", action="store_true")
	status_parser = system_commands.add_parser("status")
	status_parser.add_argument("--boot-job-id")
	cancel_parser = system_commands.add_parser("cancel")
	cancel_parser.add_argument("--boot-job-id")
	cancel_parser.add_argument("--no-apply", action="store_true", help=argparse.SUPPRESS)
	reboot_parser = system_commands.add_parser("reboot")
	reboot_parser.add_argument("--confirm-reboot", action="store_true")
	reboot_parser.add_argument("--no-apply", action="store_true", help=argparse.SUPPRESS)
	system_commands.add_parser("boot-self-test")
	secure_boot_parser = system_commands.add_parser("secure-boot-status")
	secure_boot_parser.add_argument("--certificate")
	return parser


def main(argv: list[str] | None = None) -> int:
	args = build_parser().parse_args(argv)
	if args.command in {"start", "stop", "restart"}:
		return _systemctl(args.command)
	if args.command == "status":
		return status()
	if args.command == "diagnose":
		return diagnose(args.json)
	if args.command == "version":
		print(__version__)
		return 0
	if args.command == "open":
		config = load_config()
		return 0 if webbrowser.open(f"http://{config.local_console_bind}:{config.local_console_port}") else 1
	if args.command == "enroll":
		return enroll(args)
	if args.command == "verify-package":
		return verify_package(args.artifact, args.manifest, args.trust_store)
	if args.command == "validate-hardware":
		from .hardware_validation import HardwareValidationError
		try:
			harness = _hardware_validation_harness(args)
			if args.validation_class == "nvme" and args.operation == "prepare":
				harness.prepare_nvme(args.device, execute=args.execute)
			elif args.validation_class == "nvme":
				harness.validate_nvme(args.device, execute=args.execute,
					poll_seconds=args.poll_seconds, timeout_seconds=args.timeout_seconds)
			elif args.validation_class == "sata-ssd" and args.operation == "prepare":
				harness.prepare_sata_ssd(args.device, execute=args.execute)
			elif args.validation_class == "sata-ssd":
				harness.validate_sata_ssd(
					args.device, execute=args.execute,
					poll_seconds=args.poll_seconds, timeout_seconds=args.timeout_seconds,
				)
			elif args.operation == "prepare":
				harness.prepare(args.device, execute=args.execute)
			else:
				harness.validate(
					args.device, execute=args.execute,
					poll_seconds=args.poll_seconds, timeout_seconds=args.timeout_seconds,
				)
			return 0
		except HardwareValidationError as exc:
			print(f"Hardware validation stopped safely: {exc}", file=sys.stderr)
			return 2
	if args.command == "system-disk":
		try:
			if args.system_disk_command == "secure-boot-status":
				from .secure_boot import secure_boot_status
				report = secure_boot_status(signing_certificate=args.certificate)
				print(json.dumps(report, indent=2, sort_keys=True))
				return 0 if report["status"] in {"SUPPORTED", "REQUIRES_KEY_ENROLLMENT"} else 1
			if args.system_disk_command == "boot-self-test":
				from .vm_validation import BootSelfTest
				report = BootSelfTest().run()
				print(json.dumps(report, indent=2, sort_keys=True))
				return 0 if report["boot_self_test"] == "PASS" else 1
			service = _system_disk_service()
			if args.system_disk_command == "prepare":
				if not args.dry_run and not args.authorize_system_disk:
					print("Non-dry-run preparation requires --authorize-system-disk. No boot job was created.", file=sys.stderr)
					return 2
				settings = load_config()
				credential_file = Path(os.getenv("VYPER_AGENT_CREDENTIAL_PATH", "/etc/vyper/agent-identity.json"))
				agent_id = None
				credential_payload = None
				if args.central_job_id and credential_file.is_file():
					credential_payload = json.loads(credential_file.read_text(encoding="utf-8"))
					agent_id = credential_payload.get("agent_id")
				if args.central_job_id and (not agent_id or not settings.central_api_url):
					raise RuntimeError("Remote boot jobs require an enrolled agent credential and configured central HTTPS URL.")
				vm_validation = None
				if args.vm_validation_manifest:
					from .vm_validation import VirtualizationInspector, load_vm_validation_manifest
					if os.getenv("VYPER_VM_VALIDATION") != "1":
						raise RuntimeError("VM validation manifest requires VYPER_VM_VALIDATION=1.")
					vm_validation = load_vm_validation_manifest(args.vm_validation_manifest)
					host = VirtualizationInspector().inspect()
					if host.get("virtualbox_proven") is not True:
						raise RuntimeError("VirtualBox environment could not be proven.")
					vm_validation["preparation_virtualization"] = host
					vm_validation["allow_destructive_vm_test"] = bool(args.allow_destructive_vm_test)
					if not args.dry_run and (not vm_validation["destructive_test_enabled"] or not args.allow_destructive_vm_test):
						raise RuntimeError("Destructive VM preparation requires both manifest authorization and --allow-destructive-vm-test.")
				prepared = service.prepare(dry_run=args.dry_run, requested_method=args.method,
					central_job_id=args.central_job_id, agent_id=agent_id,
					central_api_url=settings.central_api_url or None, agent_credential_path=credential_file,
					expires_in_seconds=args.expires_in_seconds,
					apply_handoff=not args.no_apply, vm_validation=vm_validation)
				if args.central_job_id and credential_payload:
					_report_prepared_boot_events(central_url=settings.central_api_url,
						central_job_id=args.central_job_id, boot_job_id=prepared["boot_job"]["boot_job_id"],
						credential=credential_payload, events=prepared["state"].get("events") or [])
				device = prepared["device"]
				print(f"System disk: {device['device_path']} | {device.get('model') or 'Unknown'} | {device.get('serial_number') or 'stable non-serial identity'}")
				print(f"Boot job: {prepared['boot_job']['boot_job_id']}")
				print("System disk sanitization is prepared. No data has been erased yet.")
				print("A fresh confirmation will be required inside the temporary boot environment.")
				return 0
			if args.system_disk_command == "status":
				print(json.dumps(service.status(args.boot_job_id), indent=2, sort_keys=True))
				return 0
			if args.system_disk_command == "cancel":
				print(json.dumps(service.cancel(args.boot_job_id, apply_handoff=not args.no_apply), indent=2, sort_keys=True))
				return 0
			if not args.confirm_reboot:
				print("Reboot handoff requires --confirm-reboot. No reboot was requested.", file=sys.stderr)
				return 2
			status_payload = service.status()
			if status_payload.get("status") != "AWAITING_REBOOT":
				print("No boot job is awaiting reboot.", file=sys.stderr)
				return 2
			service.handoff.reboot(apply=not args.no_apply)
			return 0
		except Exception as exc:
			print(f"System-disk operation stopped safely: {exc}", file=sys.stderr)
			return 2
	return 2


def diagnose_main() -> int:
	return diagnose("--json" in sys.argv[1:])


if __name__ == "__main__":
	raise SystemExit(main())
