from __future__ import annotations

import hashlib
import getpass
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.certificate import verify_certificate_integrity
from agent.command_runner import CommandExecutor, CommandResult, SubprocessCommandExecutor
from agent.evidence import EvidenceCollector
from agent.policy import PolicyEngine
from agent.profiler import DeviceProfile, DeviceProfiler
from agent.nvme_status import parse_sanitize_log, sanitize_log_command
from agent.nvme_scope import NVMeControllerResolver
from agent.pathways.nvme_sanitize import sanact_for_method
from vyper_version import __version__


TERMINAL_STATES = {"VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"}
REPORT_LIMITATIONS = [
	"Validation applies to one explicitly identified disposable rotational HDD.",
	"Independent post-checks use the logical block interface and representative samples, not every physical sector.",
	"Drive firmware, remapped sectors, hidden areas, and physical magnetic domains are outside the sampled proof.",
]


def utc_now() -> str:
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_identifier(value: str) -> str:
	cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "unknown")).strip("-.")
	return cleaned[-64:] or "unknown"


def _redact(value: Any) -> Any:
	markers = ("password", "secret", "token", "credential", "passphrase", "authorization")
	if isinstance(value, dict):
		return {
			str(key): item if str(key) == "ata_password_used" and isinstance(item, bool)
			else "<redacted>" if any(marker in str(key).lower() for marker in markers) else _redact(item)
			for key, item in value.items()
		}
	if isinstance(value, (list, tuple)):
		return [_redact(item) for item in value]
	return value


class HardwareValidationError(RuntimeError):
	pass


class LocalValidationClient:
	"""Small typed client for the existing loopback local-agent job API."""

	def __init__(self, base_url: str, *, api_key: str | None = None) -> None:
		self.base_url = base_url.rstrip("/")
		self.api_key = api_key

	def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
		headers = {"Accept": "application/json"}
		if self.api_key:
			headers["X-VYPER-API-Key"] = self.api_key
		data = None
		if payload is not None:
			headers["Content-Type"] = "application/json"
			data = json.dumps(payload).encode("utf-8")
		request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
		try:
			with urllib.request.urlopen(request, timeout=30) as response:
				decoded = json.loads(response.read().decode("utf-8"))
		except (OSError, ValueError, urllib.error.URLError) as exc:
			raise HardwareValidationError(f"Local agent request failed: {type(exc).__name__}") from exc
		if not isinstance(decoded, dict):
			raise HardwareValidationError("Local agent returned a non-object response.")
		return decoded

	def submit_hdd_job(self, device: str) -> dict[str, Any]:
		return self._request("POST", "/jobs/sanitize", {
			"target": device,
			"authorization": {"approved": True, "ata_password": None},
			"dry_run": False,
		})

	def submit_ata_job(self, device: str, ata_password: str) -> dict[str, Any]:
		return self._request("POST", "/jobs/sanitize", {
			"target": device,
			"authorization": {"approved": True, "ata_password": ata_password},
			"dry_run": False,
		})

	def submit_nvme_job(self, namespace: str) -> dict[str, Any]:
		return self._request("POST", "/jobs/sanitize", {
			"target": namespace,
			"authorization": {"approved": True, "ata_password": None},
			"dry_run": False,
		})

	def get_job(self, local_job_id: str) -> dict[str, Any]:
		return self._request("GET", f"/jobs/{local_job_id}")


class HardwareValidationHarness:
	def __init__(
		self,
		*,
		profiler: DeviceProfiler | None = None,
		command_executor: CommandExecutor | None = None,
		local_client: Any | None = None,
		output_directory: str | Path = "hardware-validation",
		input_fn: Callable[[str], str] = input,
		print_fn: Callable[[str], None] = print,
		sleep_fn: Callable[[float], None] = time.sleep,
		read_sample: Callable[[str, int, int], bytes] | None = None,
		getpass_fn: Callable[[str], str] = getpass.getpass,
		nvme_scope_resolver: Callable[[str], dict[str, Any]] | None = None,
	) -> None:
		self.command_executor = command_executor or SubprocessCommandExecutor()
		self.profiler = profiler or DeviceProfiler(command_executor=self.command_executor)
		self.local_client = local_client
		self.output_directory = Path(output_directory)
		self.input_fn = input_fn
		self.print_fn = print_fn
		self.sleep_fn = sleep_fn
		self.read_sample = read_sample or self._pread
		self.getpass_fn = getpass_fn
		self.nvme_scope_resolver = nvme_scope_resolver or self._resolve_nvme_scope

	def plan(self, device: str, *, operation: str = "validate") -> dict[str, Any]:
		self._require_explicit_device(device)
		profile = self.profiler.profile(device)
		filesystem = self._filesystem_snapshot(device)
		self._assert_safe_hdd(profile, filesystem)
		identity = self._identity(profile)
		plan = {
			"mode": "read-only-plan",
			"operation": operation,
			"created_at": utc_now(),
			"device_identity": identity,
			"pre_test_profile": asdict(profile),
			"filesystem_info": filesystem,
			"confirmation_required": self._confirmation_phrase(identity, operation),
			"planned_steps": self._planned_steps(operation),
			"destructive_execution_started": False,
		}
		self._print_plan(plan)
		return plan

	def validate(
		self,
		device: str,
		*,
		execute: bool = False,
		poll_seconds: float = 1.0,
		timeout_seconds: float = 172800,
	) -> dict[str, Any]:
		plan = self.plan(device, operation="validate")
		if not execute:
			self.print_fn("PLAN ONLY: no sanitization job was submitted. Re-run with --execute after reviewing the identity.")
			return plan
		if self.local_client is None:
			raise HardwareValidationError("The local agent client is unavailable; no job was submitted.")
		fresh = self.profiler.profile(device)
		fresh_filesystem = self._filesystem_snapshot(device)
		self._assert_safe_hdd(fresh, fresh_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(fresh))
		self._confirm(plan["confirmation_required"], fresh)
		armed = self.profiler.profile(device)
		armed_filesystem = self._filesystem_snapshot(device)
		self._assert_safe_hdd(armed, armed_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(armed))

		accepted = self.local_client.submit_hdd_job(device)
		local_job_id = str(accepted.get("local_job_id") or "")
		if not local_job_id:
			raise HardwareValidationError("Local agent did not return a durable job ID.")
		job, progress = self._wait_for_job(local_job_id, poll_seconds=poll_seconds, timeout_seconds=timeout_seconds)
		post_profile = self.profiler.profile(device)
		identity_preserved = self._identity_matches(asdict(fresh), asdict(post_profile))
		post_checks = self._post_checks(device, post_profile.size_bytes)
		report = self._build_report(
			plan=plan, job=job, progress=progress, post_profile=post_profile,
			identity_preserved=identity_preserved, post_checks=post_checks,
		)
		paths = self._write_report(report)
		report["report_files"] = {key: str(path) for key, path in paths.items()}
		self.print_fn(f"Hardware validation conclusion: {report['conclusion']}")
		self.print_fn(f"JSON report: {paths['json']}")
		self.print_fn(f"Markdown report: {paths['markdown']}")
		return report

	def plan_sata_ssd(self, device: str, *, operation: str = "validate") -> dict[str, Any]:
		self._require_explicit_device(device)
		profile = self.profiler.profile(device)
		filesystem = self._filesystem_snapshot(device)
		self._assert_safe_sata_ssd(profile, filesystem, require_erasable=False)
		identity = self._identity(profile)
		capabilities = self._ata_capability_summary(profile)
		policy_preview = PolicyEngine(dry_run=True).decide(profile)
		plan = {
			"mode": "read-only-plan",
			"operation": operation,
			"validation_kind": "physical_sata_ssd",
			"created_at": utc_now(),
			"device_identity": identity,
			"pre_test_profile": asdict(profile),
			"ata_capabilities": capabilities,
			"filesystem_info": filesystem,
			"selected_vyper_pathway": policy_preview.selected_pathway,
			"policy_preview": asdict(policy_preview),
			"execution_blockers": self._sata_execution_blockers(profile),
			"confirmation_required": self._confirmation_phrase(identity, operation),
			"planned_steps": self._planned_sata_steps(operation),
			"destructive_execution_started": False,
		}
		self._print_sata_plan(plan)
		return plan

	def validate_sata_ssd(
		self,
		device: str,
		*,
		execute: bool = False,
		poll_seconds: float = 1.0,
		timeout_seconds: float = 172800,
	) -> dict[str, Any]:
		plan = self.plan_sata_ssd(device, operation="validate")
		if not execute:
			self.print_fn("PLAN ONLY: no ATA password was requested and no sanitization job was submitted. Re-run with --execute after reviewing the identity and ATA state.")
			return plan
		if self.local_client is None:
			raise HardwareValidationError("The local agent client is unavailable; no job was submitted.")
		fresh = self.profiler.profile(device)
		fresh_filesystem = self._filesystem_snapshot(device)
		self._assert_safe_sata_ssd(fresh, fresh_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(fresh))
		self._confirm(plan["confirmation_required"], fresh)
		armed = self.profiler.profile(device)
		armed_filesystem = self._filesystem_snapshot(device)
		self._assert_safe_sata_ssd(armed, armed_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(armed))

		ata_password = self.getpass_fn("Transient ATA password (input hidden; never persisted by this harness): ")
		if not ata_password:
			raise HardwareValidationError("A non-empty transient ATA password is required; no job was submitted.")
		try:
			accepted = self.local_client.submit_ata_job(device, ata_password)
		finally:
			ata_password = ""
		local_job_id = str(accepted.get("local_job_id") or "")
		if not local_job_id:
			raise HardwareValidationError("Local agent did not return a durable job ID.")
		job, progress = self._wait_for_job(
			local_job_id, poll_seconds=poll_seconds, timeout_seconds=timeout_seconds,
			capture_indeterminate=True,
		)
		post_profile = self.profiler.profile(device)
		identity_preserved = self._identity_matches(asdict(armed), asdict(post_profile))
		post_checks = self._post_checks_sata(device, post_profile)
		report = self._build_sata_report(
			plan=plan, job=job, progress=progress, post_profile=post_profile,
			identity_preserved=identity_preserved, post_checks=post_checks,
		)
		paths = self._write_sata_report(report)
		report["report_files"] = {key: str(path) for key, path in paths.items()}
		self.print_fn(f"SATA SSD hardware validation conclusion: {report['conclusion']}")
		self.print_fn(f"JSON report: {paths['json']}")
		self.print_fn(f"Markdown report: {paths['markdown']}")
		return report

	def prepare_sata_ssd(self, device: str, *, execute: bool = False) -> dict[str, Any]:
		return self._prepare_test_data(device, execute=execute, validation_type="sata-ssd")

	def plan_nvme(self, device: str, *, operation: str = "validate") -> dict[str, Any]:
		self._require_explicit_nvme_namespace(device)
		profile = self.profiler.profile(device)
		filesystem = self._filesystem_snapshot(device)
		scope = self.nvme_scope_resolver(device)
		self._assert_safe_nvme(profile, filesystem, scope, require_executable=False)
		identity = self._nvme_identity(profile, scope)
		asset_identity = {key: identity.get(key) for key in (
			"namespace_path", "namespace_id", "size_bytes", "nguid", "eui64", "namespace_uuid", "stable_id"
		)}
		controller_identity = scope.get("controller_identity") if isinstance(scope.get("controller_identity"), dict) else {
			"path": identity.get("controller_path"), "serial_number": identity.get("serial_number"),
			"model": identity.get("model"), "firmware_revision": identity.get("firmware_revision"),
			"pci_controller_identity": identity.get("pci_controller_identity"),
		}
		capabilities = self._nvme_capability_summary(profile, scope)
		policy = PolicyEngine(dry_run=True).decide(profile)
		method = str(policy.selected_pathway or "")
		plan = {
			"mode": "read-only-plan", "operation": operation, "validation_kind": "physical_nvme",
			"created_at": utc_now(), "device_identity": identity,
			"asset_namespace_identity": asset_identity, "controller_identity": controller_identity,
			"pre_test_profile": asdict(profile),
			"nvme_capabilities": capabilities, "policy_preview": asdict(policy),
			"policy_selected_method": method or None, "expected_sanact": sanact_for_method(self._canonical_nvme_method(method)),
			"requested_namespace": device, "resolved_controller": scope.get("controller_path"),
			"sanitize_target": scope.get("sanitize_target"), "scope_validation": scope,
			"filesystem_info": filesystem, "execution_blockers": self._nvme_execution_blockers(profile, scope, policy),
			"confirmation_required": self._confirmation_phrase(identity, operation),
			"planned_steps": self._planned_nvme_steps(operation), "destructive_execution_started": False,
		}
		self._print_nvme_plan(plan)
		return plan

	def validate_nvme(self, device: str, *, execute: bool = False, poll_seconds: float = 1.0,
		timeout_seconds: float = 172800) -> dict[str, Any]:
		plan = self.plan_nvme(device)
		if not execute:
			self.print_fn("PLAN ONLY: no NVMe sanitize job was submitted. Re-run with --execute only after every scope and capability blocker is resolved.")
			return plan
		if self.local_client is None:
			raise HardwareValidationError("The local agent client is unavailable; no job was submitted.")
		fresh = self.profiler.profile(device)
		fresh_fs = self._filesystem_snapshot(device)
		fresh_scope = self.nvme_scope_resolver(device)
		self._assert_safe_nvme(fresh, fresh_fs, fresh_scope)
		self._assert_nvme_identity_unchanged(plan, fresh, fresh_scope)
		self._confirm(plan["confirmation_required"], fresh)
		armed = self.profiler.profile(device)
		armed_fs = self._filesystem_snapshot(device)
		armed_scope = self.nvme_scope_resolver(device)
		self._assert_safe_nvme(armed, armed_fs, armed_scope)
		self._assert_nvme_identity_unchanged(plan, armed, armed_scope)
		armed_policy = PolicyEngine(dry_run=True).decide(armed)
		if armed_policy.selected_pathway != plan["policy_selected_method"]:
			raise HardwareValidationError("NVMe policy selection changed after confirmation; no job was submitted.")
		accepted = self.local_client.submit_nvme_job(device)
		local_job_id = str(accepted.get("local_job_id") or "")
		if not local_job_id:
			raise HardwareValidationError("Local agent did not return a durable job ID.")
		job, timeline = self._wait_for_nvme_job(local_job_id, armed_scope["controller_path"],
			poll_seconds=poll_seconds, timeout_seconds=timeout_seconds)
		post_profile = self.profiler.profile(device)
		post_scope = self.nvme_scope_resolver(device)
		identity_preserved = self._nvme_identity_matches(plan["device_identity"], post_profile, post_scope)
		post_checks = self._post_checks_nvme(device, post_scope)
		report = self._build_nvme_report(plan=plan, job=job, timeline=timeline,
			post_profile=post_profile, post_scope=post_scope, identity_preserved=identity_preserved,
			post_checks=post_checks)
		paths = self._write_nvme_report(report)
		report["report_files"] = {key: str(path) for key, path in paths.items()}
		self.print_fn(f"NVMe hardware validation conclusion: {report['conclusion']}")
		self.print_fn(f"JSON report: {paths['json']}")
		self.print_fn(f"Markdown report: {paths['markdown']}")
		return report

	def prepare_nvme(self, device: str, *, execute: bool = False) -> dict[str, Any]:
		return self._prepare_test_data(device, execute=execute, validation_type="nvme")

	def prepare(self, device: str, *, execute: bool = False) -> dict[str, Any]:
		return self._prepare_test_data(device, execute=execute, validation_type="hdd")

	def _prepare_test_data(self, device: str, *, execute: bool, validation_type: str) -> dict[str, Any]:
		is_sata = validation_type == "sata-ssd"
		is_nvme = validation_type == "nvme"
		plan = self.plan_nvme(device, operation="prepare") if is_nvme else self.plan_sata_ssd(device, operation="prepare") if is_sata else self.plan(device, operation="prepare")
		if not execute:
			self.print_fn("PLAN ONLY: no filesystem or test data was created. Re-run with --execute after reviewing the identity.")
			return plan
		fresh = self.profiler.profile(device)
		fresh_filesystem = self._filesystem_snapshot(device)
		if is_nvme:
			fresh_scope = self.nvme_scope_resolver(device)
			self._assert_safe_nvme(fresh, fresh_filesystem, fresh_scope)
			self._assert_nvme_identity_unchanged(plan, fresh, fresh_scope)
		else:
			(self._assert_safe_sata_ssd if is_sata else self._assert_safe_hdd)(fresh, fresh_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(fresh))
		self._confirm(plan["confirmation_required"], fresh)
		armed = self.profiler.profile(device)
		armed_filesystem = self._filesystem_snapshot(device)
		if is_nvme:
			armed_scope = self.nvme_scope_resolver(device)
			self._assert_safe_nvme(armed, armed_filesystem, armed_scope)
			self._assert_nvme_identity_unchanged(plan, armed, armed_scope)
		else:
			(self._assert_safe_sata_ssd if is_sata else self._assert_safe_hdd)(armed, armed_filesystem)
		self._assert_identity_unchanged(plan["pre_test_profile"], asdict(armed))

		identity = self._identity(armed)
		mountpoint = self.output_directory / "mount" / safe_identifier(identity["stable_id"])
		mountpoint.mkdir(parents=True, exist_ok=True)
		mkfs = self._run(["mkfs.ext4", "-F", "-L", "VYPER_VALIDATION", device], timeout=3600)
		if not mkfs.success:
			raise HardwareValidationError("Test filesystem creation failed; preparation stopped.")
		mounted = False
		try:
			mount = self._run(["mount", device, str(mountpoint)], timeout=30)
			if not mount.success:
				raise HardwareValidationError("Controlled validation mount failed.")
			mounted = True
			files = self._create_test_files(mountpoint)
			sync = self._run(["sync"], timeout=120)
			if not sync.success:
				raise HardwareValidationError("sync failed while preparing validation data.")
		finally:
			if mounted:
				unmount = self._run(["umount", str(mountpoint)], timeout=120)
				if not unmount.success:
					raise HardwareValidationError("Validation filesystem could not be unmounted; sanitization remains blocked.")
		uuid_result = self._run(["blkid", "-s", "UUID", "-o", "value", device], timeout=30)
		manifest = {
			"kind": "physical_nvme_test_data" if is_nvme else "physical_sata_ssd_test_data" if is_sata else "physical_hdd_test_data",
			"created_at": utc_now(),
			"vyper_version": __version__,
			"device_identity": identity,
			"filesystem": "ext4",
			"filesystem_uuid": uuid_result.stdout.strip() if uuid_result.success else None,
			"files": files,
			"unmounted": True,
			"limitations": ["The helper creates synthetic disposable test data only; it does not represent forensic recovery testing."],
		}
		self.output_directory.mkdir(parents=True, exist_ok=True)
		device_label = "nvme" if is_nvme else "sata-ssd" if is_sata else "hdd"
		path = self.output_directory / f"{self._timestamp()}-{device_label}-{safe_identifier(identity['stable_id'])}-test-data.json"
		path.write_text(json.dumps(_redact(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")
		self._restrict_report_permissions(path)
		manifest["manifest_path"] = str(path)
		self.print_fn(f"Prepared deterministic disposable test data and unmounted {device}.")
		self.print_fn(f"Test-data manifest: {path}")
		return manifest

	def _assert_safe_hdd(self, profile: DeviceProfile, filesystem: dict[str, Any]) -> None:
		if profile.errors:
			raise HardwareValidationError("Device profiling reported errors; safety state is unknown.")
		if profile.is_system_device is not False:
			raise HardwareValidationError("System-associated or unknown system-device state is refused.")
		if profile.mounted or filesystem.get("mounted"):
			raise HardwareValidationError("Mounted devices or child filesystems are refused.")
		if profile.device_type != "HDD" or profile.rotational is not True:
			raise HardwareValidationError("Physical HDD validation requires an explicitly rotational HDD.")
		if not isinstance(profile.size_bytes, int) or profile.size_bytes <= 0:
			raise HardwareValidationError("Unknown or invalid device capacity is refused.")
		if not profile.serial_number and not (profile.capabilities or {}).get("wwn"):
			raise HardwareValidationError("A stable serial number or WWN is required; a device path alone is insufficient.")
		if filesystem.get("query_succeeded") is not True:
			raise HardwareValidationError("Filesystem/topology state could not be read; execution is refused.")

	def _assert_safe_sata_ssd(self, profile: DeviceProfile, filesystem: dict[str, Any], *, require_erasable: bool = True) -> None:
		if profile.errors:
			raise HardwareValidationError("Device profiling reported errors; SATA safety state is unknown.")
		if profile.is_system_device is not False:
			raise HardwareValidationError("System-associated or unknown system-device state is refused.")
		if profile.mounted or filesystem.get("mounted"):
			raise HardwareValidationError("Mounted devices or child filesystems are refused.")
		if profile.device_type not in {"SATA SSD", "SATA_SSD", "SSD"} or profile.rotational is not False:
			raise HardwareValidationError("SATA SSD validation requires a positively identified non-rotational SATA/ATA SSD; HDD and NVMe devices are refused.")
		if not isinstance(profile.size_bytes, int) or profile.size_bytes <= 0:
			raise HardwareValidationError("Unknown or invalid device capacity is refused.")
		if not profile.serial_number and not (profile.capabilities or {}).get("wwn"):
			raise HardwareValidationError("A stable serial number or WWN is required; a device path alone is insufficient.")
		if filesystem.get("query_succeeded") is not True:
			raise HardwareValidationError("Filesystem/topology state could not be read; execution is refused.")
		if require_erasable:
			blockers = self._sata_execution_blockers(profile)
			if blockers:
				raise HardwareValidationError(blockers[0])

	def _sata_execution_blockers(self, profile: DeviceProfile) -> list[str]:
		blockers: list[str] = []
		transport = str(profile.transport or "").strip().lower()
		interface = str(profile.interface or "").strip().lower()
		if "usb" in transport or "usb" in interface:
			if (profile.capabilities or {}).get("ata_pass_through_verified") is not True:
				blockers.append("USB-to-SATA bridge detected without proven ATA pass-through; direct SATA attachment is preferred and execution is refused.")
		elif not any(marker in interface or marker in transport for marker in ("ata", "sata")):
			blockers.append("The interface is not positively identified as ATA/SATA; execution is refused.")
		capabilities = self._ata_capability_summary(profile)
		if capabilities["hdparm_available"] is not True or capabilities["security_supported"] is not True or capabilities["secure_erase_supported"] is not True:
			blockers.append("ATA Security/Secure Erase support is unavailable or unproven; no fallback pathway is permitted.")
		if capabilities["security_frozen"] is True:
			blockers.append("ATA security is frozen; automatic unfreeze is not implemented. Use hardware-appropriate manual handling and re-plan.")
		policy_preview = PolicyEngine(dry_run=True).decide(profile)
		if policy_preview.selected_pathway != "ATA_ERASE":
			blockers.append(f"Current VYPER policy would select {policy_preview.selected_pathway or 'no pathway'}, not ATA_ERASE; validation refuses substitution or fallback.")
		return blockers

	def _ata_capability_summary(self, profile: DeviceProfile) -> dict[str, Any]:
		capabilities = profile.capabilities or {}
		security = capabilities.get("security") if isinstance(capabilities.get("security"), dict) else {}
		raw = str(security.get("raw_output") or "")
		lowered = raw.lower()
		enabled = bool(security.get("enabled"))
		if "not enabled" in lowered or "security: disabled" in lowered or "security disabled" in lowered:
			enabled = False
		elif re.search(r"(?m)^\s*enabled\s*$", lowered) or "security: enabled" in lowered:
			enabled = True
		frozen = bool(security.get("frozen"))
		if "not frozen" in lowered:
			frozen = False
		elif re.search(r"(?m)^\s*frozen\s*$", lowered) or "security: frozen" in lowered:
			frozen = True
		erase_times = [line.strip() for line in raw.splitlines() if "erase unit" in line.lower()]
		ata_standard = next((line.strip() for line in raw.splitlines() if any(marker in line.lower() for marker in ("ata version is", "ata standard", "transport:"))), None)
		return {
			"hdparm_available": capabilities.get("hdparm_available") is True,
			"security_supported": security.get("supported") is True,
			"security_enabled": enabled,
			"security_frozen": frozen,
			"secure_erase_supported": security.get("secure_erase_supported") is True or "security erase unit" in lowered,
			"enhanced_secure_erase_supported": "enhanced erase" in lowered or "enhanced secure erase" in lowered,
			"estimated_erase_time": erase_times or None,
			"ata_standard_or_version": ata_standard,
		}

	def _assert_safe_nvme(self, profile: DeviceProfile, filesystem: dict[str, Any], scope: dict[str, Any],
		*, require_executable: bool = True) -> None:
		if profile.errors or profile.device_type != "NVMe":
			raise HardwareValidationError("Physical NVMe validation requires a positively identified NVMe namespace with no profile errors.")
		if profile.is_system_device is not False:
			raise HardwareValidationError("System-associated or unknown NVMe system-device state is refused.")
		if profile.mounted or filesystem.get("mounted"):
			raise HardwareValidationError("Mounted NVMe namespaces or child filesystems are refused.")
		if not isinstance(profile.size_bytes, int) or profile.size_bytes <= 0:
			raise HardwareValidationError("Unknown or invalid NVMe namespace capacity is refused.")
		if filesystem.get("query_succeeded") is not True or scope.get("topology_known") is not True:
			raise HardwareValidationError("NVMe topology/holder state is unknown; execution is refused.")
		if scope.get("active_holders"):
			raise HardwareValidationError("NVMe namespace has active holders or RAID/LVM/device-mapper dependencies.")
		if not self._nvme_identity(profile, scope).get("stable_id"):
			raise HardwareValidationError("Stable NGUID, EUI-64, namespace UUID, or controller identity tuple is required.")
		if require_executable:
			policy = PolicyEngine(dry_run=True).decide(profile)
			blockers = self._nvme_execution_blockers(profile, scope, policy)
			if blockers:
				raise HardwareValidationError(blockers[0])

	def _nvme_execution_blockers(self, profile: DeviceProfile, scope: dict[str, Any], policy: Any) -> list[str]:
		blockers: list[str] = list(scope.get("execution_blockers") or [])
		if scope.get("scope_proven") is not True:
			limitation = str(scope.get("scope_limitation") or "Controller/namespace sanitize scope is not proven; execution is blocked.")
			if limitation not in blockers:
				blockers.append(limitation)
		if scope.get("controller_reachable") is not True:
			blockers.append("Resolved NVMe controller is not reachable through read-only identify commands.")
		capabilities = self._nvme_capability_summary(profile, scope)
		method = str(policy.selected_pathway or "")
		canonical = self._canonical_nvme_method(method)
		if capabilities.get("sanicap_raw") is None:
			blockers.append("NVMe SANICAP is missing or unknown; support is not inferred from device type.")
		if not self._nvme_method_supported(canonical, capabilities):
			blockers.append(f"Policy-selected method {method or 'none'} is not supported by the observed SANICAP; no fallback is allowed.")
		if sanact_for_method(canonical) is None:
			blockers.append(f"No exact SANACT mapping exists for policy-selected method {method or 'none'}.")
		return blockers

	def _nvme_capability_summary(self, profile: DeviceProfile, scope: dict[str, Any]) -> dict[str, Any]:
		sanicap = (profile.capabilities or {}).get("sanicap")
		sanicap = sanicap if isinstance(sanicap, dict) else {}
		controller = scope.get("controller_identify") if isinstance(scope.get("controller_identify"), dict) else {}
		controller_sanicap = scope.get("controller_sanicap") if isinstance(scope.get("controller_sanicap"), dict) else {}
		controller_raw = controller_sanicap.get("raw") if controller_sanicap else controller.get("sanicap")
		raw = controller_raw if controller_raw is not None else sanicap.get("raw")
		try:
			raw_bits = int(str(raw), 0) if raw is not None else None
		except (TypeError, ValueError):
			raw_bits = None
		# The directly identified controller is authoritative when it reports
		# SANICAP. Profile booleans remain the read-only fallback for older
		# profiler fixtures and must never add support absent from that value.
		if controller_raw is not None:
			crypto_supported = bool(raw_bits is not None and raw_bits & 0x1)
			block_supported = bool(raw_bits is not None and raw_bits & 0x2)
			overwrite_supported = bool(raw_bits is not None and raw_bits & 0x4)
		else:
			crypto_supported = sanicap.get("crypto_erase") is True
			block_supported = sanicap.get("block_erase") is True
			overwrite_supported = sanicap.get("overwrite") is True
		return {
			"sanicap_raw": raw,
			"crypto_erase_supported": crypto_supported,
			"block_erase_supported": block_supported,
			"overwrite_supported": overwrite_supported,
			"no_deallocate_modifies_media_after_sanitize": controller.get("nodmmas"),
			"controller_model": controller.get("mn") or profile.model,
			"controller_serial": controller.get("sn") or profile.serial_number,
			"firmware_revision": controller.get("fr"),
		}

	def _nvme_method_supported(self, method: str, capabilities: dict[str, Any]) -> bool:
		return {
			"CRYPTO_ERASE": capabilities.get("crypto_erase_supported") is True,
			"BLOCK_ERASE": capabilities.get("block_erase_supported") is True,
			"OVERWRITE": capabilities.get("overwrite_supported") is True,
		}.get(method, False)

	def _canonical_nvme_method(self, method: str) -> str:
		return "OVERWRITE" if str(method).upper() in {"NVME_OVERWRITE", "OVERWRITE"} else str(method or "").upper()

	def _nvme_identity(self, profile: DeviceProfile, scope: dict[str, Any]) -> dict[str, Any]:
		caps = profile.capabilities or {}
		ns = scope.get("namespace_identify") if isinstance(scope.get("namespace_identify"), dict) else {}
		ctrl = scope.get("controller_identify") if isinstance(scope.get("controller_identify"), dict) else {}
		# Prefer the freshly resolved namespace identify data. The profiler
		# values are a fallback only; otherwise a stale profile could mask a
		# namespace replacement observed during the final safety re-probe.
		nguid = str(ns.get("nguid") or caps.get("nvme_nguid") or "").strip().lower() or None
		eui = str(ns.get("eui64") or ns.get("eui") or caps.get("nvme_eui64") or "").strip().lower() or None
		namespace_uuid = str(ns.get("uuid") or "").strip().lower() or None
		serial = str(ctrl.get("sn") or profile.serial_number or "").strip() or None
		model = str(ctrl.get("mn") or profile.model or "").strip() or None
		fallback = f"{serial}|{model}|{scope.get('namespace_id')}|{profile.size_bytes}" if serial and model and scope.get("namespace_id") else None
		stable = nguid or eui or namespace_uuid or fallback
		return {
			"device_path": profile.device_path, "namespace_path": profile.device_path,
			"controller_path": scope.get("controller_path"), "sanitize_target": scope.get("sanitize_target"),
			"model": model, "serial_number": serial, "firmware_revision": ctrl.get("fr"),
			"size_bytes": profile.size_bytes, "namespace_id": scope.get("namespace_id"),
			"nguid": nguid, "eui64": eui, "namespace_uuid": namespace_uuid,
			"pci_controller_identity": scope.get("pci_controller_identity"), "transport": profile.transport,
			"device_type": profile.device_type, "is_system_device": profile.is_system_device,
			"mounted": profile.mounted, "stable_id": stable,
		}

	def _assert_nvme_identity_unchanged(self, plan: dict[str, Any], profile: DeviceProfile, scope: dict[str, Any]) -> None:
		if not self._nvme_identity_matches(plan["device_identity"], profile, scope):
			raise HardwareValidationError("NVMe namespace/controller identity or capacity changed; no job was submitted.")

	def _nvme_identity_matches(self, planned: dict[str, Any], profile: DeviceProfile, scope: dict[str, Any]) -> bool:
		fresh = self._nvme_identity(profile, scope)
		keys = ("controller_path", "model", "serial_number", "firmware_revision", "size_bytes", "namespace_id", "nguid", "eui64", "namespace_uuid", "stable_id")
		return bool(planned.get("stable_id")) and all(planned.get(key) == fresh.get(key) for key in keys)

	def _resolve_nvme_scope(self, namespace: str) -> dict[str, Any]:
		resolver = NVMeControllerResolver(
			profiler=self.profiler,
			command_executor=self.command_executor,
			sysfs_root=getattr(self.profiler, "sysfs_root", "/sys"),
		)
		return resolver.resolve(namespace)

	def _nvme_active_holders(self, output: str) -> list[str]:
		payload = self._json_object(output)
		unsafe: list[str] = []
		stack = list(payload.get("blockdevices") or [])
		while stack:
			node = stack.pop()
			if not isinstance(node, dict):
				continue
			if str(node.get("type") or "").lower() in {"lvm", "crypt", "raid", "raid0", "raid1", "raid5", "raid6", "raid10", "dm", "mpath"}:
				unsafe.append(str(node.get("path") or node.get("name") or node.get("type")))
			if any(node.get("mountpoints") or []):
				unsafe.append(str(node.get("path") or node.get("name") or "mounted"))
			stack.extend(node.get("children") or [])
		return unsafe

	def _json_object(self, output: str) -> dict[str, Any]:
		try:
			payload = json.loads(output or "{}")
		except json.JSONDecodeError:
			return {}
		return payload if isinstance(payload, dict) else {}

	def _identity(self, profile: DeviceProfile) -> dict[str, Any]:
		wwn = (profile.capabilities or {}).get("wwn")
		stable_id = str(wwn or profile.serial_number or "")
		return {
			"device_path": profile.device_path,
			"model": profile.model,
			"serial_number": profile.serial_number,
			"wwn": wwn,
			"stable_id": stable_id,
			"size_bytes": profile.size_bytes,
			"transport": profile.transport,
			"interface": profile.interface,
			"rotational": profile.rotational,
			"device_type": profile.device_type,
			"is_system_device": profile.is_system_device,
			"mounted": profile.mounted,
			"partitions": list(profile.mounted_partitions),
		}

	def _assert_identity_unchanged(self, planned: dict[str, Any], fresh: dict[str, Any]) -> None:
		if not self._identity_matches(planned, fresh):
			raise HardwareValidationError("Device identity changed between planning and execution; no job was submitted.")

	def _identity_matches(self, planned: dict[str, Any], fresh: dict[str, Any]) -> bool:
		planned_caps = planned.get("capabilities") or {}
		fresh_caps = fresh.get("capabilities") or {}
		for key in ("serial_number", "size_bytes", "model", "rotational", "device_type"):
			if planned.get(key) != fresh.get(key):
				return False
		for key in ("wwn",):
			if planned_caps.get(key) != fresh_caps.get(key):
				return False
		return bool(planned.get("serial_number") or planned_caps.get("wwn"))

	def _confirmation_phrase(self, identity: dict[str, Any], operation: str) -> str:
		prefix = "ERASE" if operation == "validate" else "PREPARE"
		return f"{prefix} {safe_identifier(identity['stable_id'])[-6:]}"

	def _confirm(self, phrase: str, profile: DeviceProfile) -> None:
		identity = self._identity(profile)
		self.print_fn("FINAL DEVICE IDENTITY")
		self.print_fn(json.dumps(identity, indent=2, sort_keys=True))
		entered = self.input_fn(f"Type exactly '{phrase}' to continue: ")
		if entered != phrase:
			raise HardwareValidationError("Validation confirmation did not match; no destructive action was started.")

	def _wait_for_job(self, local_job_id: str, *, poll_seconds: float, timeout_seconds: float,
		capture_indeterminate: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
		deadline = time.monotonic() + timeout_seconds
		seen: set[int] = set()
		progress: list[dict[str, Any]] = []
		while True:
			job = self.local_client.get_job(local_job_id)
			for event in job.get("state_history") or []:
				sequence = event.get("sequence")
				measurement = event.get("progress") or {}
				if sequence in seen or measurement.get("kind") not in ({"bytes", "indeterminate"} if capture_indeterminate else {"bytes"}):
					continue
				seen.add(sequence)
				entry = {"timestamp": event.get("timestamp")}
				if capture_indeterminate:
					entry["kind"] = measurement.get("kind")
				if measurement.get("kind") == "bytes":
					entry.update({"bytes_completed": measurement.get("bytes_completed"), "bytes_total": measurement.get("bytes_total")})
				progress.append(entry)
				if measurement.get("kind") == "bytes":
					self.print_fn(f"Progress: {entry['bytes_completed']}/{entry['bytes_total']} bytes at {entry['timestamp']}")
				else:
					self.print_fn(f"Progress: indeterminate ATA firmware operation at {entry['timestamp']}")
			if str(job.get("job_state")) in TERMINAL_STATES:
				return job, progress
			if time.monotonic() >= deadline:
				raise HardwareValidationError("Timed out waiting for the durable local VYPER job; inspect it before retrying.")
			self.sleep_fn(max(0.1, poll_seconds))

	def _wait_for_nvme_job(self, local_job_id: str, controller: str, *, poll_seconds: float,
		timeout_seconds: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
		deadline = time.monotonic() + timeout_seconds
		timeline: list[dict[str, Any]] = []
		while True:
			job = self.local_client.get_job(local_job_id)
			observation = self._observe_nvme_status(controller)
			if not timeline or observation.get("raw_json") != timeline[-1].get("raw_json") or observation.get("normalized_status") != timeline[-1].get("normalized_status"):
				timeline.append(observation)
				self.print_fn(f"NVMe sanitize status: {observation['normalized_status']} (indeterminate progress) at {observation['timestamp']}")
			if str(job.get("job_state")) in TERMINAL_STATES:
				return job, timeline
			if time.monotonic() >= deadline:
				raise HardwareValidationError("Timed out waiting for the durable NVMe job; sanitize is not re-submitted and completion remains unproven.")
			self.sleep_fn(max(0.1, poll_seconds))

	def _observe_nvme_status(self, controller: str) -> dict[str, Any]:
		result = self._run(sanitize_log_command(controller), timeout=30)
		raw = result.stdout.strip() if result.success else None
		parsed = parse_sanitize_log(raw or "") if result.success else None
		return {
			"timestamp": utc_now(), "query_succeeded": result.success,
			"raw_json": raw, "sstat_raw": parsed.get("sstat") if parsed else None,
			"status_bits": parsed.get("status_code") if parsed else None,
			"normalized_status": parsed.get("status") if parsed else "UNKNOWN",
			"global_data_erased": parsed.get("global_data_erased") if parsed else None,
			"status_text": (self._json_object(raw or "").get("sstat") if raw else None),
		}

	def _post_checks(self, device: str, size_bytes: int | None) -> dict[str, Any]:
		lsblk = self._run(["lsblk", "--json", "--fs", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,FSVER,LABEL,UUID,SIZE,MOUNTPOINTS", device], timeout=30)
		blkid = self._run(["blkid", "-p", device], timeout=30)
		file_result = self._run(["file", "-s", device], timeout=30)
		filesystem_detected = self._lsblk_has_filesystem(lsblk.stdout) if lsblk.success else None
		blkid_detected = bool(blkid.success and blkid.stdout.strip())
		blkid_query_valid = blkid.exit_code in {0, 2}
		file_text = file_result.stdout.strip() if file_result.success else ""
		file_signature_detected = any(marker in file_text.lower() for marker in (
			"filesystem", "partition table", "ext2", "ext3", "ext4", "ntfs", "fat", "xfs", "btrfs",
		))
		samples: list[dict[str, Any]] = []
		sample_size = 4096
		if isinstance(size_bytes, int) and size_bytes >= sample_size:
			offsets = [0, max(0, (size_bytes // 2) - (sample_size // 2)), max(0, size_bytes - sample_size)]
			for label, offset in zip(("beginning", "middle", "end"), offsets):
				try:
					data = self.read_sample(device, offset, sample_size)
					samples.append({
						"region": label, "offset": offset, "sample_size": sample_size,
						"bytes_read": len(data), "expected_pattern": "00",
						"matches_expected_pattern": len(data) == sample_size and not any(data),
						"sha256": hashlib.sha256(data).hexdigest(),
					})
				except OSError as exc:
					samples.append({"region": label, "offset": offset, "sample_size": sample_size,
						"bytes_read": 0, "expected_pattern": "00", "matches_expected_pattern": False,
						"read_error": type(exc).__name__})
		consistent = (
			lsblk.success and blkid_query_valid and file_result.success
			and filesystem_detected is False and not blkid_detected and not file_signature_detected and len(samples) == 3
			and all(sample.get("matches_expected_pattern") is True for sample in samples)
		)
		return {
			"lsblk_f": self._result_summary(lsblk),
			"blkid": self._result_summary(blkid),
			"file_s": self._result_summary(file_result),
			"filesystem_detected": filesystem_detected,
			"blkid_detected": blkid_detected,
			"blkid_query_valid": blkid_query_valid,
			"file_type": file_text or None,
			"file_signature_detected": file_signature_detected if file_result.success else None,
			"sample_offsets": [sample.get("offset") for sample in samples],
			"sample_size": sample_size,
			"sample_results": samples,
			"known_test_data_accessible": False if consistent else None,
			"consistent_with_zero_overwrite": consistent,
		}

	def _post_checks_sata(self, device: str, post_profile: DeviceProfile) -> dict[str, Any]:
		lsblk = self._run(["lsblk", "--json", "--fs", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,FSVER,LABEL,UUID,SIZE,MOUNTPOINTS", device], timeout=30)
		blkid = self._run(["blkid", "-p", device], timeout=30)
		file_result = self._run(["file", "-s", device], timeout=30)
		udevadm = self._run(["udevadm", "info", "--query=property", "--name", device], timeout=30)
		hdparm = self._run(["hdparm", "-I", device], timeout=30)
		smartctl = self._run(["smartctl", "-i", device], timeout=30)
		filesystem_detected = self._lsblk_has_filesystem(lsblk.stdout) if lsblk.success else None
		filesystem_uuid, lsblk_capacity = self._lsblk_uuid_and_capacity(lsblk.stdout) if lsblk.success else (None, None)
		blkid_detected = bool(blkid.success and blkid.stdout.strip())
		blkid_query_valid = blkid.exit_code in {0, 2}
		file_text = file_result.stdout.strip() if file_result.success else ""
		file_signature_detected = any(marker in file_text.lower() for marker in (
			"filesystem", "partition table", "ext2", "ext3", "ext4", "ntfs", "fat", "xfs", "btrfs",
		))
		udev_properties = self._parse_key_value_lines(udevadm.stdout) if udevadm.success else {}
		ata_state = self._ata_state_from_output(hdparm.stdout if hdparm.success else "", post_profile)
		serial_reported = udev_properties.get("ID_SERIAL_SHORT")
		wwn_reported = udev_properties.get("ID_WWN") or udev_properties.get("ID_WWN_WITH_EXTENSION")
		identity_consistent = (
			(serial_reported is None or serial_reported == post_profile.serial_number)
			and (wwn_reported is None or str(wwn_reported).lower() == str((post_profile.capabilities or {}).get("wwn") or "").lower())
			and (lsblk_capacity is None or lsblk_capacity == post_profile.size_bytes)
		)
		required_probes_succeeded = lsblk.success and blkid_query_valid and file_result.success and udevadm.success and hdparm.success
		old_filesystem_inaccessible = filesystem_detected is False and not blkid_detected and not file_signature_detected
		controller_accessible = bool(hdparm.success and post_profile.device_type in {"SATA SSD", "SATA_SSD", "SSD"})
		consistent = bool(
			required_probes_succeeded and identity_consistent and controller_accessible
			and old_filesystem_inaccessible and ata_state.get("security_supported") is True
			and ata_state.get("security_enabled") is False and ata_state.get("security_frozen") is False
		)
		return {
			"lsblk_f": self._result_summary(lsblk),
			"blkid": self._result_summary(blkid),
			"file_s": self._result_summary(file_result),
			"udevadm_info": self._result_summary(udevadm),
			"hdparm_identify": self._result_summary(hdparm),
			"smartctl_identify": self._result_summary(smartctl),
			"smartctl_available": smartctl.success,
			"filesystem_detected": filesystem_detected,
			"filesystem_uuid": filesystem_uuid,
			"blkid_detected": blkid_detected,
			"blkid_query_valid": blkid_query_valid,
			"file_signature": file_text or None,
			"file_signature_detected": file_signature_detected if file_result.success else None,
			"ata_security_state": ata_state,
			"model": post_profile.model,
			"serial_number": post_profile.serial_number,
			"wwn": (post_profile.capabilities or {}).get("wwn"),
			"capacity": post_profile.size_bytes,
			"udev_properties": udev_properties,
			"identity_consistent": identity_consistent,
			"controller_accessible": controller_accessible,
			"old_filesystem_normally_accessible": False if old_filesystem_inaccessible else True,
			"required_probes_succeeded": required_probes_succeeded,
			"consistent_with_ata_secure_erase": consistent,
		}

	def _post_checks_nvme(self, namespace: str, scope: dict[str, Any]) -> dict[str, Any]:
		controller = str(scope.get("controller_path") or "")
		id_ctrl = self._run(["nvme", "id-ctrl", controller, "--output-format=json"], timeout=30)
		id_ns = self._run(["nvme", "id-ns", namespace, "--output-format=json"], timeout=30)
		sanitize_log = self._run(sanitize_log_command(controller), timeout=30)
		lsblk = self._run(["lsblk", "--json", "--fs", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,FSVER,LABEL,UUID,SIZE,MOUNTPOINTS", namespace], timeout=30)
		blkid = self._run(["blkid", "-p", namespace], timeout=30)
		file_result = self._run(["file", "-s", namespace], timeout=30)
		udevadm = self._run(["udevadm", "info", "--query=property", "--name", namespace], timeout=30)
		parsed = parse_sanitize_log(sanitize_log.stdout) if sanitize_log.success else None
		filesystem_detected = self._lsblk_has_filesystem(lsblk.stdout) if lsblk.success else None
		filesystem_uuid, capacity = self._lsblk_uuid_and_capacity(lsblk.stdout) if lsblk.success else (None, None)
		blkid_valid = blkid.exit_code in {0, 2}
		blkid_detected = bool(blkid.success and blkid.stdout.strip())
		file_text = file_result.stdout.strip() if file_result.success else ""
		file_signature = any(marker in file_text.lower() for marker in ("filesystem", "partition table", "ext4", "ntfs", "fat", "xfs", "btrfs"))
		critical = bool(id_ctrl.success and id_ns.success and sanitize_log.success and lsblk.success and blkid_valid and file_result.success and udevadm.success)
		return {
			"nvme_id_ctrl": self._result_summary(id_ctrl), "nvme_id_ns": self._result_summary(id_ns),
			"nvme_sanitize_log": self._result_summary(sanitize_log), "lsblk_f": self._result_summary(lsblk),
			"blkid": self._result_summary(blkid), "file_s": self._result_summary(file_result),
			"udevadm_info": self._result_summary(udevadm),
			"controller_accessible": id_ctrl.success, "namespace_accessible": id_ns.success,
			"controller_identify": self._json_object(id_ctrl.stdout) if id_ctrl.success else None,
			"namespace_identify": self._json_object(id_ns.stdout) if id_ns.success else None,
			"sanitize_status": parsed, "sanitize_log_raw_json": sanitize_log.stdout.strip() if sanitize_log.success else None,
			"filesystem_detected": filesystem_detected, "filesystem_uuid": filesystem_uuid,
			"blkid_detected": blkid_detected, "file_signature": file_text or None,
			"file_signature_detected": file_signature if file_result.success else None,
			"capacity": capacity, "critical_probes_succeeded": critical,
			"contradictory_interface_evidence": bool(filesystem_detected or blkid_detected or file_signature),
			"logical_post_checks_are_secondary": True,
		}

	def _ata_state_from_output(self, output: str, profile: DeviceProfile) -> dict[str, Any]:
		fallback = self._ata_capability_summary(profile)
		lowered = output.lower()
		supported = fallback["security_supported"] or "security:" in lowered or "security support" in lowered
		enabled = fallback["security_enabled"]
		if "not enabled" in lowered or "security: disabled" in lowered or "security disabled" in lowered:
			enabled = False
		elif re.search(r"(?m)^\s*enabled\s*$", lowered) or "security: enabled" in lowered:
			enabled = True
		frozen = fallback["security_frozen"]
		if "not frozen" in lowered:
			frozen = False
		elif re.search(r"(?m)^\s*frozen\s*$", lowered) or "security: frozen" in lowered:
			frozen = True
		return {
			"security_supported": bool(supported),
			"security_enabled": bool(enabled),
			"security_frozen": bool(frozen),
			"secure_erase_supported": fallback["secure_erase_supported"],
			"enhanced_secure_erase_supported": fallback["enhanced_secure_erase_supported"],
			"raw_output": output.strip() or None,
		}

	def _lsblk_uuid_and_capacity(self, output: str) -> tuple[str | None, int | None]:
		try:
			payload = json.loads(output or "{}")
		except json.JSONDecodeError:
			return None, None
		devices = payload.get("blockdevices") or []
		if not devices or not isinstance(devices[0], dict):
			return None, None
		device = devices[0]
		try:
			capacity = int(device.get("size")) if device.get("size") is not None else None
		except (TypeError, ValueError):
			capacity = None
		stack = [device]
		uuid = None
		while stack:
			node = stack.pop()
			if isinstance(node, dict):
				uuid = uuid or (str(node.get("uuid")) if node.get("uuid") else None)
				stack.extend(node.get("children") or [])
		return uuid, capacity

	def _parse_key_value_lines(self, output: str) -> dict[str, str]:
		values: dict[str, str] = {}
		for line in output.splitlines():
			if "=" not in line:
				continue
			key, value = line.split("=", 1)
			if key.strip():
				values[key.strip()] = value.strip()
		return values

	def _build_report(self, *, plan: dict[str, Any], job: dict[str, Any], progress: list[dict[str, Any]],
		post_profile: DeviceProfile, identity_preserved: bool, post_checks: dict[str, Any]) -> dict[str, Any]:
		evidence = job.get("evidence") if isinstance(job.get("evidence"), dict) else {}
		certificate = job.get("certificate") if isinstance(job.get("certificate"), dict) else {}
		verification = job.get("verification") if isinstance(job.get("verification"), dict) else {}
		evidence_ok = bool(evidence.get("integrity_hash")) and EvidenceCollector().verify_integrity(evidence)
		certificate_ok = bool(certificate.get("certificate_hash")) and verify_certificate_integrity(certificate)
		bound = str((certificate.get("evidence_integrity") or {}).get("hash") or "") == str(evidence.get("integrity_hash") or "")
		execution = job.get("execution") if isinstance(job.get("execution"), dict) else {}
		execution_metadata = execution.get("metadata") if isinstance(execution.get("metadata"), dict) else {}
		pathway = str((job.get("policy") or {}).get("selected_pathway") or execution_metadata.get("method") or "")
		vyper_verified = (
			job.get("final_status") == "VERIFIED" and verification.get("status") == "VERIFIED"
			and verification.get("verified") is True and pathway == "HDD_OVERWRITE"
			and evidence.get("final_status") == "VERIFIED"
			and certificate.get("final_status") == "VERIFIED"
			and certificate.get("outcome_kind") == "sanitization_certificate"
			and certificate.get("successful_sanitization_claim") is True
		)
		integrity_ok = evidence_ok and certificate_ok and bound
		if job.get("final_status") == "FAILED":
			conclusion = "FAIL"
		elif identity_preserved and vyper_verified and integrity_ok and post_checks.get("consistent_with_zero_overwrite") is True:
			conclusion = "PASS"
		else:
			conclusion = "INCONCLUSIVE"
		statement = (
			"Known test data is no longer accessible through the logical block interface and sampled regions match the expected overwrite pattern."
			if conclusion == "PASS" else
			"The available VYPER result or independent logical-interface checks did not support a complete hardware-validation pass."
		)
		return _redact({
			"schema_version": 1,
			"validation_kind": "physical_hdd",
			"generated_at": utc_now(),
			"vyper_version": __version__,
			"device_identity": plan["device_identity"],
			"pre_test_profile": plan["pre_test_profile"],
			"test_data_manifest": self._load_latest_test_manifest(plan["device_identity"]["stable_id"]),
			"local_job_id": job.get("local_job_id"),
			"selected_pathway": pathway,
			"policy_result": job.get("policy"),
			"execution_metadata": job.get("execution"),
			"progress_summary": {
				"measurements": progress,
				"measurement_count": len(progress),
				"final": progress[-1] if progress else None,
			},
			"verification_result": verification,
			"evidence_hash": evidence.get("integrity_hash"),
			"certificate_hash": certificate.get("certificate_hash"),
			"integrity": {"evidence_valid": evidence_ok, "certificate_valid": certificate_ok, "evidence_certificate_bound": bound},
			"identity_preserved": identity_preserved,
			"post_test_profile": asdict(post_profile),
			"independent_post_checks": post_checks,
			"limitations": REPORT_LIMITATIONS,
			"conclusion": conclusion,
			"conclusion_statement": statement,
		})

	def _build_sata_report(self, *, plan: dict[str, Any], job: dict[str, Any], progress: list[dict[str, Any]],
		post_profile: DeviceProfile, identity_preserved: bool, post_checks: dict[str, Any]) -> dict[str, Any]:
		evidence = job.get("evidence") if isinstance(job.get("evidence"), dict) else {}
		certificate = job.get("certificate") if isinstance(job.get("certificate"), dict) else {}
		verification = job.get("verification") if isinstance(job.get("verification"), dict) else {}
		execution = job.get("execution") if isinstance(job.get("execution"), dict) else {}
		execution_metadata = execution.get("metadata") if isinstance(execution.get("metadata"), dict) else {}
		evidence_ok = bool(evidence.get("integrity_hash")) and EvidenceCollector().verify_integrity(evidence)
		certificate_ok = bool(certificate.get("certificate_hash")) and verify_certificate_integrity(certificate)
		bound = str((certificate.get("evidence_integrity") or {}).get("hash") or "") == str(evidence.get("integrity_hash") or "")
		pathway = str((job.get("policy") or {}).get("selected_pathway") or execution_metadata.get("method") or "")
		vyper_verified = (
			job.get("final_status") == "VERIFIED" and verification.get("status") == "VERIFIED"
			and verification.get("verified") is True and pathway == "ATA_ERASE"
			and evidence.get("final_status") == "VERIFIED"
			and certificate.get("final_status") == "VERIFIED"
			and certificate.get("outcome_kind") == "sanitization_certificate"
			and certificate.get("successful_sanitization_claim") is True
		)
		integrity_ok = evidence_ok and certificate_ok and bound
		post_ata_state = post_checks.get("ata_security_state") or {}
		post_state_consistent = (
			post_ata_state.get("security_supported") is True
			and post_ata_state.get("security_enabled") is False
			and post_ata_state.get("security_frozen") is False
		)
		if job.get("final_status") == "FAILED":
			conclusion = "FAIL"
		elif (
			identity_preserved and post_profile.device_type in {"SATA SSD", "SATA_SSD", "SSD"}
			and post_profile.rotational is False and vyper_verified and integrity_ok
			and execution_metadata.get("erase_command_completed") is True
			and post_state_consistent and post_checks.get("consistent_with_ata_secure_erase") is True
		):
			conclusion = "PASS"
		else:
			conclusion = "INCONCLUSIVE"
		statement = (
			"The controller-native ATA erase completed, VYPER verified the device-reported post-state, and independent logical/interface checks found no contradictory old filesystem evidence."
			if conclusion == "PASS" else
			"The VYPER result, ATA controller state, integrity evidence, or independent checks did not support a complete SATA SSD hardware-validation pass."
		)
		ata_execution_evidence = {
			"ata_password_used": True,
			"pre_erase_security_state": plan["ata_capabilities"],
			"security_set_result_metadata": execution_metadata.get("set_password_result"),
			"erase_prepare_result_metadata": execution_metadata.get("erase_prepare_result"),
			"erase_execution_result_metadata": execution_metadata.get("erase_result"),
			"erase_command_completed": execution_metadata.get("erase_command_completed"),
			"security_frozen_before": execution_metadata.get("security_frozen_before"),
			"post_status": execution_metadata.get("post_status"),
			"duration_seconds": execution_metadata.get("duration_seconds"),
			"warnings": execution.get("warnings") or [],
			"errors": execution.get("errors") or [],
		}
		return _redact({
			"schema_version": 1,
			"validation_kind": "physical_sata_ssd",
			"verification_basis": ["controller/native command evidence", "VYPER verifier", "independent logical/interface checks"],
			"generated_at": utc_now(),
			"vyper_version": __version__,
			"device_identity": plan["device_identity"],
			"pre_test_profile": plan["pre_test_profile"],
			"ata_capabilities": plan["ata_capabilities"],
			"test_data_manifest": self._load_latest_test_manifest(plan["device_identity"]["stable_id"], device_label="sata-ssd"),
			"local_job_id": job.get("local_job_id"),
			"selected_pathway": pathway,
			"policy_result": job.get("policy"),
			"ata_execution_evidence": ata_execution_evidence,
			"execution_metadata": execution,
			"progress_summary": {
				"mode": "indeterminate",
				"measurements": progress,
				"measurement_count": len(progress),
				"percentage_claimed": False,
			},
			"verification_metadata": verification,
			"post_erase_security_state": post_ata_state,
			"evidence_hash": evidence.get("integrity_hash"),
			"certificate_hash": certificate.get("certificate_hash"),
			"integrity": {"evidence_valid": evidence_ok, "certificate_valid": certificate_ok, "evidence_certificate_bound": bound},
			"identity_preserved": identity_preserved,
			"post_test_profile": asdict(post_profile),
			"independent_post_checks": post_checks,
			"limitations": [
				"ATA Secure Erase validation relies primarily on controller command completion and device-reported security state.",
				"Logical checks do not prove every NAND cell, spare block, remapped block, or over-provisioned area was independently read.",
				"No aggressive forensic recovery is performed.",
			],
			"conclusion": conclusion,
			"conclusion_statement": statement,
		})

	def _write_sata_report(self, report: dict[str, Any]) -> dict[str, Path]:
		self.output_directory.mkdir(parents=True, exist_ok=True)
		identity = report["device_identity"]["stable_id"]
		stem = f"{self._timestamp()}-sata-ssd-{safe_identifier(identity)}"
		json_path = self.output_directory / f"{stem}.json"
		markdown_path = self.output_directory / f"{stem}.md"
		json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
		markdown_path.write_text(self._sata_markdown(report), encoding="utf-8")
		self._restrict_report_permissions(json_path)
		self._restrict_report_permissions(markdown_path)
		return {"json": json_path, "markdown": markdown_path}

	def _build_nvme_report(self, *, plan: dict[str, Any], job: dict[str, Any], timeline: list[dict[str, Any]],
		post_profile: DeviceProfile, post_scope: dict[str, Any], identity_preserved: bool,
		post_checks: dict[str, Any]) -> dict[str, Any]:
		evidence = job.get("evidence") if isinstance(job.get("evidence"), dict) else {}
		certificate = job.get("certificate") if isinstance(job.get("certificate"), dict) else {}
		verification = job.get("verification") if isinstance(job.get("verification"), dict) else {}
		execution = job.get("execution") if isinstance(job.get("execution"), dict) else {}
		metadata = execution.get("metadata") if isinstance(execution.get("metadata"), dict) else {}
		method = str(plan.get("policy_selected_method") or "")
		canonical = self._canonical_nvme_method(method)
		expected_sanact = sanact_for_method(canonical)
		effective_method = self._canonical_nvme_method(str(metadata.get("sanitize_method") or ""))
		evidence_ok = bool(evidence.get("integrity_hash")) and EvidenceCollector().verify_integrity(evidence)
		certificate_ok = bool(certificate.get("certificate_hash")) and verify_certificate_integrity(certificate)
		bound = str((certificate.get("evidence_integrity") or {}).get("hash") or "") == str(evidence.get("integrity_hash") or "")
		post_status = post_checks.get("sanitize_status") if isinstance(post_checks.get("sanitize_status"), dict) else {}
		controller_status = str(post_status.get("status") or "UNKNOWN")
		verified = (
			job.get("final_status") == "VERIFIED" and verification.get("status") == "VERIFIED"
			and verification.get("verified") is True and evidence.get("final_status") == "VERIFIED"
			and certificate.get("final_status") == "VERIFIED"
			and certificate.get("successful_sanitization_claim") is True
			and certificate.get("outcome_kind") == "sanitization_certificate"
		)
		mapping_ok = effective_method == canonical and str(metadata.get("sanact")) == expected_sanact
		command_submitted = metadata.get("command_submitted") is True
		failure_state = controller_status in {"FAILED", "ABORTED"} or job.get("final_status") == "FAILED"
		if failure_state:
			conclusion = "FAIL"
		elif (
			identity_preserved and post_profile.device_type == "NVMe" and post_scope.get("scope_proven") is True
			and self._nvme_method_supported(canonical, plan["nvme_capabilities"])
			and mapping_ok and command_submitted and controller_status == "COMPLETED" and verified
			and evidence_ok and certificate_ok and bound and post_checks.get("critical_probes_succeeded") is True
			and post_checks.get("contradictory_interface_evidence") is False
		):
			conclusion = "PASS"
		else:
			conclusion = "INCONCLUSIVE"
		wording = {
			"CRYPTO_ERASE": "controller-reported completion of NVMe cryptographic sanitize",
			"BLOCK_ERASE": "controller-reported completion of NVMe block erase sanitize",
			"OVERWRITE": "controller-reported completion of NVMe overwrite sanitize",
		}.get(canonical, "controller-reported NVMe sanitize completion")
		return _redact({
			"schema_version": 1, "validation_kind": "physical_nvme", "generated_at": utc_now(),
			"vyper_version": __version__, "device_identity": plan["device_identity"],
			"asset_namespace_identity": plan.get("asset_namespace_identity"),
			"controller_identity": plan.get("controller_identity"),
			"requested_namespace": plan["requested_namespace"], "resolved_controller": plan["resolved_controller"],
			"sanitize_target": plan["sanitize_target"], "scope_validation": plan["scope_validation"],
			"nvme_capabilities": plan["nvme_capabilities"], "policy_selected_method": method,
			"expected_sanact": expected_sanact, "actual_effective_method": effective_method or None,
			"actual_sanact": str(metadata.get("sanact")) if metadata.get("sanact") is not None else None,
			"pre_test_profile": plan["pre_test_profile"],
			"test_data_manifest": self._load_latest_test_manifest(plan["device_identity"]["stable_id"], device_label="nvme"),
			"command_submission_result": {"submitted": command_submitted, "completion_status": metadata.get("completion_status"),
				"duration_seconds": metadata.get("duration_seconds"), "warnings": execution.get("warnings") or [], "errors": execution.get("errors") or []},
			"controller_completion_result": post_status or None,
			"sanitize_status_timeline": timeline,
			"progress_summary": {"mode": "indeterminate", "percentage_claimed": False,
				"display": "RUNNING — controller sanitize operation in progress"},
			"verification_result": verification, "evidence_hash": evidence.get("integrity_hash"),
			"certificate_hash": certificate.get("certificate_hash"),
			"integrity": {"evidence_valid": evidence_ok, "certificate_valid": certificate_ok, "evidence_certificate_bound": bound},
			"identity_preserved": identity_preserved, "post_test_profile": asdict(post_profile),
			"independent_post_checks": post_checks,
			"verification_basis": self._nvme_verification_basis(canonical, expected_sanact),
			"limitations": [
				"NVMe sanitize completion is controller-reported and depends on controller firmware correctness.",
				"Host logical reads do not independently prove every NAND location, spare area, remapped block, or encryption key state.",
				"ABORTED is distinguished from FAILED only when textual status attached to structured SSTAT contains an abort hint.",
				"Temporary controller disappearance is recorded and does not become VERIFIED without a later structured COMPLETED status.",
			],
			"conclusion": conclusion,
			"conclusion_statement": f"Validation basis: {wording}." if conclusion == "PASS" else "NVMe controller completion, scope, integrity, or independent checks did not support a complete validation pass.",
		})

	def _nvme_verification_basis(self, method: str, sanact: str | None) -> list[str]:
		return [f"SANICAP support for {method}", f"policy-selected {method}", f"SANACT {sanact}",
			"structured sanitize-log SSTAT COMPLETED", "VYPER verifier VERIFIED", "valid bound evidence and certificate"]

	def _write_nvme_report(self, report: dict[str, Any]) -> dict[str, Path]:
		self.output_directory.mkdir(parents=True, exist_ok=True)
		stem = f"{self._timestamp()}-nvme-{safe_identifier(report['device_identity']['stable_id'])}"
		json_path, markdown_path = self.output_directory / f"{stem}.json", self.output_directory / f"{stem}.md"
		json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
		markdown_path.write_text(self._nvme_markdown(report), encoding="utf-8")
		self._restrict_report_permissions(json_path)
		self._restrict_report_permissions(markdown_path)
		return {"json": json_path, "markdown": markdown_path}

	def _nvme_markdown(self, report: dict[str, Any]) -> str:
		identity, caps, checks = report["device_identity"], report["nvme_capabilities"], report["independent_post_checks"]
		lines = ["# VYPER controlled physical NVMe validation", "",
			f"- Conclusion: **{report['conclusion']}**", f"- VYPER version: `{report['vyper_version']}`",
			f"- Namespace: `{report['requested_namespace']}`", f"- Controller: `{report['resolved_controller']}`",
			f"- Sanitize target: `{report['sanitize_target']}`", f"- Model: `{identity.get('model')}`",
			f"- Serial: `{identity.get('serial_number')}`", f"- Firmware: `{identity.get('firmware_revision')}`",
			f"- NGUID: `{identity.get('nguid')}`", f"- EUI-64: `{identity.get('eui64')}`", "",
			"## Capability and method", "", f"- SANICAP: `{caps.get('sanicap_raw')}`",
			f"- Crypto erase: `{caps['crypto_erase_supported']}`", f"- Block erase: `{caps['block_erase_supported']}`",
			f"- Overwrite: `{caps['overwrite_supported']}`", f"- Policy method: `{report['policy_selected_method']}`",
			f"- Expected/actual SANACT: `{report['expected_sanact']}` / `{report['actual_sanact']}`", "",
			"## Completion evidence", "", f"- Command submitted: `{report['command_submission_result']['submitted']}`",
			f"- Controller status: `{(report.get('controller_completion_result') or {}).get('status')}`",
			f"- VYPER verification: `{(report.get('verification_result') or {}).get('status')}`",
			f"- Progress: `indeterminate`", f"- Critical probes succeeded: `{checks['critical_probes_succeeded']}`", "",
			"## Verification basis", ""]
		lines.extend(f"- {item}" for item in report["verification_basis"])
		lines.extend(["", "## Conclusion", "", report["conclusion_statement"], "", "## Limitations", ""])
		lines.extend(f"- {item}" for item in report["limitations"])
		return "\n".join(lines) + "\n"

	def _sata_markdown(self, report: dict[str, Any]) -> str:
		identity = report["device_identity"]
		capabilities = report["ata_capabilities"]
		checks = report["independent_post_checks"]
		integrity = report["integrity"]
		lines = [
			"# VYPER controlled physical SATA SSD validation", "",
			f"- Conclusion: **{report['conclusion']}**",
			f"- VYPER version: `{report['vyper_version']}`",
			f"- Generated: `{report['generated_at']}`",
			f"- Device: `{identity['device_path']}`",
			f"- Model: `{identity.get('model') or 'unknown'}`",
			f"- Serial: `{identity.get('serial_number') or 'not reported'}`",
			f"- WWN: `{identity.get('wwn') or 'not reported'}`",
			f"- Capacity: `{identity['size_bytes']}` bytes", "",
			"## ATA capabilities", "",
			f"- ATA Security supported: `{capabilities['security_supported']}`",
			f"- Secure Erase supported: `{capabilities['secure_erase_supported']}`",
			f"- Enhanced Secure Erase supported: `{capabilities['enhanced_secure_erase_supported']}`",
			f"- Frozen before execution: `{capabilities['security_frozen']}`", "",
			"## Product-path result", "",
			f"- Local job: `{report.get('local_job_id')}`",
			f"- Selected pathway: `{report.get('selected_pathway')}`",
			f"- VYPER verification: `{(report.get('verification_metadata') or {}).get('status')}`",
			f"- Progress: `indeterminate` (no percentage claimed)",
			f"- Evidence hash: `{report.get('evidence_hash')}`",
			f"- Certificate hash: `{report.get('certificate_hash')}`",
			f"- Evidence integrity valid: `{integrity['evidence_valid']}`",
			f"- Certificate integrity valid: `{integrity['certificate_valid']}`", "",
			"## Independent post-checks", "",
			f"- Controller accessible: `{checks['controller_accessible']}`",
			f"- ATA security enabled: `{checks['ata_security_state'].get('security_enabled')}`",
			f"- ATA security frozen: `{checks['ata_security_state'].get('security_frozen')}`",
			f"- Filesystem detected: `{checks['filesystem_detected']}`",
			f"- Old filesystem normally accessible: `{checks['old_filesystem_normally_accessible']}`", "",
			"## Verification basis", "",
		]
		lines.extend(f"- {item}" for item in report["verification_basis"])
		lines.extend(["", "## Conclusion", "", report["conclusion_statement"], "", "## Limitations", ""])
		lines.extend(f"- {item}" for item in report["limitations"])
		return "\n".join(lines) + "\n"

	def _write_report(self, report: dict[str, Any]) -> dict[str, Path]:
		self.output_directory.mkdir(parents=True, exist_ok=True)
		identity = report["device_identity"]["stable_id"]
		stem = f"{self._timestamp()}-hdd-{safe_identifier(identity)}"
		json_path = self.output_directory / f"{stem}.json"
		markdown_path = self.output_directory / f"{stem}.md"
		json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
		markdown_path.write_text(self._markdown(report), encoding="utf-8")
		self._restrict_report_permissions(json_path)
		self._restrict_report_permissions(markdown_path)
		return {"json": json_path, "markdown": markdown_path}

	def _markdown(self, report: dict[str, Any]) -> str:
		identity = report["device_identity"]
		checks = report["independent_post_checks"]
		integrity = report["integrity"]
		lines = [
			"# VYPER controlled physical HDD validation", "",
			f"- Conclusion: **{report['conclusion']}**",
			f"- VYPER version: `{report['vyper_version']}`",
			f"- Generated: `{report['generated_at']}`",
			f"- Device: `{identity['device_path']}`",
			f"- Model: `{identity.get('model') or 'unknown'}`",
			f"- Serial: `{identity.get('serial_number') or 'not reported'}`",
			f"- WWN: `{identity.get('wwn') or 'not reported'}`",
			f"- Capacity: `{identity['size_bytes']}` bytes", "",
			"## Product-path result", "",
			f"- Local job: `{report.get('local_job_id')}`",
			f"- Selected pathway: `{report.get('selected_pathway')}`",
			f"- VYPER final status: `{(report.get('verification_result') or {}).get('status')}`",
			f"- Evidence hash: `{report.get('evidence_hash')}`",
			f"- Certificate hash: `{report.get('certificate_hash')}`",
			f"- Evidence integrity valid: `{integrity['evidence_valid']}`",
			f"- Certificate integrity valid: `{integrity['certificate_valid']}`", "",
			"## Independent post-checks", "",
			f"- Filesystem detected: `{checks['filesystem_detected']}`",
			f"- blkid signature detected: `{checks['blkid_detected']}`",
			f"- Sampled regions match zero pattern: `{checks['consistent_with_zero_overwrite']}`",
			f"- Progress measurements: `{report['progress_summary']['measurement_count']}`", "",
			"## Conclusion", "", report["conclusion_statement"], "",
			"## Limitations", "",
		]
		lines.extend(f"- {item}" for item in report["limitations"])
		return "\n".join(lines) + "\n"

	def _filesystem_snapshot(self, device: str) -> dict[str, Any]:
		result = self._run(["lsblk", "--json", "--fs", "--bytes", "--output",
			"NAME,PATH,TYPE,FSTYPE,FSVER,LABEL,UUID,SIZE,MOUNTPOINTS", device], timeout=30)
		if not result.success:
			return {"query_succeeded": False, "mounted": None, "filesystems": [], "error": "lsblk filesystem query failed"}
		try:
			payload = json.loads(result.stdout or "{}")
		except json.JSONDecodeError:
			return {"query_succeeded": False, "mounted": None, "filesystems": [], "error": "lsblk returned malformed JSON"}
		filesystems: list[dict[str, Any]] = []
		def visit(node: dict[str, Any]) -> None:
			mountpoints = [item for item in (node.get("mountpoints") or []) if item]
			filesystems.append({key: node.get(key) for key in ("name", "path", "type", "fstype", "fsver", "label", "uuid", "size")})
			filesystems[-1]["mountpoints"] = mountpoints
			for child in node.get("children") or []:
				if isinstance(child, dict):
					visit(child)
		for node in payload.get("blockdevices") or []:
			if isinstance(node, dict):
				visit(node)
		return {"query_succeeded": True, "mounted": any(item["mountpoints"] for item in filesystems), "filesystems": filesystems}

	def _lsblk_has_filesystem(self, output: str) -> bool | None:
		try:
			payload = json.loads(output or "{}")
		except json.JSONDecodeError:
			return None
		stack = list(payload.get("blockdevices") or [])
		while stack:
			node = stack.pop()
			if not isinstance(node, dict):
				continue
			if node.get("fstype") or node.get("uuid"):
				return True
			stack.extend(node.get("children") or [])
		return False

	def _create_test_files(self, mountpoint: Path) -> list[dict[str, Any]]:
		root = mountpoint / "vyper-validation"
		root.mkdir(parents=True, exist_ok=False)
		files = {
			"secret.txt": b"VYPER DISPOSABLE HARDWARE VALIDATION DATA\n" * 16,
			"sample.bin": bytes(range(256)) * 4096,
			"random.bin": b"".join(hashlib.sha256(f"vyper-{index}".encode()).digest() for index in range(32768)),
		}
		manifest: list[dict[str, Any]] = []
		for name, content in files.items():
			path = root / name
			path.write_bytes(content)
			manifest.append({"path": f"vyper-validation/{name}", "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
		return manifest

	def _load_latest_test_manifest(self, stable_id: str, *, device_label: str = "hdd") -> dict[str, Any] | None:
		pattern = f"*-{device_label}-{safe_identifier(stable_id)}-test-data.json"
		paths = sorted(self.output_directory.glob(pattern), reverse=True)
		if not paths:
			return None
		try:
			return json.loads(paths[0].read_text(encoding="utf-8"))
		except (OSError, json.JSONDecodeError):
			return None

	def _run(self, command: list[str], *, timeout: float) -> CommandResult:
		try:
			return self.command_executor.run(command, timeout=timeout)
		except (FileNotFoundError, OSError) as exc:
			return CommandResult(command=command, success=False, exit_code=None, stderr=type(exc).__name__)

	def _result_summary(self, result: CommandResult) -> dict[str, Any]:
		return {"command": list(result.command), "success": result.success, "exit_code": result.exit_code,
			"stdout": result.stdout, "stderr": result.stderr}

	def _pread(self, device: str, offset: int, size: int) -> bytes:
		fd = os.open(device, os.O_RDONLY)
		try:
			return os.pread(fd, size, offset)
		finally:
			os.close(fd)

	def _planned_steps(self, operation: str) -> list[str]:
		if operation == "prepare":
			return ["Freshly re-profile exact identity", "Require typed PREPARE confirmation", "Create ext4 filesystem",
				"Mount controlled path", "Create and hash deterministic disposable files", "sync", "Unmount", "Write test-data manifest"]
		return ["Freshly re-profile exact identity", "Require typed ERASE confirmation", "Submit existing local API v2 job",
			"Poll durable progress", "Require HDD_OVERWRITE verification and integrity evidence", "Run read-only independent checks", "Write JSON and Markdown reports"]

	def _planned_sata_steps(self, operation: str) -> list[str]:
		if operation == "prepare":
			return ["Freshly re-profile exact SATA SSD identity and ATA state", "Require typed PREPARE confirmation",
				"Create a small ext4 test filesystem", "Create and hash deterministic disposable files", "sync", "Unmount", "Write test-data manifest"]
		return ["Freshly re-profile exact SATA SSD identity and ATA state", "Require typed ERASE confirmation",
			"Re-profile again after confirmation", "Prompt invisibly for a transient ATA password",
			"Submit existing local API v2 job", "Poll durable indeterminate lifecycle state",
			"Require ATA_ERASE controller-state verification and integrity evidence", "Run read-only ATA/interface checks", "Write JSON and Markdown reports"]

	def _planned_nvme_steps(self, operation: str) -> list[str]:
		if operation == "prepare":
			return ["Re-profile namespace/controller identity", "Require typed PREPARE confirmation",
				"Create a small test filesystem and deterministic files", "sync and unmount", "Write test-data manifest"]
		return ["Re-profile namespace/controller identity and topology", "Require typed ERASE confirmation",
			"Re-run policy and SANICAP checks", "Submit existing local API v2 job",
			"Observe structured sanitize-log without percentages", "Require controller COMPLETED and VYPER VERIFIED",
			"Run independent controller/namespace checks", "Write JSON and Markdown reports"]

	def _print_plan(self, plan: dict[str, Any]) -> None:
		identity = plan["device_identity"]
		self.print_fn("VYPER CONTROLLED PHYSICAL HDD VALIDATION PLAN")
		self.print_fn(json.dumps(identity, indent=2, sort_keys=True))
		self.print_fn("Filesystem/topology:")
		self.print_fn(json.dumps(plan["filesystem_info"], indent=2, sort_keys=True))
		for index, step in enumerate(plan["planned_steps"], start=1):
			self.print_fn(f"{index}. {step}")
		self.print_fn(f"Required confirmation during execution: {plan['confirmation_required']}")

	def _print_sata_plan(self, plan: dict[str, Any]) -> None:
		self.print_fn("VYPER CONTROLLED PHYSICAL SATA SSD VALIDATION PLAN")
		self.print_fn(json.dumps(plan["device_identity"], indent=2, sort_keys=True))
		capabilities = plan["ata_capabilities"]
		self.print_fn(f"ATA Security: {'supported' if capabilities['security_supported'] else 'unsupported/unknown'}")
		self.print_fn(f"Secure Erase: {'supported' if capabilities['secure_erase_supported'] else 'unsupported/unknown'}")
		self.print_fn(f"Enhanced Secure Erase: {'supported' if capabilities['enhanced_secure_erase_supported'] else 'unsupported'}")
		self.print_fn(f"Frozen: {str(capabilities['security_frozen']).lower()}")
		self.print_fn(f"Selected VYPER pathway: {plan['selected_vyper_pathway'] or 'none'}")
		for blocker in plan["execution_blockers"]:
			self.print_fn(f"EXECUTION BLOCKER: {blocker}")
		self.print_fn("Filesystem/topology:")
		self.print_fn(json.dumps(plan["filesystem_info"], indent=2, sort_keys=True))
		for index, step in enumerate(plan["planned_steps"], start=1):
			self.print_fn(f"{index}. {step}")
		self.print_fn(f"Required confirmation during execution: {plan['confirmation_required']}")

	def _print_nvme_plan(self, plan: dict[str, Any]) -> None:
		caps = plan["nvme_capabilities"]
		self.print_fn("VYPER CONTROLLED PHYSICAL NVME VALIDATION PLAN")
		self.print_fn(json.dumps(plan["device_identity"], indent=2, sort_keys=True))
		self.print_fn("NVMe Sanitize capabilities:")
		self.print_fn(f"  Crypto Erase: {'supported' if caps['crypto_erase_supported'] else 'unsupported'}")
		self.print_fn(f"  Block Erase: {'supported' if caps['block_erase_supported'] else 'unsupported'}")
		self.print_fn(f"  Overwrite: {'supported' if caps['overwrite_supported'] else 'unsupported'}")
		self.print_fn(f"  SANICAP: {caps['sanicap_raw'] if caps['sanicap_raw'] is not None else 'unknown'}")
		self.print_fn(f"Policy-selected method: {plan['policy_selected_method'] or 'none'}")
		self.print_fn(f"SANACT: {plan['expected_sanact'] or 'unmapped'}")
		self.print_fn(f"Requested namespace: {plan['requested_namespace']}")
		self.print_fn(f"Resolved controller: {plan['resolved_controller'] or 'unknown'}")
		self.print_fn(f"Sanitize scope: {plan['scope_validation'].get('sanitize_scope') or 'unknown'}")
		self.print_fn("Controller namespaces:")
		for namespace in plan["scope_validation"].get("controller_namespaces") or []:
			self.print_fn(f"  - {namespace}")
		self.print_fn(f"Sanitize target: {plan['sanitize_target'] or 'unknown'}")
		self.print_fn(f"Physical execution eligibility: {'ELIGIBLE' if not plan['execution_blockers'] else 'BLOCKED'}")
		for blocker in plan["execution_blockers"]:
			self.print_fn(f"EXECUTION BLOCKER: {blocker}")
		for index, step in enumerate(plan["planned_steps"], start=1):
			self.print_fn(f"{index}. {step}")
		self.print_fn(f"Required confirmation during execution: {plan['confirmation_required']}")

	def _require_explicit_device(self, device: str) -> None:
		value = str(device or "").strip()
		if not value.startswith("/dev/") or value == "/dev/" or any(char in value for char in "*?[]"):
			raise HardwareValidationError("An explicit whole-device /dev path is required; wildcards and defaults are forbidden.")

	def _require_explicit_nvme_namespace(self, device: str) -> None:
		value = str(device or "").strip()
		if not re.fullmatch(r"/dev/nvme\d+(?:c\d+)?n\d+", value) or any(char in value for char in "*?[]"):
			raise HardwareValidationError("An explicit whole NVMe namespace path such as /dev/nvme0n1 is required; controllers, partitions, defaults, and wildcards are refused.")

	def _timestamp(self) -> str:
		return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

	def _restrict_report_permissions(self, path: Path) -> None:
		try:
			os.chmod(path, 0o600)
		except OSError:
			pass
