from __future__ import annotations

import importlib
import json
import os
import platform
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor
from vyper_version import __version__

from .boot_sanitize import (
    BOOT_ENVIRONMENT_VERSION, BootJobError, device_identifiers, durable_write_text,
    identity_matches, sha256_file,
)


VM_VALIDATION_MODE = "virtualbox_system_disk"
REQUIRED_INITRAMFS_COMPONENTS = (
    "local_agent/boot_console.py", "local_agent/boot_sanitize.py", "agent/agent.py",
    "python", "lsblk", "findmnt", "swapon", "pvs", "hdparm", "nvme",
)
SECRET_MARKERS = ("agent_token", "ata_password", "hmac_secret", "enrollment_token", "operator_secret")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_vm_validation_manifest(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BootJobError(f"VM validation manifest is unavailable or invalid: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or payload.get("validation_mode") != VM_VALIDATION_MODE:
        raise BootJobError("VM validation manifest mode is invalid.")
    identity = payload.get("allowed_target_identity")
    if not isinstance(identity, dict):
        raise BootJobError("VM validation manifest lacks an allowed target identity.")
    normalized = device_identifiers(identity)
    if not normalized.get("model") or not normalized.get("serial_number") or not normalized.get("size_bytes"):
        raise BootJobError("VM target authorization requires model, serial, and size_bytes.")
    payload["allowed_target_identity"] = normalized
    evidence = payload.get("evidence_disk_identity")
    if evidence is not None:
        if not isinstance(evidence, dict):
            raise BootJobError("Evidence-disk identity is malformed.")
        normalized_evidence = device_identifiers(evidence)
        if (not normalized_evidence.get("model") or not normalized_evidence.get("serial_number")
                or not normalized_evidence.get("size_bytes")):
            raise BootJobError("Evidence-disk authorization requires model, serial, and size_bytes.")
        payload["evidence_disk_identity"] = normalized_evidence
    payload["destructive_test_enabled"] = payload.get("destructive_test_enabled") is True
    return payload


class VirtualizationInspector:
    def __init__(self, *, command_executor: CommandExecutor | None = None, dmi_root: str | Path = "/sys/class/dmi/id") -> None:
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.dmi_root = Path(dmi_root)

    def inspect(self) -> dict[str, Any]:
        try:
            result = self.command_executor.run(["systemd-detect-virt"], timeout=10)
            virt = result.stdout.strip().lower() if result.success and result.exit_code == 0 else None
        except (OSError, FileNotFoundError):
            virt = None
        vendor = self._read("sys_vendor")
        product = self._read("product_name")
        combined = f"{virt or ''} {vendor or ''} {product or ''}".lower()
        proven = virt in {"oracle", "virtualbox"} and ("virtualbox" in combined or "innotek" in combined or "oracle" in combined)
        return {
            "virtualization_type": virt,
            "system_vendor": vendor,
            "product_name": product,
            "virtualbox_proven": proven,
        }

    def _read(self, name: str) -> str | None:
        try:
            text = (self.dmi_root / name).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        return text or None


class VMValidationGate:
    def __init__(self, *, virtualization_inspector: VirtualizationInspector, discovery: Any) -> None:
        self.virtualization_inspector = virtualization_inspector
        self.discovery = discovery

    def evaluate(self, manifest: dict[str, Any], target: dict[str, Any], *, allow_destructive: bool,
        boot_environment_independent: bool) -> dict[str, Any]:
        host = self.virtualization_inspector.inspect()
        blockers: list[str] = []
        if host.get("virtualbox_proven") is not True:
            blockers.append("VirtualBox virtualization could not be proven.")
        observed_target = device_identifiers(target)
        expected_target = device_identifiers(manifest.get("allowed_target_identity") or {})
        if not identity_matches(expected_target, observed_target):
            blockers.append("Observed system-disk identity does not match the disposable VM authorization manifest.")
        model = str(observed_target.get("model") or "").upper()
        if "VBOX HARDDISK" not in model:
            blockers.append("Target model is not the explicitly expected VirtualBox disk model.")
        if not boot_environment_independent:
            blockers.append("Temporary boot environment independence from the target is not proven.")

        evidence_expected = device_identifiers(manifest.get("evidence_disk_identity") or {}) if manifest.get("evidence_disk_identity") else None
        evidence_observed = self._find_identity(evidence_expected) if evidence_expected else None
        if evidence_observed and identity_matches(expected_target, device_identifiers(evidence_observed)):
            blockers.append("Evidence disk identity equals the sanitization target identity.")

        destructive_gates = {
            "virtualbox_proven": host.get("virtualbox_proven") is True,
            "target_identity_matches": identity_matches(expected_target, observed_target),
            "target_model_expected": "VBOX HARDDISK" in model,
            "target_serial_expected": bool(expected_target.get("serial_number") and expected_target.get("serial_number") == observed_target.get("serial_number")),
            "target_size_expected": expected_target.get("size_bytes") == observed_target.get("size_bytes"),
            "target_is_vm_system_disk": manifest.get("prepared_target_was_system_disk") is True,
            "boot_environment_independent": bool(boot_environment_independent),
            "evidence_storage_separate": bool(evidence_observed and not identity_matches(expected_target, device_identifiers(evidence_observed))),
            "destructive_test_enabled": manifest.get("destructive_test_enabled") is True,
            "allow_destructive_vm_test": bool(allow_destructive),
            "fresh_boot_confirmation_required": True,
        }
        destructive_eligible = all(destructive_gates.values()) and not blockers
        return {
            "host_virtualization": host,
            "target_identity": observed_target,
            "evidence_disk_identity": device_identifiers(evidence_observed) if evidence_observed else None,
            "evidence_disk_path": evidence_observed.get("device_path") if evidence_observed else None,
            "evidence_storage": "SEPARATE_DISK" if evidence_observed else "RETAINED_IN_BOOT_MEMORY",
            "destructive_gates": destructive_gates,
            "destructive_eligible": destructive_eligible,
            "blockers": blockers,
        }

    def _find_identity(self, expected: dict[str, Any] | None) -> dict[str, Any] | None:
        if not expected:
            return None
        matches = []
        for item in self.discovery.discover():
            device = item.to_dict() if hasattr(item, "to_dict") else dict(item)
            if identity_matches(expected, device_identifiers(device)):
                matches.append(device)
        return matches[0] if len(matches) == 1 else None


class EvidenceDiskManager:
    """Mount a preformatted, positively identified result disk; never formats it."""
    def __init__(self, *, command_executor: CommandExecutor | None = None,
        mount_point: str | Path = "/var/lib/vyper-vm-evidence") -> None:
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.mount_point = Path(mount_point)

    def mount(self, gate: dict[str, Any]) -> dict[str, Any]:
        device = str(gate.get("evidence_disk_path") or "")
        if not device:
            return {"status": "RETAINED_IN_BOOT_MEMORY", "mounted": False, "result_directory": None}
        self.mount_point.mkdir(parents=True, exist_ok=True)
        result = self.command_executor.run(
            ["mount", "-o", "rw,nodev,nosuid,noexec", device, str(self.mount_point)], timeout=30)
        if not result.success or result.exit_code != 0:
            return {"status": "RETAINED_IN_BOOT_MEMORY", "mounted": False, "result_directory": None,
                "error": "Authorized evidence disk could not be mounted."}
        result_directory = self.mount_point / "hardware-validation"
        result_directory.mkdir(parents=True, exist_ok=True)
        return {"status": "SEPARATE_EVIDENCE_DISK", "mounted": True,
            "device": device, "result_directory": str(result_directory)}


class BootSelfTest:
    def __init__(self, *, command_executor: CommandExecutor | None = None,
        active_job_path: str | Path = "/etc/vyper/active-boot-job",
        key_path: str | Path = "/var/lib/vyper/boot-jobs/job-mac.key",
        result_directory: str | Path = "/var/lib/vyper/boot-results",
        cmdline_path: str | Path = "/proc/cmdline",
        which: Callable[[str], str | None] = shutil.which,
        importer: Callable[[str], Any] = importlib.import_module) -> None:
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.active_job_path = Path(active_job_path)
        self.key_path = Path(key_path)
        self.result_directory = Path(result_directory)
        self.cmdline_path = Path(cmdline_path)
        self.which = which
        self.importer = importer

    def run(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        self._check(checks, "linux_kernel", os.name == "posix" and bool(platform.release()), platform.release())
        cmdline = self._read(self.cmdline_path) or ""
        self._check(checks, "boot_environment", self.active_job_path.is_file() and "vyper.mode=boot_sanitize" in cmdline,
            "active job and boot_sanitize kernel mode")
        self._check(checks, "python_runtime", Path(sys.executable).is_file(), f"{sys.executable} ({platform.python_version()})")
        for tool in ("lsblk", "hdparm", "nvme"):
            self._check(checks, tool, self.which(tool) is not None, self.which(tool) or "missing")
        network = self.which("ip") or self.which("dhclient")
        self._check(checks, "network_tool", network is not None, network or "missing")
        shutdown = self.which("poweroff") or self.which("systemctl")
        self._check(checks, "shutdown_tool", shutdown is not None, shutdown or "missing")
        for module in ("agent.agent", "agent.evidence", "agent.certificate", "local_agent.boot_sanitize"):
            try:
                self.importer(module)
                available = True
            except Exception:
                available = False
            self._check(checks, f"import:{module}", available, "available" if available else "missing")
        self._check(checks, "boot_manifest_parser", self.active_job_path.is_file(), str(self.active_job_path))
        self._check(checks, "hmac_key", self.key_path.is_file() and self.key_path.stat().st_size >= 32, str(self.key_path))
        writable = self.result_directory.is_dir() and os.access(self.result_directory, os.W_OK)
        self._check(checks, "result_location", writable, str(self.result_directory))
        return {
            "boot_self_test": "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL",
            "timestamp": _now(), "kernel_version": platform.release(),
            "boot_environment_version": BOOT_ENVIRONMENT_VERSION, "checks": checks,
        }

    def _check(self, checks: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    def _read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


def validate_linux_boot_artifact(manifest_path: str | Path, *, listing: str) -> dict[str, Any]:
    path = Path(manifest_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    blockers = []
    if payload.get("bootable") is not True or payload.get("build_kind") != "ubuntu-debian-initramfs-tools":
        blockers.append("Artifact is not a validated Linux host-specific boot image.")
    missing = [item for item in REQUIRED_INITRAMFS_COMPONENTS if item not in listing]
    if missing:
        blockers.append(f"Initramfs is missing required components: {', '.join(missing)}")
    initramfs = path.parent / str(payload.get("initramfs_filename") or "")
    if not initramfs.is_file() or sha256_file(initramfs) != payload.get("initramfs_sha256"):
        blockers.append("Initramfs checksum does not match its manifest.")
    embedded = [marker for marker in SECRET_MARKERS if marker in listing.lower()]
    if payload.get("contains_agent_credentials") is not False or payload.get("contains_operator_secrets") is not False:
        embedded.append("manifest_secret_declaration")
    if embedded:
        blockers.append("Boot artifact inspection found a forbidden secret marker.")
    return {
        "status": "PASS" if not blockers else "FAIL", "kernel_version": payload.get("kernel_version"),
        "initramfs_sha256": payload.get("initramfs_sha256"), "boot_environment_version": payload.get("version"),
        "build_kind": payload.get("build_kind"), "included_components": list(REQUIRED_INITRAMFS_COMPONENTS),
        "missing_components": missing, "blockers": blockers,
    }


class BootValidationLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, event: str, **fields: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_redact_log_fields(
                {"timestamp": _now(), "event": event, **fields}), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def _redact_log_fields(value: Any, *, key: str = "") -> Any:
    forbidden = ("password", "secret", "token", "credential", "authorization")
    if any(marker in key.lower() for marker in forbidden):
        return "<redacted>"
    if isinstance(value, dict):
        return {item_key: _redact_log_fields(item_value, key=str(item_key))
            for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_log_fields(item) for item in value]
    return value


def build_vm_validation_report(*, output_directory: str | Path, boot_job: dict[str, Any], state: dict[str, Any],
    gate: dict[str, Any], boot_artifact: dict[str, Any], grub_handoff: dict[str, Any], result: dict[str, Any] | None,
    post_checks: dict[str, Any] | None = None) -> dict[str, Any]:
    dry_run = bool(boot_job.get("dry_run"))
    lifecycle = state.get("events") or []
    required = {"PREPARING_BOOT", "AWAITING_REBOOT", "BOOT_ENVIRONMENT_STARTED", "VALIDATING_TARGET",
        "WAITING_LOCAL_APPROVAL", "RUNNING", "VERIFYING"}
    seen = {str(item.get("state")) for item in lifecycle}
    workflow_pass = (required.issubset(seen)
        and gate.get("host_virtualization", {}).get("virtualbox_proven") is True
        and boot_artifact.get("status") == "PASS"
        and grub_handoff.get("normal_default_unchanged") is True)
    explicit_failure = (boot_artifact.get("status") == "FAIL"
        or gate.get("host_virtualization", {}).get("virtualbox_proven") is False
        or grub_handoff.get("normal_default_unchanged") is False
        or "FAILED" in seen
        or (result or {}).get("final_status") == "FAILED")
    sanitization_validation = "NOT_EXECUTED" if dry_run else "PASS" if (result or {}).get("final_status") == "VERIFIED" else "INCONCLUSIVE"
    final_conclusion = ("PASS" if workflow_pass and (dry_run or sanitization_validation == "PASS")
        else "FAIL" if explicit_failure else "INCONCLUSIVE")
    report = {
        "schema_version": 1, "validation_kind": "system_disk_virtualbox", "generated_at": _now(),
        "vyper_version": __version__, "host_virtualization": gate.get("host_virtualization"), "vm_platform": "VirtualBox",
        "boot_image_version": boot_job.get("boot_image_version"), "boot_image_hash": boot_job.get("boot_image_sha256"),
        "boot_artifact_validation": boot_artifact, "grub_handoff_status": grub_handoff,
        "target_identity": gate.get("target_identity"), "evidence_disk_identity": gate.get("evidence_disk_identity"),
        "boot_job_id": boot_job.get("boot_job_id"), "local_job_id": (result or {}).get("local_job_id") or boot_job.get("boot_job_id"),
        "central_job_id": boot_job.get("central_job_id"), "agent_id": boot_job.get("agent_id"),
        "boot_job_lifecycle": lifecycle, "mode": "dry-run" if dry_run else "destructive",
        "selected_pathway": (result or {}).get("selected_pathway"), "verification": (result or {}).get("verification"),
        "result_preservation": (result or {}).get("upload_status") or gate.get("evidence_storage"),
        "central_upload_state": (result or {}).get("upload_status") or "NOT_ATTEMPTED",
        "evidence_hash": ((result or {}).get("engine_evidence") or {}).get("integrity_hash"),
        "certificate_hash": ((result or {}).get("certificate") or {}).get("certificate_hash"),
        "execution_environment": "boot_sanitize", "post_checks": post_checks or {},
        "workflow_validation": "PASS" if workflow_pass else "INCONCLUSIVE",
        "sanitization_validation": sanitization_validation,
        "virtual_disk_sanitization_validation": sanitization_validation,
        "physical_media_validation": "NOT_APPLICABLE",
        "sanitization_status": (result or {}).get("final_status") or "NOT_EXECUTED",
        "shutdown_status": ((result or {}).get("shutdown") or {}).get("shutdown_status") or "NOT_REQUESTED",
        "shutdown_method": ((result or {}).get("shutdown") or {}).get("shutdown_method"),
        "shutdown_warning": ((result or {}).get("shutdown") or {}).get("shutdown_warning"),
        "final_conclusion": final_conclusion,
        "conclusion_statement": ("boot workflow validation passed; disk sanitization was not executed"
            if workflow_pass and dry_run else "boot workflow and sanitization validation passed"
            if workflow_pass else "workflow validation failed" if explicit_failure else "workflow validation was incomplete"),
    }
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_kind = "system-disk-vm-dry-run" if dry_run else "system-disk-vm-destructive"
    json_path = output / f"{stamp}-{report_kind}.json"
    md_path = output / f"{stamp}-{report_kind}.md"
    durable_write_text(json_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    durable_write_text(md_path, _markdown(report))
    report["report_files"] = {"json": str(json_path), "markdown": str(md_path)}
    return report


def _markdown(report: dict[str, Any]) -> str:
    return "\n".join([
        "# VYPER VirtualBox system-disk validation", "",
        f"- Workflow validation: **{report['workflow_validation']}**",
        f"- Sanitization validation: **{report['sanitization_validation']}**",
        f"- Virtual-disk sanitization validation: **{report['virtual_disk_sanitization_validation']}**",
        f"- Physical-media validation: **{report['physical_media_validation']}**",
        f"- Sanitization status: **{report['sanitization_status']}**",
        f"- Shutdown status: **{report['shutdown_status']}**",
        f"- Boot job: `{report['boot_job_id']}`", f"- Mode: `{report['mode']}`",
        f"- Boot image SHA-256: `{report['boot_image_hash']}`",
        f"- Result preservation: `{report['result_preservation']}`", "",
        "## Conclusion", "", report["conclusion_statement"], "",
        "VirtualBox validates the application boot workflow and virtual block-device behavior; it does not establish physical-media sanitization.", "",
    ])
