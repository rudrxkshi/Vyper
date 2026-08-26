from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.command_runner import CommandResult
from local_agent.boot_handoff import BootImage, GrubOneShotHandoff
from local_agent.boot_shutdown import BootShutdownCoordinator
from local_agent.boot_image import build_fixture_boot_image, write_manifest
from local_agent.boot_console import _attempt_wired_dhcp
from local_agent.boot_sanitize import BootIntegrityError, BootJobError, BootJobStore, BootSanitizeRuntime
from local_agent.vm_validation import (
    BootSelfTest, BootValidationLogger, REQUIRED_INITRAMFS_COMPONENTS, VMValidationGate,
    VirtualizationInspector, build_vm_validation_report, load_vm_validation_manifest,
    validate_linux_boot_artifact,
)


TARGET = {"device_path": "/dev/sda", "device_type": "HDD", "model": "VBOX HARDDISK",
    "serial_number": "VB-SYSTEM-001", "size_bytes": 8 * 1024 * 1024,
    "mounted": False, "is_system_device": False, "capabilities": {}, "interface": "SATA"}
EVIDENCE = {"device_path": "/dev/sdb", "device_type": "HDD", "model": "VBOX HARDDISK",
    "serial_number": "VB-EVIDENCE-001", "size_bytes": 4 * 1024 * 1024,
    "mounted": False, "is_system_device": False, "capabilities": {}}


class Discovery:
    def __init__(self, devices): self.devices = devices
    def discover(self): return list(self.devices)


class Virt:
    def __init__(self, proven=True): self.proven = proven
    def inspect(self):
        return {"virtualization_type": "oracle" if self.proven else "none", "system_vendor": "innotek GmbH",
            "product_name": "VirtualBox", "virtualbox_proven": self.proven}


class Agent:
    def __init__(self, *, crash=False): self.crash = crash; self.calls = []
    def sanitize_device(self, target, authorization, dry_run=False):
        self.calls.append((target, dry_run))
        if self.crash: raise RuntimeError("simulated crash")
        status = "INCONCLUSIVE" if dry_run else "VERIFIED"
        return {"job_state": status, "final_status": status, "profile": TARGET,
            "policy": {"selected_pathway": "HDD_OVERWRITE"},
            "execution": {"status": status, "dry_run": dry_run, "metadata": {"method": "HDD_OVERWRITE"}},
            "verification": {"status": status, "verified": status == "VERIFIED"},
            "evidence": {"final_status": status, "integrity_hash": "evidence-hash"},
            "certificate": {"final_status": status, "certificate_hash": "certificate-hash",
                "successful_sanitization_claim": status == "VERIFIED"}, "state_history": [status]}


class Safety:
    def inspect(self, target):
        return {"commands_known": True,
            "lsblk": {"blockdevices": [{"path": target, "type": "disk", "fstype": None, "mountpoints": []}]},
            "swap_devices": [], "root": {"filesystems": [{"source": "tmpfs", "target": "/"}]},
            "lvm": {"report": [{"pv": []}]}, "holders": []}


class Exec:
    def __init__(self, *, virt="oracle", vendor="innotek GmbH", product="VirtualBox", grub="saved_entry=Ubuntu\n"):
        self.virt, self.grub, self.calls = virt, grub, []
    def run(self, command, timeout=None, cwd=None):
        self.calls.append(list(command))
        if command == ["systemd-detect-virt"]: return self.result(command, self.virt)
        if command == ["grub-editenv", "-", "list"]: return self.result(command, self.grub)
        if command[:2] == ["mokutil", "--sb-state"]: return self.result(command, "SecureBoot disabled\n")
        return self.result(command, "")
    def result(self, command, stdout):
        return CommandResult(command=command, success=True, exit_code=0, stdout=stdout, stderr="")


def vm_manifest(*, destructive=False, evidence=True):
    payload = {"validation_mode": "virtualbox_system_disk", "allowed_target_identity": dict(TARGET),
        "destructive_test_enabled": destructive, "prepared_target_was_system_disk": True}
    if evidence: payload["evidence_disk_identity"] = dict(EVIDENCE)
    return payload


def gate(manifest=None, *, devices=None, proven=True, allow=False, independent=True):
    return VMValidationGate(virtualization_inspector=Virt(proven),
        discovery=Discovery(devices or [TARGET, EVIDENCE])).evaluate(
            manifest or vm_manifest(), TARGET, allow_destructive=allow,
            boot_environment_independent=independent)


def prepared(tmp_path, *, dry_run=True, expires=3600):
    image_manifest = build_fixture_boot_image(tmp_path / "image")
    image = BootImage.load(image_manifest)
    store = BootJobStore(tmp_path / "jobs")
    document = store.create(device={**TARGET, "is_system_device": True}, boot_image_path=image.initramfs_path,
        dry_run=dry_run, expires_in_seconds=expires, agent_id="agent-vm", central_job_id="central-vm",
        vm_validation=vm_manifest())
    store.transition(document["payload"]["boot_job_id"], "AWAITING_REBOOT")
    return store, document, image


def test_windows_fixture_is_rejected_as_bootable(tmp_path):
    manifest = build_fixture_boot_image(tmp_path / "fixture")
    report = validate_linux_boot_artifact(manifest, listing="\n".join(REQUIRED_INITRAMFS_COMPONENTS))
    assert report["status"] == "FAIL" and "host-specific" in report["blockers"][0]


def test_vm_manifest_requires_complete_positive_evidence_identity(tmp_path):
    manifest = vm_manifest()
    manifest["evidence_disk_identity"].pop("serial_number")
    path = tmp_path / "vm-validation.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BootJobError, match="Evidence-disk authorization requires"):
        load_vm_validation_manifest(path)


def test_linux_image_is_accepted_only_with_validated_listing_and_checksum(tmp_path):
    kernel, initramfs = tmp_path / "vmlinuz", tmp_path / "initramfs.img"
    kernel.write_bytes(b"linux-kernel"); initramfs.write_bytes(b"linux-initramfs")
    manifest = write_manifest(tmp_path, kernel=kernel, initramfs=initramfs, bootable=True,
        secure_boot_compatible=False, build_kind="ubuntu-debian-initramfs-tools", kernel_version="6.8-test",
        included_components=list(REQUIRED_INITRAMFS_COMPONENTS))
    assert validate_linux_boot_artifact(manifest, listing="\n".join(REQUIRED_INITRAMFS_COMPONENTS))["status"] == "PASS"
    assert validate_linux_boot_artifact(manifest, listing="local_agent/boot_console.py")["status"] == "FAIL"


@pytest.mark.parametrize("missing", ["nvme", "hdparm"])
def test_boot_self_test_fails_when_required_storage_tool_is_missing(tmp_path, monkeypatch, missing):
    active, key, result, cmdline = tmp_path / "active", tmp_path / "key", tmp_path / "results", tmp_path / "cmdline"
    active.write_text("job", encoding="utf-8"); key.write_bytes(b"x" * 32); result.mkdir()
    cmdline.write_text("vyper.mode=boot_sanitize", encoding="utf-8")
    monkeypatch.setattr("local_agent.vm_validation.os.name", "posix")
    which = lambda tool: None if tool == missing else f"/usr/bin/{tool}"
    report = BootSelfTest(active_job_path=active, key_path=key, result_directory=result, cmdline_path=cmdline,
        which=which, importer=lambda _name: object()).run()
    assert report["boot_self_test"] == "FAIL"
    assert next(item for item in report["checks"] if item["name"] == missing)["status"] == "FAIL"


def test_boot_console_treats_dhcp_timeout_as_offline(monkeypatch):
    monkeypatch.setattr("local_agent.boot_console.Path.is_file", lambda _path: True)
    def timeout(command, **_kwargs):
        assert command == ["/sbin/dhclient", "-1", "-d", "-v"]
        raise __import__("subprocess").TimeoutExpired(["/sbin/dhclient"], 60)
    monkeypatch.setattr("local_agent.boot_console.subprocess.run", timeout)
    assert _attempt_wired_dhcp() == "OFFLINE"


def test_grub_one_shot_records_next_entry_and_preserves_default(tmp_path):
    _store, document, image = prepared(tmp_path)
    executor = Exec()
    handoff = GrubOneShotHandoff(command_executor=executor, grub_script_path=tmp_path / "42_vyper")
    report = handoff.prepare(boot_job_id=document["payload"]["boot_job_id"], image=image, apply=True)
    assert report["current_default_entry"] == "Ubuntu"
    assert report["next_entry"] == "VYPER Boot Sanitize" and report["normal_default_unchanged"] is True
    handoff.cancel(apply=True)
    assert ["grub-editenv", "-", "unset", "next_entry"] in executor.calls


def test_virtualbox_detection_from_dmi_fixture(tmp_path):
    dmi = tmp_path / "dmi"; dmi.mkdir()
    (dmi / "sys_vendor").write_text("innotek GmbH", encoding="utf-8")
    (dmi / "product_name").write_text("VirtualBox", encoding="utf-8")
    result = VirtualizationInspector(command_executor=Exec(), dmi_root=dmi).inspect()
    assert result["virtualbox_proven"] is True


def test_non_virtual_host_destructive_mode_is_blocked():
    assert gate(vm_manifest(destructive=True), proven=False, allow=True)["destructive_eligible"] is False


def test_target_identity_mismatch_is_blocked():
    manifest = vm_manifest(); manifest["allowed_target_identity"]["serial_number"] = "OTHER"
    assert any("identity" in item for item in gate(manifest)["blockers"])


def test_evidence_disk_equal_to_target_is_blocked():
    manifest = vm_manifest(); manifest["evidence_disk_identity"] = dict(TARGET)
    result = gate(manifest, devices=[TARGET])
    assert any("Evidence disk identity equals" in item for item in result["blockers"])


@pytest.mark.parametrize(("manifest,allow"), [(vm_manifest(destructive=True), False), (vm_manifest(destructive=False), True)])
def test_destructive_cli_and_manifest_gates_are_both_required(manifest, allow):
    assert gate(manifest, allow=allow)["destructive_eligible"] is False


def test_all_independent_destructive_gates_can_become_eligible_without_executing():
    result = gate(vm_manifest(destructive=True), allow=True)
    assert result["destructive_eligible"] is True


def test_dry_run_complete_flow_is_inconclusive_and_never_verified(tmp_path):
    store, document, _image = prepared(tmp_path, dry_run=True)
    job_id = document["payload"]["boot_job_id"]
    agent = Agent()
    runtime = BootSanitizeRuntime(store=store, discovery=Discovery([TARGET]), safety_inspector=Safety(), agent=agent,
        result_directory=tmp_path / "results", upload_result=lambda _payload: False, durable_result_storage=True,
        validation_guard=lambda _document, _target: gate(vm_manifest(), devices=[TARGET]))
    result = runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
    assert agent.calls == [("/dev/sda", True)]
    assert result["final_status"] == "INCONCLUSIVE"
    assert all(item["state"] != "VERIFIED" for item in store.state(job_id)["events"])


def test_tampered_and_expired_boot_jobs_remain_blocked(tmp_path):
    store, document, _image = prepared(tmp_path)
    job_id = document["payload"]["boot_job_id"]
    path = store.root / job_id / "manifest.json"
    tampered = json.loads(path.read_text()); tampered["payload"]["dry_run"] = False
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(BootIntegrityError): store.validate(job_id)
    expired_store, expired, _ = prepared(tmp_path / "expired", expires=-1)
    with pytest.raises(BootJobError, match="expired"): expired_store.validate(expired["payload"]["boot_job_id"])


def test_missing_evidence_disk_falls_back_to_memory_and_central_failure_retains_offline(tmp_path):
    missing = gate(vm_manifest(evidence=True), devices=[TARGET])
    assert missing["evidence_storage"] == "RETAINED_IN_BOOT_MEMORY" and missing["destructive_eligible"] is False
    store, document, _ = prepared(tmp_path, dry_run=True); job_id = document["payload"]["boot_job_id"]
    runtime = BootSanitizeRuntime(store=store, discovery=Discovery([TARGET]), safety_inspector=Safety(), agent=Agent(),
        result_directory=tmp_path / "results", upload_result=lambda _payload: False, durable_result_storage=True)
    assert runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")["upload_status"] == "RETAINED_OFFLINE"


@pytest.mark.parametrize("scenario", ["shutdown_before_reboot", "confirmation_absent", "reboot_during_validation",
    "crash_before_execution", "crash_during_running", "network_unavailable"])
def test_interruption_scenarios_never_create_verified_state(tmp_path, scenario):
    store, document, _ = prepared(tmp_path / scenario, dry_run=True); job_id = document["payload"]["boot_job_id"]
    if scenario == "shutdown_before_reboot":
        store.transition(job_id, "CANCELLED")
    elif scenario == "confirmation_absent":
        store.transition(job_id, "WAITING_LOCAL_APPROVAL")
    else:
        store.begin_execution(job_id)
        store.transition(job_id, "INCONCLUSIVE", error=f"simulated {scenario}")
    state = store.state(job_id)
    assert state["status"] != "VERIFIED" and all(item["state"] != "VERIFIED" for item in state["events"])


def test_boot_validation_log_redacts_secrets(tmp_path):
    logger = BootValidationLogger(tmp_path / "boot.jsonl")
    logger.write("manifest", boot_job_id="job", agent_token="do-not-log", ata_password="do-not-log",
        nested={"operator_secret": "nested-do-not-log"})
    text = (tmp_path / "boot.jsonl").read_text()
    assert "do-not-log" not in text and text.count("<redacted>") == 3


def test_lifecycle_correlation_and_workflow_report_distinguish_dry_run(tmp_path):
    store, document, _ = prepared(tmp_path, dry_run=True); job_id = document["payload"]["boot_job_id"]
    runtime = BootSanitizeRuntime(store=store, discovery=Discovery([TARGET]), safety_inspector=Safety(), agent=Agent(),
        result_directory=tmp_path / "results", durable_result_storage=True)
    result = runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
    state = store.state(job_id)
    report = build_vm_validation_report(output_directory=tmp_path / "reports", boot_job=document["payload"], state=state,
        gate=gate(vm_manifest()), boot_artifact={"status": "PASS"},
        grub_handoff={"normal_default_unchanged": True, "next_entry": "VYPER Boot Sanitize"}, result=result)
    assert report["boot_job_id"] == job_id and report["local_job_id"] == job_id
    assert report["central_job_id"] == "central-vm" and report["agent_id"] == "agent-vm"
    assert report["workflow_validation"] == "PASS"
    assert report["sanitization_validation"] == "NOT_EXECUTED"
    assert report["virtual_disk_sanitization_validation"] == "NOT_EXECUTED"
    assert report["physical_media_validation"] == "NOT_APPLICABLE"
    assert "disk sanitization was not executed" in report["conclusion_statement"]
    assert report["report_files"]["json"].endswith("-system-disk-vm-dry-run.json")
    assert report["report_files"]["markdown"].endswith("-system-disk-vm-dry-run.md")


def test_destructive_report_names_and_semantics_are_explicit(tmp_path):
    events = [{"state": state} for state in ("PREPARING_BOOT", "AWAITING_REBOOT",
        "BOOT_ENVIRONMENT_STARTED", "VALIDATING_TARGET", "WAITING_LOCAL_APPROVAL",
        "RUNNING", "VERIFYING", "VERIFIED")]
    report = build_vm_validation_report(output_directory=tmp_path / "reports",
        boot_job={"boot_job_id": "job-destructive", "dry_run": False}, state={"events": events},
        gate={"host_virtualization": {"virtualbox_proven": True}}, boot_artifact={"status": "PASS"},
        grub_handoff={"normal_default_unchanged": True}, result={"final_status": "VERIFIED",
            "shutdown": {"shutdown_status": "FAILED", "shutdown_method": "poweroff",
                "shutdown_warning": "VM still running."}})
    assert report["virtual_disk_sanitization_validation"] == "PASS"
    assert report["physical_media_validation"] == "NOT_APPLICABLE"
    assert report["sanitization_status"] == "VERIFIED"
    assert report["shutdown_status"] == "FAILED"
    assert report["shutdown_method"] == "poweroff"
    assert report["final_conclusion"] == "PASS"
    assert report["report_files"]["json"].endswith("-system-disk-vm-destructive.json")
    assert report["report_files"]["markdown"].endswith("-system-disk-vm-destructive.md")


def test_worker_crash_during_overwrite_never_creates_verified_state(tmp_path):
    store, document, _ = prepared(tmp_path, dry_run=False)
    job_id = document["payload"]["boot_job_id"]
    runtime = BootSanitizeRuntime(store=store, discovery=Discovery([TARGET]), safety_inspector=Safety(),
        agent=Agent(crash=True), result_directory=tmp_path / "results", durable_result_storage=True)
    with pytest.raises(BootJobError, match="INCONCLUSIVE"):
        runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
    state = store.state(job_id)
    assert state["status"] == "INCONCLUSIVE"
    assert all(item["state"] != "VERIFIED" for item in state["events"])


def test_evidence_write_failure_never_creates_verified_state(tmp_path, monkeypatch):
    store, document, _ = prepared(tmp_path, dry_run=False)
    job_id = document["payload"]["boot_job_id"]
    runtime = BootSanitizeRuntime(store=store, discovery=Discovery([TARGET]), safety_inspector=Safety(),
        agent=Agent(), result_directory=tmp_path / "results", durable_result_storage=True)
    original = __import__("local_agent.boot_sanitize", fromlist=["durable_write_text"]).durable_write_text
    def fail_result_write(path, *args, **kwargs):
        if Path(path).name.endswith(".result.json"):
            raise OSError("simulated evidence write failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr("local_agent.boot_sanitize.durable_write_text", fail_result_write)
    with pytest.raises(OSError, match="evidence write failure"):
        runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
    state = store.state(job_id)
    assert state["status"] == "VERIFYING"
    assert all(item["state"] != "VERIFIED" for item in state["events"])


class ShutdownRunner:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes); self.calls = []
    def __call__(self, command, **_kwargs):
        self.calls.append(command)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return subprocess.CompletedProcess(command, outcome, stdout="", stderr="")


def test_systemd_pid1_prefers_systemctl_poweroff(tmp_path):
    pid1 = tmp_path / "comm"; pid1.write_text("systemd\n", encoding="utf-8")
    runner = ShutdownRunner([0, 1, 1, 1, 1])
    records = []
    coordinator = BootShutdownCoordinator(runner=runner, which=lambda name: f"/sbin/{name}",
        pid1_comm_path=pid1, completion_timeout=0, wait=lambda _seconds: None)
    coordinator.attempt(durability=lambda: {"sync": "done"}, record=records.append)
    assert runner.calls[0] == ["/sbin/systemctl", "poweroff"]


def test_non_systemd_uses_bounded_fallbacks_and_records_failure(tmp_path):
    pid1 = tmp_path / "comm"; pid1.write_text("init\n", encoding="utf-8")
    runner = ShutdownRunner([FileNotFoundError(), subprocess.TimeoutExpired(["shutdown"], 1), 1, 1])
    records = []; waits = []
    coordinator = BootShutdownCoordinator(runner=runner, which=lambda name: f"/sbin/{name}",
        pid1_comm_path=pid1, command_timeout=0.01, completion_timeout=0.01, wait=waits.append)
    result = coordinator.attempt(durability=lambda: {"sync": "done"}, record=records.append)
    assert [call[0] for call in runner.calls] == ["/sbin/poweroff", "/sbin/shutdown", "/sbin/reboot", "/sbin/busybox"]
    assert result["shutdown_status"] == "FAILED" and result["shutdown_fallback_used"] is True
    assert result["shutdown_warning"] and "sanitization outcome is unchanged" in result["shutdown_warning"]
    assert all("secret" not in json.dumps(record).lower() for record in records)
    assert len(waits) <= 4


def test_missing_shutdown_commands_are_skipped_and_durability_precedes_attempt(tmp_path):
    pid1 = tmp_path / "comm"; pid1.write_text("init\n", encoding="utf-8")
    order = []; records = []
    runner = ShutdownRunner([1])
    coordinator = BootShutdownCoordinator(runner=runner,
        which=lambda name: "/sbin/reboot" if name == "reboot" else None,
        pid1_comm_path=pid1, wait=lambda _seconds: None)
    result = coordinator.attempt(durability=lambda: order.append("durability") or {"fsync": True},
        record=lambda value: (order.append("record"), records.append(value)))
    assert order[:2] == ["record", "durability"]
    assert runner.calls == [["/sbin/reboot", "-p"]]
    assert result["shutdown_status"] == "FAILED"


def test_report_uses_fail_for_an_explicit_validation_failure(tmp_path):
    report = build_vm_validation_report(output_directory=tmp_path / "reports",
        boot_job={"boot_job_id": "job-failed", "dry_run": True},
        state={"events": [{"state": "FAILED"}]},
        gate={"host_virtualization": {"virtualbox_proven": True}},
        boot_artifact={"status": "FAIL"}, grub_handoff={"normal_default_unchanged": True}, result=None)
    assert report["workflow_validation"] == "INCONCLUSIVE"
    assert report["sanitization_validation"] == "NOT_EXECUTED"
    assert report["final_conclusion"] == "FAIL"
