from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.agent import VYPERAgent
from agent.command_runner import CommandResult
from agent.profiler import DeviceProfile
from local_agent.boot_handoff import BootImage, GrubOneShotHandoff
from local_agent.boot_image import build_fixture_boot_image
from local_agent.boot_sanitize import (
	BootIntegrityError, BootJobError, BootJobStore, BootSanitizeRuntime, BootTargetValidationError,
)
from local_agent.system_disk import SystemDiskService


def _device(path="/dev/sda", *, serial="SYSTEM-001", model="Test Disk", size=1024 * 1024,
	mounted=False, system=False, device_type="HDD", capabilities=None):
	return {
		"device_path": path, "device_type": device_type, "model": model, "serial_number": serial,
		"size_bytes": size, "mounted": mounted, "is_system_device": system,
		"eligible_for_sanitization": not mounted and not system, "capabilities": capabilities or {},
		"interface": "SATA", "transport": "sata",
	}


class Discovery:
	def __init__(self, devices): self.devices = devices
	def discover(self): return self.devices


class Safety:
	def __init__(self, payload=None): self.payload = payload
	def inspect(self, target): return self.payload or _safe_topology(target)


def _safe_topology(target="/dev/sda"):
	return {
		"commands_known": True,
		"lsblk": {"blockdevices": [{"path": target, "type": "disk", "fstype": None, "mountpoints": [], "children": []}]},
		"swap_devices": [], "root": {"filesystems": [{"source": "rootfs", "target": "/", "fstype": "tmpfs"}]},
		"lvm": {"report": [{"pv": []}]}, "holders": [],
	}


class AgentStub:
	def __init__(self, final_status="VERIFIED", pathway="HDD_OVERWRITE"):
		self.final_status = final_status; self.pathway = pathway; self.calls = []; self.destructive_calls = 0
	def sanitize_device(self, target, authorization, dry_run=False):
		self.calls.append((target, dict(authorization), dry_run))
		self.destructive_calls += int(not dry_run)
		status = "INCONCLUSIVE" if dry_run else self.final_status
		return {
			"job_state": status, "final_status": status, "profile": _device(target, system=False),
			"policy": {"selected_pathway": self.pathway}, "execution": {"status": status, "dry_run": dry_run,
				"metadata": {"method": self.pathway}},
			"verification": {"status": status, "verified": status == "VERIFIED"},
			"evidence": {"final_status": status, "integrity_hash": "mocked-isolated-evidence"},
			"certificate": {"certificate_id": "boot-cert", "final_status": status,
				"successful_sanitization_claim": status == "VERIFIED"}, "state_history": [status],
		}


@dataclass
class Executor:
	secure_boot: str = "disabled"
	def __post_init__(self): self.calls = []
	def run(self, command, timeout=None):
		self.calls.append(command)
		if command[:2] == ["mokutil", "--sb-state"]:
			return CommandResult(command=command, success=True, exit_code=0, stdout=f"SecureBoot {self.secure_boot}\n", stderr="", dry_run=True)
		return CommandResult(command=command, success=True, exit_code=0, stdout="", stderr="", dry_run=True)


def _prepared(tmp_path, *, device=None, dry_run=False, central_job_id=None, expires=3600, requested_method="POLICY"):
	manifest_path = build_fixture_boot_image(tmp_path / "boot-image")
	image = BootImage.load(manifest_path)
	store = BootJobStore(tmp_path / "jobs")
	document = store.create(device=device or _device(), boot_image_path=image.initramfs_path,
		central_job_id=central_job_id, requested_method=requested_method, dry_run=dry_run, expires_in_seconds=expires)
	return store, document, image


def _runtime(tmp_path, store, document, *, devices=None, safety=None, agent=None, uploader=None):
	return BootSanitizeRuntime(store=store, discovery=Discovery(devices or [_device("/dev/vda")]),
		safety_inspector=Safety(safety), agent=agent or AgentStub(), result_directory=tmp_path / "results",
		upload_result=uploader, durable_result_storage=True)


def test_memory_only_offline_result_is_not_claimed_durable(tmp_path):
	store, document, _ = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	runtime = BootSanitizeRuntime(store=store, discovery=Discovery([_device("/dev/vda")]),
		safety_inspector=Safety(), agent=AgentStub(), result_directory=tmp_path / "ram-results")
	result = runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert result["upload_status"] == "RETAINED_IN_BOOT_MEMORY"
	assert json.loads(Path(result["result_path"]).read_text())["upload_status"] == "RETAINED_IN_BOOT_MEMORY"


def test_normal_mode_still_rejects_active_system_disk():
	class Profiler:
		def profile(self, target):
			return DeviceProfile(device_path=target, device_type="HDD", size_bytes=1024, rotational=True, is_system_device=True)
	agent = VYPERAgent(dry_run=False, profiler=Profiler())
	result = agent.sanitize_device("/dev/system", {"approved": True}, dry_run=False)
	assert result.job_state.value == "FAILED"
	assert "System-associated" in result.message


def test_boot_job_creation_does_not_execute_and_never_stores_ata_password(tmp_path):
	store, document, _ = _prepared(tmp_path)
	assert store.state(document["payload"]["boot_job_id"])["status"] == "PREPARING_BOOT"
	assert document["payload"]["ata_password_transfer"] == "NOT_STORED_REENTER_IN_BOOT_ENVIRONMENT"
	assert "temporary-password" not in json.dumps(document)
	assert document["payload"]["local_confirmation_state"] == "REQUIRED_IN_BOOT_ENVIRONMENT"


def test_expired_job_is_rejected(tmp_path):
	store, document, _ = _prepared(tmp_path, expires=-1)
	with pytest.raises(BootJobError, match="expired"):
		store.validate(document["payload"]["boot_job_id"])


def test_tampered_manifest_is_rejected(tmp_path):
	store, document, _ = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	path = store.root / job_id / "manifest.json"
	tampered = json.loads(path.read_text()); tampered["payload"]["dry_run"] = True
	path.write_text(json.dumps(tampered), encoding="utf-8")
	with pytest.raises(BootIntegrityError): store.validate(job_id)


def test_tampered_replay_state_is_rejected(tmp_path):
	store, document, _ = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	path = store.root / job_id / "state.json"
	tampered = json.loads(path.read_text())
	tampered["state"]["execution_attempted"] = True
	path.write_text(json.dumps(tampered), encoding="utf-8")
	with pytest.raises(BootIntegrityError, match="state authentication"):
		store.begin_execution(job_id)


def test_boot_image_checksum_tampering_is_rejected(tmp_path):
	manifest_path = build_fixture_boot_image(tmp_path / "boot-image")
	(manifest_path.parent / "initramfs.img").write_bytes(b"tampered")
	with pytest.raises(BootJobError, match="checksum"):
		BootImage.load(manifest_path)


def test_path_change_matches_stable_identity(tmp_path):
	store, document, _ = _prepared(tmp_path)
	runtime = _runtime(tmp_path, store, document, devices=[_device("/dev/nvme9n1")])
	assert runtime.identify_target(document).device_path == "/dev/nvme9n1"


@pytest.mark.parametrize("devices,message", [
	([_device("/dev/vda", serial="OTHER")], "No disk"),
	([_device("/dev/vda"), _device("/dev/vdb")], "Multiple disks"),
])
def test_identity_mismatch_or_ambiguity_blocks(tmp_path, devices, message):
	store, document, _ = _prepared(tmp_path)
	with pytest.raises(BootTargetValidationError, match=message): _runtime(tmp_path, store, document, devices=devices).identify_target(document)


def test_missing_stable_identity_blocks_preparation(tmp_path):
	manifest = build_fixture_boot_image(tmp_path / "image")
	image = BootImage.load(manifest)
	store = BootJobStore(tmp_path / "jobs")
	with pytest.raises(BootJobError, match="stable identity"):
		store.create(device=_device(serial=None, model=None), boot_image_path=image.initramfs_path)


@pytest.mark.parametrize("device,safety,message", [
	(_device("/dev/vda", mounted=True), None, "mounted"),
	(_device("/dev/vda"), {**_safe_topology("/dev/vda"), "root": {"filesystems": [{"source": "/dev/vda1"}]}}, "active boot"),
	(_device("/dev/vda"), {**_safe_topology("/dev/vda"), "holders": ["dm-0"]}, "holders"),
	(_device("/dev/vda"), {**_safe_topology("/dev/vda"), "lvm": {"report": [{"pv": [{"pv_name": "/dev/vda1"}]}]}}, "LVM"),
])
def test_boot_safety_refuses_mounted_root_or_complex_topology(tmp_path, device, safety, message):
	store, document, _ = _prepared(tmp_path)
	runtime = _runtime(tmp_path, store, document, devices=[device], safety=safety)
	target = runtime.identify_target(document)
	with pytest.raises(BootTargetValidationError, match=message): runtime.validate_target(target)


def test_mdraid_membership_is_refused_by_default(tmp_path):
	store, document, _ = _prepared(tmp_path)
	safety = _safe_topology("/dev/vda")
	safety["lsblk"]["blockdevices"][0]["fstype"] = "linux_raid_member"
	runtime = _runtime(tmp_path, store, document, devices=[_device("/dev/vda")], safety=safety)
	with pytest.raises(BootTargetValidationError, match="linux_raid_member"):
		runtime.validate_target(runtime.identify_target(document))


def test_fresh_local_confirmation_required_even_for_remote_approval(tmp_path):
	store, document, _ = _prepared(tmp_path, central_job_id="central-1")
	job_id = document["payload"]["boot_job_id"]
	runtime = _runtime(tmp_path, store, document)
	with pytest.raises(BootJobError, match="Fresh local"):
		runtime.run(job_id, confirmation="YES")
	assert runtime.agent.calls == []


@pytest.mark.parametrize("pathway,device_type", [("HDD_OVERWRITE", "HDD"), ("ATA_ERASE", "SATA SSD"), ("BLOCK_ERASE", "NVMe")])
def test_boot_runtime_reuses_selected_engine_pathway(tmp_path, pathway, device_type):
	device = _device(device_type=device_type)
	store, document, _ = _prepared(tmp_path, device=device)
	job_id = document["payload"]["boot_job_id"]
	agent = AgentStub(pathway=pathway)
	runtime = _runtime(tmp_path, store, document, devices=[_device("/dev/vda", device_type=device_type)], agent=agent)
	result = runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert result["selected_pathway"] == pathway
	assert agent.calls[0][0] == "/dev/vda"


def test_nonce_replay_and_power_loss_never_auto_repeat_or_verify(tmp_path):
	store, document, _ = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	store.begin_execution(job_id)
	with pytest.raises(BootJobError, match="already consumed"): store.begin_execution(job_id)
	state = store.state(job_id)
	assert state["status"] == "INCONCLUSIVE"
	assert state.get("result") is None


def test_explicit_method_is_never_silently_substituted(tmp_path):
	device = _device(device_type="SATA SSD", capabilities={"security": {"supported": True}})
	store, document, _ = _prepared(tmp_path, device=device, requested_method="CRYPTO_ERASE")
	job_id = document["payload"]["boot_job_id"]
	class PreflightAgent(AgentStub):
		def __init__(self):
			super().__init__(); self.policy_engine = object()
			self.profiler = SimpleNamespace(profile=lambda _target: DeviceProfile(
				device_path="/dev/vda", device_type="SATA SSD", serial_number="SYSTEM-001", model="Test Disk",
				size_bytes=1024 * 1024, capabilities={"security": {"supported": True}}, is_system_device=False))
	agent = PreflightAgent()
	runtime = _runtime(tmp_path, store, document, devices=[_device("/dev/vda", device_type="SATA SSD",
		capabilities={"security": {"supported": True}})], agent=agent)
	with pytest.raises(BootJobError, match="no substitution"):
		runtime.run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert agent.calls == []


def test_offline_result_retained_with_boot_evidence_shape(tmp_path):
	store, document, _ = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	result = _runtime(tmp_path, store, document).run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert result["execution_environment"] == "boot_sanitize"
	assert result["final_status"] == "VERIFIED"
	assert result["upload_status"] == "RETAINED_OFFLINE"
	assert Path(result["result_path"]).is_file()


def test_verified_result_upload_callback(tmp_path):
	uploads = []
	store, document, _ = _prepared(tmp_path, central_job_id="central-1")
	job_id = document["payload"]["boot_job_id"]
	result = _runtime(tmp_path, store, document, uploader=lambda payload: not uploads.append(payload)).run(
		job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert uploads and result["upload_status"] == "UPLOADED"


def test_dry_run_executes_no_destructive_agent_call(tmp_path):
	store, document, _ = _prepared(tmp_path, dry_run=True)
	job_id = document["payload"]["boot_job_id"]
	agent = AgentStub()
	result = _runtime(tmp_path, store, document, agent=agent).run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert agent.destructive_calls == 0
	assert result["final_status"] == "INCONCLUSIVE"


def test_grub_handoff_is_one_shot_and_secure_boot_is_surfaced(tmp_path):
	_, document, image = _prepared(tmp_path)
	job_id = document["payload"]["boot_job_id"]
	executor = Executor("disabled")
	handoff = GrubOneShotHandoff(command_executor=executor, grub_script_path=tmp_path / "42_vyper")
	result = handoff.prepare(boot_job_id=job_id, image=image, apply=True)
	assert result["normal_default_unchanged"] is True
	assert ["grub-reboot", "VYPER Boot Sanitize"] in executor.calls
	assert "noresume" in result["configuration"]
	with pytest.raises(BootJobError, match="Secure Boot"):
		GrubOneShotHandoff(command_executor=Executor("enabled"), grub_script_path=tmp_path / "secure").prepare(
			boot_job_id=job_id, image=image, apply=False)
	handoff.cancel(apply=True)
	assert ["grub-editenv", "-", "unset", "next_entry"] in executor.calls


def test_system_disk_prepare_uses_fixture_without_applying_and_preserves_default(tmp_path):
	manifest = build_fixture_boot_image(tmp_path / "image")
	store = BootJobStore(tmp_path / "jobs")
	service = SystemDiskService(discovery=Discovery([_device(system=True)]), store=store,
		handoff=GrubOneShotHandoff(command_executor=Executor(), grub_script_path=tmp_path / "grub"),
		boot_image_manifest=manifest, boot_directory=tmp_path / "boot")
	prepared = service.prepare(dry_run=True, apply_handoff=False)
	assert prepared["state"]["status"] == "AWAITING_REBOOT"
	assert prepared["handoff"]["normal_default_unchanged"] is True
	assert (tmp_path / "boot" / "jobs" / prepared["boot_job"]["boot_job_id"] / "initramfs.img").is_file()


def test_non_destructive_disk_image_fixture_is_unchanged(tmp_path):
	disk = tmp_path / "disposable-system-disk.img"
	disk.write_bytes(b"TEST-FILESYSTEM-DATA" * 512)
	before = disk.read_bytes()
	store, document, _ = _prepared(tmp_path / "job", dry_run=True)
	job_id = document["payload"]["boot_job_id"]
	_runtime(tmp_path / "job", store, document, agent=AgentStub()).run(job_id, confirmation=f"ERASE {job_id[-8:]}")
	assert disk.read_bytes() == before


def test_boot_artifact_manifest_and_payload_exclude_credentials(tmp_path):
	manifest_path = build_fixture_boot_image(tmp_path / "boot")
	manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
	combined = b"".join(path.read_bytes() for path in manifest_path.parent.iterdir() if path.is_file()).lower()
	assert manifest["contains_agent_credentials"] is False
	assert manifest["contains_operator_secrets"] is False
	assert b"agent_token" not in combined and b"ata_password" not in combined
