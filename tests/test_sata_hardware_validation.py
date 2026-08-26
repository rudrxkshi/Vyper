from __future__ import annotations

import json
from dataclasses import replace

import pytest
from fastapi.encoders import jsonable_encoder

from agent.certificate import CertificateBuilder
from agent.command_runner import CommandResult
from agent.common import SanitizationResult, SanitizationStatus
from agent.evidence import EvidenceCollector
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult
from local_agent.cli import build_parser
from local_agent.hardware_validation import HardwareValidationError, HardwareValidationHarness


DEVICE = "/dev/sdy"
PASSWORD = "fixture-ata-secret"
ATA_ENABLED = """ATA device, with non-removable media
ATA Version is: ACS-4
Security:
        supported
        enabled
        not frozen
        supported: enhanced erase
        2min for SECURITY ERASE UNIT. 2min for ENHANCED SECURITY ERASE UNIT.
"""
ATA_DISABLED = ATA_ENABLED.replace("        enabled\n", "        not enabled\n")


def sata_profile(**changes):
	base = DeviceProfile(
		device_path=DEVICE, device_type="SATA SSD", serial_number="SATA-SSD-123456",
		model="Disposable SATA SSD", size_bytes=4 * 1024 * 1024, rotational=False,
		interface="ATA/SATA", transport="sata", is_system_device=False, mounted=False,
		capabilities={
			"type": "ATA/SATA", "wwn": "wwn-sata-123456", "hdparm_available": True,
			"security": {"supported": True, "enabled": True, "frozen": False,
				"secure_erase_supported": True, "raw_output": ATA_ENABLED},
		},
	)
	return replace(base, **changes)


def post_sata_profile(**changes):
	capabilities = dict(sata_profile().capabilities)
	capabilities["security"] = {"supported": True, "enabled": False, "frozen": False,
		"secure_erase_supported": True, "raw_output": ATA_DISABLED}
	return sata_profile(capabilities=capabilities, **changes)


class SequenceProfiler:
	def __init__(self, *profiles):
		self.profiles = list(profiles)

	def profile(self, _device):
		if len(self.profiles) > 1:
			return self.profiles.pop(0)
		return self.profiles[0]


class SATAFixtureExecutor:
	def __init__(self, *, filesystem=False, post_hdparm=ATA_DISABLED, probe_failure=None):
		self.filesystem = filesystem
		self.post_hdparm = post_hdparm
		self.probe_failure = probe_failure
		self.calls = []

	def run(self, command, timeout=None, cwd=None):
		self.calls.append(list(command))
		if command[0] == self.probe_failure:
			return self._result(command, success=False, exit_code=1, stderr="fixture probe failed")
		if command[0] == "lsblk":
			payload = {"blockdevices": [{"name": "sdy", "path": DEVICE, "type": "disk",
				"fstype": "ext4" if self.filesystem else None, "fsver": None, "label": None,
				"uuid": "old-fixture-uuid" if self.filesystem else None,
				"size": 4 * 1024 * 1024, "mountpoints": []}]}
			return self._result(command, stdout=json.dumps(payload))
		if command[0] == "blkid" and "UUID" in command:
			return self._result(command, stdout="prepared-fixture-uuid\n")
		if command[0] == "blkid":
			return self._result(command, success=self.filesystem, exit_code=0 if self.filesystem else 2,
				stdout=f"{DEVICE}: UUID=old-fixture-uuid TYPE=ext4\n" if self.filesystem else "")
		if command[0] == "file":
			return self._result(command, stdout=f"{DEVICE}: Linux rev 1.0 ext4 filesystem data\n" if self.filesystem else f"{DEVICE}: data\n")
		if command[0] == "udevadm":
			return self._result(command, stdout="ID_BUS=ata\nID_MODEL=Disposable_SATA_SSD\nID_SERIAL_SHORT=SATA-SSD-123456\nID_WWN=wwn-sata-123456\n")
		if command[0] == "hdparm":
			return self._result(command, stdout=self.post_hdparm)
		if command[0] == "smartctl":
			return self._result(command, stdout="Device Model: Disposable SATA SSD\nSerial Number: SATA-SSD-123456\n")
		return self._result(command)

	def _result(self, command, *, success=True, exit_code=0, stdout="", stderr=""):
		return CommandResult(command=command, success=success, exit_code=exit_code, stdout=stdout, stderr=stderr)


class FakeATAClient:
	def __init__(self, job):
		self.job = job
		self.submitted = []

	def submit_ata_job(self, device, password):
		self.submitted.append((device, password))
		return {"local_job_id": self.job["local_job_id"]}

	def get_job(self, local_job_id):
		assert local_job_id == self.job["local_job_id"]
		return self.job


def verified_ata_job():
	pre_profile = sata_profile()
	policy = PolicyDecision(selected_pathway="ATA_ERASE", device_type="SATA SSD", reason="fixture", unsupported=False)
	execution = SanitizationResult(
		status=SanitizationStatus.RUNNING, target_device=DEVICE, dry_run=False,
		message="ATA secure erase commands were issued; verification remains separate.",
		metadata={"method": "ATA_ERASE", "security_supported": True, "security_frozen_before": False,
			"erase_command_completed": True, "post_status": ATA_DISABLED, "duration_seconds": 120.0},
	)
	verification = VerificationResult(
		status=SanitizationStatus.VERIFIED, device=DEVICE, pathway="ATA_ERASE", verified=True,
		message="ATA security disabled and unfrozen.",
		evidence={"source": "hdparm", "status": "security_disabled", "raw": ATA_DISABLED},
	)
	evidence = EvidenceCollector(dry_run=False, agent_version="vyper-test").create_record(
		device_profile=pre_profile, policy_decision=policy, execution_result=execution,
		verification_result=verification, started_at="2026-08-25T00:00:00Z", completed_at="2026-08-25T00:02:00Z",
	)
	certificate = CertificateBuilder().build(evidence)
	return {
		"local_job_id": "ata-fixture-job", "target": DEVICE, "job_state": "VERIFIED", "final_status": "VERIFIED",
		"policy": jsonable_encoder(policy), "execution": jsonable_encoder(execution),
		"verification": jsonable_encoder(verification), "evidence": jsonable_encoder(evidence),
		"certificate": jsonable_encoder(certificate),
		"state_history": [
			{"sequence": 1, "state": "PENDING", "timestamp": "2026-08-25T00:00:00Z", "progress": None},
			{"sequence": 5, "state": "RUNNING", "timestamp": "2026-08-25T00:00:10Z", "progress": {"kind": "indeterminate"}},
			{"sequence": 6, "state": "VERIFYING", "timestamp": "2026-08-25T00:02:00Z", "progress": {"kind": "indeterminate"}},
		],
	}


def make_harness(tmp_path, *, profiles=None, job=None, confirmation="ERASE 123456", filesystem=False,
	post_hdparm=ATA_DISABLED, probe_failure=None, output=None):
	executor = SATAFixtureExecutor(filesystem=filesystem, post_hdparm=post_hdparm, probe_failure=probe_failure)
	client = FakeATAClient(job or verified_ata_job())
	messages = output if output is not None else []
	instance = HardwareValidationHarness(
		profiler=SequenceProfiler(*(profiles or [sata_profile()])), command_executor=executor,
		local_client=client, output_directory=tmp_path, input_fn=lambda _prompt: confirmation,
		getpass_fn=lambda _prompt: PASSWORD, print_fn=messages.append, sleep_fn=lambda _seconds: None,
	)
	return instance, executor, client, messages


def test_cli_exposes_sata_plan_and_prepare_forms():
	plan = build_parser().parse_args(["validate-hardware", "sata-ssd", "--device", DEVICE])
	prepare = build_parser().parse_args(["validate-hardware", "sata-ssd", "prepare", "--device", DEVICE, "--execute"])
	assert (plan.operation, plan.execute) == ("validate", False)
	assert (prepare.operation, prepare.execute) == ("prepare", True)


def test_sata_plan_mode_never_executes_or_requests_password(tmp_path):
	instance, executor, client, _messages = make_harness(tmp_path)
	result = instance.validate_sata_ssd(DEVICE)
	assert result["mode"] == "read-only-plan" and client.submitted == []
	assert result["ata_capabilities"]["enhanced_secure_erase_supported"] is True
	assert result["ata_capabilities"]["estimated_erase_time"]
	assert result["ata_capabilities"]["ata_standard_or_version"] == "ATA Version is: ACS-4"
	assert all("--security-erase" not in call for call in executor.calls)


def test_execute_flag_is_required_for_sata_submission(tmp_path):
	instance, _executor, client, _messages = make_harness(tmp_path)
	instance.validate_sata_ssd(DEVICE, execute=False)
	assert client.submitted == []


@pytest.mark.parametrize("unsafe", [sata_profile(device_type="HDD", rotational=True), sata_profile(device_type="NVMe", rotational=False)])
def test_hdd_and_nvme_are_rejected(tmp_path, unsafe):
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[unsafe])
	with pytest.raises(HardwareValidationError, match="SATA SSD validation"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


@pytest.mark.parametrize("unsafe, message", [
	(sata_profile(is_system_device=True), "System-associated"),
	(sata_profile(mounted=True, mounted_partitions=["/mnt/ssd"]), "Mounted"),
])
def test_system_and_mounted_sata_ssds_are_rejected(tmp_path, unsafe, message):
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[unsafe])
	with pytest.raises(HardwareValidationError, match=message):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_frozen_ssd_plan_shows_blocker_and_execution_refuses(tmp_path):
	frozen_caps = dict(sata_profile().capabilities)
	frozen_caps["security"] = {**frozen_caps["security"], "frozen": True, "raw_output": ATA_ENABLED.replace("not frozen", "frozen")}
	frozen = sata_profile(capabilities=frozen_caps)
	instance, _executor, client, messages = make_harness(tmp_path, profiles=[frozen])
	plan = instance.validate_sata_ssd(DEVICE)
	assert any("frozen" in blocker.lower() for blocker in plan["execution_blockers"])
	assert any("EXECUTION BLOCKER" in message for message in messages)
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[frozen])
	with pytest.raises(HardwareValidationError, match="frozen"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_unsupported_ata_security_is_rejected(tmp_path):
	caps = dict(sata_profile().capabilities)
	caps["security"] = {"supported": False, "enabled": False, "frozen": False, "secure_erase_supported": False, "raw_output": ""}
	unsupported = sata_profile(capabilities=caps)
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[unsupported])
	with pytest.raises(HardwareValidationError, match="support is unavailable"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_usb_bridge_without_proven_passthrough_is_rejected(tmp_path):
	usb = sata_profile(interface="USB", transport="usb")
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[usb])
	with pytest.raises(HardwareValidationError, match="USB-to-SATA"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_policy_that_would_select_crypto_is_blocked_without_substitution(tmp_path):
	caps = dict(sata_profile().capabilities)
	caps.update({"crypto_erase_supported": True, "crypto_erase_applicable": True})
	crypto_selected = sata_profile(capabilities=caps)
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[crypto_selected])
	plan = instance.validate_sata_ssd(DEVICE)
	assert plan["selected_vyper_pathway"] == "CRYPTO_ERASE"
	assert any("not ATA_ERASE" in blocker for blocker in plan["execution_blockers"])
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[crypto_selected])
	with pytest.raises(HardwareValidationError, match="not ATA_ERASE"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


@pytest.mark.parametrize("changed", [sata_profile(serial_number="OTHER-123456"), sata_profile(size_bytes=8 * 1024 * 1024)])
def test_identity_or_capacity_change_is_rejected(tmp_path, changed):
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[sata_profile(), changed])
	with pytest.raises(HardwareValidationError, match="identity changed"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_typed_confirmation_mismatch_is_rejected(tmp_path):
	instance, _executor, client, _messages = make_harness(tmp_path, profiles=[sata_profile(), sata_profile()], confirmation="yes")
	with pytest.raises(HardwareValidationError, match="confirmation did not match"):
		instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == []


def test_product_api_is_used_and_harness_never_calls_destructive_hdparm(tmp_path):
	instance, executor, client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()],
	)
	report = instance.validate_sata_ssd(DEVICE, execute=True)
	assert client.submitted == [(DEVICE, PASSWORD)]
	assert report["selected_pathway"] == "ATA_ERASE"
	assert all(not any(str(part).startswith("--security-") for part in call) for call in executor.calls)


def test_password_is_absent_from_report_and_printed_messages(tmp_path):
	messages = []
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()], output=messages,
	)
	report = instance.validate_sata_ssd(DEVICE, execute=True)
	text = json.dumps(report) + "\n" + "\n".join(messages)
	assert PASSWORD not in text
	assert report["ata_execution_evidence"]["ata_password_used"] is True


def test_ata_progress_remains_indeterminate(tmp_path):
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()],
	)
	report = instance.validate_sata_ssd(DEVICE, execute=True)
	assert report["progress_summary"]["mode"] == "indeterminate"
	assert report["progress_summary"]["percentage_claimed"] is False
	assert {item["kind"] for item in report["progress_summary"]["measurements"]} == {"indeterminate"}


def test_verified_with_consistent_controller_post_state_is_pass(tmp_path):
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()],
	)
	assert instance.validate_sata_ssd(DEVICE, execute=True)["conclusion"] == "PASS"


@pytest.mark.parametrize("post_hdparm, filesystem, probe_failure", [
	(ATA_ENABLED, False, None),
	(ATA_DISABLED, True, None),
	(ATA_DISABLED, False, "udevadm"),
])
def test_inconsistent_post_state_old_filesystem_or_probe_failure_is_inconclusive(tmp_path, post_hdparm, filesystem, probe_failure):
	post = sata_profile() if post_hdparm == ATA_ENABLED else post_sata_profile()
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post],
		post_hdparm=post_hdparm, filesystem=filesystem, probe_failure=probe_failure,
	)
	assert instance.validate_sata_ssd(DEVICE, execute=True)["conclusion"] == "INCONCLUSIVE"


def test_failed_vyper_execution_is_fail(tmp_path):
	job = verified_ata_job()
	job.update({"job_state": "FAILED", "final_status": "FAILED", "verification": None, "evidence": None, "certificate": None})
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()], job=job,
	)
	assert instance.validate_sata_ssd(DEVICE, execute=True)["conclusion"] == "FAIL"


def test_certificate_hash_mismatch_prevents_pass(tmp_path):
	job = verified_ata_job()
	job["certificate"]["certificate_hash"] = "0" * 64
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()], job=job,
	)
	report = instance.validate_sata_ssd(DEVICE, execute=True)
	assert report["conclusion"] == "INCONCLUSIVE"
	assert report["integrity"]["certificate_valid"] is False


def test_report_records_controller_native_verification_basis(tmp_path):
	instance, _executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile(), sata_profile(), post_sata_profile()],
	)
	report = instance.validate_sata_ssd(DEVICE, execute=True)
	assert report["validation_kind"] == "physical_sata_ssd"
	assert report["verification_basis"] == [
		"controller/native command evidence", "VYPER verifier", "independent logical/interface checks",
	]
	assert next(tmp_path.glob("*-sata-ssd-*.json"))
	assert next(tmp_path.glob("*-sata-ssd-*.md"))


def test_sata_prepare_is_plan_only_without_execute(tmp_path):
	instance, executor, _client, _messages = make_harness(tmp_path)
	plan = instance.prepare_sata_ssd(DEVICE)
	assert plan["operation"] == "prepare"
	assert all(call[0] not in {"mkfs.ext4", "mount"} for call in executor.calls)


def test_sata_prepare_execute_uses_mocked_filesystem_commands_and_hashes_data(tmp_path):
	instance, executor, _client, _messages = make_harness(
		tmp_path, profiles=[sata_profile(), sata_profile()], confirmation="PREPARE 123456",
	)
	manifest = instance.prepare_sata_ssd(DEVICE, execute=True)
	assert manifest["kind"] == "physical_sata_ssd_test_data" and manifest["unmounted"] is True
	assert len(manifest["files"]) == 3 and all(len(item["sha256"]) == 64 for item in manifest["files"])
	assert [call[0] for call in executor.calls if call[0] in {"mkfs.ext4", "mount", "sync", "umount"}] == [
		"mkfs.ext4", "mount", "sync", "umount",
	]
