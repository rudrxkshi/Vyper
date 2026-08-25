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
from local_agent.hardware_validation import HardwareValidationError, HardwareValidationHarness
from local_agent.cli import build_parser


DEVICE = "/dev/sdz"


def test_cli_plan_and_prepare_forms_require_an_explicit_device():
	plan = build_parser().parse_args(["validate-hardware", "hdd", "--device", DEVICE])
	prepare = build_parser().parse_args(["validate-hardware", "hdd", "prepare", "--device", DEVICE, "--execute"])
	assert (plan.operation, plan.execute, plan.device) == ("validate", False, DEVICE)
	assert (prepare.operation, prepare.execute, prepare.device) == ("prepare", True, DEVICE)


def profile(**changes):
	base = DeviceProfile(
		device_path=DEVICE, device_type="HDD", serial_number="HDD-SERIAL-123456",
		model="Disposable HDD", size_bytes=1024 * 1024, rotational=True,
		interface="ATA/SATA", transport="sata", is_system_device=False,
		mounted=False, capabilities={"type": "ATA/SATA", "wwn": "wwn-hdd-123456"},
	)
	return replace(base, **changes)


class SequenceProfiler:
	def __init__(self, *profiles):
		self.profiles = list(profiles)
		self.calls = []

	def profile(self, device):
		self.calls.append(device)
		if len(self.profiles) > 1:
			return self.profiles.pop(0)
		return self.profiles[0]


class FixtureExecutor:
	def __init__(self, *, filesystem=False):
		self.calls = []
		self.filesystem = filesystem

	def run(self, command, timeout=None, cwd=None):
		self.calls.append(list(command))
		if command[0] == "lsblk":
			payload = {"blockdevices": [{
				"name": "sdz", "path": DEVICE, "type": "disk", "fstype": "ext4" if self.filesystem else None,
				"fsver": None, "label": None, "uuid": "fixture-uuid" if self.filesystem else None,
				"size": 1024 * 1024, "mountpoints": [],
			}]}
			return self._result(command, stdout=json.dumps(payload))
		if command[0] == "blkid" and "UUID" in command:
			return self._result(command, stdout="fixture-uuid\n")
		if command[0] == "blkid":
			return self._result(command, success=False, exit_code=2)
		if command[0] == "file":
			return self._result(command, stdout=f"{DEVICE}: data\n")
		return self._result(command)

	def _result(self, command, *, success=True, exit_code=0, stdout="", stderr=""):
		return CommandResult(command=command, success=success, exit_code=exit_code, stdout=stdout, stderr=stderr)


class FakeLocalClient:
	def __init__(self, job):
		self.job = job
		self.submitted = []

	def submit_hdd_job(self, device):
		self.submitted.append(device)
		return {"local_job_id": self.job["local_job_id"]}

	def get_job(self, local_job_id):
		assert local_job_id == self.job["local_job_id"]
		return self.job


def verified_job():
	device_profile = profile()
	policy = PolicyDecision(selected_pathway="HDD_OVERWRITE", device_type="HDD", reason="fixture", unsupported=False)
	execution = SanitizationResult(
		status=SanitizationStatus.RUNNING, target_device=DEVICE, dry_run=False, message="complete",
		metadata={"method": "HDD_OVERWRITE", "bytes_written": 1024 * 1024, "total_bytes": 1024 * 1024,
			"start_time": "2026-08-25T00:00:00Z", "end_time": "2026-08-25T00:01:00Z", "duration_seconds": 60},
	)
	verification = VerificationResult(
		status=SanitizationStatus.VERIFIED, device=DEVICE, pathway="HDD_OVERWRITE", verified=True,
		message="Representative zero samples matched.", evidence={"sample_count": 3},
	)
	evidence = EvidenceCollector(dry_run=False, agent_version="vyper-test").create_record(
		device_profile=device_profile, policy_decision=policy, execution_result=execution,
		verification_result=verification, started_at="2026-08-25T00:00:00Z", completed_at="2026-08-25T00:01:00Z",
	)
	certificate = CertificateBuilder().build(evidence)
	return {
		"local_job_id": "fixture-job", "target": DEVICE, "job_state": "VERIFIED", "final_status": "VERIFIED",
		"policy": jsonable_encoder(policy), "execution": jsonable_encoder(execution),
		"verification": jsonable_encoder(verification), "evidence": jsonable_encoder(evidence),
		"certificate": jsonable_encoder(certificate),
		"state_history": [
			{"sequence": 1, "state": "PENDING", "timestamp": "2026-08-25T00:00:00Z", "progress": None},
			{"sequence": 5, "state": "RUNNING", "timestamp": "2026-08-25T00:00:30Z",
				"progress": {"kind": "bytes", "bytes_completed": 524288, "bytes_total": 1048576}},
			{"sequence": 7, "state": "VERIFIED", "timestamp": "2026-08-25T00:01:00Z",
				"progress": {"kind": "bytes", "bytes_completed": 1048576, "bytes_total": 1048576}},
		],
	}


def harness(tmp_path, *, profiles=None, job=None, confirmation="ERASE 123456", filesystem=False, sample=b"\0" * 4096):
	executor = FixtureExecutor(filesystem=filesystem)
	client = FakeLocalClient(job or verified_job())
	instance = HardwareValidationHarness(
		profiler=SequenceProfiler(*(profiles or [profile()])), command_executor=executor,
		local_client=client, output_directory=tmp_path, input_fn=lambda _prompt: confirmation,
		print_fn=lambda _message: None, sleep_fn=lambda _seconds: None,
		read_sample=lambda _device, _offset, _size: sample,
	)
	return instance, executor, client


def test_plan_mode_never_executes(tmp_path):
	instance, executor, client = harness(tmp_path)
	result = instance.validate(DEVICE)
	assert result["mode"] == "read-only-plan"
	assert result["destructive_execution_started"] is False
	assert client.submitted == []
	assert all(call[0] not in {"mkfs.ext4", "mount", "dd"} for call in executor.calls)


def test_execute_flag_is_required_for_submission(tmp_path):
	instance, _executor, client = harness(tmp_path)
	instance.validate(DEVICE, execute=False)
	assert not client.submitted


@pytest.mark.parametrize("unsafe_profile, message", [
	(profile(is_system_device=True), "System-associated"),
	(profile(mounted=True, mounted_partitions=["/mnt/data"]), "Mounted"),
	(profile(device_type="SATA SSD", rotational=False), "rotational HDD"),
])
def test_unsafe_device_classes_are_rejected(tmp_path, unsafe_profile, message):
	instance, _executor, client = harness(tmp_path, profiles=[unsafe_profile])
	with pytest.raises(HardwareValidationError, match=message):
		instance.validate(DEVICE, execute=True)
	assert client.submitted == []


def test_unknown_identity_is_rejected(tmp_path):
	instance, _executor, _client = harness(tmp_path, profiles=[profile(serial_number=None, capabilities={})])
	with pytest.raises(HardwareValidationError, match="serial number or WWN"):
		instance.plan(DEVICE)


def test_identity_mismatch_is_rejected_before_product_job(tmp_path):
	instance, _executor, client = harness(tmp_path, profiles=[profile(), profile(serial_number="OTHER-123456")])
	with pytest.raises(HardwareValidationError, match="identity changed"):
		instance.validate(DEVICE, execute=True)
	assert client.submitted == []


def test_capacity_mismatch_is_rejected_before_product_job(tmp_path):
	instance, _executor, client = harness(tmp_path, profiles=[profile(), profile(size_bytes=2 * 1024 * 1024)])
	with pytest.raises(HardwareValidationError, match="identity changed"):
		instance.validate(DEVICE, execute=True)
	assert client.submitted == []


def test_confirmation_mismatch_is_rejected(tmp_path):
	instance, _executor, client = harness(tmp_path, profiles=[profile(), profile()], confirmation="yes")
	with pytest.raises(HardwareValidationError, match="confirmation did not match"):
		instance.validate(DEVICE, execute=True)
	assert client.submitted == []


def test_product_local_job_path_is_used_and_direct_dd_is_not(tmp_path):
	instance, executor, client = harness(tmp_path, profiles=[profile(), profile(), profile()])
	report = instance.validate(DEVICE, execute=True)
	assert client.submitted == [DEVICE]
	assert report["selected_pathway"] == "HDD_OVERWRITE"
	assert all(call[0] != "dd" for call in executor.calls)


def test_measured_progress_is_captured_with_event_timestamps(tmp_path):
	instance, _executor, _client = harness(tmp_path, profiles=[profile(), profile(), profile()])
	report = instance.validate(DEVICE, execute=True)
	measurements = report["progress_summary"]["measurements"]
	assert measurements == [
		{"timestamp": "2026-08-25T00:00:30Z", "bytes_completed": 524288, "bytes_total": 1048576},
		{"timestamp": "2026-08-25T00:01:00Z", "bytes_completed": 1048576, "bytes_total": 1048576},
	]


def test_verified_and_consistent_independent_checks_produce_pass(tmp_path):
	instance, _executor, _client = harness(tmp_path, profiles=[profile(), profile(), profile()])
	report = instance.validate(DEVICE, execute=True)
	assert report["conclusion"] == "PASS"
	assert "Known test data is no longer accessible" in report["conclusion_statement"]


def test_verified_with_nonzero_post_sample_is_inconclusive(tmp_path):
	instance, _executor, _client = harness(tmp_path, profiles=[profile(), profile(), profile()], sample=b"x" * 4096)
	report = instance.validate(DEVICE, execute=True)
	assert report["conclusion"] == "INCONCLUSIVE"


def test_verified_with_remaining_filesystem_signature_is_inconclusive(tmp_path):
	instance, _executor, _client = harness(
		tmp_path, profiles=[profile(), profile(), profile()], filesystem=True,
	)
	report = instance.validate(DEVICE, execute=True)
	assert report["conclusion"] == "INCONCLUSIVE"


def test_failed_vyper_result_produces_fail(tmp_path):
	job = verified_job()
	job.update({"job_state": "FAILED", "final_status": "FAILED", "verification": None, "evidence": None, "certificate": None})
	instance, _executor, _client = harness(tmp_path, profiles=[profile(), profile(), profile()], job=job)
	report = instance.validate(DEVICE, execute=True)
	assert report["conclusion"] == "FAIL"


def test_report_contains_integrity_hashes_and_no_secrets(tmp_path):
	instance, _executor, _client = harness(tmp_path, profiles=[profile(), profile(), profile()])
	report = instance.validate(DEVICE, execute=True)
	assert report["evidence_hash"] and report["certificate_hash"]
	json_path = next(tmp_path.glob("*-hdd-*.json"))
	text = json_path.read_text(encoding="utf-8").lower()
	assert "ata_password" not in text
	assert "super-secret" not in text


def test_prepare_plan_is_read_only(tmp_path):
	instance, executor, _client = harness(tmp_path)
	result = instance.prepare(DEVICE)
	assert result["operation"] == "prepare"
	assert all(call[0] not in {"mkfs.ext4", "mount"} for call in executor.calls)


def test_prepare_execute_creates_hashed_fixture_manifest_using_mocked_commands(tmp_path):
	instance, executor, _client = harness(
		tmp_path, profiles=[profile(), profile()], confirmation="PREPARE 123456",
	)
	manifest = instance.prepare(DEVICE, execute=True)
	assert manifest["unmounted"] is True
	assert {item["path"] for item in manifest["files"]} == {
		"vyper-validation/secret.txt", "vyper-validation/sample.bin", "vyper-validation/random.bin",
	}
	assert all(len(item["sha256"]) == 64 for item in manifest["files"])
	assert [call[0] for call in executor.calls if call[0] in {"mkfs.ext4", "mount", "sync", "umount"}] == [
		"mkfs.ext4", "mount", "sync", "umount",
	]
