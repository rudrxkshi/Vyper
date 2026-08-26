from __future__ import annotations

import json
from dataclasses import replace

import pytest
from fastapi.encoders import jsonable_encoder

from agent.certificate import CertificateBuilder
from agent.command_runner import CommandResult
from agent.common import SanitizationResult, SanitizationStatus
from agent.evidence import EvidenceCollector
from agent.nvme_status import parse_sanitize_log
from agent.pathways.nvme_sanitize import NVMeSanitizePathway, sanact_for_method
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult
from local_agent.cli import build_parser
from local_agent.hardware_validation import HardwareValidationError, HardwareValidationHarness


DEVICE = "/dev/nvme9n1"
CONTROLLER = "/dev/nvme9"
COMPLETED = '{"sstat": 1}'
IN_PROGRESS = '{"sstat": 2}'
FAILED = '{"sstat": 3}'
ABORTED = '{"sstat": "3 (sanitize aborted by reset)"}'


def nvme_profile(method="CRYPTO_ERASE", **changes):
	bits = {"CRYPTO_ERASE": (True, True, True), "BLOCK_ERASE": (False, True, True), "NVME_OVERWRITE": (False, False, True)}[method]
	capabilities = {
		"type": "NVMe", "nvme_cli_available": True, "nvme_nguid": "00112233445566778899aabbccddeeff",
		"nvme_eui64": "0011223344556677", "crypto_erase_applicable": method == "CRYPTO_ERASE",
		"sanicap": {"raw": hex((1 if bits[0] else 0) | (2 if bits[1] else 0) | (4 if bits[2] else 0)),
			"crypto_erase": bits[0], "block_erase": bits[1], "overwrite": bits[2]},
	}
	base = DeviceProfile(device_path=DEVICE, device_type="NVMe", serial_number="NVME-SERIAL-123456",
		model="Disposable NVMe", size_bytes=8 * 1024 * 1024, rotational=False, interface="NVMe",
		transport="pcie", is_system_device=False, mounted=False, capabilities=capabilities)
	return replace(base, **changes)


def proven_scope(**changes):
	base = {
		"requested_namespace": DEVICE, "resolved_controller": CONTROLLER, "controller_path": CONTROLLER,
		"sanitize_target": CONTROLLER, "sanitize_scope": "controller", "controller_namespaces": [DEVICE],
		"namespace_id": 1, "namespace_identify": {"nguid": "00112233445566778899aabbccddeeff",
			"eui64": "0011223344556677", "uuid": "11111111-2222-3333-4444-555555555555"},
		"controller_identify": {"mn": "Disposable NVMe", "sn": "NVME-SERIAL-123456", "fr": "1.0", "sanicap": 7, "nodmmas": 0},
		"controller_reachable": True, "topology_known": True, "active_holders": [],
		"pci_controller_identity": "/sys/devices/pci0000:00/0000:00:01.0/nvme/nvme9",
		"scope_proven": True, "execution_eligible": True, "execution_blockers": [], "scope_limitation": None,
		"controller_sanicap": {"raw": 7, "crypto_erase": True, "block_erase": True, "overwrite": True},
	}
	return {**base, **changes}


class SequenceProfiler:
	def __init__(self, *values): self.values = list(values)
	def profile(self, _device):
		if len(self.values) > 1: return self.values.pop(0)
		return self.values[0]


class SequenceScope:
	def __init__(self, *values): self.values = list(values)
	def __call__(self, _device):
		if len(self.values) > 1: return self.values.pop(0)
		return dict(self.values[0])


class NVMeExecutor:
	def __init__(self, *, status=COMPLETED, filesystem=False, fail=None):
		self.status, self.filesystem, self.fail, self.calls = status, filesystem, fail, []
	def run(self, command, timeout=None, cwd=None):
		self.calls.append(list(command))
		if command[0] == self.fail: return self.result(command, False, 1, stderr="fixture failure")
		if command[:2] == ["nvme", "sanitize-log"]: return self.result(command, stdout=self.status)
		if command[:2] == ["nvme", "id-ctrl"]: return self.result(command, stdout=json.dumps(proven_scope()["controller_identify"]))
		if command[:2] == ["nvme", "id-ns"]: return self.result(command, stdout=json.dumps(proven_scope()["namespace_identify"]))
		if command[0] == "lsblk":
			return self.result(command, stdout=json.dumps({"blockdevices": [{"name": "nvme9n1", "path": DEVICE,
				"type": "disk", "fstype": "ext4" if self.filesystem else None, "uuid": "old-uuid" if self.filesystem else None,
				"size": 8 * 1024 * 1024, "mountpoints": []}]}))
		if command[0] == "blkid" and "UUID" in command: return self.result(command, stdout="prepared-uuid\n")
		if command[0] == "blkid": return self.result(command, self.filesystem, 0 if self.filesystem else 2,
			stdout=f"{DEVICE}: UUID=old-uuid TYPE=ext4" if self.filesystem else "")
		if command[0] == "file": return self.result(command, stdout=f"{DEVICE}: ext4 filesystem" if self.filesystem else f"{DEVICE}: data")
		if command[0] == "udevadm": return self.result(command, stdout="ID_BUS=nvme\nID_SERIAL_SHORT=NVME-SERIAL-123456\n")
		return self.result(command)
	def result(self, command, success=True, exit_code=0, stdout="", stderr=""):
		return CommandResult(command=command, success=success, exit_code=exit_code, stdout=stdout, stderr=stderr)


class FakeClient:
	def __init__(self, job): self.job, self.submitted = job, []
	def submit_nvme_job(self, device): self.submitted.append(device); return {"local_job_id": self.job["local_job_id"]}
	def get_job(self, local_job_id): assert local_job_id == self.job["local_job_id"]; return self.job


def nvme_job(method="CRYPTO_ERASE"):
	profile = nvme_profile(method)
	policy = PolicyDecision(selected_pathway=method, device_type="NVMe", reason="fixture", unsupported=False)
	canonical = "OVERWRITE" if method == "NVME_OVERWRITE" else method
	execution = SanitizationResult(status=SanitizationStatus.RUNNING, target_device=DEVICE, dry_run=False,
		message="Controller completed.", metadata={"method": "NVME_SANITIZE", "sanitize_method": canonical,
			"sanact": sanact_for_method(canonical), "sanitize_target": CONTROLLER,
			"requested_namespace": DEVICE, "resolved_controller": CONTROLLER, "sanitize_scope": "controller",
			"controller_namespaces": [DEVICE], "command_submitted": True,
			"completion_status": "COMPLETED", "duration_seconds": 10.0})
	verification = VerificationResult(status=SanitizationStatus.VERIFIED, device=DEVICE, pathway=method,
		verified=True, message="completed", evidence={"source": "nvme_sanitize_log", "status": "completed",
			"sstat": 1, "status_code": 1, "global_data_erased": False})
	evidence = EvidenceCollector(dry_run=False, agent_version="vyper-test").create_record(device_profile=profile,
		policy_decision=policy, execution_result=execution, verification_result=verification,
		started_at="2026-08-25T00:00:00Z", completed_at="2026-08-25T00:00:10Z")
	certificate = CertificateBuilder().build(evidence)
	return {"local_job_id": "nvme-fixture-job", "job_state": "VERIFIED", "final_status": "VERIFIED",
		"policy": jsonable_encoder(policy), "execution": jsonable_encoder(execution),
		"verification": jsonable_encoder(verification), "evidence": jsonable_encoder(evidence),
		"certificate": jsonable_encoder(certificate), "state_history": []}


def make_harness(tmp_path, *, method="CRYPTO_ERASE", profiles=None, scopes=None, job=None, status=COMPLETED,
	filesystem=False, confirmation="ERASE ddeeff", fail=None, output=None):
	executor = NVMeExecutor(status=status, filesystem=filesystem, fail=fail)
	client = FakeClient(job or nvme_job(method))
	harness = HardwareValidationHarness(profiler=SequenceProfiler(*(profiles or [nvme_profile(method)])),
		command_executor=executor, local_client=client, nvme_scope_resolver=SequenceScope(*(scopes or [proven_scope()])),
		output_directory=tmp_path, input_fn=lambda _prompt: confirmation, print_fn=(output or []).append,
		sleep_fn=lambda _seconds: None, read_sample=lambda *_args: (_ for _ in ()).throw(AssertionError("NVMe validation must not require zero reads")))
	return harness, executor, client


def test_cli_exposes_nvme_plan_and_prepare():
	assert build_parser().parse_args(["validate-hardware", "nvme", "--device", DEVICE]).execute is False
	assert build_parser().parse_args(["validate-hardware", "nvme", "prepare", "--device", DEVICE, "--execute"]).operation == "prepare"


def test_plan_mode_never_executes_and_execute_flag_is_required(tmp_path):
	harness, executor, client = make_harness(tmp_path)
	plan = harness.validate_nvme(DEVICE)
	assert plan["mode"] == "read-only-plan" and client.submitted == []
	assert all(call[:2] != ["nvme", "sanitize"] for call in executor.calls)


@pytest.mark.parametrize("device", ["", "/dev/nvme9", "/dev/nvme9n1p1", "/dev/nvme*n1"])
def test_only_one_explicit_namespace_is_accepted(tmp_path, device):
	harness, _executor, _client = make_harness(tmp_path)
	with pytest.raises(HardwareValidationError, match="explicit whole NVMe namespace"):
		harness.validate_nvme(device)


@pytest.mark.parametrize("unsafe", [nvme_profile(device_type="HDD"), nvme_profile(device_type="SATA SSD")])
def test_hdd_and_sata_are_rejected(tmp_path, unsafe):
	harness, _executor, client = make_harness(tmp_path, profiles=[unsafe])
	with pytest.raises(HardwareValidationError, match="positively identified NVMe"):
		harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


@pytest.mark.parametrize("unsafe, message", [(nvme_profile(is_system_device=True), "System-associated"),
	(nvme_profile(mounted=True), "Mounted")])
def test_system_and_mounted_nvme_are_rejected(tmp_path, unsafe, message):
	harness, _executor, _client = make_harness(tmp_path, profiles=[unsafe])
	with pytest.raises(HardwareValidationError, match=message): harness.validate_nvme(DEVICE, execute=True)


def test_active_holders_are_rejected(tmp_path):
	scope = proven_scope(active_holders=[{"type": "lvm", "name": "vg-data"}])
	harness, _executor, client = make_harness(tmp_path, scopes=[scope])
	with pytest.raises(HardwareValidationError, match="active holders"):
		harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


def test_typed_confirmation_mismatch_is_rejected(tmp_path):
	harness, _executor, client = make_harness(tmp_path, confirmation="yes")
	with pytest.raises(HardwareValidationError, match="confirmation did not match"):
		harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


@pytest.mark.parametrize("scope_change", [
	proven_scope(namespace_identify={**proven_scope()["namespace_identify"], "nguid": "ffffffffffffffffffffffffffffffff"}),
	proven_scope(namespace_identify={**proven_scope()["namespace_identify"], "eui64": "ffffffffffffffff"}),
])
def test_nguid_or_eui_change_is_rejected(tmp_path, scope_change):
	harness, _executor, client = make_harness(tmp_path, scopes=[proven_scope(), scope_change])
	with pytest.raises(HardwareValidationError, match="identity or capacity changed"): harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


def test_serial_model_capacity_fallback_change_is_rejected(tmp_path):
	base = nvme_profile(); base.capabilities.pop("nvme_nguid"); base.capabilities.pop("nvme_eui64")
	scope = proven_scope(namespace_identify={})
	changed = replace(base, size_bytes=base.size_bytes + 4096)
	harness, _executor, _client = make_harness(tmp_path, profiles=[base, changed], scopes=[scope, scope])
	with pytest.raises(HardwareValidationError, match="identity or capacity changed"): harness.validate_nvme(DEVICE, execute=True)


def test_controller_identity_change_is_rejected(tmp_path):
	changed = proven_scope(controller_identify={**proven_scope()["controller_identify"], "sn": "OTHER-CONTROLLER"})
	harness, _executor, client = make_harness(tmp_path, scopes=[proven_scope(), changed])
	with pytest.raises(HardwareValidationError, match="identity or capacity changed"):
		harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


def test_unknown_sanicap_and_unsupported_selected_method_are_blocked(tmp_path):
	unknown = nvme_profile(); unknown.capabilities["sanicap"] = {"raw": None, "crypto_erase": False, "block_erase": False, "overwrite": False}
	unknown_scope = proven_scope(controller_identify={**proven_scope()["controller_identify"], "sanicap": None})
	harness, _executor, _client = make_harness(tmp_path, profiles=[unknown], scopes=[unknown_scope])
	plan = harness.validate_nvme(DEVICE)
	assert any("SANICAP" in blocker for blocker in plan["execution_blockers"])
	unsupported_scope = proven_scope(controller_sanicap={"raw": 6, "crypto_erase": False, "block_erase": True, "overwrite": True})
	harness, _executor, _client = make_harness(tmp_path, scopes=[unsupported_scope])
	assert any("not supported" in blocker for blocker in harness.validate_nvme(DEVICE)["execution_blockers"])


@pytest.mark.parametrize("method, expected", [("CRYPTO_ERASE", "4"), ("BLOCK_ERASE", "2"), ("NVME_OVERWRITE", "3")])
def test_method_to_sanact_mapping_has_not_drifted(method, expected):
	canonical = "OVERWRITE" if method == "NVME_OVERWRITE" else method
	assert sanact_for_method(canonical) == expected
	assert NVMeSanitizePathway(dry_run=True)._build_command(canonical, CONTROLLER) == ["nvme", "sanitize", CONTROLLER, "-a", expected]


def test_no_silent_fallback_when_policy_method_is_unsupported(tmp_path):
	unsupported_scope = proven_scope(controller_sanicap={"raw": 6, "crypto_erase": False, "block_erase": True, "overwrite": True})
	harness, _executor, client = make_harness(tmp_path, scopes=[unsupported_scope])
	with pytest.raises(HardwareValidationError, match="not supported"): harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


def test_product_api_used_and_harness_never_executes_nvme_sanitize(tmp_path):
	harness, executor, client = make_harness(tmp_path, profiles=[nvme_profile()] * 4)
	report = harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == [DEVICE] and report["conclusion"] == "PASS"
	assert all(call[:2] != ["nvme", "sanitize"] for call in executor.calls)


@pytest.mark.parametrize("status, expected", [(COMPLETED, "PASS"), (IN_PROGRESS, "INCONCLUSIVE"),
	('{"sstat": 0}', "INCONCLUSIVE"), ("not-json", "INCONCLUSIVE"), ('{"other": 1}', "INCONCLUSIVE")])
def test_structured_controller_status_controls_pass(status, expected, tmp_path):
	harness, _executor, _client = make_harness(tmp_path, profiles=[nvme_profile()] * 4, status=status)
	assert harness.validate_nvme(DEVICE, execute=True)["conclusion"] == expected


@pytest.mark.parametrize("status", [FAILED, ABORTED])
def test_failed_or_aborted_sstat_is_fail(status, tmp_path):
	harness, _executor, _client = make_harness(tmp_path, profiles=[nvme_profile()] * 4, status=status)
	assert harness.validate_nvme(DEVICE, execute=True)["conclusion"] == "FAIL"


def test_global_data_erased_bit_alone_cannot_pass():
	parsed = parse_sanitize_log('{"sstat": 256}')
	assert parsed and parsed["global_data_erased"] is True and parsed["status"] == "INVALID"


@pytest.mark.parametrize("field", ["evidence", "certificate"])
def test_integrity_hash_mismatch_prevents_pass(field, tmp_path):
	job = nvme_job()
	key = "integrity_hash" if field == "evidence" else "certificate_hash"
	job[field][key] = "0" * 64
	harness, _executor, _client = make_harness(tmp_path, profiles=[nvme_profile()] * 4, job=job)
	assert harness.validate_nvme(DEVICE, execute=True)["conclusion"] == "INCONCLUSIVE"


def test_namespace_controller_scope_ambiguity_blocks_execution(tmp_path):
	ambiguous = proven_scope(scope_proven=False, scope_limitation="namespace/controller scope ambiguous")
	harness, _executor, client = make_harness(tmp_path, scopes=[ambiguous])
	plan = harness.validate_nvme(DEVICE)
	assert any("ambiguous" in blocker for blocker in plan["execution_blockers"])
	harness, _executor, client = make_harness(tmp_path, scopes=[ambiguous])
	with pytest.raises(HardwareValidationError, match="ambiguous"): harness.validate_nvme(DEVICE, execute=True)
	assert client.submitted == []


def test_multiple_controller_namespaces_block_execution(tmp_path):
	multi = proven_scope(scope_proven=False, execution_eligible=False,
		controller_namespaces=[DEVICE, "/dev/nvme9n2"], sanitize_target=None,
		execution_blockers=["NVMe Sanitize operates at controller scope. This controller exposes multiple namespaces; destructive execution is blocked until controller-wide impact is explicitly supported."])
	harness, _executor, client = make_harness(tmp_path, scopes=[multi])
	plan = harness.validate_nvme(DEVICE)
	assert plan["sanitize_target"] is None
	assert any("multiple namespaces" in item for item in plan["execution_blockers"])
	assert client.submitted == []


@pytest.mark.parametrize("method", ["CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"])
def test_method_reports_controller_evidence_and_secondary_logical_checks(method, tmp_path):
	profiles = [nvme_profile(method)] * 4
	harness, _executor, _client = make_harness(tmp_path, method=method, profiles=profiles)
	report = harness.validate_nvme(DEVICE, execute=True)
	assert report["conclusion"] == "PASS"
	assert report["independent_post_checks"]["logical_post_checks_are_secondary"] is True
	assert report["actual_sanact"] == {"CRYPTO_ERASE": "4", "BLOCK_ERASE": "2", "NVME_OVERWRITE": "3"}[method]


def test_report_contains_no_secret_markers_and_progress_is_indeterminate(tmp_path):
	harness, _executor, _client = make_harness(tmp_path, profiles=[nvme_profile()] * 4)
	report = harness.validate_nvme(DEVICE, execute=True)
	assert report["progress_summary"]["mode"] == "indeterminate" and report["progress_summary"]["percentage_claimed"] is False
	assert "password" not in json.dumps(report).lower() and "token" not in json.dumps(report).lower()


def test_prepare_is_plan_only_by_default_and_mock_execute_uses_prepare_confirmation(tmp_path):
	harness, executor, client = make_harness(tmp_path)
	plan = harness.prepare_nvme(DEVICE)
	assert plan["operation"] == "prepare" and plan["confirmation_required"] == "PREPARE ddeeff"
	assert all(call[0] not in {"mkfs.ext4", "mount"} for call in executor.calls)
	assert client.submitted == []

	harness, executor, client = make_harness(
		tmp_path, profiles=[nvme_profile()] * 3, scopes=[proven_scope()] * 3,
		confirmation="PREPARE ddeeff",
	)
	manifest = harness.prepare_nvme(DEVICE, execute=True)
	assert manifest["kind"] == "physical_nvme_test_data" and manifest["unmounted"] is True
	assert [call[0] for call in executor.calls].count("mkfs.ext4") == 1
	assert [call[0] for call in executor.calls].count("mount") == 1
	assert [call[0] for call in executor.calls].count("umount") == 1
	assert client.submitted == []
