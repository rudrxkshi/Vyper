from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from agent.command_runner import CommandResult
from agent.common import SanitizationStatus
from agent.evidence import EvidenceCollector
from agent.pathways.nvme_sanitize import NVMeSanitizePathway
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult


class RecordingExecutor:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def run(self, command, timeout=None, cwd=None):
        self.calls.append({"command": list(command), "timeout": timeout, "cwd": cwd})
        if not self.responses:
            return CommandResult(command=list(command), success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully"), stderr="", dry_run=False, metadata={})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _nvme_profile(**kwargs):
    defaults = {
        "device_path": "/dev/nvme0n1",
        "device_type": "NVMe",
        "capabilities": {
            "sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
            "crypto_erase_applicable": True,
            "controller_scope": {
                "scope_proven": True,
                "execution_eligible": True,
                "requested_namespace": "/dev/nvme0n1",
                "resolved_controller": "/dev/nvme0",
                "sanitize_target": "/dev/nvme0",
                "sanitize_scope": "controller",
                "controller_namespaces": ["/dev/nvme0n1"],
                "controller_sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
                "execution_blockers": [],
            },
        },
    }
    if "capabilities" in kwargs:
        supplied = kwargs["capabilities"]
        sanicap = supplied.get("sanicap") or {}
        supplied["controller_scope"] = {
            **defaults["capabilities"]["controller_scope"],
            "controller_sanicap": {
                "crypto_erase": sanicap.get("crypto_erase") is True,
                "block_erase": sanicap.get("block_erase") is True,
                "overwrite": sanicap.get("overwrite") is True,
            },
        }
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


def _sanitize_log_json(status: int, description: str = "") -> str:
    return json.dumps({"nvme0n1": {"sstat": {"status": f"({status}) {description}"}}})


def _sanitize_log_json_with_flags(status: int, *, global_data_erased: bool = False, description: str = "") -> str:
    sstat_value = status | (0x100 if global_data_erased else 0)
    return json.dumps({"nvme0n1": {"sstat": {"status": f"({sstat_value}) {description}"}}})


def test_hdd_rejected():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(device_type="HDD", device_path="/dev/sda")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_sata_ssd_rejected():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(device_type="SATA SSD", device_path="/dev/sdb")

    result = pathway.execute("/dev/sdb", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_unknown_device_rejected():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(device_type="UNKNOWN", device_path="/dev/ram0")

    result = pathway.execute("/dev/ram0", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_nvme_accepted():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True


def test_crypto_sanitize_selection():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.metadata["sanitize_method"] == "CRYPTO_ERASE"


def test_block_sanitize_selection():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(capabilities={"sanicap": {"crypto_erase": False, "block_erase": True, "overwrite": False}})

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.metadata["sanitize_method"] == "BLOCK_ERASE"


def test_no_supported_method_returns_unsupported():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(capabilities={"sanicap": {"crypto_erase": False, "block_erase": False, "overwrite": False}})

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_missing_capability_information_is_unsupported():
    pathway = NVMeSanitizePathway(dry_run=True)
    profile = _nvme_profile(capabilities={})

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_authorization_required():
    pathway = NVMeSanitizePathway(dry_run=False)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=False)

    assert result.status == SanitizationStatus.FAILED
    assert "authorization" in result.message.lower()


def test_dry_run_does_not_execute_destructive_commands():
    executor = RecordingExecutor()
    pathway = NVMeSanitizePathway(dry_run=True, command_executor=executor)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert executor.calls == []


@pytest.mark.parametrize(
    ("selected_method", "expected_method", "expected_action"),
    [
        ("CRYPTO_ERASE", "CRYPTO_ERASE", "4"),
        ("BLOCK_ERASE", "BLOCK_ERASE", "2"),
        ("NVME_OVERWRITE", "OVERWRITE", "3"),
    ],
)
def test_selected_method_builds_the_exact_sanitize_argv(selected_method, expected_method, expected_action):
    executor = RecordingExecutor([
        CommandResult(command=[], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=[], success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)

    result = pathway.execute(
        "/dev/nvme0n1",
        profile=_nvme_profile(),
        authorized=True,
        selected_method=selected_method,
    )

    assert result.status == SanitizationStatus.RUNNING
    assert result.metadata["sanitize_method"] == expected_method
    assert executor.calls[0]["command"] == ["nvme", "sanitize", "/dev/nvme0", "-a", expected_action]


def test_controller_scope_metadata_preserves_requested_namespace():
    pathway = NVMeSanitizePathway(dry_run=True)
    result = pathway.execute("/dev/nvme0n1", profile=_nvme_profile(), authorized=True, selected_method="CRYPTO_ERASE")
    assert result.target_device == "/dev/nvme0n1"
    assert result.metadata == {
        **result.metadata,
        "requested_namespace": "/dev/nvme0n1",
        "resolved_controller": "/dev/nvme0",
        "sanitize_target": "/dev/nvme0",
        "sanitize_scope": "controller",
        "controller_namespaces": ["/dev/nvme0n1"],
        "selected_method": "CRYPTO_ERASE",
        "effective_sanact": "4",
    }
    verification = VerificationResult(status=SanitizationStatus.INCONCLUSIVE, device="/dev/nvme0n1",
        pathway="CRYPTO_ERASE", verified=False)
    evidence = EvidenceCollector().create_record(device_profile=_nvme_profile(),
        policy_decision=PolicyDecision(selected_pathway="CRYPTO_ERASE", device_type="NVMe"),
        execution_result=result, verification_result=verification)
    assert evidence.device == "/dev/nvme0n1"
    assert evidence.execution["metadata"]["resolved_controller"] == "/dev/nvme0"
    assert evidence.execution["metadata"]["sanitize_target"] == "/dev/nvme0"


def test_unproven_or_multi_namespace_scope_never_executes():
    executor = RecordingExecutor()
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor)
    scope = {**_nvme_profile().capabilities["controller_scope"],
        "controller_namespaces": ["/dev/nvme0n1", "/dev/nvme0n2"]}
    result = pathway.execute("/dev/nvme0n1", profile=_nvme_profile(), authorized=True,
        selected_method="CRYPTO_ERASE", controller_scope=scope)
    assert result.status == SanitizationStatus.UNSUPPORTED and executor.calls == []


def test_unknown_selected_method_is_rejected_without_a_command():
    executor = RecordingExecutor()
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor)

    result = pathway.execute(
        "/dev/nvme0n1",
        profile=_nvme_profile(),
        authorized=True,
        selected_method="UNRECOGNIZED_METHOD",
    )

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert executor.calls == []


def test_unknown_method_cannot_build_a_sanitize_command():
    pathway = NVMeSanitizePathway()

    assert pathway._build_command("UNRECOGNIZED_METHOD", "/dev/nvme0n1") is None


def test_sanitize_command_failure():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=False, exit_code=1, stdout="", stderr="sanitize failed", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "sanitize" in result.message.lower()


def test_sanitize_in_progress_polling():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize started", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json(2, "In Progress"), stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.metadata["completion_status"] == "COMPLETED"


def test_sanitize_completion_status():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.metadata["completion_status"] == "COMPLETED"
    assert result.metadata["command_submitted"] is True


def test_sanitize_failure_from_status_log():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json(3, "Failed"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert result.metadata["completion_status"] == "FAILED"


def test_sanitize_timeout():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json(2, "In Progress"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=0.01)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "timeout" in result.message.lower()


def test_nvme_cli_unavailable():
    class MissingExecutor:
        def run(self, command, timeout=None, cwd=None):
            raise FileNotFoundError("nvme not installed")

    pathway = NVMeSanitizePathway(dry_run=False, command_executor=MissingExecutor())
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "nvme" in result.message.lower() or "unavailable" in result.message.lower()


def test_malformed_sanitize_log_output():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout="??garbage??", stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "invalid" in result.message.lower() or "malformed" in result.message.lower()


def test_destructive_command_goes_through_command_executor():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json_with_flags(1, global_data_erased=True, description="Completed Successfully"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    with patch("builtins.open", side_effect=AssertionError("generic host write attempted")):
        result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert executor.calls and executor.calls[0]["command"][:3] == ["nvme", "sanitize", "/dev/nvme0"]


def test_no_generic_host_overwrite_is_executed():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"], success=True, exit_code=0, stdout=_sanitize_log_json_with_flags(1, global_data_erased=True, description="Completed Successfully"), stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    with patch("builtins.open", side_effect=AssertionError("open() should never be used")):
        result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert "open()" not in str(result.message)


def test_crypto_is_preferred_when_supported_and_applicable():
    executor = RecordingExecutor([
        CommandResult(command=["nvme", "sanitize", "/dev/nvme0n1", "-a", "4"], success=True, exit_code=0, stdout="sanitize submitted", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["nvme", "sanitize-log", "/dev/nvme0n1"], success=True, exit_code=0, stdout="status: completed", stderr="", dry_run=False, metadata={}),
    ])
    pathway = NVMeSanitizePathway(dry_run=False, command_executor=executor, timeout=5)
    profile = _nvme_profile()

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.metadata["sanitize_method"] == "CRYPTO_ERASE"
