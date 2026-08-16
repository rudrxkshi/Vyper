from __future__ import annotations

import pytest

from agent.common import (
    ErrorRecord,
    JobState,
    SanitizationResult,
    SanitizationStatus,
    WarningRecord,
)
from agent.command_runner import CommandExecutor, CommandResult, DryRunCommandExecutor, SubprocessCommandExecutor
from agent.evidence import EvidenceRecord
from agent.pathways.base import SanitizationPathway
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult


class DummyPathway(SanitizationPathway):
    def execute(self, target: str):
        return SanitizationResult(
            status=SanitizationStatus.RUNNING,
            target_device=target,
            dry_run=self.dry_run,
            message="dummy pathway",
        )


def test_job_states_include_required_values():
    assert JobState.PENDING == "PENDING"
    assert JobState.PROFILING == "PROFILING"
    assert JobState.POLICY_SELECTED == "POLICY_SELECTED"
    assert JobState.AWAITING_AUTHORIZATION == "AWAITING_AUTHORIZATION"
    assert JobState.RUNNING == "RUNNING"
    assert JobState.VERIFYING == "VERIFYING"
    assert JobState.VERIFIED == "VERIFIED"
    assert JobState.FAILED == "FAILED"
    assert JobState.UNSUPPORTED == "UNSUPPORTED"
    assert JobState.CANCELLED == "CANCELLED"


def test_sanitization_result_has_structured_status_and_issues():
    result = SanitizationResult(
        status=SanitizationStatus.VERIFIED,
        target_device="/dev/sdb",
        dry_run=False,
        message="sanitization completed",
        errors=[ErrorRecord(code="E001", message="sample error")],
        warnings=[WarningRecord(code="W001", message="sample warning")],
    )

    assert result.status == SanitizationStatus.VERIFIED
    assert result.target_device == "/dev/sdb"
    assert result.errors[0].code == "E001"
    assert result.warnings[0].code == "W001"


def test_dry_run_command_executor_does_not_execute_real_commands():
    executor = DryRunCommandExecutor()
    result = executor.run(["ls", "/tmp"], timeout=5)

    assert result.command == ["ls", "/tmp"]
    assert result.success is True
    assert result.dry_run is True
    assert result.exit_code == 0


def test_subprocess_command_executor_wraps_exit_status():
    executor = SubprocessCommandExecutor()
    result = executor.run(["python", "-c", "print('ok')"], timeout=5)

    assert result.success is True
    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_pathway_base_requires_execute_override_and_dry_run_flag():
    pathway = DummyPathway(dry_run=True)

    result = pathway.execute("/dev/sdc")

    assert pathway.dry_run is True
    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True
    assert result.target_device == "/dev/sdc"


def test_supporting_foundation_types_are_present():
    profile = DeviceProfile(device_path="/dev/nvme0n1", device_type="NVMe")
    decision = PolicyDecision(policy_name="crypto_erase", rationale="supported")
    verification = VerificationResult(status=SanitizationStatus.VERIFIED, details="verified")
    evidence = EvidenceRecord(
        job_id="job-1",
        device="/dev/nvme0n1",
        device_profile={"device_path": "/dev/nvme0n1", "device_type": "NVMe"},
        policy_decision={"selected_pathway": "CRYPTO_ERASE"},
        pathway={"selected": "CRYPTO_ERASE", "executed": "CRYPTO_ERASE"},
        execution={"status": "RUNNING"},
        verification={"status": "VERIFIED", "verified": True},
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_seconds=1.0,
        final_status="VERIFIED",
        warnings=[],
        errors=[],
        limitations=[],
        agent_version="vyper-test",
        integrity_algorithm="sha256",
        integrity_hash="abc",
    )

    assert profile.device_path == "/dev/nvme0n1"
    assert decision.policy_name == "crypto_erase"
    assert verification.status == SanitizationStatus.VERIFIED
    assert evidence.job_id == "job-1"


def test_command_executor_is_an_abstract_interface():
    with pytest.raises(TypeError):
        CommandExecutor()
