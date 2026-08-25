from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent.agent import VYPERAgent
from agent.common import JobState, SanitizationStatus
from agent.pathways.ata_erase import ATAErasePathway
from agent.pathways.hdd_overwrite import HDDOverwritePathway
from agent.pathways.nvme_sanitize import NVMeSanitizePathway
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult


@dataclass
class StubProfiler:
    profile_result: DeviceProfile | None = None
    error: Exception | None = None

    def profile(self, target: str) -> DeviceProfile:
        if self.error is not None:
            raise self.error
        assert self.profile_result is not None
        return self.profile_result


@dataclass
class StubPolicyEngine:
    decision: PolicyDecision | None = None
    error: Exception | None = None

    def decide(self, profile=None, **kwargs) -> PolicyDecision:
        if self.error is not None:
            raise self.error
        assert self.decision is not None
        return self.decision


@dataclass
class StubVerifier:
    result: VerificationResult
    calls: int = 0

    def verify(self, **kwargs):
        self.calls += 1
        return self.result


def _profile(device_type: str = "HDD", **kwargs) -> DeviceProfile:
    base = DeviceProfile(
        device_path="/dev/sdx",
        device_type=device_type,
        model="model",
        serial_number="serial",
        size_bytes=1024,
        interface="ATA" if device_type != "NVMe" else "NVMe",
        transport="SATA" if device_type != "NVMe" else "PCIe",
        is_system_device=False,
        capabilities={"sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True}, "crypto_erase_applicable": True},
    )
    for key, value in kwargs.items():
        setattr(base, key, value)
    return base


def _decision(pathway: str | None, device_type: str = "HDD", unsupported: bool = False) -> PolicyDecision:
    return PolicyDecision(
        selected_pathway=pathway,
        device_type=device_type,
        reason="policy reason",
        supported_methods=[pathway] if pathway else [],
        unsupported=unsupported,
        metadata={"capabilities": {"proof": True}},
    )


class DummyPathway:
    def __init__(self, result, call_log):
        self._result = result
        self._call_log = call_log

    def execute(self, target, **kwargs):
        self._call_log.append((target, kwargs))
        return self._result


def _execution_result(status: SanitizationStatus, method: str, dry_run: bool = False):
    from agent.common import SanitizationResult

    return SanitizationResult(
        status=status,
        target_device="/dev/sdx",
        dry_run=dry_run,
        message="execution",
        metadata={"method": method, "sanitize_method": method, "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T00:00:01Z", "duration_seconds": 1.0},
    )


def _verification(status: SanitizationStatus, verified: bool) -> VerificationResult:
    return VerificationResult(
        status=status,
        device="/dev/sdx",
        pathway="HDD_OVERWRITE",
        verified=verified,
        evidence={"source": "test", "status": status.value.lower()},
        warnings=[],
        errors=[],
        limitations=[],
    )


def test_successful_hdd_workflow():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.VERIFIED
    assert result.evidence is not None and result.evidence.final_status == "VERIFIED"
    assert result.certificate is not None and result.certificate.successful_sanitization_claim is True
    assert calls


def test_successful_nvme_crypto_workflow():
    calls = []
    profile = _profile("NVMe", device_path="/dev/nvme0n1")
    profiler = StubProfiler(profile_result=profile)
    policy = StubPolicyEngine(decision=_decision("CRYPTO_ERASE", "NVMe"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    scope = {
        "scope_proven": True, "execution_eligible": True,
        "requested_namespace": "/dev/nvme0n1", "resolved_controller": "/dev/nvme0",
        "sanitize_target": "/dev/nvme0", "sanitize_scope": "controller",
        "controller_namespaces": ["/dev/nvme0n1"], "execution_blockers": [],
        "controller_sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
    }
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier,
        nvme_scope_resolver=lambda _target: scope)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "NVME_SANITIZE"), calls)

    result = agent.sanitize_device("/dev/nvme0n1", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.VERIFIED
    assert calls[0][1]["selected_method"] == "CRYPTO_ERASE"
    assert calls[0][1]["profile"].capabilities == profile.capabilities
    assert calls[0][1]["controller_scope"] == scope
    assert result.evidence is not None and result.evidence.device == "/dev/nvme0n1"


def test_nvme_crypto_resolves_to_nvme_sanitize_pathway():
    agent = VYPERAgent(dry_run=True)

    pathway = agent._resolve_pathway("CRYPTO_ERASE", dry_run=True)

    assert isinstance(pathway, NVMeSanitizePathway)


def test_ata_erase_resolution_remains_separate():
    agent = VYPERAgent(dry_run=True)

    pathway = agent._resolve_pathway("ATA_ERASE", dry_run=True)

    assert isinstance(pathway, ATAErasePathway)


def test_hdd_overwrite_resolution_remains_unchanged():
    agent = VYPERAgent(dry_run=True)

    pathway = agent._resolve_pathway("HDD_OVERWRITE", dry_run=True)

    assert isinstance(pathway, HDDOverwritePathway)


def test_nvme_crypto_fallback_to_block():
    calls = []
    profiler = StubProfiler(profile_result=_profile("NVMe"))
    policy = StubPolicyEngine(decision=_decision("BLOCK_ERASE", "NVMe"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "NVME_SANITIZE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.VERIFIED
    assert calls[0][1]["selected_method"] == "BLOCK_ERASE"


def test_nvme_overwrite_selected_method_is_preserved():
    calls = []
    profile = _profile("NVMe")
    profiler = StubProfiler(profile_result=profile)
    policy = StubPolicyEngine(decision=_decision("NVME_OVERWRITE", "NVMe"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "NVME_SANITIZE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.VERIFIED
    assert calls[0][1]["selected_method"] == "NVME_OVERWRITE"


def test_sata_ssd_never_uses_hdd_overwrite():
    calls = []
    profiler = StubProfiler(profile_result=_profile("SATA SSD"))
    policy = StubPolicyEngine(decision=_decision("ATA_ERASE", "SATA SSD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    def _route(pathway_name, dry_run):
        assert pathway_name != "HDD_OVERWRITE"
        return DummyPathway(_execution_result(SanitizationStatus.RUNNING, "ATA_ERASE"), calls)

    agent._resolve_pathway = _route
    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True, "ata_password": "abc"}, dry_run=False)

    assert result.job_state == JobState.VERIFIED


def test_sata_crypto_erase_is_unsupported_without_pathway_execution(monkeypatch):
    route_calls = []

    def fail_subprocess(*args, **kwargs):
        raise AssertionError("No command may execute for unsupported SATA crypto erase")

    def fail_route(pathway_name, dry_run):
        route_calls.append((pathway_name, dry_run))
        raise AssertionError("SATA CRYPTO_ERASE must be rejected before pathway resolution")

    monkeypatch.setattr("subprocess.run", fail_subprocess)
    profiler = StubProfiler(profile_result=_profile("SATA SSD"))
    policy = StubPolicyEngine(decision=_decision("CRYPTO_ERASE", "SATA SSD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    scope = {
        "scope_proven": True, "execution_eligible": True,
        "requested_namespace": "/dev/nvme0n1", "resolved_controller": "/dev/nvme0",
        "sanitize_target": "/dev/nvme0", "sanitize_scope": "controller",
        "controller_namespaces": ["/dev/nvme0n1"], "execution_blockers": [],
        "controller_sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
    }
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier,
        nvme_scope_resolver=lambda _target: scope)
    agent._resolve_pathway = fail_route

    result = agent.sanitize_device(
        "/dev/sdx",
        authorization={"approved": True},
        dry_run=False,
    )

    assert route_calls == []
    assert verifier.calls == 0
    assert result.job_state == JobState.UNSUPPORTED
    assert result.execution is not None
    assert result.execution.status == SanitizationStatus.UNSUPPORTED
    assert result.execution.metadata["requested_method"] == "CRYPTO_ERASE"
    assert result.execution.metadata["method"] == "UNSUPPORTED"
    assert "no implemented" in result.execution.message.lower()
    assert "nvme sanitize will not be used" in result.execution.message.lower()
    assert "ata_erase will not be substituted" in result.execution.message.lower()
    assert result.evidence is not None
    assert result.evidence.final_status == "UNSUPPORTED"
    assert result.evidence.pathway["selected_pathway"] == "CRYPTO_ERASE"
    assert result.evidence.pathway["executed_pathway"] == "UNSUPPORTED"
    assert any("no implemented" in limitation.lower() for limitation in result.evidence.limitations)
    assert result.certificate is not None
    assert result.certificate.successful_sanitization_claim is False


def test_unsupported_device():
    profiler = StubProfiler(profile_result=_profile("UNKNOWN"))
    policy = StubPolicyEngine(decision=_decision(None, "UNKNOWN", unsupported=True))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/nvme0n1", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.UNSUPPORTED
    assert result.execution is not None and result.execution.status == SanitizationStatus.UNSUPPORTED


def test_profiling_failure():
    profiler = StubProfiler(error=RuntimeError("probe failed"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.FAILED
    assert result.execution is not None and result.execution.status == SanitizationStatus.FAILED


def test_policy_failure():
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(error=RuntimeError("policy exploded"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.FAILED


def test_authorization_missing():
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": False}, dry_run=False)

    assert result.job_state == JobState.AWAITING_AUTHORIZATION
    assert result.execution is not None and result.execution.status == SanitizationStatus.AWAITING_AUTHORIZATION


def test_dry_run_never_destructive():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE", dry_run=True), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": False}, dry_run=True)

    assert result.execution is not None and result.execution.dry_run is True
    assert calls and calls[0][1]["authorized"] is True


def test_agent_default_dry_run_is_inherited_when_not_overridden():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(dry_run=True, profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE", dry_run=dry_run), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": False})

    assert result.execution is not None and result.execution.dry_run is True
    assert calls and calls[0][1]["authorized"] is True


def test_system_associated_device_rejected():
    profile = _profile("HDD")
    profile.is_system_device = True
    profiler = StubProfiler(profile_result=profile)
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.FAILED
    assert "system" in (result.execution.message.lower() if result.execution else "")


def test_execution_failure():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.FAILED, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.FAILED
    assert result.evidence is not None and result.evidence.final_status == "FAILED"


def test_verification_failure():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.FAILED, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.FAILED
    assert result.evidence is not None and result.evidence.final_status == "FAILED"


def test_verification_inconclusive():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.evidence is not None and result.evidence.final_status == "INCONCLUSIVE"


def test_certificate_generated_from_evidence():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.evidence is not None and result.certificate is not None
    assert result.certificate.job_id == result.evidence.job_id


def test_failed_workflow_never_produces_successful_certificate():
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.FAILED, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), [])

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.certificate is not None
    assert result.certificate.successful_sanitization_claim is False


def test_unknown_pathway_rejected():
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("UNKNOWN_PATHWAY", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.job_state == JobState.UNSUPPORTED


def test_no_destructive_command_during_tests(monkeypatch):
    def fail_open(*args, **kwargs):
        raise AssertionError("open() should not be called")

    def fail_subprocess(*args, **kwargs):
        raise AssertionError("subprocess.run should not be called")

    monkeypatch.setattr("builtins.open", fail_open)
    monkeypatch.setattr("subprocess.run", fail_subprocess)

    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), [])

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)
    assert result.job_state == JobState.VERIFIED


def test_no_password_secret_leakage():
    calls = []
    profiler = StubProfiler(profile_result=_profile("ATA"))
    policy = StubPolicyEngine(decision=_decision("ATA_ERASE", "ATA"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "ATA_ERASE"), calls)

    result = agent.sanitize_device(
        "/dev/sdx",
        authorization={"approved": True, "ata_password": "very-secret", "token": "abc"},
        dry_run=False,
    )

    evidence_json = result.evidence.to_json() if result.evidence else ""
    cert_json = result.certificate.to_json() if result.certificate else ""
    assert "very-secret" not in evidence_json
    assert "very-secret" not in cert_json


def test_lifecycle_states():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.VERIFIED, True))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(_execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE"), calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.state_history[0] == JobState.PENDING
    assert JobState.PROFILING in result.state_history
    assert JobState.POLICY_SELECTED in result.state_history
    assert JobState.RUNNING in result.state_history
    assert JobState.VERIFYING in result.state_history
    assert result.state_history[-1] == JobState.VERIFIED


def test_evidence_generated_from_actual_workflow_results():
    calls = []
    profiler = StubProfiler(profile_result=_profile("HDD"))
    policy = StubPolicyEngine(decision=_decision("HDD_OVERWRITE", "HDD"))
    verifier = StubVerifier(result=_verification(SanitizationStatus.INCONCLUSIVE, False))
    agent = VYPERAgent(profiler=profiler, policy_engine=policy, verifier=verifier)
    execution = _execution_result(SanitizationStatus.RUNNING, "HDD_OVERWRITE")
    agent._resolve_pathway = lambda pathway_name, dry_run: DummyPathway(execution, calls)

    result = agent.sanitize_device("/dev/sdx", authorization={"approved": True}, dry_run=False)

    assert result.evidence is not None
    assert result.evidence.execution["status"] == "RUNNING"
    assert result.evidence.verification["status"] == "INCONCLUSIVE"
