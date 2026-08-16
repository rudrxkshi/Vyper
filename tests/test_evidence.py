from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

import pytest

from agent.common import SanitizationStatus
from agent.evidence import EvidenceCollector, EvidenceRecord, verify_integrity
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult


@dataclass(slots=True)
class DummyExecutionResult:
    status: SanitizationStatus
    target_device: str
    dry_run: bool = False
    message: str = ""
    warnings: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


def _profile(**overrides):
    base = DeviceProfile(
        device_path="/dev/nvme0n1",
        device_type="NVMe",
        model="Sample Model",
        serial_number="ABC123",
        size_bytes=1024,
        interface="NVMe",
        transport="PCIe",
        capabilities={"sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True}},
    )
    data = asdict(base)
    data.update(overrides)
    return DeviceProfile(**data)


def _policy(**overrides):
    base = PolicyDecision(
        selected_pathway="CRYPTO_ERASE",
        device_type="NVMe",
        reason="NVMe crypto erase is supported and applicable.",
        supported_methods=["CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"],
        unsupported=False,
        metadata={"capabilities": {"sanicap": {"crypto_erase": True}}},
    )
    data = asdict(base)
    data.update(overrides)
    return PolicyDecision(**data)


def _execution(**overrides):
    base = DummyExecutionResult(
        status=SanitizationStatus.RUNNING,
        target_device="/dev/nvme0n1",
        message="sanitize submitted",
        metadata={
            "method": "CRYPTO_ERASE",
            "sanitize_method": "CRYPTO_ERASE",
            "duration_seconds": 2.0,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:00:02Z",
            "planned_commands": [["nvme", "sanitize", "/dev/nvme0n1", "-a", "0"]],
        },
    )
    data = asdict(base)
    data.update(overrides)
    return DummyExecutionResult(**data)


def _verification(**overrides):
    base = VerificationResult(
        status=SanitizationStatus.VERIFIED,
        device="/dev/nvme0n1",
        pathway="CRYPTO_ERASE",
        verified=True,
        evidence={"source": "nvme_sanitize_log", "status": "completed"},
        warnings=[],
        errors=[],
        limitations=["Controller-reported completion evidence only."],
    )
    data = asdict(base)
    data.update(overrides)
    return VerificationResult(**data)


def _build_record(**overrides):
    collector = EvidenceCollector(agent_version="vyper-test")
    profile = overrides.pop("profile", _profile())
    policy = overrides.pop("policy", _policy())
    execution = overrides.pop("execution", _execution())
    verification = overrides.pop("verification", _verification())
    return collector.create_record(
        device_profile=profile,
        policy_decision=policy,
        execution_result=execution,
        verification_result=verification,
        **overrides,
    )


def test_record_creation():
    record = _build_record()
    assert isinstance(record, EvidenceRecord)
    assert record.job_id
    assert record.final_status == "VERIFIED"


def test_unique_job_id():
    first = _build_record()
    second = _build_record()
    assert first.job_id != second.job_id


def test_device_profile_inclusion():
    record = _build_record()
    assert record.device_profile["device_path"] == "/dev/nvme0n1"
    assert record.device_profile["serial"] == "ABC123"


def test_policy_inclusion():
    record = _build_record()
    assert record.policy_decision["selected_pathway"] == "CRYPTO_ERASE"
    assert record.pathway["policy_reason"]


def test_execution_inclusion():
    record = _build_record()
    assert record.execution["status"] == "RUNNING"
    assert record.execution["metadata"]["method"] == "CRYPTO_ERASE"


def test_verification_inclusion():
    record = _build_record()
    assert record.verification["status"] == "VERIFIED"
    assert record.verification["evidence"]["source"] == "nvme_sanitize_log"


def test_final_status_calculation_verified():
    record = _build_record()
    assert record.final_status == "VERIFIED"


def test_final_status_failed_execution():
    record = _build_record(execution=_execution(status=SanitizationStatus.FAILED))
    assert record.final_status == "FAILED"


def test_final_status_failed_verification():
    record = _build_record(verification=_verification(status=SanitizationStatus.FAILED, verified=False))
    assert record.final_status == "FAILED"


def test_final_status_inconclusive_verification():
    record = _build_record(verification=_verification(status=SanitizationStatus.INCONCLUSIVE, verified=False))
    assert record.final_status == "INCONCLUSIVE"


def test_final_status_unsupported_pathway():
    record = _build_record(policy=_policy(selected_pathway=None, unsupported=True))
    assert record.final_status == "UNSUPPORTED"


def test_secret_password_exclusion():
    execution = _execution(
        metadata={
            "method": "ATA_ERASE",
            "password": "super-secret",
            "authorization_token": "token-123",
            "planned_commands": [["hdparm", "--security-erase", "super-secret", "/dev/sda"]],
        }
    )
    record = _build_record(execution=execution)
    serialized = record.to_json().lower()
    assert "super-secret" not in serialized
    assert "token-123" not in serialized
    assert "<redacted>" in serialized


def test_deterministic_serialization():
    fixed_record = _build_record(
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:02Z",
    )
    first = fixed_record.to_json()
    second = fixed_record.to_json()
    assert first == second
    assert json.loads(first) == json.loads(second)


def test_integrity_hash_generation():
    record = _build_record()
    assert record.integrity_algorithm == "sha256"
    assert len(record.integrity_hash) == 64


def test_integrity_verification_valid_record():
    record = _build_record()
    assert verify_integrity(record) is True


def test_tampered_record_detection_for_field_change():
    record = _build_record().to_dict()
    record["agent_version"] = "tampered"
    assert verify_integrity(record) is False


def test_tampered_record_detection_for_verification_change():
    record = _build_record().to_dict()
    record["verification"]["verified"] = False
    assert verify_integrity(record) is False


def test_tampered_record_detection_for_pathway_change():
    record = _build_record().to_dict()
    record["pathway"]["executed_pathway"] = "HDD_OVERWRITE"
    assert verify_integrity(record) is False


def test_tampered_record_detection_for_device_identity_change():
    record = _build_record().to_dict()
    record["device_profile"]["serial"] = "CHANGED-SERIAL"
    assert verify_integrity(record) is False


def test_missing_optional_device_metadata_is_explicit_none():
    record = _build_record(profile=_profile(model=None, serial_number=None, interface=None, transport=None))
    assert record.device_profile["model"] is None
    assert record.device_profile["serial"] is None
    assert record.device_profile["interface"] is None
    assert record.device_profile["transport"] is None


def test_no_destructive_commands(monkeypatch):
    called = {"subprocess": False}

    def _fail(*args, **kwargs):
        called["subprocess"] = True
        raise AssertionError("subprocess execution is not allowed in evidence collection")

    monkeypatch.setattr("subprocess.run", _fail)
    record = _build_record()
    assert record.final_status == "VERIFIED"
    assert called["subprocess"] is False
