from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from agent.certificate import (
    CertificateBuilder,
    SanitizationCertificate,
    certificate_to_dict,
    certificate_to_json,
    verify_certificate_integrity,
)
from agent.evidence import EvidenceRecord


def _evidence(final_status: str = "VERIFIED", **overrides) -> EvidenceRecord:
    base = EvidenceRecord(
        job_id="job-123",
        device="/dev/nvme0n1",
        device_profile={
            "device_path": "/dev/nvme0n1",
            "device_type": "NVMe",
            "model": "Sample",
            "serial": "XYZ-1",
            "capacity_bytes": 1024,
            "interface": "NVMe",
            "transport": "PCIe",
        },
        policy_decision={
            "selected_pathway": "CRYPTO_ERASE",
            "reason": "Crypto supported and applicable.",
        },
        pathway={
            "selected_pathway": "CRYPTO_ERASE",
            "executed_pathway": "CRYPTO_ERASE",
            "sanitization_method": "CRYPTO_ERASE",
            "policy_reason": "Crypto supported and applicable.",
        },
        execution={
            "status": "RUNNING",
            "metadata": {"method": "CRYPTO_ERASE"},
        },
        verification={
            "status": "VERIFIED",
            "verified": True,
            "evidence": {"source": "nvme_sanitize_log", "status": "completed"},
            "limitations": ["Controller-reported evidence."],
            "warnings": [],
            "errors": [],
        },
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:02Z",
        duration_seconds=2.0,
        final_status=final_status,
        warnings=[],
        errors=[],
        limitations=["Controller evidence only."],
        agent_version="vyper-test",
        integrity_algorithm="sha256",
        integrity_hash="a" * 64,
    )
    data = asdict(base)
    data.update(overrides)
    return EvidenceRecord(**data)


def _build_certificate(final_status: str = "VERIFIED", **evidence_overrides) -> SanitizationCertificate:
    builder = CertificateBuilder(certificate_version="1.0.0")
    return builder.build(_evidence(final_status=final_status, **evidence_overrides))


def test_verified_evidence_produces_successful_certificate():
    certificate = _build_certificate("VERIFIED")
    assert certificate.final_status == "VERIFIED"
    assert certificate.outcome_kind == "sanitization_certificate"
    assert certificate.successful_sanitization_claim is True


def test_failed_evidence_produces_unsuccessful_outcome():
    certificate = _build_certificate("FAILED")
    assert certificate.final_status == "FAILED"
    assert certificate.outcome_kind == "outcome_report"
    assert certificate.successful_sanitization_claim is False


def test_inconclusive_evidence_produces_unsuccessful_outcome():
    certificate = _build_certificate("INCONCLUSIVE")
    assert certificate.final_status == "INCONCLUSIVE"
    assert certificate.outcome_kind == "outcome_report"
    assert certificate.successful_sanitization_claim is False


def test_unsupported_evidence_produces_unsupported_outcome():
    certificate = _build_certificate("UNSUPPORTED")
    assert certificate.final_status == "UNSUPPORTED"
    assert certificate.outcome_kind == "outcome_report"
    assert certificate.successful_sanitization_claim is False


def test_certificate_id_uniqueness():
    first = _build_certificate()
    second = _build_certificate()
    assert first.certificate_id != second.certificate_id


def test_evidence_fields_preserved():
    certificate = _build_certificate()
    assert certificate.job_id == "job-123"
    assert certificate.device["device_path"] == "/dev/nvme0n1"
    assert certificate.sanitization["selected_pathway"] == "CRYPTO_ERASE"


def test_evidence_integrity_hash_preserved():
    certificate = _build_certificate()
    assert certificate.evidence_integrity["algorithm"] == "sha256"
    assert certificate.evidence_integrity["hash"] == "a" * 64


def test_certificate_hash_generated():
    certificate = _build_certificate()
    assert certificate.certificate_hash_algorithm == "sha256"
    assert len(certificate.certificate_hash) == 64


def test_certificate_integrity_verification_true_for_unchanged_certificate():
    certificate = _build_certificate()
    assert verify_certificate_integrity(certificate) is True


def test_tampered_device_detected():
    certificate = certificate_to_dict(_build_certificate())
    certificate["device"]["serial"] = "tampered"
    assert verify_certificate_integrity(certificate) is False


def test_tampered_final_status_detected():
    certificate = certificate_to_dict(_build_certificate())
    certificate["final_status"] = "FAILED"
    assert verify_certificate_integrity(certificate) is False


def test_tampered_verification_detected():
    certificate = certificate_to_dict(_build_certificate())
    certificate["verification"]["verified"] = False
    assert verify_certificate_integrity(certificate) is False


def test_tampered_pathway_detected():
    certificate = certificate_to_dict(_build_certificate())
    certificate["sanitization"]["executed_pathway"] = "HDD_OVERWRITE"
    assert verify_certificate_integrity(certificate) is False


def test_tampered_evidence_hash_detected():
    certificate = certificate_to_dict(_build_certificate())
    certificate["evidence_integrity"]["hash"] = "b" * 64
    assert verify_certificate_integrity(certificate) is False


def test_deterministic_json_serialization():
    certificate = _build_certificate()
    first = certificate_to_json(certificate)
    second = certificate_to_json(certificate)
    assert first == second
    assert json.loads(first) == json.loads(second)


def test_human_readable_rendering_contains_required_sections():
    certificate = _build_certificate()
    text = certificate.render_human_readable()
    assert "VYPER SANITIZATION CERTIFICATE" in text
    assert "DEVICE" in text
    assert "SANITIZATION" in text
    assert "EXECUTION" in text
    assert "VERIFICATION" in text
    assert "FINAL STATUS" in text
    assert "INTEGRITY" in text
    assert "AGENT" in text


def test_missing_optional_device_metadata():
    certificate = _build_certificate(
        device_profile={
            "device_path": "/dev/nvme0n1",
            "device_type": "NVMe",
            "model": None,
            "serial": None,
            "capacity_bytes": None,
            "interface": None,
            "transport": None,
        }
    )
    assert certificate.device["model"] is None
    assert certificate.device["serial"] is None


def test_secret_password_exclusion():
    certificate = _build_certificate(
        verification={
            "status": "VERIFIED",
            "verified": True,
            "evidence": {"source": "nvme_sanitize_log", "status": "completed"},
            "limitations": [],
            "warnings": [],
            "errors": [],
            "password": "secret-value",
            "authorization_token": "token-value",
        },
        pathway={
            "selected_pathway": "ATA_ERASE",
            "executed_pathway": "ATA_ERASE",
            "sanitization_method": "ATA_ERASE",
            "policy_reason": "test",
            "auth_secret": "should-not-leak",
        },
    )
    payload = certificate.to_json().lower()
    assert "secret-value" not in payload
    assert "token-value" not in payload
    assert "should-not-leak" not in payload


def test_no_destructive_commands(monkeypatch):
    called = {"subprocess": False}

    def _boom(*args, **kwargs):
        called["subprocess"] = True
        raise AssertionError("subprocess is not allowed")

    monkeypatch.setattr("subprocess.run", _boom)
    certificate = _build_certificate()
    assert certificate.final_status == "VERIFIED"
    assert called["subprocess"] is False


def test_certificate_generation_requires_no_device_access(monkeypatch):
    def _open_guard(*args, **kwargs):
        raise AssertionError("device/file access is not allowed")

    monkeypatch.setattr("builtins.open", _open_guard)
    certificate = _build_certificate()
    assert certificate.job_id == "job-123"
