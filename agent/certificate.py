from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any

from agent.common import SanitizationStatus
from agent.evidence import EvidenceRecord

_SECRET_KEYWORDS = {"password", "secret", "token", "credential", "passphrase", "authorization"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _contains_secret_marker(text: str) -> bool:
    lowered = str(text).lower()
    return any(marker in lowered for marker in _SECRET_KEYWORDS)


def _serialize(value: Any) -> Any:
    if isinstance(value, SanitizationStatus):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if is_dataclass(value):
        return {k: _serialize(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    return value


def _sanitize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            key_text = str(key)
            if _contains_secret_marker(key_text):
                out[key_text] = "<redacted>"
                continue
            out[key_text] = _sanitize(val, key_text)
        return out

    if isinstance(value, list):
        return [_sanitize(item, parent_key) for item in value]

    if isinstance(value, tuple):
        return [_sanitize(item, parent_key) for item in value]

    if isinstance(value, str) and _contains_secret_marker(parent_key):
        return "<redacted>"

    return value


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _status_text(value: Any) -> str:
    if isinstance(value, SanitizationStatus):
        return value.value
    if value is None:
        return ""
    return str(value).strip().upper()


def _capacity_text(value: Any) -> str:
    if value is None:
        return "N/A"
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return str(value)


def _text_or_na(value: Any) -> str:
    if value is None:
        return "N/A"
    text = str(value).strip()
    return text if text else "N/A"


def _bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


@dataclass(slots=True)
class SanitizationCertificate:
    certificate_id: str
    certificate_version: str
    issued_at: str
    job_id: str
    device: dict[str, Any]
    sanitization: dict[str, Any]
    execution: dict[str, Any]
    verification: dict[str, Any]
    final_status: str
    evidence_integrity: dict[str, Any]
    agent: dict[str, Any]
    certificate_hash_algorithm: str = "sha256"
    certificate_hash: str = ""
    outcome_kind: str = "outcome_report"
    successful_sanitization_claim: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("certificate_hash", None)
        return payload

    def canonical_json(self) -> str:
        return _canonical_json(self.canonical_payload())

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def render_human_readable(self) -> str:
        device = self.device
        sanitization = self.sanitization
        execution = self.execution
        verification = self.verification
        evidence_text = _canonical_json(verification.get("evidence", {}))
        limitations = verification.get("limitations", []) or []
        limitations_text = " | ".join(str(item) for item in limitations) if limitations else "N/A"

        return "\n".join(
            [
                "VYPER SANITIZATION CERTIFICATE",
                "",
                f"Certificate ID: {self.certificate_id}",
                f"Job ID: {self.job_id}",
                f"Issued At: {self.issued_at}",
                "",
                "DEVICE",
                f"Model: {_text_or_na(device.get('model'))}",
                f"Serial: {_text_or_na(device.get('serial'))}",
                f"Type: {_text_or_na(device.get('device_type'))}",
                f"Capacity: {_capacity_text(device.get('capacity_bytes'))}",
                f"Interface: {_text_or_na(device.get('interface'))}",
                f"Transport: {_text_or_na(device.get('transport'))}",
                "",
                "SANITIZATION",
                f"Selected Pathway: {_text_or_na(sanitization.get('selected_pathway'))}",
                f"Executed Pathway: {_text_or_na(sanitization.get('executed_pathway'))}",
                f"Method: {_text_or_na(sanitization.get('sanitization_method'))}",
                f"Policy Reason: {_text_or_na(sanitization.get('policy_reason'))}",
                "",
                "EXECUTION",
                f"Status: {_text_or_na(execution.get('status'))}",
                f"Started: {_text_or_na(execution.get('started_at'))}",
                f"Completed: {_text_or_na(execution.get('completed_at'))}",
                f"Duration: {_text_or_na(execution.get('duration_seconds'))}",
                "",
                "VERIFICATION",
                f"Status: {_text_or_na(verification.get('status'))}",
                f"Verified: {_bool_text(verification.get('verified'))}",
                f"Evidence: {evidence_text}",
                f"Limitations: {limitations_text}",
                "",
                f"FINAL STATUS: {_text_or_na(self.final_status)}",
                "",
                "INTEGRITY",
                f"Evidence SHA-256: {_text_or_na(self.evidence_integrity.get('hash'))}",
                f"Certificate SHA-256: {_text_or_na(self.certificate_hash)}",
                "",
                "AGENT",
                f"Version: {_text_or_na(self.agent.get('version'))}",
            ]
        )


class CertificateBuilder:
    def __init__(self, *, certificate_version: str = "1.0.0") -> None:
        self.certificate_version = certificate_version

    def build(self, evidence_record: EvidenceRecord | dict[str, Any]) -> SanitizationCertificate:
        evidence = self._normalize_evidence(evidence_record)

        final_status = _status_text(evidence.get("final_status"))
        success_claim = final_status == SanitizationStatus.VERIFIED.value
        outcome_kind = "sanitization_certificate" if success_claim else "outcome_report"

        certificate = SanitizationCertificate(
            certificate_id=str(uuid.uuid4()),
            certificate_version=self.certificate_version,
            issued_at=_utc_now_iso(),
            job_id=str(evidence.get("job_id", "")),
            device=self._build_device(evidence),
            sanitization=self._build_sanitization(evidence),
            execution=self._build_execution(evidence),
            verification=self._build_verification(evidence),
            final_status=final_status,
            evidence_integrity={
                "algorithm": str(evidence.get("integrity_algorithm", "sha256")),
                "hash": str(evidence.get("integrity_hash", "")),
            },
            agent={"version": str(evidence.get("agent_version", "unknown"))},
            outcome_kind=outcome_kind,
            successful_sanitization_claim=success_claim,
        )

        certificate.certificate_hash = self._compute_certificate_hash(certificate)
        return certificate

    def _compute_certificate_hash(self, certificate: SanitizationCertificate) -> str:
        canonical = certificate.canonical_json()
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _normalize_evidence(self, evidence_record: EvidenceRecord | dict[str, Any]) -> dict[str, Any]:
        if isinstance(evidence_record, EvidenceRecord):
            evidence_data = evidence_record.to_dict()
        elif isinstance(evidence_record, dict):
            evidence_data = _serialize(evidence_record)
        else:
            raise TypeError("evidence_record must be an EvidenceRecord or dict")
        return _sanitize(evidence_data)

    def _build_device(self, evidence: dict[str, Any]) -> dict[str, Any]:
        profile = evidence.get("device_profile", {}) or {}
        return {
            "device_path": profile.get("device_path"),
            "device_type": profile.get("device_type"),
            "model": profile.get("model"),
            "serial": profile.get("serial"),
            "capacity_bytes": profile.get("capacity_bytes"),
            "interface": profile.get("interface"),
            "transport": profile.get("transport"),
        }

    def _build_sanitization(self, evidence: dict[str, Any]) -> dict[str, Any]:
        pathway = evidence.get("pathway", {}) or {}
        return {
            "selected_pathway": pathway.get("selected_pathway"),
            "executed_pathway": pathway.get("executed_pathway"),
            "sanitization_method": pathway.get("sanitization_method"),
            "policy_reason": pathway.get("policy_reason"),
        }

    def _build_execution(self, evidence: dict[str, Any]) -> dict[str, Any]:
        execution = evidence.get("execution", {}) or {}
        return {
            "status": execution.get("status"),
            "started_at": evidence.get("started_at"),
            "completed_at": evidence.get("completed_at"),
            "duration_seconds": evidence.get("duration_seconds"),
        }

    def _build_verification(self, evidence: dict[str, Any]) -> dict[str, Any]:
        verification = evidence.get("verification", {}) or {}
        return {
            "status": verification.get("status"),
            "verified": bool(verification.get("verified", False)),
            "evidence": verification.get("evidence", {}),
            "limitations": verification.get("limitations", []),
            "warnings": verification.get("warnings", []),
            "errors": verification.get("errors", []),
        }


def verify_certificate_integrity(certificate: SanitizationCertificate | dict[str, Any]) -> bool:
    if isinstance(certificate, SanitizationCertificate):
        payload = certificate.to_dict()
    elif isinstance(certificate, dict):
        payload = _serialize(certificate)
    else:
        return False

    if str(payload.get("certificate_version", "")).split(".", 1)[0] != "1":
        return False
    algorithm = str(payload.get("certificate_hash_algorithm", "sha256")).lower()
    expected = str(payload.get("certificate_hash", ""))
    if algorithm != "sha256" or not expected:
        return False

    canonical_payload = _sanitize(payload)
    canonical_payload.pop("certificate_hash", None)
    actual = hashlib.sha256(_canonical_json(canonical_payload).encode("utf-8")).hexdigest()
    return actual == expected


def certificate_to_dict(certificate: SanitizationCertificate) -> dict[str, Any]:
    return certificate.to_dict()


def certificate_to_json(certificate: SanitizationCertificate) -> str:
    return certificate.to_json()
