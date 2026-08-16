from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any

from agent.common import SanitizationStatus

_SECRET_KEYWORDS = {"password", "secret", "token", "credential", "passphrase", "authorization"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_status_text(value: Any) -> str:
    if isinstance(value, SanitizationStatus):
        return value.value
    if value is None:
        return ""
    raw = str(value).strip()
    return raw.upper() if raw else ""


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


def _contains_secret_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _SECRET_KEYWORDS)


def _sanitize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, val in value.items():
            key_text = str(key)
            if _contains_secret_marker(key_text):
                sanitized[key_text] = "<redacted>"
                continue
            sanitized[key_text] = _sanitize(val, key_text)
        return sanitized

    if isinstance(value, list):
        return [_sanitize(item, parent_key) for item in value]

    if isinstance(value, tuple):
        return [_sanitize(item, parent_key) for item in value]

    if isinstance(value, str):
        return "<redacted>" if _contains_secret_marker(parent_key) else value

    return value


def _redact_command_sequence(command: list[Any]) -> list[Any]:
    redacted: list[Any] = []
    redact_next = False
    for token in command:
        text = str(token)
        lower = text.lower()
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if _contains_secret_marker(lower):
            if text.startswith("--"):
                redacted.append(text)
                redact_next = True
            else:
                redacted.append("<redacted>")
            continue
        redacted.append(token)
    return redacted


def _redact_command_metadata(value: Any) -> Any:
    if isinstance(value, list):
        if value and all(not isinstance(item, (dict, list, tuple)) for item in value):
            return _redact_command_sequence(list(value))
        return [_redact_command_metadata(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_command_metadata(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _redact_command_metadata(v) for k, v in value.items()}
    return value


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(slots=True)
class EvidenceRecord:
    job_id: str
    device: str
    device_profile: dict[str, Any]
    policy_decision: dict[str, Any]
    pathway: dict[str, Any]
    execution: dict[str, Any]
    verification: dict[str, Any]
    started_at: str
    completed_at: str
    duration_seconds: float
    final_status: str
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    agent_version: str = "unknown"
    integrity_algorithm: str = "sha256"
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("integrity_algorithm", None)
        payload.pop("integrity_hash", None)
        return payload

    def canonical_json(self) -> str:
        return _canonical_json(self.canonical_payload())

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


class EvidenceCollector:
    def __init__(self, *, dry_run: bool = True, agent_version: str = "vyper-dev") -> None:
        self.dry_run = dry_run
        self.agent_version = agent_version

    def create_record(
        self,
        *,
        device_profile: Any,
        policy_decision: Any,
        execution_result: Any,
        verification_result: Any,
        started_at: str | None = None,
        completed_at: str | None = None,
        app_metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        started = started_at or self._resolve_start_time(execution_result)
        completed = completed_at or self._resolve_end_time(execution_result)
        duration = self._resolve_duration(execution_result, started, completed)

        profile = self._build_device_profile(device_profile)
        policy = _sanitize(_serialize(policy_decision)) if policy_decision is not None else {}
        execution = self._build_execution(execution_result)
        verification = self._build_verification(verification_result)
        pathway = self._build_pathway(policy, execution, verification)

        warnings = self._collect_strings(execution.get("warnings", [])) + self._collect_strings(verification.get("warnings", []))
        errors = self._collect_strings(execution.get("errors", [])) + self._collect_strings(verification.get("errors", []))
        limitations = self._collect_strings(policy.get("limitations", [])) + self._collect_strings(verification.get("limitations", []))

        final_status = self._determine_final_status(policy, execution, verification)

        if app_metadata:
            pathway["app_metadata"] = _sanitize(_serialize(app_metadata))

        record = EvidenceRecord(
            job_id=str(uuid.uuid4()),
            device=profile.get("device_path") or execution.get("target_device") or verification.get("device") or "",
            device_profile=profile,
            policy_decision=policy,
            pathway=pathway,
            execution=execution,
            verification=verification,
            started_at=started,
            completed_at=completed,
            duration_seconds=duration,
            final_status=final_status,
            warnings=warnings,
            errors=errors,
            limitations=limitations,
            agent_version=self.agent_version,
        )

        record.integrity_hash = self._compute_integrity_hash(record)
        return record

    def verify_integrity(self, record: EvidenceRecord | dict[str, Any]) -> bool:
        if isinstance(record, EvidenceRecord):
            algorithm = record.integrity_algorithm
            expected = record.integrity_hash
            payload = record.canonical_payload()
        elif isinstance(record, dict):
            algorithm = str(record.get("integrity_algorithm", "sha256"))
            expected = str(record.get("integrity_hash", ""))
            payload = _sanitize(_serialize(record))
            payload.pop("integrity_algorithm", None)
            payload.pop("integrity_hash", None)
        else:
            return False

        if algorithm.lower() != "sha256":
            return False
        actual = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        return bool(expected) and actual == expected

    def _compute_integrity_hash(self, record: EvidenceRecord) -> str:
        canonical = record.canonical_json()
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _resolve_start_time(self, execution_result: Any) -> str:
        metadata = self._metadata_from_result(execution_result)
        candidate = metadata.get("started_at") or metadata.get("start_time")
        text = self._normalize_timestamp(candidate)
        return text or _utc_now_iso()

    def _resolve_end_time(self, execution_result: Any) -> str:
        metadata = self._metadata_from_result(execution_result)
        candidate = metadata.get("completed_at") or metadata.get("end_time")
        text = self._normalize_timestamp(candidate)
        return text or _utc_now_iso()

    def _resolve_duration(self, execution_result: Any, started_at: str, completed_at: str) -> float:
        metadata = self._metadata_from_result(execution_result)
        value = metadata.get("duration_seconds")
        if isinstance(value, (int, float)):
            return max(0.0, float(value))
        return self._duration_from_timestamps(started_at, completed_at)

    def _duration_from_timestamps(self, started_at: str, completed_at: str) -> float:
        try:
            start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            end = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            return max(0.0, (end - start).total_seconds())
        except ValueError:
            return 0.0

    def _normalize_timestamp(self, value: Any) -> str | None:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
        return None

    def _metadata_from_result(self, result: Any) -> dict[str, Any]:
        metadata = getattr(result, "metadata", {}) if result is not None else {}
        return metadata if isinstance(metadata, dict) else {}

    def _build_device_profile(self, profile: Any) -> dict[str, Any]:
        profile_data = _sanitize(_serialize(profile)) if profile is not None else {}
        return {
            "device_path": profile_data.get("device_path"),
            "device_type": profile_data.get("device_type"),
            "model": profile_data.get("model"),
            "serial": profile_data.get("serial_number"),
            "capacity_bytes": profile_data.get("size_bytes"),
            "interface": profile_data.get("interface"),
            "transport": profile_data.get("transport"),
            "mounted": profile_data.get("mounted"),
            "is_system_device": profile_data.get("is_system_device"),
            "capabilities": profile_data.get("capabilities"),
        }

    def _build_execution(self, execution_result: Any) -> dict[str, Any]:
        execution_data = _sanitize(_serialize(execution_result)) if execution_result is not None else {}
        return {
            "status": _to_status_text(execution_data.get("status")),
            "target_device": execution_data.get("target_device"),
            "message": execution_data.get("message", ""),
            "dry_run": bool(execution_data.get("dry_run", False)),
            "warnings": self._extract_issue_messages(execution_data.get("warnings", [])),
            "errors": self._extract_issue_messages(execution_data.get("errors", [])),
            "metadata": self._safe_execution_metadata(execution_data.get("metadata", {})),
        }

    def _safe_execution_metadata(self, metadata: Any) -> dict[str, Any]:
        raw = metadata if isinstance(metadata, dict) else {}
        sanitized = _sanitize(_serialize(raw))
        sanitized = _redact_command_metadata(sanitized)
        sanitized.pop("password", None)
        sanitized.pop("authorization", None)
        return sanitized

    def _build_verification(self, verification_result: Any) -> dict[str, Any]:
        data = _sanitize(_serialize(verification_result)) if verification_result is not None else {}
        return {
            "status": _to_status_text(data.get("status")),
            "verified": bool(data.get("verified", False)),
            "pathway": data.get("pathway"),
            "device": data.get("device"),
            "message": data.get("message", ""),
            "evidence": data.get("evidence", {}),
            "samples_checked": int(data.get("samples_checked") or 0),
            "samples_passed": int(data.get("samples_passed") or 0),
            "samples_failed": int(data.get("samples_failed") or 0),
            "bytes_checked": int(data.get("bytes_checked") or 0),
            "warnings": self._collect_strings(data.get("warnings", [])),
            "errors": self._collect_strings(data.get("errors", [])),
            "limitations": self._collect_strings(data.get("limitations", [])),
            "metadata": data.get("metadata", {}),
        }

    def _build_pathway(self, policy: dict[str, Any], execution: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
        selected = policy.get("selected_pathway") or policy.get("policy_name")
        executed = execution.get("metadata", {}).get("method")
        executed = executed or execution.get("metadata", {}).get("planned_method") or selected
        method = execution.get("metadata", {}).get("sanitize_method") or executed
        discrepancy = None
        if selected and executed and str(selected).upper() != str(executed).upper():
            discrepancy = {
                "selected": selected,
                "executed": executed,
                "reason": "Execution metadata does not match selected policy pathway.",
            }

        return {
            "selected_pathway": selected,
            "executed_pathway": executed,
            "sanitization_method": method,
            "policy_reason": policy.get("reason") or policy.get("rationale"),
            "capability_evidence": policy.get("metadata", {}).get("capabilities"),
            "verification_pathway": verification.get("pathway"),
            "discrepancy": discrepancy,
        }

    def _determine_final_status(self, policy: dict[str, Any], execution: dict[str, Any], verification: dict[str, Any]) -> str:
        selected = policy.get("selected_pathway") or policy.get("policy_name")
        if policy.get("unsupported") is True or not selected:
            return SanitizationStatus.UNSUPPORTED.value

        execution_status = _to_status_text(execution.get("status"))
        verification_status = _to_status_text(verification.get("status"))

        if execution_status == SanitizationStatus.UNSUPPORTED.value:
            return SanitizationStatus.UNSUPPORTED.value

        if execution_status == SanitizationStatus.FAILED.value:
            return SanitizationStatus.FAILED.value

        execution_succeeded = execution_status in {
            SanitizationStatus.RUNNING.value,
            SanitizationStatus.VERIFIED.value,
        }

        if not execution_succeeded:
            return SanitizationStatus.FAILED.value

        if verification_status == SanitizationStatus.FAILED.value:
            return SanitizationStatus.FAILED.value
        if verification_status == SanitizationStatus.INCONCLUSIVE.value:
            return SanitizationStatus.INCONCLUSIVE.value
        if verification_status == SanitizationStatus.VERIFIED.value and verification.get("verified") is True:
            return SanitizationStatus.VERIFIED.value
        if verification_status == SanitizationStatus.UNSUPPORTED.value:
            return SanitizationStatus.UNSUPPORTED.value
        return SanitizationStatus.INCONCLUSIVE.value

    def _extract_issue_messages(self, issues: Any) -> list[str]:
        messages: list[str] = []
        if not isinstance(issues, list):
            return messages
        for item in issues:
            if isinstance(item, dict):
                msg = item.get("message")
                if msg:
                    messages.append(str(msg))
            elif isinstance(item, str):
                messages.append(item)
        return self._collect_strings(messages)

    def _collect_strings(self, values: Any) -> list[str]:
        if not isinstance(values, list):
            return []
        out = []
        for value in values:
            if value is None:
                continue
            out.append(str(value))
        return out


def verify_integrity(record: EvidenceRecord | dict[str, Any]) -> bool:
    return EvidenceCollector().verify_integrity(record)
