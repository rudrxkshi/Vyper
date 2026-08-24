from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any
from uuid import uuid4

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.certificate import verify_certificate_integrity
from agent.evidence import EvidenceCollector
from agent.profiler import DeviceProfile

from .models import AuditLogRecord, AssetRecord, CertificateRecord, JobRecord, ResultRecord
from .security import record_audit_event


class ResultIntegrityError(ValueError):
	pass


def validate_result_integrity(result: dict[str, Any]) -> tuple[bool, str | None]:
	"""Validate successful claims and every supplied integrity hash."""
	job_state = str(result.get("job_state") or result.get("terminal_state") or "")
	verification = dict(to_payload(result.get("verification") or {}))
	evidence = dict(to_payload(result.get("evidence") or {}))
	certificate = dict(to_payload(result.get("certificate") or {}))
	final_status = str(evidence.get("final_status") or result.get("final_status") or job_state)
	evidence_hash = str(evidence.get("integrity_hash") or "")
	certificate_hash = str(certificate.get("certificate_hash") or "")

	if evidence_hash and not EvidenceCollector().verify_integrity(evidence):
		return False, "Evidence integrity validation failed."
	if certificate_hash and not verify_certificate_integrity(certificate):
		return False, "Certificate integrity validation failed."
	if evidence_hash and certificate_hash:
		bound_hash = str((certificate.get("evidence_integrity") or {}).get("hash") or "")
		if bound_hash != evidence_hash:
			return False, "Certificate is not bound to the supplied evidence hash."

	successful_claim = certificate.get("successful_sanitization_claim") is True
	if final_status == "VERIFIED" or job_state == "VERIFIED" or successful_claim:
		verified = (
			job_state == "VERIFIED" and final_status == "VERIFIED"
			and verification.get("status") == "VERIFIED" and verification.get("verified") is True
			and evidence.get("final_status") == "VERIFIED"
			and certificate.get("final_status") == "VERIFIED"
			and certificate.get("outcome_kind") == "sanitization_certificate"
			and successful_claim and bool(evidence_hash) and bool(certificate_hash)
		)
		if not verified:
			return False, "VERIFIED requires matching verification, evidence, certificate, and integrity hashes."

	return True, None


def to_payload(value: Any) -> Any:
    if value is None:
        return {}
    if is_dataclass(value):
        return jsonable_encoder(asdict(value))
    return jsonable_encoder(value)


def sanitize_authorization_payload(authorization: dict[str, Any]) -> dict[str, Any]:
    payload = dict(authorization or {})
    if payload.get("ata_password"):
        payload["has_ata_password"] = True
        payload["ata_password"] = "<redacted>"
    else:
        payload["has_ata_password"] = False
    return payload


def upsert_asset(session: Session, profile: DeviceProfile | None, target: str) -> AssetRecord:
    profile_payload = to_payload(profile) if profile is not None else {}
    device_path = str(profile_payload.get("device_path") or target or "")
    asset = session.execute(select(AssetRecord).where(AssetRecord.device_path == device_path)).scalar_one_or_none()
    if asset is None:
        asset = AssetRecord(
            id=str(uuid4()),
            asset_type="storage",
            device_path=device_path,
            device_type=str(profile_payload.get("device_type") or "UNKNOWN"),
        )
        session.add(asset)

    asset.device_type = str(profile_payload.get("device_type") or asset.device_type or "UNKNOWN")
    asset.model = profile_payload.get("model")
    asset.serial_number = profile_payload.get("serial_number")
    asset.profile_json = profile_payload
    asset.is_system_device = bool(profile_payload.get("is_system_device", False))
    asset.mounted = bool(profile_payload.get("mounted", False))
    asset.mounted_partitions = list(profile_payload.get("mounted_partitions") or [])
    return asset


def persist_job(
    session: Session,
    *,
    result: dict[str, Any],
    authorization: dict[str, Any],
    requested_dry_run: bool | None,
    actor: str | None = None,
) -> JobRecord:
    integrity_ok, integrity_error = validate_result_integrity(result)
    if not integrity_ok:
        raise ResultIntegrityError(integrity_error or "Result integrity validation failed.")
    profile_payload = dict(to_payload(result.get("profile") or {}))
    policy_payload = dict(to_payload(result.get("policy") or {}))
    execution_payload = dict(to_payload(result.get("execution") or {}))
    verification_payload = dict(to_payload(result.get("verification") or {}))
    evidence_payload = dict(to_payload(result.get("evidence") or {}))
    certificate_payload = dict(to_payload(result.get("certificate") or {}))
    state_history = list(to_payload(result.get("state_history") or []))

    asset = upsert_asset(session, profile=DeviceProfile(**profile_payload) if profile_payload else None, target=str(result.get("target") or ""))

    job_state = str(result.get("job_state") or result.get("terminal_state") or "PENDING")
    final_status = str(evidence_payload.get("final_status") or result.get("final_status") or job_state)
    pathway = policy_payload.get("selected_pathway") or execution_payload.get("metadata", {}).get("method") or execution_payload.get("metadata", {}).get("sanitize_method")
    certificate_id = certificate_payload.get("certificate_id")
    certificate_hash = certificate_payload.get("certificate_hash")
    outcome_kind = certificate_payload.get("outcome_kind")
    successful_claim = bool(certificate_payload.get("successful_sanitization_claim", False))

    job = JobRecord(
        id=str(uuid4()),
        asset=asset,
        target=str(result.get("target") or ""),
        dry_run=bool(execution_payload.get("dry_run", requested_dry_run if requested_dry_run is not None else False)),
        job_state=job_state,
        final_status=final_status,
        pathway=str(pathway) if pathway else None,
        outcome_kind=outcome_kind,
        successful_sanitization_claim=successful_claim,
        message=str(result.get("message") or ""),
        state_history_json=state_history,
        authorization_json=sanitize_authorization_payload(authorization),
        profile_json=profile_payload,
        policy_json=policy_payload,
        execution_json=execution_payload,
        verification_json=verification_payload,
        evidence_json=evidence_payload,
        certificate_json=certificate_payload,
        certificate_id=certificate_id,
        certificate_hash=certificate_hash,
    )
    session.add(job)
    session.flush()
    result_row = ResultRecord(
        id=str(uuid4()),
        job=job,
        started_at=str(evidence_payload.get("started_at") or execution_payload.get("metadata", {}).get("start_time") or "") or None,
        completed_at=str(evidence_payload.get("completed_at") or execution_payload.get("metadata", {}).get("end_time") or "") or None,
        duration_seconds=evidence_payload.get("duration_seconds") if isinstance(evidence_payload.get("duration_seconds"), (int, float)) else execution_payload.get("metadata", {}).get("duration_seconds"),
        execution_json=execution_payload,
        verification_json=verification_payload,
        evidence_json=evidence_payload,
    )
    certificate_row = CertificateRecord(
        id=str(uuid4()),
        job=job,
        certificate_id=certificate_id,
        target=str(result.get("target") or ""),
        final_status=final_status,
        certificate_hash=certificate_hash,
        outcome_kind=outcome_kind,
        successful_sanitization_claim=successful_claim,
        certificate_json=certificate_payload,
    )
    session.add_all([result_row, certificate_row])
    record_audit_event(session, actor=actor, action="sanitize_device", resource=f"job:{job.id}", job_id=job.id,
        metadata={"target": result.get("target"), "authorization": sanitize_authorization_payload(authorization),
            "dry_run": requested_dry_run, "job_state": job_state, "final_status": final_status,
            "certificate_id": certificate_id})
    return job


def job_to_dict(job: JobRecord) -> dict[str, Any]:
    asset = job.asset
    result = job.result
    certificate = job.certificate
    audit_logs = list(job.audit_logs or [])
    return {
        "id": job.id,
        "target": job.target,
        "dry_run": job.dry_run,
        "job_state": job.job_state,
        "final_status": job.final_status,
        "pathway": job.pathway,
        "outcome_kind": job.outcome_kind,
        "successful_sanitization_claim": job.successful_sanitization_claim,
        "message": job.message,
        "state_history_json": job.state_history_json or [],
        "authorization_json": job.authorization_json or {},
        "profile_json": job.profile_json or {},
        "policy_json": job.policy_json or {},
        "execution_json": job.execution_json or {},
        "verification_json": job.verification_json or {},
        "evidence_json": job.evidence_json or {},
        "certificate_json": job.certificate_json or {},
        "certificate_id": job.certificate_id,
        "certificate_hash": job.certificate_hash,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "asset": asset_to_dict(asset),
        "device": asset_to_dict(asset),
        "result": result_to_dict(result) if result is not None else None,
        "certificate": certificate_to_dict(certificate) if certificate is not None else None,
        "audit_logs": [audit_log_to_dict(audit_log) for audit_log in audit_logs],
    }


def asset_to_dict(asset: AssetRecord) -> dict[str, Any]:
    return {
        "id": asset.id,
        "asset_type": asset.asset_type,
        "device_path": asset.device_path,
        "device_type": asset.device_type,
        "model": asset.model,
        "serial_number": asset.serial_number,
        "profile_json": asset.profile_json or {},
        "is_system_device": asset.is_system_device,
        "mounted": asset.mounted,
        "mounted_partitions": asset.mounted_partitions or [],
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


def result_to_dict(result: ResultRecord) -> dict[str, Any]:
    return {
        "id": result.id,
        "job_id": result.job_id,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_seconds": result.duration_seconds,
        "execution_json": result.execution_json or {},
        "verification_json": result.verification_json or {},
        "evidence_json": result.evidence_json or {},
        "created_at": result.created_at,
        "updated_at": result.updated_at,
    }


def certificate_to_dict(certificate: CertificateRecord) -> dict[str, Any]:
    return {
        "id": certificate.id,
        "certificate_id": certificate.certificate_id,
        "job_id": certificate.job_id,
        "target": certificate.target,
        "final_status": certificate.final_status,
        "certificate_hash": certificate.certificate_hash,
        "outcome_kind": certificate.outcome_kind,
        "successful_sanitization_claim": certificate.successful_sanitization_claim,
        "certificate_json": certificate.certificate_json or {},
        "created_at": certificate.created_at,
        "updated_at": certificate.updated_at,
    }


def audit_log_to_dict(audit_log: AuditLogRecord) -> dict[str, Any]:
    return {
        "id": audit_log.id,
        "job_id": audit_log.job_id,
        "action": audit_log.action,
        "actor": audit_log.actor,
        "request_json": audit_log.request_json or {},
        "response_json": audit_log.response_json or {},
        "created_at": audit_log.created_at,
        "resource": audit_log.resource,
        "request_id": audit_log.request_id,
        "previous_hash": audit_log.previous_hash,
        "event_hash": audit_log.event_hash,
    }
