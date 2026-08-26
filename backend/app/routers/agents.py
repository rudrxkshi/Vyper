from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..agent_protocol import (
	AGENT_PROTOCOL_VERSION,
	authenticated_agent,
	contains_unredacted_secret,
	derived_agent_status,
	new_token,
	require_protocol,
	token_hash,
	utc_now,
)
from ..auth import OperatorPrincipal, OperatorRole, require_roles
from ..db import get_db
from ..models import AgentAssetRecord, AgentRecord, CentralCertificateRecord, CentralJobEventRecord, CentralJobRecord, EnrollmentTokenRecord
from ..schemas import (
	AgentEnrollRequest,
	AgentEnrollResponse,
	AgentHeartbeat,
	AgentJobEventUpload,
	AgentJobResultUpload,
	CentralJobCreate,
	EnrollmentTokenCreate,
	EnrollmentTokenRead,
	InventoryUpload,
)
from ..services import validate_result_integrity
from ..security import record_audit_event


router = APIRouter(tags=["agents"])
_TERMINAL = {"VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"}
_OPERATOR_READ = require_roles(OperatorRole.ADMIN, OperatorRole.OPERATOR, OperatorRole.AUDITOR)
_OPERATOR_WRITE = require_roles(OperatorRole.ADMIN, OperatorRole.OPERATOR)


def _index_accepted_sanitization_certificate(db: Session, job: CentralJobRecord, result: dict[str, Any]) -> None:
	certificate = result.get("certificate") or {}
	if not (
		result.get("final_status") == "VERIFIED"
		and certificate.get("outcome_kind") == "sanitization_certificate"
		and certificate.get("successful_sanitization_claim") is True
	):
		return
	if db.scalar(select(CentralCertificateRecord.id).where(CentralCertificateRecord.central_job_id == job.central_job_id)):
		return
	device = certificate.get("device") or {}
	db.add(CentralCertificateRecord(
		id=str(uuid4()), central_job_id=job.central_job_id,
		local_job_id=str(result.get("local_job_id") or job.local_job_id),
		certificate_id=certificate["certificate_id"],
		target=str(device.get("device_path") or job.requested_target),
		final_status=certificate["final_status"], certificate_hash=certificate["certificate_hash"],
		outcome_kind=certificate["outcome_kind"], successful_sanitization_claim=True,
		certificate_json=certificate,
	))


def _iso(value):
	return value.isoformat().replace("+00:00", "Z") if value is not None else None


def _agent_dict(agent: AgentRecord, db: Session) -> dict[str, Any]:
	asset_count = db.scalar(select(func.count()).select_from(AgentAssetRecord).where(AgentAssetRecord.agent_id == agent.agent_id)) or 0
	active_jobs = db.scalar(
		select(func.count()).select_from(CentralJobRecord).where(
			CentralJobRecord.agent_id == agent.agent_id,
			CentralJobRecord.status.not_in(tuple(_TERMINAL | {"EXPIRED"})),
		)
	) or 0
	verified_jobs = db.scalar(
		select(func.count()).select_from(CentralJobRecord).where(
			CentralJobRecord.agent_id == agent.agent_id,
			CentralJobRecord.final_status == "VERIFIED",
		)
	) or 0
	return {
		"agent_id": agent.agent_id,
		"display_name": agent.display_name,
		"hostname": agent.hostname,
		"platform": agent.platform,
		"architecture": agent.architecture,
		"agent_version": agent.agent_version,
		"api_version": agent.api_version,
		"agent_protocol_version": agent.agent_protocol_version,
		"status": derived_agent_status(agent),
		"last_seen_at": _iso(agent.last_seen_at),
		"created_at": _iso(agent.created_at),
		"updated_at": _iso(agent.updated_at),
		"enrolled_at": _iso(agent.enrolled_at),
		"revoked_at": _iso(agent.revoked_at),
		"metadata_json": agent.metadata_json or {},
		"asset_count": asset_count,
		"active_jobs": active_jobs,
		"verified_jobs": verified_jobs,
	}


def _asset_dict(asset: AgentAssetRecord) -> dict[str, Any]:
	return {
		"id": asset.id,
		"agent_id": asset.agent_id,
		"hardware_identity": asset.hardware_identity,
		"device_path": asset.device_path,
		"device_type": asset.device_type,
		"model": asset.model,
		"serial_number": asset.serial_number,
		"identity_confidence": asset.identity_confidence,
		"size_bytes": asset.size_bytes,
		"profile_json": asset.profile_json or {},
		"observations_json": asset.observations_json or [],
		"first_seen_at": _iso(asset.first_seen_at),
		"last_seen_at": _iso(asset.last_seen_at),
	}


def _job_dict(job: CentralJobRecord, db: Session) -> dict[str, Any]:
	events = db.execute(
		select(CentralJobEventRecord).where(CentralJobEventRecord.central_job_id == job.central_job_id).order_by(CentralJobEventRecord.sequence)
	).scalars().all()
	return {
		"central_job_id": job.central_job_id,
		"agent_id": job.agent_id,
		"asset_id": job.asset_id,
		"target_identity": job.target_identity,
		"requested_target": job.requested_target,
		"requested_by": job.requested_by,
		"dry_run": job.dry_run,
		"status": job.status,
		"local_execution_state": job.local_execution_state,
		"final_status": job.final_status,
		"progress": job.progress_json,
		"created_at": _iso(job.created_at),
		"claimed_at": _iso(job.claimed_at),
		"started_at": _iso(job.started_at),
		"finished_at": _iso(job.finished_at),
		"updated_at": _iso(job.updated_at),
		"expires_at": _iso(job.expires_at),
		"local_job_id": job.local_job_id,
		"request": job.request_json or {},
		"result": job.result_json,
		"error": job.error_json,
		"idempotency_key": job.idempotency_key,
		"nonce": job.nonce,
		"integrity_status": job.integrity_status,
		"execution_mode": (job.request_json or {}).get("execution_mode", "normal_local"),
		"events": [
			{
				"sequence": event.sequence,
				"local_job_id": event.local_job_id,
				"state": event.state,
				"timestamp": event.timestamp,
				"message": event.message,
				"progress": event.progress_json,
			}
			for event in events
		],
	}


def _hardware_identity(device: dict[str, Any], agent_id: str) -> tuple[str, str]:
	capabilities = device.get("capabilities") if isinstance(device.get("capabilities"), dict) else {}
	for key in ("nvme_nguid", "nvme_eui64", "wwn"):
		value = str(device.get(key) or capabilities.get(key) or "").strip().lower()
		if value:
			return hashlib.sha256(f"{key}:{value}".encode("utf-8")).hexdigest(), "HIGH"
	serial = str(device.get("serial_number") or "").strip().lower()
	model = str(device.get("model") or "").strip().lower()
	size = str(device.get("size_bytes") or "")
	stable = f"serial:{serial}|model:{model}|size:{size}" if serial else (
		f"fallback:{agent_id}|model:{model}|size:{size}|type:{device.get('device_type') or ''}|path:{device.get('device_path') or ''}"
	)
	return hashlib.sha256(stable.encode("utf-8")).hexdigest(), "HIGH" if serial else "LOW"


@router.post("/agents/enrollment-tokens", response_model=EnrollmentTokenRead)
def create_enrollment_token(payload: EnrollmentTokenCreate, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	token = new_token("enroll")
	expires_at = utc_now() + timedelta(seconds=payload.ttl_seconds)
	db.add(EnrollmentTokenRecord(id=str(uuid4()), token_hash=token_hash(token), expires_at=expires_at))
	record_audit_event(db, actor=principal.audit_identity, action="ENROLLMENT_TOKEN_CREATED", resource="agent-enrollment",
		metadata={"expires_at": _iso(expires_at)})
	db.commit()
	return {"token": token, "expires_at": expires_at, "single_use": True}


@router.post("/agents/enroll", response_model=AgentEnrollResponse)
def enroll_agent(payload: AgentEnrollRequest, db: Session = Depends(get_db)):
	require_protocol(payload.agent_protocol_version)
	now = utc_now()
	record = db.execute(select(EnrollmentTokenRecord).where(EnrollmentTokenRecord.token_hash == token_hash(payload.enrollment_token))).scalar_one_or_none()
	if record is None or record.consumed_at is not None:
		raise HTTPException(status_code=409, detail="Enrollment token is invalid or already used.")
	expires = record.expires_at.replace(tzinfo=record.expires_at.tzinfo or now.tzinfo)
	if expires <= now:
		raise HTTPException(status_code=410, detail="Enrollment token has expired.")
	agent_id = str(uuid4())
	agent_token = new_token("agent")
	agent = AgentRecord(
		agent_id=agent_id,
		display_name=payload.display_name or payload.hostname,
		hostname=payload.hostname,
		platform=payload.platform,
		architecture=payload.architecture,
		agent_version=payload.agent_version,
		api_version=payload.api_version,
		agent_protocol_version=payload.agent_protocol_version,
		status="OFFLINE",
		enrolled_at=now,
		metadata_json={},
		token_hash=token_hash(agent_token),
	)
	claimed = db.execute(
		update(EnrollmentTokenRecord).where(
			EnrollmentTokenRecord.id == record.id,
			EnrollmentTokenRecord.consumed_at.is_(None),
			EnrollmentTokenRecord.expires_at > now,
		).values(consumed_at=now, consumed_by_agent_id=agent_id).execution_options(synchronize_session=False)
	)
	if claimed.rowcount != 1:
		db.rollback()
		raise HTTPException(status_code=409, detail="Enrollment token was already consumed.")
	db.add(agent)
	record_audit_event(db, actor=f"enrollment-token:{record.id}", action="AGENT_ENROLLED", resource=f"agent:{agent_id}",
		metadata={"hostname": payload.hostname, "platform": payload.platform, "architecture": payload.architecture})
	try:
		db.commit()
	except IntegrityError as exc:
		db.rollback()
		raise HTTPException(status_code=409, detail="Enrollment token was already consumed.") from exc
	return {"agent_id": agent_id, "agent_token": agent_token, "agent_protocol_version": AGENT_PROTOCOL_VERSION}


@router.get("/agents", dependencies=[Depends(_OPERATOR_READ)])
def list_agents(db: Session = Depends(get_db)):
	return [_agent_dict(agent, db) for agent in db.execute(select(AgentRecord).order_by(AgentRecord.created_at.desc())).scalars()]


@router.post("/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	agent = db.get(AgentRecord, agent_id)
	if agent is None:
		raise HTTPException(status_code=404, detail="Agent not found.")
	agent.revoked_at = utc_now()
	agent.status = "REVOKED"
	record_audit_event(db, actor=principal.audit_identity, action="AGENT_REVOKED", resource=f"agent:{agent_id}")
	db.commit()
	return _agent_dict(agent, db)


@router.post("/agent/heartbeat")
def heartbeat(payload: AgentHeartbeat, agent: AgentRecord = Depends(authenticated_agent), db: Session = Depends(get_db)):
	require_protocol(payload.agent_protocol_version)
	agent.last_seen_at = utc_now()
	agent.status = "ONLINE"
	agent.hostname = payload.hostname
	agent.platform = payload.platform
	agent.architecture = payload.architecture
	agent.agent_version = payload.agent_version
	agent.api_version = payload.api_version
	agent.metadata_json = {"active_job_count": payload.active_job_count, "local_status": payload.local_status}
	db.commit()
	return {"agent_id": agent.agent_id, "status": "ONLINE", "server_time": _iso(agent.last_seen_at)}


@router.put("/agent/inventory")
def upload_inventory(payload: InventoryUpload, agent: AgentRecord = Depends(authenticated_agent), db: Session = Depends(get_db)):
	require_protocol(payload.agent_protocol_version)
	for model in payload.devices:
		device = model.model_dump()
		identity, identity_confidence = _hardware_identity(device, agent.agent_id)
		asset = db.execute(
			select(AgentAssetRecord).where(AgentAssetRecord.agent_id == agent.agent_id, AgentAssetRecord.hardware_identity == identity)
		).scalar_one_or_none()
		observation = {"inventory_version": payload.inventory_version, "observed_at": _iso(payload.observed_at), "device_path": device["device_path"]}
		if asset is None:
			asset = AgentAssetRecord(
				id=str(uuid4()), agent_id=agent.agent_id, hardware_identity=identity,
				device_path=device["device_path"], device_type=device["device_type"], model=device.get("model"),
				serial_number=device.get("serial_number"), identity_confidence=identity_confidence,
				size_bytes=device.get("size_bytes"), profile_json=device,
				observations_json=[observation], first_seen_at=payload.observed_at, last_seen_at=payload.observed_at,
			)
			db.add(asset)
		else:
			asset.device_path = device["device_path"]
			asset.device_type = device["device_type"]
			asset.model = device.get("model")
			asset.serial_number = device.get("serial_number")
			asset.identity_confidence = identity_confidence
			asset.size_bytes = device.get("size_bytes")
			asset.profile_json = device
			asset.last_seen_at = payload.observed_at
			observations = list(asset.observations_json or [])
			if observation not in observations:
				observations.append(observation)
			asset.observations_json = observations
	record_audit_event(db, actor=f"agent:{agent.agent_id}", action="INVENTORY_SYNCHRONIZED", resource=f"agent:{agent.agent_id}",
		metadata={"inventory_version": payload.inventory_version, "device_count": len(payload.devices)})
	db.commit()
	assets = db.execute(select(AgentAssetRecord).where(AgentAssetRecord.agent_id == agent.agent_id)).scalars().all()
	return {"agent_id": agent.agent_id, "inventory_version": payload.inventory_version, "asset_count": len(assets)}


@router.get("/agents/{agent_id}/assets", dependencies=[Depends(_OPERATOR_READ)])
def list_agent_assets(agent_id: str, db: Session = Depends(get_db)):
	return [_asset_dict(asset) for asset in db.execute(select(AgentAssetRecord).where(AgentAssetRecord.agent_id == agent_id)).scalars()]


@router.post("/agents/{agent_id}/jobs", status_code=201)
def create_central_job(agent_id: str, payload: CentralJobCreate, principal: OperatorPrincipal = Depends(_OPERATOR_WRITE), db: Session = Depends(get_db)):
	agent = db.get(AgentRecord, agent_id)
	asset = db.get(AgentAssetRecord, payload.asset_id)
	if agent is None or agent.revoked_at is not None:
		raise HTTPException(status_code=404, detail="Active agent not found.")
	if asset is None or asset.agent_id != agent_id:
		raise HTTPException(status_code=422, detail="Asset does not belong to the selected agent.")
	if payload.execution_mode == "boot_sanitize" and (asset.profile_json or {}).get("is_system_device") is not True:
		raise HTTPException(status_code=422, detail="Boot sanitization requires a synchronized system-disk asset.")
	if not payload.dry_run and not payload.central_authorized:
		raise HTTPException(status_code=403, detail="Central destructive authorization is required.")
	if not payload.dry_run and payload.destructive_confirmation != "SANITIZE":
		raise HTTPException(status_code=422, detail="Destructive confirmation must exactly equal SANITIZE.")
	if not payload.dry_run and not principal.development_identity and principal.mfa_assurance not in {"TOTP", "RECOVERY"}:
		raise HTTPException(status_code=403, detail="An MFA-authenticated operator session is required for destructive central jobs.")
	profile = asset.profile_json or {}
	if payload.execution_mode == "normal_local" and not payload.dry_run and (
		profile.get("is_system_device") is True
		or profile.get("mounted") is not False
		or profile.get("eligible_for_sanitization") is not True
	):
		raise HTTPException(status_code=422, detail="The synchronized asset is not currently eligible for destructive sanitization.")
	existing = db.execute(
		select(CentralJobRecord).where(CentralJobRecord.agent_id == agent_id, CentralJobRecord.idempotency_key == payload.idempotency_key)
	).scalar_one_or_none()
	if existing is not None:
		return _job_dict(existing, db)
	now = utc_now()
	job = CentralJobRecord(
		central_job_id=str(uuid4()), agent_id=agent_id, asset_id=asset.id,
		target_identity=asset.hardware_identity, requested_target=asset.device_path, dry_run=payload.dry_run,
		requested_by_user_id=principal.user_id, requested_by=principal.audit_identity,
		authorization_json={"central_approved": payload.central_authorized,
			"local_approval_required": not payload.dry_run or payload.execution_mode == "boot_sanitize"},
		status="QUEUED", created_at=now, updated_at=now,
		expires_at=now + timedelta(seconds=payload.expires_in_seconds),
		request_json={"asset_id": asset.id, "dry_run": payload.dry_run, "execution_mode": payload.execution_mode,
			"target_observed_at_request": asset.device_path,
			"identity_confidence": asset.identity_confidence},
		idempotency_key=payload.idempotency_key, nonce=new_token("job"),
	)
	db.add(job)
	record_audit_event(db, actor=principal.audit_identity, action="REMOTE_JOB_REQUESTED", resource=f"central-job:{job.central_job_id}",
		metadata={"agent_id": agent_id, "asset_id": asset.id, "target_identity": asset.hardware_identity,
			"requested_target": asset.device_path, "dry_run": payload.dry_run})
	try:
		db.commit()
	except IntegrityError as exc:
		db.rollback()
		existing = db.execute(
			select(CentralJobRecord).where(
				CentralJobRecord.agent_id == agent_id,
				CentralJobRecord.idempotency_key == payload.idempotency_key,
			)
		).scalar_one_or_none()
		if existing is None:
			raise HTTPException(status_code=409, detail="Central job creation conflicted with an existing record.") from exc
		return _job_dict(existing, db)
	return _job_dict(job, db)


@router.get("/central-jobs", dependencies=[Depends(_OPERATOR_READ)])
def list_central_jobs(db: Session = Depends(get_db)):
	return [_job_dict(job, db) for job in db.execute(select(CentralJobRecord).order_by(CentralJobRecord.created_at.desc())).scalars()]


@router.get("/agent/jobs/next")
def claim_next_job(response: Response, agent: AgentRecord = Depends(authenticated_agent), db: Session = Depends(get_db)):
	now = utc_now()
	expired = db.execute(select(CentralJobRecord).where(
		CentralJobRecord.agent_id == agent.agent_id, CentralJobRecord.status == "QUEUED", CentralJobRecord.expires_at <= now,
	)).scalars().all()
	for job in expired:
		job.status = "EXPIRED"
		job.updated_at = now
	job = db.execute(select(CentralJobRecord).where(
		CentralJobRecord.agent_id == agent.agent_id, CentralJobRecord.status == "QUEUED", CentralJobRecord.expires_at > now,
	).order_by(CentralJobRecord.created_at)).scalars().first()
	if job is None:
		db.commit()
		response.status_code = status.HTTP_204_NO_CONTENT
		return None
	execution_mode = (job.request_json or {}).get("execution_mode", "normal_local")
	claimed_status = "WAITING_LOCAL_APPROVAL" if execution_mode == "boot_sanitize" or not job.dry_run else "CLAIMED"
	updated = db.execute(update(CentralJobRecord).where(
		CentralJobRecord.central_job_id == job.central_job_id, CentralJobRecord.status == "QUEUED",
	).values(status=claimed_status, claimed_at=now, updated_at=now))
	db.commit()
	if updated.rowcount != 1:
		response.status_code = status.HTTP_204_NO_CONTENT
		return None
	db.refresh(job)
	return {
		"agent_protocol_version": AGENT_PROTOCOL_VERSION,
		"central_job_id": job.central_job_id,
		"target_identity": job.target_identity,
		"requested_target": job.requested_target,
		"dry_run": job.dry_run,
		"authorization_policy": job.authorization_json,
		"expires_at": _iso(job.expires_at),
		"nonce": job.nonce,
		"idempotency_key": job.idempotency_key,
		"status": job.status,
		"execution_mode": (job.request_json or {}).get("execution_mode", "normal_local"),
	}


def _owned_job(db: Session, central_job_id: str, agent: AgentRecord) -> CentralJobRecord:
	job = db.get(CentralJobRecord, central_job_id)
	if job is None or job.agent_id != agent.agent_id:
		raise HTTPException(status_code=404, detail="Central job not found for authenticated agent.")
	return job


@router.post("/agent/jobs/{central_job_id}/events")
def upload_event(central_job_id: str, payload: AgentJobEventUpload, agent: AgentRecord = Depends(authenticated_agent), db: Session = Depends(get_db)):
	require_protocol(payload.agent_protocol_version)
	job = _owned_job(db, central_job_id, agent)
	existing = db.execute(select(CentralJobEventRecord).where(
		CentralJobEventRecord.central_job_id == central_job_id, CentralJobEventRecord.sequence == payload.sequence,
	)).scalar_one_or_none()
	if existing is not None:
		if (
			existing.local_job_id != payload.local_job_id
			or existing.state != payload.state
			or existing.timestamp != payload.timestamp
			or existing.message != payload.message
			or existing.progress_json != payload.progress
		):
			raise HTTPException(status_code=409, detail="Event sequence was already used by a different payload.")
		return {"accepted": True, "duplicate": True, "sequence": payload.sequence}
	if job.local_job_id is not None and job.local_job_id != payload.local_job_id:
		raise HTTPException(status_code=409, detail="Local job ID does not match the central job mapping.")
	maximum = db.scalar(select(func.max(CentralJobEventRecord.sequence)).where(CentralJobEventRecord.central_job_id == central_job_id)) or 0
	if payload.sequence != maximum + 1:
		raise HTTPException(status_code=409, detail={"reason": "OUT_OF_ORDER", "expected_sequence": maximum + 1})
	db.add(CentralJobEventRecord(
		id=str(uuid4()), central_job_id=central_job_id, local_job_id=payload.local_job_id,
		sequence=payload.sequence, state=payload.state, timestamp=payload.timestamp,
		message=payload.message, progress_json=payload.progress,
	))
	job.local_job_id = payload.local_job_id
	job.local_execution_state = payload.state
	job.progress_json = payload.progress
	job.updated_at = utc_now()
	if payload.state == "RUNNING":
		job.status = "RUNNING"
		job.started_at = job.started_at or utc_now()
	elif payload.state == "VERIFYING":
		job.status = "VERIFYING"
	elif payload.state in {"PREPARING_BOOT", "AWAITING_REBOOT", "BOOT_ENVIRONMENT_STARTED", "VALIDATING_TARGET", "WAITING_LOCAL_APPROVAL"}:
		job.status = payload.state
	record_audit_event(db, actor=f"agent:{agent.agent_id}", action="JOB_EVENT_ACCEPTED", resource=f"central-job:{central_job_id}",
		metadata={"local_job_id": payload.local_job_id, "sequence": payload.sequence, "state": payload.state})
	db.commit()
	return {"accepted": True, "duplicate": False, "sequence": payload.sequence}


@router.post("/agent/jobs/{central_job_id}/result")
def upload_result(central_job_id: str, payload: AgentJobResultUpload, agent: AgentRecord = Depends(authenticated_agent), db: Session = Depends(get_db)):
	require_protocol(payload.agent_protocol_version)
	job = _owned_job(db, central_job_id, agent)
	if job.result_idempotency_key == payload.idempotency_key and job.result_json is not None:
		_index_accepted_sanitization_certificate(db, job, job.result_json)
		db.commit()
		return {"accepted": True, "duplicate": True, "central_job_id": central_job_id, "final_status": job.final_status}
	if job.result_json is not None and job.result_idempotency_key != payload.idempotency_key:
		raise HTTPException(status_code=409, detail="A final result already exists with a different idempotency key.")
	if job.local_job_id is not None and job.local_job_id != payload.local_job_id:
		raise HTTPException(status_code=409, detail="Local job ID does not match the central job mapping.")
	result = payload.model_dump()
	if contains_unredacted_secret(result):
		raise HTTPException(status_code=422, detail="Secret-bearing fields are not accepted in central results.")
	if payload.job_state not in _TERMINAL or payload.final_status not in _TERMINAL:
		raise HTTPException(status_code=422, detail="Final upload must contain terminal states.")
	if payload.job_state != payload.final_status:
		raise HTTPException(status_code=422, detail="Terminal job_state and final_status must agree.")
	evidence = payload.evidence or {}
	certificate = payload.certificate or {}
	integrity_ok, _integrity_error = validate_result_integrity(result)
	if not integrity_ok:
		job.status = "INCONCLUSIVE"
		job.final_status = "INCONCLUSIVE"
		job.integrity_status = "QUARANTINED"
		job.error_json = {"code": "INTEGRITY_REJECTED", "message": "Final result failed structural or integrity validation."}
		job.updated_at = utc_now()
		record_audit_event(db, actor=f"agent:{agent.agent_id}", action="RESULT_QUARANTINED", resource=f"central-job:{central_job_id}",
			metadata={"local_job_id": payload.local_job_id, "claimed_status": payload.final_status})
		db.commit()
		raise HTTPException(status_code=422, detail="Final result failed structural or integrity validation and was quarantined.")
	job.local_job_id = payload.local_job_id
	job.local_execution_state = payload.job_state
	job.status = payload.final_status
	job.final_status = payload.final_status
	job.result_json = result
	job.result_idempotency_key = payload.idempotency_key
	job.finished_at = utc_now()
	job.updated_at = job.finished_at
	job.integrity_status = "VALID" if evidence.get("integrity_hash") or certificate.get("certificate_hash") else "NOT_PROVIDED"
	_index_accepted_sanitization_certificate(db, job, result)
	record_audit_event(db, actor=f"agent:{agent.agent_id}", action="RESULT_ACCEPTED", resource=f"central-job:{central_job_id}",
		metadata={"local_job_id": payload.local_job_id, "final_status": payload.final_status,
			"integrity_status": job.integrity_status})
	db.commit()
	return {"accepted": True, "duplicate": False, "central_job_id": central_job_id, "final_status": job.final_status}
