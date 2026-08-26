from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_api_key
from ..db import get_db
from ..models import JobRecord
from ..schemas import JobRead, SanitizeJobCreate
from ..services import job_to_dict, persist_job

router = APIRouter(tags=["jobs"], dependencies=[Depends(require_api_key)])


@router.post("/sanitize", response_model=JobRead, status_code=status.HTTP_201_CREATED)
def create_sanitization_job(payload: SanitizeJobCreate, request: Request, db: Session = Depends(get_db)):
	agent_gateway = request.app.state.agent_gateway
	authorization = payload.authorization.model_dump(exclude_none=True)
	agent_api_key = request.headers.get("X-VYPER-Agent-API-Key") or request.headers.get("X-VYPER-API-Key")
	agent_device_id = request.headers.get("X-VYPER-Agent-Device-Id")
	if agent_api_key:
		authorization["agent_api_key"] = agent_api_key
	if agent_device_id:
		authorization["agent_device_id"] = agent_device_id
	result = agent_gateway.dispatch(target=payload.target, authorization=authorization, dry_run=payload.dry_run)
	job = persist_job(db, result=result, authorization=authorization, requested_dry_run=payload.dry_run, actor=request.headers.get("X-VYPER-Actor"))
	db.commit()
	db.refresh(job)
	return job_to_dict(job)


@router.get("", response_model=list[JobRead])
def list_jobs(db: Session = Depends(get_db)):
	jobs = db.execute(select(JobRecord).order_by(JobRecord.created_at.desc())).scalars().all()
	return [job_to_dict(job) for job in jobs]


@router.get("/{job_id}", response_model=JobRead)
def get_job(job_id: str, db: Session = Depends(get_db)):
	job = db.get(JobRecord, job_id)
	if job is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
	return job_to_dict(job)
