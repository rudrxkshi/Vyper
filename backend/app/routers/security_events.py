from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import OperatorRole, require_roles
from ..db import get_db
from ..models import SecurityEventRecord


router = APIRouter(tags=["security-events"], dependencies=[Depends(require_roles(OperatorRole.ADMIN, OperatorRole.OPERATOR, OperatorRole.AUDITOR))])


def _event_dict(record: SecurityEventRecord) -> dict:
	return {
		"id": record.id,
		"event_type": record.event_type,
		"severity": record.severity,
		"actor": record.actor,
		"resource": record.resource,
		"agent_id": record.agent_id,
		"central_job_id": record.central_job_id,
		"metadata_json": record.metadata_json or {},
		"created_at": record.created_at,
	}


@router.get("")
def list_security_events(db: Session = Depends(get_db)):
	records = db.execute(select(SecurityEventRecord).order_by(SecurityEventRecord.created_at.desc())).scalars().all()
	return [_event_dict(record) for record in records]
