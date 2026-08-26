from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import OperatorPrincipal, OperatorRole, organization_ids, require_roles
from ..db import get_db
from ..models import SecurityEventRecord


router = APIRouter(tags=["security-events"], dependencies=[Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN, OperatorRole.SECURITY_ADMIN, OperatorRole.OPERATOR, OperatorRole.AUDITOR, OperatorRole.VIEWER))])


def _event_dict(record: SecurityEventRecord) -> dict:
	return {
		"id": record.id,
		"event_type": record.event_type,
		"severity": record.severity,
		"actor": record.actor,
		"resource": record.resource,
		"agent_id": record.agent_id,
		"central_job_id": record.central_job_id,
		"organization_id": record.organization_id,
		"metadata_json": record.metadata_json or {},
		"created_at": record.created_at,
	}


@router.get("")
def list_security_events(principal: OperatorPrincipal = Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN, OperatorRole.SECURITY_ADMIN, OperatorRole.OPERATOR, OperatorRole.AUDITOR, OperatorRole.VIEWER)), db: Session = Depends(get_db)):
	scope = organization_ids(db, principal)
	query = select(SecurityEventRecord).order_by(SecurityEventRecord.created_at.desc())
	if scope is not None:
		query = query.where(SecurityEventRecord.organization_id.in_(scope))
	records = db.execute(query).scalars().all()
	return [_event_dict(record) for record in records]
