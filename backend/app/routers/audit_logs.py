from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import OperatorRole, require_roles
from ..db import get_db
from ..models import AuditLogRecord
from ..schemas import AuditLogRead
from ..services import audit_log_to_dict

router = APIRouter(tags=["audit-logs"], dependencies=[Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN, OperatorRole.SECURITY_ADMIN, OperatorRole.OPERATOR, OperatorRole.AUDITOR, OperatorRole.VIEWER))])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(db: Session = Depends(get_db)):
	audit_logs = db.execute(select(AuditLogRecord).order_by(AuditLogRecord.created_at.desc())).scalars().all()
	return [audit_log_to_dict(audit_log) for audit_log in audit_logs]
