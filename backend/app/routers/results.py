from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_global_scope
from ..db import get_db
from ..models import ResultRecord
from ..schemas import ResultRead
from ..services import result_to_dict

router = APIRouter(tags=["results"], dependencies=[Depends(require_global_scope)])


@router.get("", response_model=list[ResultRead])
def list_results(db: Session = Depends(get_db)):
	results = db.execute(select(ResultRecord).order_by(ResultRecord.created_at.desc())).scalars().all()
	return [result_to_dict(result) for result in results]


@router.get("/{job_id}", response_model=ResultRead)
def get_result(job_id: str, db: Session = Depends(get_db)):
	result = db.execute(select(ResultRecord).where(ResultRecord.job_id == job_id)).scalar_one_or_none()
	if result is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found.")
	return result_to_dict(result)
