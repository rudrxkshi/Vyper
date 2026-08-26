from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_api_key
from ..db import get_db
from ..models import CentralCertificateRecord, CertificateRecord
from ..schemas import CertificateRead
from ..services import certificate_to_dict

router = APIRouter(tags=["certificates"], dependencies=[Depends(require_api_key)])


@router.get("", response_model=list[CertificateRead])
def list_certificates(db: Session = Depends(get_db)):
	certificates = list(db.execute(select(CertificateRecord)).scalars())
	certificates.extend(db.execute(select(CentralCertificateRecord)).scalars())
	certificates.sort(key=lambda certificate: certificate.created_at, reverse=True)
	return [certificate_to_dict(certificate) for certificate in certificates]


@router.get("/{certificate_id}", response_model=CertificateRead)
def get_certificate(certificate_id: str, db: Session = Depends(get_db)):
	certificate = db.execute(select(CertificateRecord).where(CertificateRecord.certificate_id == certificate_id)).scalar_one_or_none()
	if certificate is None:
		certificate = db.execute(select(CentralCertificateRecord).where(CentralCertificateRecord.certificate_id == certificate_id)).scalar_one_or_none()
	if certificate is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found.")
	return certificate_to_dict(certificate)
