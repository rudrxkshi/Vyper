from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_global_scope
from ..db import get_db
from ..models import AssetRecord
from ..schemas import AssetRead
from ..services import asset_to_dict

router = APIRouter(tags=["assets"], dependencies=[Depends(require_global_scope)])


@router.get("", response_model=list[AssetRead])
def list_assets(response: Response, db: Session = Depends(get_db)):
	"""Return persisted asset history; this is not live local device discovery."""
	response.headers["X-VYPER-Inventory-Source"] = "persisted-assets"
	assets = db.execute(select(AssetRecord).order_by(AssetRecord.updated_at.desc().nullslast(), AssetRecord.created_at.desc())).scalars().all()
	return [asset_to_dict(asset) for asset in assets]


@router.get("/{device_path:path}", response_model=AssetRead)
def get_asset(device_path: str, db: Session = Depends(get_db)):
	asset = db.execute(select(AssetRecord).where(AssetRecord.device_path == f"/{device_path.lstrip('/')}" )).scalar_one_or_none()
	if asset is None:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
	return asset_to_dict(asset)
