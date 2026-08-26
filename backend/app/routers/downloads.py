from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse


router = APIRouter(prefix="/downloads", tags=["downloads"])


def release_directory() -> Path:
	configured = os.getenv("VYPER_RELEASE_DIRECTORY")
	return Path(configured) if configured else Path(__file__).resolve().parents[3] / "release"


def load_release_manifest() -> dict | None:
	manifest_path = Path(os.getenv("VYPER_RELEASE_MANIFEST") or release_directory() / "manifest.json")
	try:
		payload = json.loads(manifest_path.read_text(encoding="utf-8"))
	except (OSError, ValueError):
		return None
	required = {"version", "platform", "architecture", "filename", "sha256", "size_bytes", "download_url"}
	return payload if required.issubset(payload) else None


@router.get("")
def list_downloads():
	manifest = load_release_manifest()
	if manifest is None:
		return []
	artifact = release_directory() / Path(manifest["filename"]).name
	if not artifact.is_file():
		return []
	return [manifest]


@router.get("/{filename}")
def download_artifact(filename: str):
	manifest = load_release_manifest()
	if manifest is None or filename != manifest.get("filename") or Path(filename).name != filename:
		raise HTTPException(status_code=404, detail="Release artifact not found.")
	artifact = release_directory() / filename
	if not artifact.is_file():
		raise HTTPException(status_code=404, detail="Release artifact not found.")
	return FileResponse(artifact, media_type="application/gzip", filename=filename)
