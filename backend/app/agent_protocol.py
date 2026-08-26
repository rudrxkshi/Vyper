from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import AgentRecord


AGENT_PROTOCOL_VERSION = "1"
_bearer = HTTPBearer(auto_error=False)


def utc_now() -> datetime:
	return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
	pepper = os.getenv("VYPER_AGENT_TOKEN_PEPPER", "")
	return hashlib.sha256(f"{pepper}:{token}".encode("utf-8")).hexdigest()


def new_token(prefix: str) -> str:
	return f"{prefix}_{secrets.token_urlsafe(32)}"


def require_protocol(version: str) -> None:
	if str(version) != AGENT_PROTOCOL_VERSION:
		raise HTTPException(status_code=409, detail="Incompatible agent protocol version.")


def authenticated_agent(
	credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
	db: Session = Depends(get_db),
) -> AgentRecord:
	if credentials is None or credentials.scheme.lower() != "bearer":
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent authentication required.")
	digest = token_hash(credentials.credentials)
	agent = db.execute(select(AgentRecord).where(AgentRecord.token_hash == digest)).scalar_one_or_none()
	if agent is None or not hmac.compare_digest(agent.token_hash, digest):
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credential.")
	if agent.revoked_at is not None or agent.status == "REVOKED":
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent credential has been revoked.")
	return agent


def derived_agent_status(agent: AgentRecord, *, timeout_seconds: int | None = None) -> str:
	if agent.revoked_at is not None or agent.status == "REVOKED":
		return "REVOKED"
	if agent.last_seen_at is None:
		return "OFFLINE"
	timeout = timeout_seconds or int(os.getenv("VYPER_AGENT_OFFLINE_SECONDS", "60"))
	last_seen = agent.last_seen_at
	if last_seen.tzinfo is None:
		last_seen = last_seen.replace(tzinfo=timezone.utc)
	return "ONLINE" if utc_now() - last_seen <= timedelta(seconds=timeout) else "OFFLINE"


def contains_unredacted_secret(value: Any, parent_key: str = "") -> bool:
	markers = ("password", "secret", "token", "credential", "passphrase", "authorization")
	if isinstance(value, dict):
		for key, item in value.items():
			key_text = str(key).lower()
			if any(marker in key_text for marker in markers) and item not in (None, "", "<redacted>", False):
				return True
			if contains_unredacted_secret(item, key_text):
				return True
	elif isinstance(value, (list, tuple)):
		return any(contains_unredacted_secret(item, parent_key) for item in value)
	return False
