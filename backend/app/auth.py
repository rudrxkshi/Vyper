from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from fastapi import Cookie, Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import OperatorSessionRecord, UserRecord
from .security import production_mode, token_digest


class OperatorRole(str, Enum):
	ADMIN = "ADMIN"
	OPERATOR = "OPERATOR"
	AUDITOR = "AUDITOR"


@dataclass(frozen=True)
class OperatorPrincipal:
	user_id: str | None
	username: str
	role: OperatorRole
	development_identity: bool = False

	@property
	def audit_identity(self) -> str:
		return f"operator:{self.username}"


api_key_header = APIKeyHeader(name="X-VYPER-API-Key", auto_error=False)
bearer = HTTPBearer(auto_error=False)


def _session_principal(token: str | None, db: Session) -> OperatorPrincipal | None:
	if not token:
		return None
	now = datetime.now(timezone.utc)
	record = db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.token_hash == token_digest(token))).scalar_one_or_none()
	if record is None or record.revoked_at is not None:
		return None
	expires = record.expires_at.replace(tzinfo=record.expires_at.tzinfo or timezone.utc)
	if expires <= now:
		return None
	user = db.get(UserRecord, record.user_id)
	if user is None or user.disabled_at is not None:
		return None
	record.last_seen_at = now
	return OperatorPrincipal(user.id, user.username, OperatorRole(user.role))


def require_api_key(
	request: Request, db: Session = Depends(get_db),
	session_cookie: str | None = Cookie(default=None, alias="vyper_session"),
	credentials: HTTPAuthorizationCredentials | None = Security(bearer),
	api_key: str | None = Security(api_key_header),
) -> OperatorPrincipal:
	token = session_cookie or (credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else None)
	principal = _session_principal(token, db)
	if principal:
		request.state.operator = principal
		return principal

	# Explicitly development-only compatibility. It is impossible to enable in production.
	if not production_mode():
		expected = os.getenv("VYPER_API_KEY")
		if expected and api_key and hmac.compare_digest(api_key, expected):
			principal = OperatorPrincipal(None, "development-api-key", OperatorRole.ADMIN, True)
			request.state.operator = principal
			return principal
		if os.getenv("VYPER_DEV_ANONYMOUS_OPERATOR", "true").lower() in {"1", "true", "yes"}:
			principal = OperatorPrincipal(None, "development-anonymous", OperatorRole.ADMIN, True)
			request.state.operator = principal
			return principal
	raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Operator authentication is required.")


def require_roles(*roles: OperatorRole) -> Callable:
	def dependency(principal: OperatorPrincipal = Depends(require_api_key)) -> OperatorPrincipal:
		if principal.role not in roles:
			raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator role is not authorized for this action.")
		return principal
	return dependency
