from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable

from fastapi import Cookie, Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import OperatorSessionRecord, OrganizationMembershipRecord, UserRecord
from .security import production_mode, token_digest


class OperatorRole(str, Enum):
	SUPER_ADMIN = "SUPER_ADMIN"
	ADMIN = "ADMIN"
	SECURITY_ADMIN = "SECURITY_ADMIN"
	OPERATOR = "OPERATOR"
	AUDITOR = "AUDITOR"
	VIEWER = "VIEWER"


@dataclass(frozen=True)
class OperatorPrincipal:
	user_id: str | None
	username: str
	role: OperatorRole
	development_identity: bool = False
	mfa_assurance: str = "PASSWORD"

	@property
	def audit_identity(self) -> str:
		return f"operator:{self.username}"


from agent.credentials import AgentCredentialStore

api_key_header = APIKeyHeader(name="X-VYPER-API-Key", auto_error=False)
bearer = HTTPBearer(auto_error=False)


def _local_agent_api_key() -> str | None:
    credentials = AgentCredentialStore().load()
    return credentials.api_key if credentials else None


def _session_principal(token: str | None, db: Session) -> OperatorPrincipal | None:
	if not token:
		return None
	now = datetime.now(timezone.utc)
	record = db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.token_hash == token_digest(token))).scalar_one_or_none()
	if record is None or record.revoked_at is not None:
		return None
	expires = record.expires_at.replace(tzinfo=record.expires_at.tzinfo or timezone.utc)
	absolute = record.absolute_expires_at.replace(tzinfo=record.absolute_expires_at.tzinfo or timezone.utc)
	idle_seconds = int(os.getenv("VYPER_SESSION_IDLE_SECONDS", "1800"))
	last_seen = record.last_seen_at.replace(tzinfo=record.last_seen_at.tzinfo or timezone.utc)
	if expires <= now or absolute <= now or last_seen + timedelta(seconds=idle_seconds) <= now:
		record.revoked_at = now
		return None
	user = db.get(UserRecord, record.user_id)
	if user is None or user.disabled_at is not None:
		return None
	record.last_seen_at = now
	return OperatorPrincipal(user.id, user.username, OperatorRole(user.role), False, record.mfa_assurance)


def require_api_key(
	request: Request, db: Session = Depends(get_db),
	session_cookie: str | None = Cookie(default=None, alias="vyper_session"),
	credentials: HTTPAuthorizationCredentials | None = Security(bearer),
	api_key: str | None = Security(api_key_header),
) -> OperatorPrincipal:
	token = session_cookie or (credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else None)
	principal = _session_principal(token, db)
	if principal:
		if production_mode() and session_cookie and request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
			csrf = request.headers.get("X-CSRF-Token")
			record = db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.token_hash == token_digest(session_cookie))).scalar_one()
			if not csrf or not hmac.compare_digest(token_digest(csrf), record.csrf_token_hash):
				raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")
		request.state.operator = principal
		return principal

	# Explicitly development-only compatibility. It is impossible to enable in production.
	if not production_mode():
		expected = os.getenv("VYPER_API_KEY") or _local_agent_api_key()
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


def organization_ids(db: Session, principal: OperatorPrincipal) -> set[str] | None:
	"""Return the tenant scope for an operator; None is the explicit global scope."""
	if principal.development_identity or principal.role is OperatorRole.SUPER_ADMIN:
		return None
	if principal.user_id is None:
		return set()
	return set(db.execute(select(OrganizationMembershipRecord.organization_id).where(
		OrganizationMembershipRecord.user_id == principal.user_id,
		OrganizationMembershipRecord.disabled_at.is_(None),
	)).scalars())


def require_organization_access(db: Session, principal: OperatorPrincipal, organization_id: str | None) -> None:
	"""Fail closed for unassigned/legacy tenant resources outside global administration."""
	if organization_id is None:
		if organization_ids(db, principal) is None:
			return
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This legacy resource is not assigned to your organization.")
	scope = organization_ids(db, principal)
	if scope is not None and organization_id not in scope:
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator is not a member of this organization.")


def require_global_scope(principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)) -> OperatorPrincipal:
	"""Guard legacy records with no organization ownership until they are migrated."""
	if organization_ids(db, principal) is not None:
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This legacy resource is available only in the global scope.")
	return principal


def require_organization_manager(db: Session, principal: OperatorPrincipal, organization_id: str) -> None:
	"""Only global administrators or an organization's owner may change membership."""
	if organization_ids(db, principal) is None:
		return
	if principal.user_id is None or db.scalar(select(OrganizationMembershipRecord.role).where(
		OrganizationMembershipRecord.organization_id == organization_id,
		OrganizationMembershipRecord.user_id == principal.user_id,
		OrganizationMembershipRecord.disabled_at.is_(None),
	)) != "OWNER":
		raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organization ownership is required to manage membership.")
