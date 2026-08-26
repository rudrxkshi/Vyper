from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import OperatorPrincipal, OperatorRole, require_api_key, require_roles
from ..db import get_db
from ..models import LoginAttemptRecord, OperatorSessionRecord, UserRecord
from ..schemas import LoginRequest, MFACodeRequest, MFAEnrollRequest, UserCreate, UserRead, UserUpdate
from ..security import (
	decrypt_mfa_secret, encrypt_mfa_secret, hash_password, new_totp_secret, production_mode,
	record_audit_event, token_digest, verify_password, verify_totp,
)

router = APIRouter(tags=["authentication"])
SESSION_COOKIE = "vyper_session"
CSRF_COOKIE = "vyper_csrf"


def _now() -> datetime:
	return datetime.now(timezone.utc)


def _user_dict(user: UserRecord) -> dict:
	return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role,
		"disabled_at": user.disabled_at, "created_at": user.created_at}


def _issue_session(db: Session, response: Response, user: UserRecord, *, assurance: str, now: datetime) -> tuple[str, str]:
	token = secrets.token_urlsafe(48); csrf = secrets.token_urlsafe(32)
	idle_ttl = int(os.getenv("VYPER_SESSION_TTL_SECONDS", "28800"))
	absolute_ttl = int(os.getenv("VYPER_SESSION_ABSOLUTE_SECONDS", "86400"))
	db.add(OperatorSessionRecord(id=str(uuid4()), user_id=user.id, token_hash=token_digest(token), created_at=now,
		expires_at=now + timedelta(seconds=idle_ttl), absolute_expires_at=now + timedelta(seconds=absolute_ttl),
		last_seen_at=now, mfa_assurance=assurance, csrf_token_hash=token_digest(csrf)))
	response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=production_mode(), samesite="lax", max_age=idle_ttl, path="/")
	response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=production_mode(), samesite="strict", max_age=idle_ttl, path="/")
	return token, csrf


def _rotate_session(request: Request, response: Response, db: Session, user: UserRecord, assurance: str) -> str:
	now = _now(); token = request.cookies.get(SESSION_COOKIE)
	if token:
		record = db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.token_hash == token_digest(token))).scalar_one_or_none()
		if record: record.revoked_at = now
	_, csrf = _issue_session(db, response, user, assurance=assurance, now=now)
	return csrf


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
	now = _now()
	username = payload.username.strip().lower()
	remote = request.client.host if request.client else None
	window = now - timedelta(minutes=15)
	failures = db.scalar(select(func.count()).select_from(LoginAttemptRecord).where(
		LoginAttemptRecord.username == username, LoginAttemptRecord.succeeded.is_(False), LoginAttemptRecord.created_at >= window,
	)) or 0
	if failures >= int(os.getenv("VYPER_LOGIN_MAX_FAILURES", "5")):
		raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")
	user = db.execute(select(UserRecord).where(UserRecord.username == username)).scalar_one_or_none()
	succeeded = bool(user and user.disabled_at is None and verify_password(payload.password, user.password_hash))
	db.add(LoginAttemptRecord(id=str(uuid4()), username=username, remote_address=remote, succeeded=succeeded, created_at=now))
	record_audit_event(db, actor=f"operator:{username}" if succeeded else None, action="LOGIN_SUCCESS" if succeeded else "LOGIN_FAILURE",
		resource=f"user:{username}", metadata={"remote_address": remote}, request_id=getattr(request.state, "request_id", None))
	if not succeeded:
		db.commit()
		raise HTTPException(status_code=401, detail="Invalid username or password.")
	_, csrf = _issue_session(db, response, user, assurance="PASSWORD", now=now)
	db.commit()
	return {**_user_dict(user), "mfa_required": bool(user.mfa_enabled), "mfa_assurance": "PASSWORD", "csrf_token": csrf}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)):
	token = request.cookies.get(SESSION_COOKIE)
	if token:
		session = db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.token_hash == token_digest(token))).scalar_one_or_none()
		if session:
			session.revoked_at = _now()
	record_audit_event(db, actor=principal.audit_identity, action="LOGOUT", resource=f"user:{principal.username}", request_id=getattr(request.state, "request_id", None))
	db.commit()
	response.delete_cookie(SESSION_COOKIE, path="/", secure=production_mode(), httponly=True, samesite="lax")
	response.delete_cookie(CSRF_COOKIE, path="/", secure=production_mode(), httponly=False, samesite="strict")


@router.get("/auth/me")
def me(principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)):
	user = db.get(UserRecord, principal.user_id) if principal.user_id else None
	return {"id": principal.user_id, "username": principal.username, "role": principal.role.value, "mfa_assurance": principal.mfa_assurance,
		"mfa_required": bool(user and user.mfa_enabled and principal.mfa_assurance == "PASSWORD"),
		"development_identity": principal.development_identity}


@router.post("/auth/mfa/enroll")
def enroll_mfa(payload: MFAEnrollRequest, request: Request, principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)):
	user = db.get(UserRecord, principal.user_id)
	if user is None or not verify_password(payload.password, user.password_hash):
		raise HTTPException(status_code=401, detail="Password verification failed.")
	secret = new_totp_secret(); recovery_codes = [secrets.token_urlsafe(12) for _ in range(10)]
	user.mfa_secret_encrypted = encrypt_mfa_secret(secret); user.mfa_recovery_codes_json = [token_digest(code) for code in recovery_codes]
	user.mfa_enabled = False
	record_audit_event(db, actor=principal.audit_identity, action="MFA_ENROLLMENT_STARTED", resource=f"user:{user.username}",
		request_id=getattr(request.state, "request_id", None))
	db.commit()
	return {"secret": secret, "otpauth_uri": f"otpauth://totp/VYPER:{user.username}?secret={secret}&issuer=VYPER",
		"recovery_codes": recovery_codes, "warning": "These values are shown once."}


def _complete_mfa(code: str, request: Request, response: Response, principal: OperatorPrincipal, db: Session, *, enable: bool) -> dict:
	user = db.get(UserRecord, principal.user_id)
	if user is None or not user.mfa_secret_encrypted:
		raise HTTPException(status_code=409, detail="MFA enrollment is not available.")
	assurance = None; normalized = code.strip()
	if verify_totp(decrypt_mfa_secret(user.mfa_secret_encrypted), normalized):
		assurance = "TOTP"
	else:
		digest = token_digest(normalized); stored = list(user.mfa_recovery_codes_json or [])
		if digest in stored:
			stored.remove(digest); user.mfa_recovery_codes_json = stored; assurance = "RECOVERY"
	if assurance is None:
		raise HTTPException(status_code=401, detail="Invalid MFA code.")
	if enable: user.mfa_enabled = True
	csrf = _rotate_session(request, response, db, user, assurance)
	record_audit_event(db, actor=principal.audit_identity, action="MFA_VERIFIED", resource=f"user:{user.username}",
		metadata={"assurance": assurance}, request_id=getattr(request.state, "request_id", None))
	db.commit()
	return {"mfa_enabled": user.mfa_enabled, "mfa_assurance": assurance, "csrf_token": csrf}


@router.post("/auth/mfa/confirm")
def confirm_mfa(payload: MFACodeRequest, request: Request, response: Response,
	principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)):
	return _complete_mfa(payload.code, request, response, principal, db, enable=True)


@router.post("/auth/mfa/verify")
def verify_mfa(payload: MFACodeRequest, request: Request, response: Response,
	principal: OperatorPrincipal = Depends(require_api_key), db: Session = Depends(get_db)):
	user = db.get(UserRecord, principal.user_id)
	if user is None or not user.mfa_enabled:
		raise HTTPException(status_code=409, detail="MFA is not enabled.")
	return _complete_mfa(payload.code, request, response, principal, db, enable=False)


@router.get("/users", response_model=list[UserRead])
def list_users(_principal: OperatorPrincipal = Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	return [_user_dict(user) for user in db.execute(select(UserRecord).order_by(UserRecord.username)).scalars()]


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, request: Request, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	try:
		role = OperatorRole(payload.role.upper())
		password_hash = hash_password(payload.password)
	except ValueError as exc:
		raise HTTPException(status_code=422, detail=str(exc)) from exc
	now = _now()
	user = UserRecord(id=str(uuid4()), username=payload.username.strip().lower(), display_name=payload.display_name.strip(),
		password_hash=password_hash, role=role.value, password_changed_at=now)
	db.add(user)
	record_audit_event(db, actor=principal.audit_identity, action="USER_CREATED", resource=f"user:{user.username}",
		metadata={"role": role.value}, request_id=getattr(request.state, "request_id", None))
	try:
		db.commit()
	except IntegrityError as exc:
		db.rollback()
		raise HTTPException(status_code=409, detail="Username already exists.") from exc
	db.refresh(user)
	return _user_dict(user)


@router.patch("/users/{user_id}", response_model=UserRead)
def update_user(user_id: str, payload: UserUpdate, request: Request, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.SUPER_ADMIN, OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	user = db.get(UserRecord, user_id)
	if user is None:
		raise HTTPException(status_code=404, detail="User not found.")
	changes = {}
	if payload.role is not None:
		try:
			user.role = OperatorRole(payload.role.upper()).value
		except ValueError as exc:
			raise HTTPException(status_code=422, detail="Unknown operator role.") from exc
		changes["role"] = user.role
	if payload.disabled is not None:
		user.disabled_at = _now() if payload.disabled else None
		changes["disabled"] = payload.disabled
		if payload.disabled:
			for session in db.execute(select(OperatorSessionRecord).where(OperatorSessionRecord.user_id == user.id, OperatorSessionRecord.revoked_at.is_(None))).scalars():
				session.revoked_at = _now()
	record_audit_event(db, actor=principal.audit_identity, action="USER_UPDATED", resource=f"user:{user.username}",
		metadata=changes, request_id=getattr(request.state, "request_id", None))
	db.commit()
	return _user_dict(user)
