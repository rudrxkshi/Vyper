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
from ..schemas import LoginRequest, UserCreate, UserRead, UserUpdate
from ..security import hash_password, production_mode, record_audit_event, token_digest, verify_password

router = APIRouter(tags=["authentication"])
SESSION_COOKIE = "vyper_session"


def _now() -> datetime:
	return datetime.now(timezone.utc)


def _user_dict(user: UserRecord) -> dict:
	return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role,
		"disabled_at": user.disabled_at, "created_at": user.created_at}


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
	token = secrets.token_urlsafe(48)
	ttl = int(os.getenv("VYPER_SESSION_TTL_SECONDS", "28800"))
	db.add(OperatorSessionRecord(id=str(uuid4()), user_id=user.id, token_hash=token_digest(token), created_at=now,
		expires_at=now + timedelta(seconds=ttl), last_seen_at=now))
	db.commit()
	response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=production_mode(), samesite="lax", max_age=ttl, path="/")
	return _user_dict(user)


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


@router.get("/auth/me")
def me(principal: OperatorPrincipal = Depends(require_api_key)):
	return {"id": principal.user_id, "username": principal.username, "role": principal.role.value,
		"development_identity": principal.development_identity}


@router.get("/users", response_model=list[UserRead])
def list_users(_principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)), db: Session = Depends(get_db)):
	return [_user_dict(user) for user in db.execute(select(UserRecord).order_by(UserRecord.username)).scalars()]


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, request: Request, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)), db: Session = Depends(get_db)):
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
def update_user(user_id: str, payload: UserUpdate, request: Request, principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)), db: Session = Depends(get_db)):
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
