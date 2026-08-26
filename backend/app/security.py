from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import base64
import struct
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLogRecord, SecurityEventRecord

SECRET_MARKERS = ("password", "secret", "token", "credential", "passphrase", "ata_password", "authorization")
_DEV_MFA_KEY = secrets.token_bytes(32)


def _audit_timestamp(value: datetime) -> str:
	if value.tzinfo is not None:
		value = value.astimezone(timezone.utc).replace(tzinfo=None)
	return value.isoformat(timespec="microseconds")


def redact(value: Any, secrets_to_remove: tuple[str, ...] = ()) -> Any:
	if isinstance(value, dict):
		return {
			str(key): "<redacted>" if any(marker in str(key).lower() for marker in SECRET_MARKERS)
			else redact(item, secrets_to_remove)
			for key, item in value.items()
		}
	if isinstance(value, (list, tuple)):
		return [redact(item, secrets_to_remove) for item in value]
	if isinstance(value, str):
		for secret in secrets_to_remove:
			if secret:
				value = value.replace(secret, "<redacted>")
	return value


def token_digest(token: str) -> str:
	return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _mfa_key() -> bytes:
	configured = os.getenv("VYPER_MFA_ENCRYPTION_KEY")
	if production_mode() and (not configured or len(configured) < 32):
		raise RuntimeError("Production MFA requires VYPER_MFA_ENCRYPTION_KEY with at least 32 characters.")
	return hashlib.sha256(configured.encode("utf-8") if configured else _DEV_MFA_KEY).digest()


def encrypt_mfa_secret(secret: str) -> str:
	key = _mfa_key(); nonce = secrets.token_bytes(16); plain = secret.encode("ascii")
	stream = b""; counter = 0
	while len(stream) < len(plain):
		stream += hmac.new(key, b"mfa-encryption" + nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest(); counter += 1
	cipher = bytes(a ^ b for a, b in zip(plain, stream))
	tag = hmac.new(key, b"mfa-authentication" + nonce + cipher, hashlib.sha256).digest()
	return base64.urlsafe_b64encode(nonce + cipher + tag).decode("ascii")


def decrypt_mfa_secret(encoded: str) -> str:
	raw = base64.urlsafe_b64decode(encoded.encode("ascii")); nonce, body = raw[:16], raw[16:]; cipher, tag = body[:-32], body[-32:]
	key = _mfa_key(); expected = hmac.new(key, b"mfa-authentication" + nonce + cipher, hashlib.sha256).digest()
	if not hmac.compare_digest(tag, expected):
		raise ValueError("MFA secret authentication failed.")
	stream = b""; counter = 0
	while len(stream) < len(cipher):
		stream += hmac.new(key, b"mfa-encryption" + nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest(); counter += 1
	return bytes(a ^ b for a, b in zip(cipher, stream)).decode("ascii")


def new_totp_secret() -> str:
	return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, *, at_time: int | None = None) -> str:
	padding = "=" * ((8 - len(secret) % 8) % 8)
	key = base64.b32decode((secret + padding).upper()); counter = int(at_time if at_time is not None else time.time()) // 30
	digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest(); offset = digest[-1] & 0x0F
	value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
	return f"{value:06d}"


def verify_totp(secret: str, code: str, *, at_time: int | None = None) -> bool:
	now = int(at_time if at_time is not None else time.time())
	return any(hmac.compare_digest(totp_code(secret, at_time=now + drift * 30), str(code)) for drift in (-1, 0, 1))


def hash_password(password: str) -> str:
	validate_password(password)
	salt = secrets.token_bytes(16)
	n, r, p = 2**14, 8, 1
	digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
	return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
	try:
		algorithm, n, r, p, salt, expected = encoded.split("$", 5)
		if algorithm != "scrypt":
			return False
		digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
		return hmac.compare_digest(digest.hex(), expected)
	except (ValueError, TypeError):
		return False


def validate_password(password: str) -> None:
	if len(password) < 12 or len(password) > 256:
		raise ValueError("Password must contain between 12 and 256 characters.")
	classes = (
		any(c.islower() for c in password), any(c.isupper() for c in password),
		any(c.isdigit() for c in password), any(not c.isalnum() for c in password),
	)
	if sum(classes) < 3:
		raise ValueError("Password must use at least three of lowercase, uppercase, digit, and symbol characters.")


def record_audit_event(
	db: Session, *, actor: str | None, action: str, resource: str | None = None,
	metadata: dict[str, Any] | None = None, request_id: str | None = None, job_id: str | None = None,
) -> AuditLogRecord:
	previous = db.execute(select(AuditLogRecord).order_by(AuditLogRecord.created_at.desc(), AuditLogRecord.id.desc())).scalars().first()
	previous_hash = previous.event_hash if previous else None
	event_time = datetime.now(timezone.utc)
	timestamp = _audit_timestamp(event_time)
	safe_metadata = redact(metadata or {})
	canonical = json.dumps({
		"previous_hash": previous_hash, "actor": actor, "action": action, "resource": resource,
		"timestamp": timestamp, "metadata": safe_metadata, "request_id": request_id,
	}, sort_keys=True, separators=(",", ":"), default=str)
	record = AuditLogRecord(
		id=str(uuid4()), job_id=job_id, action=action, actor=actor, resource=resource,
		request_json=safe_metadata, response_json={}, request_id=request_id,
		previous_hash=previous_hash, event_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
		created_at=event_time,
	)
	db.add(record)
	return record


def record_security_event(
	db: Session, *, event_type: str, severity: str = "INFO", actor: str | None = None,
	resource: str | None = None, agent_id: str | None = None, central_job_id: str | None = None,
	metadata: dict[str, Any] | None = None,
) -> SecurityEventRecord:
	record = SecurityEventRecord(
		id=str(uuid4()),
		event_type=event_type,
		severity=severity,
		actor=actor,
		resource=resource,
		agent_id=agent_id,
		central_job_id=central_job_id,
		metadata_json=redact(metadata or {}),
		created_at=datetime.now(timezone.utc),
	)
	db.add(record)
	return record


def verify_audit_chain(records: list[AuditLogRecord]) -> bool:
	previous_hash = None
	for record in records:
		canonical = json.dumps({
			"previous_hash": previous_hash, "actor": record.actor, "action": record.action,
			"resource": record.resource, "timestamp": _audit_timestamp(record.created_at),
			"metadata": record.request_json or {}, "request_id": record.request_id,
		}, sort_keys=True, separators=(",", ":"), default=str)
		expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
		if record.previous_hash != previous_hash or not record.event_hash or not hmac.compare_digest(record.event_hash, expected):
			return False
		previous_hash = record.event_hash
	return True


def production_mode() -> bool:
	return os.getenv("VYPER_ENV", "development").strip().lower() == "production"
