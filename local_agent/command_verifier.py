from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


ALLOWED_REMOTE_OPERATIONS = {"STATUS", "PROFILE", "SANITIZE", "CANCEL", "SYNC", "UPDATE_CONFIGURATION"}


class CommandVerificationError(RuntimeError):
	pass


def canonical_command(command: dict[str, Any]) -> bytes:
	payload = {key: value for key, value in command.items() if key != "signature"}
	return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def command_signature_hash(command: dict[str, Any]) -> str:
	signature = (command.get("signature") or {}).get("value") if isinstance(command.get("signature"), dict) else ""
	return hashlib.sha256(str(signature).encode("ascii", errors="ignore")).hexdigest()


def verify_remote_command(
	command: dict[str, Any],
	*,
	agent_id: str,
	public_key_pem: str,
	expected_operation: str = "SANITIZE",
	now: datetime | None = None,
) -> None:
	if not isinstance(command, dict):
		raise CommandVerificationError("Remote command is missing.")
	if not str(command.get("command_id") or ""):
		raise CommandVerificationError("Remote command ID is missing.")
	signature = command.get("signature")
	if not isinstance(signature, dict):
		raise CommandVerificationError("Remote command signature is missing.")
	if signature.get("algorithm") != "ed25519":
		raise CommandVerificationError("Remote command uses an unsupported signature algorithm.")
	if str(command.get("device_id") or "") != str(agent_id):
		raise CommandVerificationError("Remote command targets a different agent identity.")
	operation = str(command.get("operation") or "")
	if operation not in ALLOWED_REMOTE_OPERATIONS or operation != expected_operation:
		raise CommandVerificationError("Remote command operation is not allowed for this workflow.")
	nonce = str(command.get("nonce") or "")
	if not nonce:
		raise CommandVerificationError("Remote command nonce is missing.")
	issued_at = _parse_time(str(command.get("issued_at") or ""))
	expires_at = _parse_time(str(command.get("expires_at") or ""))
	current = now or datetime.now(timezone.utc)
	if issued_at > current:
		raise CommandVerificationError("Remote command was issued in the future.")
	if expires_at <= current:
		raise CommandVerificationError("Remote command has expired.")
	if not isinstance(command.get("parameters"), dict):
		raise CommandVerificationError("Remote command parameters are missing.")

	serialization, Ed25519PublicKey = _crypto()
	public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
	if not isinstance(public_key, Ed25519PublicKey):
		raise CommandVerificationError("Remote command verification key is not Ed25519.")
	public_raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
	key_id = hashlib.sha256(public_raw).hexdigest()
	if signature.get("key_id") != key_id:
		raise CommandVerificationError("Remote command signing key identity does not match enrollment.")
	try:
		public_key.verify(base64.b64decode(str(signature.get("value") or "").encode("ascii")), canonical_command(command))
	except Exception as exc:
		raise CommandVerificationError("Remote command signature verification failed.") from exc


def _parse_time(value: str) -> datetime:
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except ValueError as exc:
		raise CommandVerificationError("Remote command expiration timestamp is invalid.") from exc
	return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _crypto():
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

	return serialization, Ed25519PublicKey
