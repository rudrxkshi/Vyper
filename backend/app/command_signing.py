from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from .security import production_mode


def _crypto():
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

	return serialization, Ed25519PrivateKey, Ed25519PublicKey


def canonical_command(command: dict[str, Any]) -> bytes:
	payload = {key: value for key, value in command.items() if key != "signature"}
	return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def development_key_path() -> Path:
	configured = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PATH")
	if configured:
		return Path(configured).expanduser()
	state_home = os.getenv("XDG_STATE_HOME")
	base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
	return base / "vyper" / "central-command-signing-key.pem"


def _load_private_key_bytes(payload: bytes, *, source: str):
	serialization, Ed25519PrivateKey, _ = _crypto()
	try:
		key = serialization.load_pem_private_key(payload, password=None)
	except Exception as exc:
		raise RuntimeError(f"Command signing private key from {source} is invalid.") from exc
	if not isinstance(key, Ed25519PrivateKey):
		raise RuntimeError(f"Command signing private key from {source} is not Ed25519.")
	return key


def _load_private_key_file(path: Path):
	try:
		if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
			raise RuntimeError("Persisted development command signing key permissions are too broad.")
		payload = path.read_bytes()
	except RuntimeError:
		raise
	except OSError as exc:
		raise RuntimeError("Persisted development command signing key could not be read.") from exc
	return _load_private_key_bytes(payload, source="the persisted key file")


def _persist_development_key(path: Path, key) -> None:
	serialization, _, _ = _crypto()
	path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
	payload = key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.PKCS8,
		serialization.NoEncryption(),
	)
	temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
	flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
	fd = os.open(temporary, flags, 0o600)
	try:
		handle = os.fdopen(fd, "wb", closefd=True)
		fd = -1
		with handle:
			handle.write(payload)
			handle.flush()
			os.fsync(handle.fileno())
		try:
			# A hard link publishes a completely written key without replacing a
			# key another Central process may have created concurrently.
			os.link(temporary, path)
		except FileExistsError:
			pass
	finally:
		if fd >= 0:
			os.close(fd)
		try:
			temporary.unlink()
		except FileNotFoundError:
			pass


def _load_or_create_development_key(path: Path):
	if path.exists():
		return _load_private_key_file(path)
	_, Ed25519PrivateKey, _ = _crypto()
	_persist_development_key(path, Ed25519PrivateKey.generate())
	return _load_private_key_file(path)


@lru_cache(maxsize=1)
def _private_key():
	serialization, Ed25519PrivateKey, _ = _crypto()
	pem = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PEM")
	if pem:
		return _load_private_key_bytes(pem.replace("\\n", "\n").encode("utf-8"), source="the PEM environment override")
	raw = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_B64")
	if raw:
		try:
			return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw.encode("ascii"), validate=True))
		except Exception as exc:
			raise RuntimeError("Command signing private key from the base64 environment override is invalid.") from exc
	configured_path = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PATH")
	if production_mode() and not configured_path:
		raise RuntimeError("Production command signing requires an Ed25519 private key.")
	path = development_key_path()
	if production_mode():
		return _load_private_key_file(path)
	return _load_or_create_development_key(path)


def command_public_key_pem() -> str:
	serialization, _, _ = _crypto()
	return _private_key().public_key().public_bytes(
		serialization.Encoding.PEM,
		serialization.PublicFormat.SubjectPublicKeyInfo,
	).decode("ascii")


def command_public_key_id() -> str:
	serialization, _, _ = _crypto()
	raw = _private_key().public_key().public_bytes(
		serialization.Encoding.Raw,
		serialization.PublicFormat.Raw,
	)
	return hashlib.sha256(raw).hexdigest()


def sign_command(command: dict[str, Any]) -> dict[str, Any]:
	signed = dict(command)
	signature = _private_key().sign(canonical_command(signed))
	signed["signature"] = {
		"algorithm": "ed25519",
		"key_id": command_public_key_id(),
		"value": base64.b64encode(signature).decode("ascii"),
	}
	return signed
