from __future__ import annotations

import base64
import hashlib
import json
import os
from functools import lru_cache
from typing import Any

from .security import production_mode


def _crypto():
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

	return serialization, Ed25519PrivateKey, Ed25519PublicKey


def canonical_command(command: dict[str, Any]) -> bytes:
	payload = {key: value for key, value in command.items() if key != "signature"}
	return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


@lru_cache(maxsize=1)
def _private_key():
	serialization, Ed25519PrivateKey, _ = _crypto()
	pem = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PEM")
	if pem:
		return serialization.load_pem_private_key(pem.replace("\\n", "\n").encode("utf-8"), password=None)
	raw = os.getenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_B64")
	if raw:
		return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw.encode("ascii")))
	if production_mode():
		raise RuntimeError("Production command signing requires an Ed25519 private key.")
	return Ed25519PrivateKey.generate()


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
