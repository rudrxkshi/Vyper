from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path


def _crypto():
	try:
		from cryptography.hazmat.primitives import serialization
		from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
	except ImportError as exc:
		raise RuntimeError("Ed25519 verification requires the pinned cryptography dependency.") from exc
	return serialization, Ed25519PublicKey


def load_public_key(pem: bytes):
	serialization, Ed25519PublicKey = _crypto(); key = serialization.load_pem_public_key(pem)
	if not isinstance(key, Ed25519PublicKey): raise ValueError("Release key is not Ed25519.")
	return key


def public_key_id(pem: bytes) -> str:
	serialization, _ = _crypto(); key = load_public_key(pem)
	raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
	return "ed25519:" + hashlib.sha256(raw).hexdigest()


def verify_detached(artifact: Path, signature: bytes, public_pem: bytes) -> None:
	load_public_key(public_pem).verify(signature, artifact.read_bytes())


def trusted_public_key(trust_store: Path, key_id: str) -> bytes:
	payload = json.loads(trust_store.read_text(encoding="utf-8"))
	for item in payload.get("keys", []):
		if item.get("key_id") == key_id and item.get("status") == "trusted":
			pem = str(item.get("public_key_pem") or "").encode("utf-8")
			if public_key_id(pem) != key_id: raise ValueError("Trusted key material does not match its key identity.")
			return pem
	raise ValueError("Release signing key is not trusted or has been revoked.")


def signature_bytes(path: Path) -> bytes:
	return base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
