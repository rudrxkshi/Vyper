from __future__ import annotations

import hashlib
import os
import platform
from dataclasses import dataclass
from pathlib import Path


def _crypto():
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

	return serialization, Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
	private_key_pem: str
	public_key_pem: str
	public_key_id: str


class Ed25519IdentityStore:
	def __init__(self, path: str | Path) -> None:
		self.path = Path(path)

	def load_or_create(self) -> DeviceIdentity:
		serialization, Ed25519PrivateKey = _crypto()
		try:
			private_pem = self.path.read_bytes()
			private_key = serialization.load_pem_private_key(private_pem, password=None)
		except FileNotFoundError:
			private_key = Ed25519PrivateKey.generate()
			private_pem = private_key.private_bytes(
				serialization.Encoding.PEM,
				serialization.PrivateFormat.PKCS8,
				serialization.NoEncryption(),
			)
			self.path.parent.mkdir(parents=True, exist_ok=True)
			fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
			try:
				with os.fdopen(fd, "wb") as handle:
					handle.write(private_pem)
			finally:
				try:
					os.chmod(self.path, 0o600)
				except OSError:
					pass
		public_pem = private_key.public_key().public_bytes(
			serialization.Encoding.PEM,
			serialization.PublicFormat.SubjectPublicKeyInfo,
		)
		public_raw = private_key.public_key().public_bytes(
			serialization.Encoding.Raw,
			serialization.PublicFormat.Raw,
		)
		return DeviceIdentity(
			private_key_pem=private_pem.decode("ascii"),
			public_key_pem=public_pem.decode("ascii"),
			public_key_id=hashlib.sha256(public_raw).hexdigest(),
		)


def endpoint_identity_fingerprint(identity: DeviceIdentity) -> str:
	"""Return a privacy-preserving, stable-enough endpoint binding value.

	The public key remains the cryptographic device identity. This fingerprint
	adds locally available host characteristics only as a tamper/change signal;
	it is not used as a replacement for the key or a hardware serial number.
	"""
	machine_id = ""
	for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
		try:
			machine_id = candidate.read_text(encoding="utf-8").strip()
		except OSError:
			continue
		if machine_id:
			break
	material = "|".join((identity.public_key_id, machine_id, platform.system(), platform.machine()))
	return hashlib.sha256(material.encode("utf-8")).hexdigest()
