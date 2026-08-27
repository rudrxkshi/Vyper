from __future__ import annotations

import base64
import hashlib
import logging
import os

import pytest

from backend.app import command_signing


@pytest.fixture(autouse=True)
def _isolated_signing_environment(tmp_path, monkeypatch):
	monkeypatch.delenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PEM", raising=False)
	monkeypatch.delenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_B64", raising=False)
	monkeypatch.setenv("VYPER_ENV", "development")
	monkeypatch.setenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PATH", str(tmp_path / "command-signing.pem"))
	command_signing._private_key.cache_clear()
	yield
	command_signing._private_key.cache_clear()


def _raw_private_key(key) -> bytes:
	serialization, _, _ = command_signing._crypto()
	return key.private_bytes(
		serialization.Encoding.Raw,
		serialization.PrivateFormat.Raw,
		serialization.NoEncryption(),
	)


def test_development_signing_identity_survives_cache_and_process_restart(tmp_path):
	key_path = command_signing.development_key_path()
	first = command_signing.command_public_key_id()
	assert command_signing.command_public_key_id() == first
	command_signing._private_key.cache_clear()
	assert command_signing.command_public_key_id() == first
	assert key_path.is_file()
	if os.name != "nt":
		assert oct(key_path.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("override_kind", ["pem", "base64"])
def test_explicit_key_overrides_precede_persisted_development_key(monkeypatch, override_kind):
	serialization, Ed25519PrivateKey, _ = command_signing._crypto()
	persisted_id = command_signing.command_public_key_id()
	override = Ed25519PrivateKey.generate()
	if override_kind == "pem":
		monkeypatch.setenv(
			"VYPER_COMMAND_SIGNING_PRIVATE_KEY_PEM",
			override.private_bytes(
				serialization.Encoding.PEM,
				serialization.PrivateFormat.PKCS8,
				serialization.NoEncryption(),
			).decode("ascii"),
		)
	else:
		monkeypatch.setenv(
			"VYPER_COMMAND_SIGNING_PRIVATE_KEY_B64",
			base64.b64encode(_raw_private_key(override)).decode("ascii"),
		)
	command_signing._private_key.cache_clear()
	raw_public = override.public_key().public_bytes(
		serialization.Encoding.Raw, serialization.PublicFormat.Raw,
	)
	assert command_signing.command_public_key_id() == hashlib.sha256(raw_public).hexdigest()
	assert command_signing.command_public_key_id() != persisted_id


def test_production_without_explicit_signing_material_fails_closed(monkeypatch):
	monkeypatch.setenv("VYPER_ENV", "production")
	monkeypatch.delenv("VYPER_COMMAND_SIGNING_PRIVATE_KEY_PATH", raising=False)
	command_signing._private_key.cache_clear()
	with pytest.raises(RuntimeError, match="Production command signing requires"):
		command_signing.command_public_key_id()


def test_corrupt_persisted_key_fails_without_rotation_or_secret_logging(tmp_path, caplog):
	key_path = command_signing.development_key_path()
	key_path.write_bytes(b"private-secret-material-that-is-not-a-key")
	if os.name != "nt":
		key_path.chmod(0o600)
	caplog.set_level(logging.DEBUG)
	command_signing._private_key.cache_clear()
	with pytest.raises(RuntimeError, match="persisted key file.*invalid"):
		command_signing.command_public_key_id()
	assert key_path.read_bytes() == b"private-secret-material-that-is-not-a-key"
	assert "private-secret-material" not in caplog.text
