from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from agent.command_runner import CommandResult
from backend.app.main import create_app
from backend.app.models import AgentAssetRecord, AgentRecord, OperatorSessionRecord, UserRecord
from backend.app.security import decrypt_mfa_secret, hash_password, token_digest, totp_code
from local_agent.cli import verify_package
from local_agent.privileged_executor import ExecutorProtocolError, MAX_REQUEST_BYTES, PrivilegedExecutor, validate_request
from local_agent.release_signing import public_key_id
from local_agent.secure_boot import secure_boot_status
from local_agent.sbom import generate_sbom
from vyper_version import __version__


ROOT = Path(__file__).resolve().parents[1]


def _user(app, username="operator", role="OPERATOR"):
	now = datetime.now(timezone.utc)
	with app.state.session_factory() as db:
		user = UserRecord(id=str(uuid4()), username=username, display_name=username, password_hash=hash_password("Correct-Horse-42!"),
			role=role, password_changed_at=now, mfa_enabled=False, mfa_recovery_codes_json=[])
		db.add(user); db.commit(); return user.id


def test_privileged_executor_schema_allowlist_and_no_command_passthrough(monkeypatch):
	base = {"version": "1", "request_id": str(uuid4()), "operation": "sanitize", "target": "/dev/sdz",
		"dry_run": True, "authorization": {"approved": False}, "execution_mode": "normal_local"}
	assert validate_request(dict(base))["operation"] == "sanitize"
	for mutation in ({"operation": "exec"}, {"argv": ["sh", "-c", "id"]}, {"target": "/tmp/not-a-device"},
		{"authorization": {"approved": True, "command": "id"}}):
		payload = {**base, **mutation}
		with pytest.raises(ExecutorProtocolError): validate_request(payload)
	with pytest.raises(ExecutorProtocolError, match="size"):
		PrivilegedExecutor().dispatch(b" " * (MAX_REQUEST_BYTES + 1))
	source = (ROOT / "local_agent/privileged_executor.py").read_text(encoding="utf-8")
	assert "AF_UNIX" in source and "AF_INET" not in source and "shell=True" not in source


def test_mfa_totp_recovery_rotation_and_destructive_enforcement(tmp_path, monkeypatch):
	monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
	monkeypatch.setenv("VYPER_MFA_ENCRYPTION_KEY", "stage13-test-encryption-key-32-bytes-minimum")
	app = create_app(database_url=f"sqlite:///{tmp_path / 'mfa.db'}")
	with TestClient(app) as client:
		user_id = _user(app)
		login = client.post("/auth/login", json={"username": "operator", "password": "Correct-Horse-42!"})
		assert login.status_code == 200 and login.json()["mfa_assurance"] == "PASSWORD"
		enrollment = client.post("/auth/mfa/enroll", json={"password": "Correct-Horse-42!"})
		body = enrollment.json(); secret = body["secret"]; recovery = body["recovery_codes"][0]
		with app.state.session_factory() as db:
			user = db.get(UserRecord, user_id)
			assert secret not in user.mfa_secret_encrypted and decrypt_mfa_secret(user.mfa_secret_encrypted) == secret
			assert recovery not in json.dumps(user.mfa_recovery_codes_json)
		confirmed = client.post("/auth/mfa/confirm", json={"code": totp_code(secret)})
		assert confirmed.status_code == 200 and confirmed.json()["mfa_assurance"] == "TOTP"
		client.post("/auth/logout")
		client.post("/auth/login", json={"username": "operator", "password": "Correct-Horse-42!"})
		assert client.post("/auth/mfa/verify", json={"code": recovery}).json()["mfa_assurance"] == "RECOVERY"
		client.post("/auth/logout"); client.post("/auth/login", json={"username": "operator", "password": "Correct-Horse-42!"})
		assert client.post("/auth/mfa/verify", json={"code": recovery}).status_code == 401


def test_password_only_session_cannot_create_destructive_central_job(tmp_path, monkeypatch):
	monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
	app = create_app(database_url=f"sqlite:///{tmp_path / 'mfa-job.db'}")
	with TestClient(app) as client:
		_user(app); now = datetime.now(timezone.utc)
		with app.state.session_factory() as db:
			agent = AgentRecord(agent_id=str(uuid4()), display_name="a", hostname="h", platform="linux", architecture="x86_64",
				agent_version="1", api_version="2", agent_protocol_version="1", status="ONLINE", enrolled_at=now,
				metadata_json={}, token_hash="a" * 64)
			asset = AgentAssetRecord(id=str(uuid4()), agent_id=agent.agent_id, hardware_identity="b" * 64,
				device_path="/dev/mock", device_type="HDD", identity_confidence="HIGH",
				profile_json={"is_system_device": False, "mounted": False, "eligible_for_sanitization": True}, observations_json=[],
				first_seen_at=now, last_seen_at=now)
			db.add_all([agent, asset]); db.commit(); agent_id, asset_id = agent.agent_id, asset.id
		client.post("/auth/login", json={"username": "operator", "password": "Correct-Horse-42!"})
		response = client.post(f"/agents/{agent_id}/jobs", json={"asset_id": asset_id, "dry_run": False,
			"central_authorized": True, "destructive_confirmation": "SANITIZE", "idempotency_key": "stage13-mfa"})
		assert response.status_code == 403 and "MFA" in response.json()["detail"]


def test_production_cookie_flags_and_csrf(monkeypatch, tmp_path):
	monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
	monkeypatch.setattr("backend.app.routers.auth.production_mode", lambda: True)
	app = create_app(database_url=f"sqlite:///{tmp_path / 'cookie.db'}")
	with TestClient(app, base_url="https://testserver") as client:
		_user(app, "admin", "ADMIN")
		login = client.post("/auth/login", json={"username": "admin", "password": "Correct-Horse-42!"})
		cookies = login.headers.get_list("set-cookie")
		assert any("Secure" in item and "HttpOnly" in item and "SameSite=lax" in item for item in cookies)
	monkeypatch.setattr("backend.app.routers.auth.production_mode", lambda: False)
	monkeypatch.setattr("backend.app.auth.production_mode", lambda: True)
	app2 = create_app(database_url=f"sqlite:///{tmp_path / 'csrf.db'}")
	with TestClient(app2) as client:
		_user(app2, "admin2", "ADMIN")
		client.post("/auth/login", json={"username": "admin2", "password": "Correct-Horse-42!"})
		assert client.post("/auth/logout").status_code == 403


def test_real_ed25519_good_bad_and_wrong_key(tmp_path, capsys):
	artifact = tmp_path / "release.tar.gz"; artifact.write_bytes(b"stage13 signed artifact")
	private = Ed25519PrivateKey.generate(); public = private.public_key()
	pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
	key_id = public_key_id(pem); signature = private.sign(artifact.read_bytes())
	(artifact.with_name(artifact.name + ".ed25519.sig")).write_text(base64.b64encode(signature).decode(), encoding="ascii")
	manifest = {"filename": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
		"signature_status": "signed", "signature_type": "ed25519", "signature_file": artifact.name + ".ed25519.sig",
		"signature_key_id": key_id}
	(tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
	trust = {"keys": [{"key_id": key_id, "status": "trusted", "public_key_pem": pem.decode()}]}
	(tmp_path / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
	assert verify_package(str(artifact), trust_store_value=str(tmp_path / "trust.json")) == 0
	assert json.loads(capsys.readouterr().out)["signature_result"] == "VERIFIED"
	wrong = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
	(tmp_path / "trust.json").write_text(json.dumps({"keys": [{"key_id": key_id, "status": "trusted", "public_key_pem": wrong.decode()}]}), encoding="utf-8")
	assert verify_package(str(artifact), trust_store_value=str(tmp_path / "trust.json")) == 1
	artifact.write_bytes(b"tampered")
	assert verify_package(str(artifact), trust_store_value=str(tmp_path / "trust.json")) == 1


class Exec:
	def __init__(self, outputs): self.outputs = iter(outputs); self.calls = []
	def run(self, command, timeout=None, cwd=None):
		self.calls.append(command); success, stdout = next(self.outputs)
		return CommandResult(command=command, success=success, exit_code=0 if success else 1, stdout=stdout, stderr="")


def test_secure_boot_status_is_read_only_and_key_aware(tmp_path):
	certificate = tmp_path / "MOK.der"; certificate.write_bytes(b"public certificate")
	executor = Exec([(True, "SecureBoot enabled"), (False, "not enrolled")])
	report = secure_boot_status(command_executor=executor, signing_certificate=certificate)
	assert report["status"] == "REQUIRES_KEY_ENROLLMENT" and report["read_only"] is True
	assert executor.calls == [["mokutil", "--sb-state"], ["mokutil", "--test-key", str(certificate)]]


def test_sbom_matches_release_version(tmp_path):
	payload = generate_sbom(tmp_path / "sbom.json")
	assert payload["bomFormat"] == "CycloneDX" and payload["metadata"]["component"]["version"] == __version__
	assert any(item["name"] == "cryptography" for item in payload["components"])
