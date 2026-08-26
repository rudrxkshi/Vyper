from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from backend.app.db import default_database_url
from backend.app.main import SUPPORTED_ALEMBIC_HEAD, create_app
from backend.app.models import (
	AgentAssetRecord, AgentRecord, AuditLogRecord, OperatorSessionRecord,
	OrganizationMembershipRecord, OrganizationRecord, UserRecord,
)
from backend.app.security import hash_password, verify_audit_chain
from local_agent.cli import verify_package
from local_agent.process_worker import ProcessJobExecutor
from local_agent import process_worker
from local_agent.storage import LocalJobStore


def _user(app, username: str, role: str, *, disabled=False):
	now = datetime.now(timezone.utc)
	with app.state.session_factory() as db:
		record = UserRecord(id=str(uuid4()), username=username, display_name=username.title(),
			password_hash=hash_password("Correct-Horse-42!"), role=role,
			disabled_at=now if disabled else None, password_changed_at=now)
		db.add(record)
		db.commit()
		return record.id


def _login(client: TestClient, username: str):
	return client.post("/auth/login", json={"username": username, "password": "Correct-Horse-42!"})


def test_login_roles_disabled_account_and_spoofed_actor_ignored(tmp_path, monkeypatch):
	monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
	app = create_app(database_url=f"sqlite:///{tmp_path / 'auth.db'}")
	with TestClient(app) as client:
		_user(app, "admin", "ADMIN")
		_user(app, "auditor", "AUDITOR")
		_user(app, "disabled", "OPERATOR", disabled=True)
		assert client.post("/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
		assert _login(client, "disabled").status_code == 401
		assert _login(client, "auditor").status_code == 200
		assert client.get("/agents").status_code == 200
		assert client.post("/agents/enrollment-tokens", json={"ttl_seconds": 600}).status_code == 403
		client.post("/auth/logout")
		assert _login(client, "admin").status_code == 200
		issued = client.post("/agents/enrollment-tokens", headers={"X-VYPER-Actor": "spoofed"}, json={"ttl_seconds": 600})
		assert issued.status_code == 200
		with app.state.session_factory() as db:
			event = db.query(AuditLogRecord).filter(AuditLogRecord.action == "ENROLLMENT_TOKEN_CREATED").one()
			assert event.actor == "operator:admin"
			assert event.event_hash and len(event.event_hash) == 64
			chain = db.query(AuditLogRecord).order_by(AuditLogRecord.created_at, AuditLogRecord.id).all()
			assert verify_audit_chain(chain)


def test_operator_can_request_but_auditor_cannot_and_confirmation_is_required(tmp_path, monkeypatch):
	monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
	app = create_app(database_url=f"sqlite:///{tmp_path / 'rbac.db'}")
	with TestClient(app) as client:
		operator_id = _user(app, "operator", "OPERATOR")
		_user(app, "auditor", "AUDITOR")
		now = datetime.now(timezone.utc)
		with app.state.session_factory() as db:
			organization = OrganizationRecord(id=str(uuid4()), name="Stage 6 organization")
			membership = OrganizationMembershipRecord(
				id=str(uuid4()), organization_id=organization.id, user_id=operator_id, role="MEMBER",
			)
			agent = AgentRecord(agent_id=str(uuid4()), display_name="Agent", hostname="host", platform="linux",
				architecture="x86_64", agent_version="1", api_version="2", agent_protocol_version="1",
				status="ONLINE", enrolled_at=now, metadata_json={}, token_hash="a" * 64,
				organization_id=organization.id)
			asset = AgentAssetRecord(id=str(uuid4()), agent_id=agent.agent_id, hardware_identity="b" * 64,
				identity_confidence="HIGH", device_path="/dev/mock", device_type="HDD",
				profile_json={"is_system_device": False, "mounted": False, "eligible_for_sanitization": True},
				observations_json=[], first_seen_at=now, last_seen_at=now)
			db.add_all([organization, membership, agent, asset]); db.commit()
			agent_id, asset_id = agent.agent_id, asset.id
		_login(client, "auditor")
		payload = {"asset_id": asset_id, "dry_run": False, "central_authorized": True,
			"destructive_confirmation": "SANITIZE", "idempotency_key": "stage6-auditor"}
		assert client.post(f"/agents/{agent_id}/jobs", json=payload).status_code == 403
		client.post("/auth/logout")
		_login(client, "operator")
		payload["destructive_confirmation"] = None
		assert client.post(f"/agents/{agent_id}/jobs", json=payload).status_code == 422
		payload["destructive_confirmation"] = "SANITIZE"
		with app.state.session_factory() as db:
			session = db.query(OperatorSessionRecord).filter(OperatorSessionRecord.revoked_at.is_(None)).one()
			session.mfa_assurance = "TOTP"; db.commit()
		response = client.post(f"/agents/{agent_id}/jobs", json=payload)
		assert response.status_code == 201
		assert response.json()["requested_by"] == "operator:operator"
		assert response.json()["status"] == "QUEUED"


def test_cors_request_id_and_readiness(tmp_path, monkeypatch):
	monkeypatch.setenv("VYPER_CORS_ORIGINS", "https://console.example")
	app = create_app(database_url=f"sqlite:///{tmp_path / 'cors.db'}")
	with TestClient(app) as client:
		allowed = client.options("/agents", headers={"Origin": "https://console.example", "Access-Control-Request-Method": "GET"})
		denied = client.options("/agents", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
		health = client.get("/health", headers={"X-Request-ID": "stage6-request"})
		assert client.get("/readiness").status_code == 200
		metrics = client.get("/metrics")
	assert allowed.headers.get("access-control-allow-origin") == "https://console.example"
	assert denied.headers.get("access-control-allow-origin") is None
	assert health.headers["x-request-id"] == "stage6-request"
	assert metrics.status_code == 200
	assert "vyper_http_requests_total" in metrics.text


def test_health_is_live_when_database_readiness_fails(tmp_path):
	app = create_app(database_url=f"sqlite:///{tmp_path / 'readiness.db'}")
	class BrokenEngine:
		def connect(self):
			raise OSError("simulated database outage")
	with TestClient(app) as client:
		app.state.engine = BrokenEngine()
		assert client.get("/health").status_code == 200
		response = client.get("/readiness")
		assert response.status_code == 503
		assert response.json()["detail"] == "Database is unavailable."


def test_production_requires_postgresql_database_url(monkeypatch):
	monkeypatch.setenv("VYPER_ENV", "production")
	monkeypatch.delenv("VYPER_DATABASE_URL", raising=False)
	monkeypatch.delenv("VYPER_DATABASE_URL_FILE", raising=False)
	with pytest.raises(RuntimeError, match="required"):
		default_database_url()
	with pytest.raises(RuntimeError, match="PostgreSQL"):
		create_app(database_url="sqlite:///not-production.db")


def test_alembic_upgrades_empty_database_and_records_revision(tmp_path):
	database = tmp_path / "migration.db"
	config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
	config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
	command.upgrade(config, "head")
	engine = create_engine(f"sqlite:///{database}")
	with engine.connect() as connection:
		tables = set(inspect(connection).get_table_names())
		version_column = next(column for column in inspect(connection).get_columns("alembic_version")
			if column["name"] == "version_num")
		revision = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
	assert {"users", "operator_sessions", "central_jobs", "audit_logs"}.issubset(tables)
	assert revision == SUPPORTED_ALEMBIC_HEAD
	assert version_column["type"].length == 32


@pytest.mark.parametrize("starting_revision", [
	None,
	"0002_stage13_mfa_sessions",
	"0003_remote_command_identity",
	"0003_central_certificates",
])
def test_postgresql_upgrade_paths_use_wide_version_table_when_ci_database_is_available(starting_revision):
	url = os.getenv("VYPER_TEST_POSTGRES_URL")
	if not url:
		pytest.skip("PostgreSQL integration database is provided by CI.")
	schema = f"vyper_migration_{uuid4().hex}"
	admin_engine = create_engine(url)
	with admin_engine.begin() as connection:
		connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
	test_url = make_url(url).update_query_dict({"options": f"-csearch_path={schema}"})
	config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
	config.set_main_option("sqlalchemy.url", test_url.render_as_string(hide_password=False).replace("%", "%%"))
	try:
		if starting_revision:
			command.upgrade(config, starting_revision)
			engine = create_engine(test_url)
			with engine.begin() as connection:
				connection.exec_driver_sql(
					"ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(32)"
				)
		command.upgrade(config, "head")
		engine = create_engine(test_url)
		with engine.connect() as connection:
			revision = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
			version_column = next(column for column in inspect(connection).get_columns("alembic_version")
				if column["name"] == "version_num")
		assert revision == "0009_merge_migration_heads"
		assert version_column["type"].length >= 64
	finally:
		with admin_engine.begin() as connection:
			connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def test_postgresql_transaction_rollback_when_ci_database_is_available():
	url = os.getenv("VYPER_TEST_POSTGRES_URL")
	if not url:
		pytest.skip("PostgreSQL integration database is provided by CI.")
	engine = create_engine(url)
	username = f"rollback-{uuid4()}"
	with engine.connect() as connection:
		transaction = connection.begin()
		connection.execute(text("INSERT INTO users (id, username, display_name, password_hash, role, password_changed_at) "
			"VALUES (:id, :username, 'Rollback', 'not-a-real-password-hash', 'AUDITOR', :changed)"),
			{"id": str(uuid4()), "username": username, "changed": datetime.now(timezone.utc)})
		transaction.rollback()
		assert connection.execute(text("SELECT count(*) FROM users WHERE username = :username"), {"username": username}).scalar_one() == 0


def test_worker_exit_is_inconclusive_and_releases_target_lock(tmp_path):
	database = tmp_path / "worker.db"
	store = LocalJobStore(database)
	store.create_job(local_job_id="crashed", api_version="2", target="/dev/mock", dry_run=False,
		authorization_metadata={"approved": True})
	store.start_job("crashed", 1234)
	executor = ProcessJobExecutor(database, max_workers=1)
	executor._handle_exit("crashed", "/dev/mock", 1234, 9)
	job = store.get_job("crashed")
	assert job["job_state"] == job["final_status"] == "INCONCLUSIVE"
	assert job["verification"] is None
	store.create_job(local_job_id="replacement", api_version="2", target="/dev/mock", dry_run=False,
		authorization_metadata={"approved": True})


def test_process_worker_force_dry_run_overrides_destructive_request(tmp_path, monkeypatch):
	observed = {}
	class WorkerStub:
		def __init__(self, *, store, agent):
			observed["agent_dry_run"] = agent.dry_run
		def run(self, local_job_id, target, authorization, dry_run):
			observed["job_dry_run"] = dry_run
	monkeypatch.setattr(process_worker, "LocalJobWorker", WorkerStub)
	process_worker._run_native_job(str(tmp_path / "worker.db"), "job", "/dev/mock",
		{"approved": True}, False, True)
	assert observed == {"agent_dry_run": True, "job_dry_run": True}


def test_verify_package_checksum_only_and_mismatch(tmp_path, capsys):
	artifact = tmp_path / "release.tar.gz"
	artifact.write_bytes(b"safe test artifact")
	manifest = {"filename": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
		"signature_status": "checksum-only", "signature_type": None}
	(tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
	assert verify_package(str(artifact)) == 0
	assert json.loads(capsys.readouterr().out)["signed"] is False
	artifact.write_bytes(b"changed")
	assert verify_package(str(artifact)) == 1
