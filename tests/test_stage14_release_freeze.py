from __future__ import annotations

import io
import json
import tomllib
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql

from agent.certificate import CertificateBuilder, verify_certificate_integrity
from agent.evidence import EvidenceRecord
from backend.app.agent_protocol import require_protocol
from backend.app.main import SUPPORTED_ALEMBIC_HEAD, require_supported_schema
from local_agent.boot_sanitize import BOOT_ENVIRONMENT_VERSION, BOOT_JOB_VERSION, BootIntegrityError, BootJobStore
from local_agent.main import API_VERSION
from local_agent.privileged_executor import ExecutorProtocolError, validate_request
from migrations import version_table
from migrations.version_table import (
	VERSION_NUM_LENGTH, VyperPostgresqlImpl, ensure_postgresql_version_table_compatibility,
)
from vyper_version import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent_everywhere():
	pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
	package = json.loads((ROOT / "frontend/user-dashboard/package.json").read_text(encoding="utf-8"))
	lock = json.loads((ROOT / "frontend/user-dashboard/package-lock.json").read_text(encoding="utf-8"))
	contract = json.loads((ROOT / "tests/fixtures/stage8_api_contract.json").read_text(encoding="utf-8"))
	page = (ROOT / "frontend/user-dashboard/app/page.js").read_text(encoding="utf-8")
	assert __version__ == "1.0.0-rc1"
	assert {pyproject["project"]["version"], package["version"], lock["version"],
		lock["packages"][""]["version"], contract["versions"]["product"], BOOT_ENVIRONMENT_VERSION} == {__version__}
	assert f'const PRODUCT_VERSION = "{__version__}"' in page


def test_frozen_protocol_and_migration_versions():
	assert API_VERSION == "2" and BOOT_JOB_VERSION == "1"
	assert SUPPORTED_ALEMBIC_HEAD == "0009_merge_migration_heads"
	migrations = sorted(path.stem for path in (ROOT / "migrations/versions").glob("*.py") if not path.name.startswith("__"))
	assert migrations == [
		"0001_stage6_baseline", "0002_stage13_mfa_sessions", "0003_central_certificates",
		"0003_remote_command_identity", "0004_organization_policy_approvals",
		"0005_organization_memberships", "0006_organization_event_scope",
		"0007_remote_policy_lifecycle", "0008_organization_membership_lifecycle",
		"0009_merge_migration_heads",
	]


def test_alembic_graph_is_complete_unique_reachable_and_has_supported_single_head():
	config = Config(str(ROOT / "alembic.ini"))
	script = ScriptDirectory.from_config(config)
	revisions = list(script.walk_revisions())
	by_id = {revision.revision: revision for revision in revisions}
	assert len(by_id) == len(revisions)
	for revision in revisions:
		parents = revision.down_revision or ()
		if isinstance(parents, str):
			parents = (parents,)
		assert set(parents) <= set(by_id)
	heads = tuple(script.get_heads())
	assert heads == (SUPPORTED_ALEMBIC_HEAD,)
	reachable: set[str] = set()
	pending = list(heads)
	while pending:
		revision_id = pending.pop()
		if revision_id in reachable:
			continue
		reachable.add(revision_id)
		parents = by_id[revision_id].down_revision or ()
		pending.extend((parents,) if isinstance(parents, str) else parents)
	assert reachable == set(by_id)


def test_postgresql_version_table_supports_every_frozen_revision_id():
	config = Config(str(ROOT / "alembic.ini"))
	revisions = list(ScriptDirectory.from_config(config).walk_revisions())
	maximum_revision_length = max(len(revision.revision) for revision in revisions)
	implementation = VyperPostgresqlImpl(postgresql.dialect(), None, True, None, None, {})
	table = implementation.version_table_impl(
		version_table="alembic_version", version_table_schema=None, version_table_pk=True,
	)
	assert maximum_revision_length == len("0008_organization_membership_lifecycle")
	assert table.c.version_num.type.length == VERSION_NUM_LENGTH
	assert VERSION_NUM_LENGTH >= maximum_revision_length


def test_offline_postgresql_migration_sql_creates_wide_version_table():
	output = io.StringIO()
	config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
	config.set_main_option("sqlalchemy.url", "postgresql://unused/test")
	# Later historical migrations use live schema inspection and therefore do not
	# support Alembic's offline mode; the baseline is sufficient to exercise the
	# version-table creation performed before the first revision is stamped.
	command.upgrade(config, "0001_stage6_baseline", sql=True)
	generated_sql = output.getvalue()
	assert "CREATE TABLE alembic_version" in generated_sql
	assert "version_num VARCHAR(64) NOT NULL" in generated_sql


def test_existing_postgresql_version_table_is_widened_before_migrations(monkeypatch):
	class InspectorStub:
		def get_table_names(self, schema=None):
			return ["alembic_version"]
		def get_columns(self, table_name, schema=None):
			return [{"name": "version_num", "type": type("Varchar", (), {"length": 32})()}]

	class ConnectionStub:
		dialect = postgresql.dialect()
		def __init__(self):
			self.statements = []
		def exec_driver_sql(self, statement):
			self.statements.append(statement)

	connection = ConnectionStub()
	monkeypatch.setattr(version_table, "inspect", lambda unused: InspectorStub())
	ensure_postgresql_version_table_compatibility(connection)
	assert connection.statements == [
		"ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(64)"
	]


def test_production_schema_gate_requires_exact_alembic_head(tmp_path):
	engine = create_engine(f"sqlite:///{tmp_path / 'schema.db'}")
	with engine.begin() as connection:
		connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(64) NOT NULL)"))
		connection.execute(text("INSERT INTO alembic_version(version_num) VALUES ('0001_stage6_baseline')"))
	with pytest.raises(RuntimeError, match="supported Alembic head"):
		require_supported_schema(engine)
	with engine.begin() as connection:
		connection.execute(text("UPDATE alembic_version SET version_num = :head"), {"head": SUPPORTED_ALEMBIC_HEAD})
	require_supported_schema(engine)


def test_unsupported_agent_and_executor_major_versions_fail_closed():
	with pytest.raises(HTTPException) as agent_error:
		require_protocol("2")
	assert agent_error.value.status_code == 409
	with pytest.raises(ExecutorProtocolError):
		validate_request({"version": "2", "request_id": "00000000-0000-0000-0000-000000000001",
			"operation": "discover", "execution_mode": "normal_local"})


def test_unsupported_boot_manifest_schema_is_rejected(tmp_path):
	image = tmp_path / "initrd"; image.write_bytes(b"fixture")
	store = BootJobStore(tmp_path / "jobs")
	document = store.create(device={"device_path": "/dev/mock", "serial_number": "DEMO-1",
		"model": "Demo disk", "size_bytes": 1024}, boot_image_path=image, dry_run=True)
	job_id = document["payload"]["boot_job_id"]
	document["payload"]["schema_version"] = "2"
	document = store._sign(document["payload"])
	(store.root / job_id / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
	with pytest.raises(BootIntegrityError, match="Unsupported"):
		store.validate(job_id)


def test_unknown_certificate_major_is_not_integrity_valid():
	evidence = EvidenceRecord(job_id="demo", device="/dev/mock", device_profile={}, policy_decision={},
		pathway={}, execution={"status": "RUNNING"}, verification={"status": "VERIFIED", "verified": True},
		started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z", duration_seconds=1,
		final_status="VERIFIED")
	certificate = CertificateBuilder(certificate_version="2.0.0").build(evidence)
	assert verify_certificate_integrity(certificate) is False


@pytest.mark.parametrize("name", ["verified-hdd-job.json", "ata-outcome.json", "nvme-controller-status.json"])
def test_demo_terminal_fixtures_are_sanitized_and_not_active(name):
	payload = json.loads((ROOT / "demo-fixtures" / name).read_text(encoding="utf-8"))
	assert payload["fixture"] is True
	assert "password" not in json.dumps(payload).lower()
	terminal = payload.get("orchestration_terminal_status") or payload.get("final_status")
	assert terminal == "VERIFIED"
