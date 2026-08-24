from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import tomllib
from types import SimpleNamespace
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import create_app
from local_agent.config import LocalConfig, load_config, write_config
from local_agent import cli
from local_agent.diagnostics import collect_diagnostics
from local_agent.storage import LocalJobStore
from local_agent.sync import AgentCredentialStore
from vyper_version import __version__


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"
ARTIFACT = RELEASE / "vyper-local-console-linux-x86_64.tar.gz"


def _load_installer():
	spec = importlib.util.spec_from_file_location("vyper_installer", ROOT / "packaging" / "linux" / "installer.py")
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def _package_fixture(tmp_path: Path) -> Path:
	package = tmp_path / "package"
	(package / "payload" / "ui").mkdir(parents=True)
	(package / "payload" / "systemd").mkdir()
	shutil.copytree(ROOT / "packaging" / "boot", package / "payload" / "boot")
	shutil.copytree(ROOT / "docs", package / "payload" / "docs")
	(package / "manifest.json").write_text('{"version":"0.5.0"}', encoding="utf-8")
	(package / "payload" / "VERSION").write_text("0.5.0\n", encoding="utf-8")
	(package / "payload" / "ui" / "index.html").write_text("VYPER", encoding="utf-8")
	for filename in ("config.toml",):
		(package / "payload" / filename).write_bytes((ROOT / "packaging" / "linux" / filename).read_bytes())
	for filename in ("vyper-agent.service", "vyper-console.service"):
		(package / "payload" / "systemd" / filename).write_bytes((ROOT / "packaging" / "linux" / "systemd" / filename).read_bytes())
	return package


def test_package_manifest_version_matches_code_and_pyproject():
	pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
	manifest = json.loads((RELEASE / "manifest.json").read_text(encoding="utf-8"))
	assert pyproject["project"]["version"] == __version__ == manifest["version"]


def test_release_checksum_and_size_match_actual_artifact():
	manifest = json.loads((RELEASE / "manifest.json").read_text(encoding="utf-8"))
	digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
	assert manifest["sha256"] == digest
	assert manifest["size_bytes"] == ARTIFACT.stat().st_size
	assert (RELEASE / "checksums.txt").read_text(encoding="utf-8").startswith(digest)


def test_installer_creates_layout_and_secure_permissions(tmp_path):
	installer = _load_installer()
	package = _package_fixture(tmp_path)
	rootfs = tmp_path / "rootfs"
	installer.install_layout(package, rootfs, test_mode=True)
	for relative in ("opt/vyper/ui", "opt/vyper/docs/SYSTEM_DISK_SANITIZATION.md", "etc/vyper/config.toml",
		"var/lib/vyper", "var/log/vyper", "usr/bin/vyper"):
		assert (rootfs / relative).exists()
	if os.name != "nt":
		assert stat.S_IMODE((rootfs / "etc/vyper/config.toml").stat().st_mode) & 0o002 == 0
		assert stat.S_IMODE((rootfs / "var/lib/vyper").stat().st_mode) & 0o007 == 0
	else:
		installer_source = (ROOT / "packaging/linux/installer.py").read_text(encoding="utf-8")
		assert "os.chmod(config, 0o640)" in installer_source
		assert "(state, 0o700)" in installer_source


def test_upgrade_preserves_config_credentials_and_state(tmp_path):
	installer = _load_installer()
	package = _package_fixture(tmp_path)
	rootfs = tmp_path / "rootfs"
	installer.install_layout(package, rootfs, test_mode=True)
	(rootfs / "etc/vyper/config.toml").write_text("preserved-config", encoding="utf-8")
	(rootfs / "etc/vyper/agent-identity.json").write_text("preserved-credential", encoding="utf-8")
	(rootfs / "var/lib/vyper/local-jobs.db").write_text("preserved-state", encoding="utf-8")
	installer.install_layout(package, rootfs, test_mode=True)
	assert (rootfs / "etc/vyper/config.toml").read_text(encoding="utf-8") == "preserved-config"
	assert (rootfs / "etc/vyper/agent-identity.json").read_text(encoding="utf-8") == "preserved-credential"
	assert (rootfs / "var/lib/vyper/local-jobs.db").read_text(encoding="utf-8") == "preserved-state"


def test_fresh_install_fixture_initializes_runtime_state_and_all_cli_wrappers(tmp_path):
	installer = _load_installer()
	rootfs = tmp_path / "fresh-rootfs"
	installer.install_layout(_package_fixture(tmp_path), rootfs, test_mode=True)
	store = LocalJobStore(rootfs / "var/lib/vyper/local-jobs.db")
	assert store.list_jobs() == [] and store.outbox_summary()["pending"] == 0
	for command in installer.COMMANDS:
		wrapper = rootfs / "usr/bin" / command
		assert wrapper.is_file() and f"/opt/vyper/runtime/bin/{command}" in wrapper.read_text(encoding="utf-8")
	assert (rootfs / "opt/vyper/ui/index.html").read_text(encoding="utf-8") == "VYPER"
	assert (rootfs / "etc/vyper/config.toml").is_file()
	assert not (rootfs / "etc/vyper/agent-identity.json").exists()


def test_upgrade_preserves_jobs_outbox_correlation_evidence_and_operator_state(tmp_path):
	installer = _load_installer()
	package = _package_fixture(tmp_path)
	rootfs = tmp_path / "upgrade-rootfs"
	installer.install_layout(package, rootfs, test_mode=True)
	state_dir = rootfs / "var/lib/vyper"
	store = LocalJobStore(state_dir / "local-jobs.db")
	store.create_job(local_job_id="local-preserved", api_version="2", target="/dev/mock", dry_run=True,
		authorization_metadata={"approved": False})
	store.complete("local-preserved", {"job_state": "INCONCLUSIVE", "final_status": "INCONCLUSIVE",
		"message": "fixture", "progress": None, "profile": {"serial_number": "SER-PRESERVED"},
		"policy": {}, "execution": {}, "verification": {}, "evidence": {"fixture": True},
		"certificate": {"successful_sanitization_claim": False}, "error": None})
	store.save_remote_request({"central_job_id": "central-preserved", "target_identity": "identity-preserved",
		"requested_target": "/dev/mock", "dry_run": True, "authorization_policy": {"central_approved": False},
		"expires_at": "2099-01-01T00:00:00Z", "idempotency_key": "upgrade-preserved",
		"nonce": "nonce-preserved", "execution_mode": "normal_local"})
	store.map_remote_job("central-preserved", "local-preserved", local_approved=False)
	store.enqueue_outbox(outbox_id="outbox-preserved", kind="job_result", idempotency_key="result-preserved",
		central_job_id="central-preserved", local_job_id="local-preserved", payload={"final_status": "INCONCLUSIVE"})
	(rootfs / "etc/vyper/agent-identity.json").write_text("preserved-credential", encoding="utf-8")
	(state_dir / "evidence").mkdir()
	(state_dir / "evidence/result.json").write_text('{"preserved":true}', encoding="utf-8")
	installer.install_layout(package, rootfs, test_mode=True)
	restarted = LocalJobStore(state_dir / "local-jobs.db")
	assert restarted.get_job("local-preserved")["evidence"] == {"fixture": True}
	assert restarted.get_remote_request("central-preserved")["local_job_id"] == "local-preserved"
	assert restarted.outbox_summary()["pending"] == 1
	assert (rootfs / "etc/vyper/agent-identity.json").read_text(encoding="utf-8") == "preserved-credential"
	assert (state_dir / "evidence/result.json").read_text(encoding="utf-8") == '{"preserved":true}'


def test_uninstall_preserves_state_unless_purge_is_explicit(tmp_path):
	installer = _load_installer()
	package = _package_fixture(tmp_path)
	rootfs = tmp_path / "rootfs"
	installer.install_layout(package, rootfs, test_mode=True)
	(rootfs / "etc/vyper/agent-identity.json").write_text("credential", encoding="utf-8")
	(rootfs / "var/lib/vyper/local-jobs.db").write_text("state", encoding="utf-8")
	installer.uninstall_layout(rootfs)
	assert not (rootfs / "opt/vyper").exists()
	assert (rootfs / "etc/vyper/agent-identity.json").exists()
	assert (rootfs / "var/lib/vyper/local-jobs.db").exists()
	installer.uninstall_layout(rootfs, purge=True)
	assert not (rootfs / "etc/vyper").exists()
	assert not (rootfs / "var/lib/vyper").exists()


def test_config_and_credentials_are_not_world_writable(tmp_path, monkeypatch):
	config_file = tmp_path / "config.toml"
	chmod_modes = []
	original_chmod = os.chmod
	monkeypatch.setattr(os, "chmod", lambda path, mode: (chmod_modes.append(mode), original_chmod(path, mode))[1])
	write_config(LocalConfig(), config_file)
	assert load_config(config_file).local_agent_bind == "127.0.0.1"
	assert 0o640 in chmod_modes
	if os.name != "nt":
		assert stat.S_IMODE(config_file.stat().st_mode) & 0o002 == 0
	modes = []
	original_open = os.open
	monkeypatch.setattr(os, "open", lambda path, flags, mode=0o777: (modes.append(mode), original_open(path, flags, mode))[1])
	credential = tmp_path / "identity.json"
	AgentCredentialStore(credential).save({"agent_id": "agent-1", "agent_token": "secret", "agent_protocol_version": "1"})
	assert modes[-1] == 0o600
	assert stat.S_IMODE(credential.stat().st_mode) & 0o077 == 0 or os.name == "nt"


def test_systemd_units_enforce_loopback_unprivileged_ui_and_no_shell_service():
	agent = (ROOT / "packaging/linux/systemd/vyper-agent.service").read_text(encoding="utf-8")
	console = (ROOT / "packaging/linux/systemd/vyper-console.service").read_text(encoding="utf-8")
	config = (ROOT / "packaging/linux/config.toml").read_text(encoding="utf-8")
	assert 'local_agent_bind = "127.0.0.1"' in config
	assert 'local_console_bind = "127.0.0.1"' in config
	assert "User=root" in agent
	assert "User=vyper-ui" in console and "User=root" not in console
	assert "/bin/sh" not in agent and "/bin/bash" not in agent
	assert "vyper-local-agent" in agent and "NoNewPrivileges=yes" in agent


def test_diagnostics_redact_credentials_and_work_without_enrollment(tmp_path, monkeypatch):
	config_file = tmp_path / "config.toml"
	credential_file = tmp_path / "identity.json"
	database_file = tmp_path / "jobs.db"
	write_config(LocalConfig(), config_file)
	monkeypatch.setenv("VYPER_CONFIG_PATH", str(config_file))
	monkeypatch.setenv("VYPER_AGENT_CREDENTIAL_PATH", str(credential_file))
	monkeypatch.setenv("VYPER_LOCAL_AGENT_DATABASE_PATH", str(database_file))
	result = collect_diagnostics(runner=lambda *args, **kwargs: type("Result", (), {"stdout": "inactive\n"})())
	assert result["enrollment_status"] == "not enrolled"
	AgentCredentialStore(credential_file).save({"agent_id": "agent-1", "agent_token": "never-print-token", "agent_protocol_version": "1"})
	result = collect_diagnostics(runner=lambda *args, **kwargs: type("Result", (), {"stdout": "active\n"})())
	assert result["enrollment_status"] == "enrolled"
	assert "never-print-token" not in json.dumps(result)


def test_enrollment_cli_enables_sync_without_printing_token(tmp_path, monkeypatch, capsys):
	config_file = tmp_path / "config.toml"
	monkeypatch.setenv("VYPER_CONFIG_PATH", str(config_file))
	monkeypatch.setattr(cli, "_post_json", lambda url, payload: {"agent_id": "agent-safe-id"})
	args = SimpleNamespace(
		central_url="https://central.example", token="one-time-secret", display_name="Test Agent", no_restart=True,
	)
	assert cli.enroll(args) == 0
	output = capsys.readouterr()
	assert "agent-safe-id" in output.out
	assert "one-time-secret" not in output.out + output.err
	config = load_config(config_file)
	assert config.sync_enabled is True
	assert config.central_api_url == "https://central.example"


def test_restart_store_preserves_database_and_outbox(tmp_path):
	path = tmp_path / "jobs.db"
	store = LocalJobStore(path)
	store.enqueue_outbox(outbox_id="one", kind="heartbeat", idempotency_key="heartbeat:one", payload={"safe": True})
	restarted = LocalJobStore(path)
	assert restarted.outbox_summary()["pending"] == 1


def test_download_metadata_and_file_are_backed_by_generated_manifest(monkeypatch, tmp_path):
	monkeypatch.setenv("VYPER_RELEASE_DIRECTORY", str(RELEASE))
	monkeypatch.setenv("VYPER_RELEASE_MANIFEST", str(RELEASE / "manifest.json"))
	with TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'central.db'}")) as client:
		items = client.get("/downloads").json()
		response = client.get(items[0]["download_url"])
	assert items[0]["platform"] == "linux" and items[0]["architecture"] == "x86_64"
	assert response.status_code == 200
	assert hashlib.sha256(response.content).hexdigest() == items[0]["sha256"]


def test_download_page_has_one_real_linux_download_and_unavailable_platforms():
	source = (ROOT / "frontend/user-dashboard/app/download/page.js").read_text(encoding="utf-8")
	assert "release.download_url" in source
	assert "Linux x86_64" in source
	assert "Windows — Coming soon (unavailable)" in source
	assert "macOS — Coming soon (unavailable)" in source
	assert "windows.download_url" not in source and "macos.download_url" not in source


def test_artifact_excludes_forbidden_development_and_secret_files():
	forbidden_parts = {".git", ".venv", "node_modules", ".pytest_cache", "__pycache__", ".env", ".env.local"}
	with tarfile.open(ARTIFACT, "r:gz") as archive:
		names = archive.getnames()
		files = [member for member in archive.getmembers() if member.isfile()]
	assert any(name.endswith("/install.sh") for name in names)
	assert any(name.endswith("/manifest.json") for name in names)
	assert any(name.endswith("/payload/ui/index.html") for name in names)
	for member in files:
		parts = set(Path(member.name).parts)
		assert not (parts & forbidden_parts)
		assert not member.name.endswith((".db", ".pyc", ".map"))
