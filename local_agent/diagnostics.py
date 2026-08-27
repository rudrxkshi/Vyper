from __future__ import annotations

import json
import platform
import shutil
import sqlite3
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from vyper_version import __version__

from .config import config_path, credential_path, database_path, load_config


REQUIRED_COMMANDS = ("lsblk", "hdparm", "nvme", "smartctl")


def _service_status(name: str, runner: Callable[..., Any] = subprocess.run) -> str:
	try:
		result = runner(["systemctl", "is-active", name], capture_output=True, text=True, timeout=3, check=False)
		return (result.stdout or "unknown").strip() or "unknown"
	except (OSError, subprocess.SubprocessError):
		return "unavailable"


def _api_health(url: str) -> str:
	try:
		with urllib.request.urlopen(url, timeout=2) as response:
			payload = json.loads(response.read().decode("utf-8"))
		return "ok" if payload.get("status") == "ok" else "unexpected"
	except (OSError, ValueError, urllib.error.URLError):
		return "unreachable"


def _state_summary(path: Path) -> dict[str, Any]:
	if not path.exists():
		return {"database_exists": False, "outbox_pending": 0, "last_heartbeat": None, "device_observations": 0}
	try:
		connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
		try:
			columns = {row[1] for row in connection.execute("PRAGMA table_info(outbox)")}
			pending_where = "delivered_at IS NULL AND abandoned_at IS NULL" if "abandoned_at" in columns else "delivered_at IS NULL"
			pending = connection.execute(f"SELECT count(*) FROM outbox WHERE {pending_where}").fetchone()[0]
			last = connection.execute("SELECT max(delivered_at) FROM outbox WHERE kind = 'heartbeat'").fetchone()[0]
			devices = 0
		except sqlite3.Error:
			pending, last, devices = 0, None, 0
		finally:
			connection.close()
		return {"database_exists": True, "outbox_pending": pending, "last_heartbeat": last, "device_observations": devices}
	except sqlite3.Error:
		return {"database_exists": True, "outbox_pending": None, "last_heartbeat": None, "device_observations": None}


def collect_diagnostics(*, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
	config = load_config()
	credential_file = credential_path()
	state = _state_summary(database_path())
	return {
		"version": __version__,
		"os": platform.system(),
		"kernel": platform.release(),
		"architecture": platform.machine(),
		"services": {
			"vyper-agent.service": _service_status("vyper-agent.service", runner),
			"vyper-console.service": _service_status("vyper-console.service", runner),
		},
		"local_api_health": _api_health(f"http://{config.local_agent_bind}:{config.local_agent_port}/health"),
		"central_sync": "enabled" if config.sync_enabled else "disabled",
		"enrollment_status": "enrolled" if credential_file.exists() else "not enrolled",
		"last_heartbeat": state["last_heartbeat"],
		"outbox_pending": state["outbox_pending"],
		"required_commands": {command: bool(shutil.which(command)) for command in REQUIRED_COMMANDS},
		"storage_discovery": {"summary": "available through local GET /devices", "observations": state["device_observations"]},
		"paths": {
			"config": str(config_path()),
			"credentials": str(credential_file),
			"database": str(database_path()),
		},
	}
