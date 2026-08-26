from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
	import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python >=3.11 is required by packaging
	tomllib = None


DEFAULT_CONFIG_PATH = Path("/etc/vyper/config.toml")
DEFAULT_CREDENTIAL_PATH = Path("/etc/vyper/agent-identity.json")
DEFAULT_DATABASE_PATH = Path("/var/lib/vyper/local-jobs.db")
DEFAULT_UI_PATH = Path("/opt/vyper/ui")


@dataclass(frozen=True)
class LocalConfig:
	central_api_url: str = ""
	local_agent_bind: str = "127.0.0.1"
	local_agent_port: int = 8765
	local_console_bind: str = "127.0.0.1"
	local_console_port: int = 8787
	sync_enabled: bool = False
	heartbeat_interval: int = 30
	inventory_interval: int = 60
	job_poll_interval: int = 5
	log_level: str = "INFO"


def config_path() -> Path:
	return Path(os.getenv("VYPER_CONFIG_PATH", str(DEFAULT_CONFIG_PATH)))


def credential_path() -> Path:
	return Path(os.getenv("VYPER_AGENT_CREDENTIAL_PATH", str(DEFAULT_CREDENTIAL_PATH)))


def database_path() -> Path:
	return Path(os.getenv("VYPER_LOCAL_AGENT_DATABASE_PATH", str(DEFAULT_DATABASE_PATH)))


def ui_path() -> Path:
	return Path(os.getenv("VYPER_UI_PATH", str(DEFAULT_UI_PATH)))


def load_config(path: str | Path | None = None) -> LocalConfig:
	resolved = Path(path) if path else config_path()
	if not resolved.exists():
		return LocalConfig()
	if tomllib is None:
		raise RuntimeError("Python 3.11 or newer is required to read VYPER configuration.")
	with resolved.open("rb") as handle:
		payload = tomllib.load(handle)
	section = payload.get("vyper", payload)
	known = {key: value for key, value in section.items() if key in LocalConfig.__dataclass_fields__}
	return LocalConfig(**known)


def write_config(config: LocalConfig, path: str | Path | None = None) -> Path:
	resolved = Path(path) if path else config_path()
	resolved.parent.mkdir(parents=True, exist_ok=True)
	lines = ["[vyper]"]
	for key, value in asdict(config).items():
		if isinstance(value, bool):
			encoded = "true" if value else "false"
		elif isinstance(value, int):
			encoded = str(value)
		else:
			encoded = '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
		lines.append(f"{key} = {encoded}")
	resolved.write_text("\n".join(lines) + "\n", encoding="utf-8")
	try:
		os.chmod(resolved, 0o640)
	except OSError:
		pass
	return resolved


def apply_runtime_environment(config: LocalConfig | None = None) -> LocalConfig:
	settings = config or load_config()
	if settings.sync_enabled and settings.central_api_url and not settings.central_api_url.startswith(
		("https://", "http://127.0.0.1", "http://localhost")
	):
		raise RuntimeError("Central synchronization requires HTTPS except for loopback development URLs.")
	mapping: dict[str, Any] = {
		"VYPER_LOCAL_AGENT_HOST": settings.local_agent_bind,
		"VYPER_LOCAL_AGENT_PORT": settings.local_agent_port,
		"VYPER_LOCAL_AGENT_DATABASE_PATH": database_path(),
		"VYPER_AGENT_CREDENTIAL_PATH": credential_path(),
		"VYPER_CENTRAL_POLL_SECONDS": settings.job_poll_interval,
		"VYPER_HEARTBEAT_INTERVAL": settings.heartbeat_interval,
		"VYPER_INVENTORY_INTERVAL": settings.inventory_interval,
		"VYPER_SYNC_ENABLED": settings.sync_enabled,
		"VYPER_LOG_LEVEL": settings.log_level,
		"VYPER_LOCAL_AGENT_CORS_ORIGINS": f"http://{settings.local_console_bind}:{settings.local_console_port}",
	}
	if settings.sync_enabled and settings.central_api_url:
		mapping["VYPER_CENTRAL_URL"] = settings.central_api_url
	else:
		os.environ.pop("VYPER_CENTRAL_URL", None)
	for key, value in mapping.items():
		os.environ[key] = str(value)
	return settings
