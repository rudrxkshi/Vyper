from __future__ import annotations

import hmac
import json
import os
import secrets
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KEY_PREFIX = "vyp_"
DEFAULT_CREDENTIAL_DIR = Path.home() / ".vyper"
DEFAULT_CREDENTIAL_FILE = DEFAULT_CREDENTIAL_DIR / "agent_credentials.json"
LEGACY_KEY_FILE = DEFAULT_CREDENTIAL_DIR / "agent_api_key"


@dataclass(frozen=True, slots=True)
class AgentCredentials:
    device_id: str
    api_key: str


class AgentCredentialStore:
    def __init__(self, *, root: Path | str | None = None, path: Path | str | None = None) -> None:
        env_path = os.getenv("VYPER_AGENT_CREDENTIALS_PATH")
        if path is not None:
            self.path = Path(path)
        elif env_path:
            self.path = Path(env_path)
        else:
            self.path = (Path(root) if root is not None else DEFAULT_CREDENTIAL_DIR) / "agent_credentials.json"
        self.legacy_key_file = self.path.parent / "agent_api_key"

    def load(self) -> AgentCredentials | None:
        credentials = self._load_json_credentials()
        if credentials is not None:
            return credentials

        legacy_key = self._load_legacy_key()
        if not legacy_key:
            return None

        credentials = AgentCredentials(device_id=self._new_device_id(), api_key=legacy_key)
        try:
            self.save(credentials)
        except OSError:
            pass
        return credentials

    def generate(self, *, device_id: str | None = None) -> AgentCredentials:
        existing = self.load()
        resolved_device_id = str(device_id or (existing.device_id if existing else self._new_device_id()))
        short_device_id = resolved_device_id.replace("-", "")[:12]
        credentials = AgentCredentials(
            device_id=resolved_device_id,
            api_key=f"{KEY_PREFIX}{short_device_id}_{secrets.token_urlsafe(32)}",
        )
        self.save(credentials)
        return credentials

    def save(self, credentials: AgentCredentials) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = {
            "device_id": credentials.device_id,
            "api_key": credentials.api_key,
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.path.chmod(0o600)

        self.legacy_key_file.write_text(credentials.api_key + "\n", encoding="utf-8")
        self.legacy_key_file.chmod(0o600)

    def verify(self, api_key: str | None, *, device_id: str | None = None) -> bool:
        credentials = self.load()
        if credentials is None or not api_key:
            return False
        if device_id and device_id != credentials.device_id:
            return False
        return hmac.compare_digest(str(api_key), credentials.api_key)

    def exists(self) -> bool:
        return self.path.exists() or self.legacy_key_file.exists()

    def _load_json_credentials(self) -> AgentCredentials | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError:
            return None

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None

        if not isinstance(payload, dict):
            return None

        device_id = payload.get("device_id")
        api_key = payload.get("api_key")
        if not isinstance(device_id, str) or not device_id.strip():
            return None
        if not isinstance(api_key, str) or not api_key.strip():
            return None
        return AgentCredentials(device_id=device_id.strip(), api_key=api_key.strip())

    def _load_legacy_key(self) -> str | None:
        try:
            key = self.legacy_key_file.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return None
        except OSError:
            return None
        return key or None

    def _new_device_id(self) -> str:
        return str(uuid.uuid4())


def configured_agent_api_key() -> str | None:
    env_key = os.getenv("VYPER_AGENT_API_KEY")
    if env_key:
        return env_key
    credentials = AgentCredentialStore().load()
    return credentials.api_key if credentials else None


def authorization_api_key(authorization: Any) -> tuple[str | None, str | None]:
    if not isinstance(authorization, dict):
        return None, None

    key = (
        authorization.get("agent_api_key")
        or authorization.get("api_key")
        or authorization.get("token")
        or authorization.get("credential")
    )
    device_id = authorization.get("agent_device_id") or authorization.get("device_id")
    return (str(key) if key else None, str(device_id) if device_id else None)
