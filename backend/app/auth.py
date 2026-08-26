from __future__ import annotations

import os
import hmac

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from agent.credentials import AgentCredentialStore

api_key_header = APIKeyHeader(name="X-VYPER-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(api_key_header)) -> None:
    expected_key = os.getenv("VYPER_API_KEY") or _local_agent_api_key()
    if not expected_key:
        return
    if not api_key or not hmac.compare_digest(api_key, expected_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")


def _local_agent_api_key() -> str | None:
    credentials = AgentCredentialStore().load()
    return credentials.api_key if credentials else None
