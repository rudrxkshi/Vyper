from __future__ import annotations

import os
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol

import httpx
from fastapi.encoders import jsonable_encoder

from agent.agent import OrchestrationJobResult, VYPERAgent


def _normalize_result(result: OrchestrationJobResult | dict[str, Any]) -> dict[str, Any]:
    if isinstance(result, dict):
        return jsonable_encoder(result)
    if is_dataclass(result):
        return jsonable_encoder(asdict(result))
    raise TypeError("Unsupported agent result type")


class AgentGateway(Protocol):
    def dispatch(self, *, target: str, authorization: dict[str, Any], dry_run: bool | None = None) -> dict[str, Any]:
        ...


class LocalAgentGateway:
    def __init__(self, agent: VYPERAgent | None = None) -> None:
        self.agent = agent or VYPERAgent(dry_run=True)

    def dispatch(self, *, target: str, authorization: dict[str, Any], dry_run: bool | None = None) -> dict[str, Any]:
        return _normalize_result(self.agent.sanitize_device(target, authorization=authorization, dry_run=dry_run))


class HttpAgentGateway:
    def __init__(self, base_url: str, *, api_key: str | None = None, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = float(timeout)

    def dispatch(self, *, target: str, authorization: dict[str, Any], dry_run: bool | None = None) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["X-VYPER-API-Key"] = self.api_key

        payload = {"target": target, "authorization": authorization, "dry_run": dry_run}
        with httpx.Client(base_url=self.base_url, timeout=self.timeout) as client:
            response = client.post("/jobs/sanitize", json=payload, headers=headers)
            response.raise_for_status()
            return jsonable_encoder(response.json())


def build_agent_gateway() -> AgentGateway:
    agent_api_url = os.getenv("VYPER_AGENT_API_URL")
    if agent_api_url:
        return HttpAgentGateway(agent_api_url, api_key=os.getenv("VYPER_AGENT_API_KEY"))
    return LocalAgentGateway()