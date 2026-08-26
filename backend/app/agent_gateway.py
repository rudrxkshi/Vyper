from __future__ import annotations

import os
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, ValidationError

from agent.agent import OrchestrationJobResult, VYPERAgent
from local_agent.schemas import LocalJobAccepted, LocalJobResponse


class _LegacyLocalJobResponse(BaseModel):
    api_version: str = "1"
    local_job_id: str
    target: str
    job_state: str
    final_status: str
    profile: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    execution: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    certificate: dict[str, Any] = Field(default_factory=dict)
    state_history: list[str] = Field(default_factory=list)
    message: str = ""


class AgentGatewayError(RuntimeError):
    """Raised when a configured local-agent transport fails safely."""


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


def _canonical_url(value: str) -> tuple[str, str, int | None, str]:
    parsed = urlsplit(value.rstrip("/"))
    port = parsed.port
    if port is None and parsed.scheme == "http":
        port = 80
    elif port is None and parsed.scheme == "https":
        port = 443
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port, parsed.path.rstrip("/")


class RemoteLocalAgentGateway:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        central_base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
        poll_interval: float = 0.25,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = float(timeout)
        self.transport = transport
        self.poll_interval = max(0.0, float(poll_interval))
        if central_base_url and _canonical_url(self.base_url) == _canonical_url(central_base_url):
            raise AgentGatewayError(
                "VYPER_AGENT_API_URL points to the central backend; refusing recursive forwarding."
            )

    def dispatch(self, *, target: str, authorization: dict[str, Any], dry_run: bool | None = None) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["X-VYPER-API-Key"] = self.api_key

        payload = {"target": target, "authorization": authorization, "dry_run": dry_run}
        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                health_response = client.get("/health", headers=headers)
                health_response.raise_for_status()
                health = health_response.json()
                agent_version = str(health.get("api_version"))
                if health.get("service") != "local-agent" or agent_version not in {"1", "2"}:
                    raise AgentGatewayError(
                        "Configured agent endpoint is not a compatible VYPER local-agent service."
                    )

                response = client.post("/jobs/sanitize", json=payload, headers=headers)
                response.raise_for_status()
                if agent_version == "1":
                    local_job = _LegacyLocalJobResponse.model_validate(response.json())
                    state_history = local_job.state_history
                else:
                    accepted = LocalJobAccepted.model_validate(response.json())
                    deadline = time.monotonic() + self.timeout
                    while True:
                        job_response = client.get(f"/jobs/{accepted.local_job_id}", headers=headers)
                        job_response.raise_for_status()
                        local_job = LocalJobResponse.model_validate(job_response.json())
                        if local_job.final_status is not None:
                            break
                        if time.monotonic() >= deadline:
                            raise AgentGatewayError("Timed out waiting for the local-agent job to finish.")
                        time.sleep(self.poll_interval)
                    state_history = [event.state for event in local_job.state_history]
        except AgentGatewayError:
            raise
        except (httpx.HTTPError, ValueError, ValidationError) as exc:
            raise AgentGatewayError(f"Local-agent request failed safely: {exc}") from exc

        return {
            "local_job_id": local_job.local_job_id,
            "target": local_job.target,
            "job_state": local_job.job_state,
            "final_status": local_job.final_status,
            "profile": local_job.profile,
            "policy": local_job.policy,
            "execution": local_job.execution,
            "verification": local_job.verification,
            "evidence": local_job.evidence,
            "certificate": local_job.certificate,
            "state_history": state_history,
            "message": local_job.message,
        }


def build_agent_gateway() -> AgentGateway:
    agent_api_url = os.getenv("VYPER_AGENT_API_URL")
    if agent_api_url:
        central_api_url = os.getenv("VYPER_CENTRAL_API_URL") or os.getenv("VYPER_PUBLIC_API_URL")
        return RemoteLocalAgentGateway(
            agent_api_url,
            api_key=os.getenv("VYPER_AGENT_API_KEY"),
            central_base_url=central_api_url,
        )
    return LocalAgentGateway()


# Backward-compatible import only; new code should use the explicit local-agent name.
HttpAgentGateway = RemoteLocalAgentGateway
