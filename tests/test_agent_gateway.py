from __future__ import annotations

import httpx
import pytest

from backend.app.agent_gateway import AgentGatewayError, RemoteLocalAgentGateway


def _job_response():
	return {
		"api_version": "1",
		"local_job_id": "local-job-1",
		"target": "/dev/sdz",
		"job_state": "VERIFIED",
		"final_status": "VERIFIED",
		"profile": {"device_path": "/dev/sdz", "device_type": "HDD"},
		"policy": {"selected_pathway": "HDD_OVERWRITE"},
		"execution": {"status": "RUNNING", "dry_run": False},
		"verification": {"status": "VERIFIED", "verified": True},
		"evidence": {"final_status": "VERIFIED"},
		"certificate": {"successful_sanitization_claim": True},
		"state_history": ["PENDING", "VERIFIED"],
		"message": "Workflow completed.",
	}


def test_remote_local_agent_gateway_parses_versioned_transport_schema():
	requests = []

	def handler(request):
		requests.append(request)
		if request.url.path == "/health":
			return httpx.Response(200, json={"status": "ok", "service": "local-agent", "api_version": "1"})
		return httpx.Response(201, json=_job_response())

	gateway = RemoteLocalAgentGateway(
		"http://local-agent.test",
		transport=httpx.MockTransport(handler),
	)
	result = gateway.dispatch(
		target="/dev/sdz",
		authorization={"approved": True},
		dry_run=False,
	)

	assert [request.url.path for request in requests] == ["/health", "/jobs/sanitize"]
	assert result["local_job_id"] == "local-job-1"
	assert result["job_state"] == "VERIFIED"
	assert result["profile"]["device_type"] == "HDD"


def test_remote_local_agent_gateway_rejects_malformed_agent_response():
	def handler(request):
		if request.url.path == "/health":
			return httpx.Response(200, json={"status": "ok", "service": "local-agent", "api_version": "1"})
		return httpx.Response(201, json={"api_version": "1", "target": "/dev/sdz"})

	gateway = RemoteLocalAgentGateway(
		"http://local-agent.test",
		transport=httpx.MockTransport(handler),
	)
	with pytest.raises(AgentGatewayError, match="failed safely"):
		gateway.dispatch(target="/dev/sdz", authorization={"approved": True}, dry_run=True)


def test_remote_local_agent_gateway_rejects_central_recursion_configuration():
	with pytest.raises(AgentGatewayError, match="recursive forwarding"):
		RemoteLocalAgentGateway(
			"http://127.0.0.1:8000/",
			central_base_url="http://127.0.0.1:8000",
		)


def test_remote_local_agent_gateway_rejects_central_health_identity_before_post():
	paths = []

	def handler(request):
		paths.append(request.url.path)
		return httpx.Response(200, json={"status": "ok", "service": "central", "api_version": "1"})

	gateway = RemoteLocalAgentGateway(
		"http://central.test",
		transport=httpx.MockTransport(handler),
	)
	with pytest.raises(AgentGatewayError, match="not a compatible"):
		gateway.dispatch(target="/dev/sdz", authorization={"approved": True}, dry_run=True)

	assert paths == ["/health"]


def test_remote_gateway_submits_and_polls_version_two_jobs():
	paths = []

	def handler(request):
		paths.append(request.url.path)
		if request.url.path == "/health":
			return httpx.Response(200, json={"status": "ok", "service": "local-agent", "api_version": "2"})
		if request.method == "POST":
			return httpx.Response(202, json={
				"api_version": "2", "local_job_id": "async-1", "target": "/dev/sdz",
				"job_state": "PENDING", "final_status": None, "message": "Job accepted.",
			})
		return httpx.Response(200, json={
			"api_version": "2", "local_job_id": "async-1", "target": "/dev/sdz",
			"dry_run": True, "job_state": "INCONCLUSIVE", "final_status": "INCONCLUSIVE",
			"created_at": "2026-01-01T00:00:00Z", "started_at": "2026-01-01T00:00:01Z",
			"finished_at": "2026-01-01T00:00:02Z", "updated_at": "2026-01-01T00:00:02Z",
			"message": "Dry run complete.", "progress": {"kind": "indeterminate"},
			"profile": {}, "policy": {}, "execution": {"dry_run": True},
			"verification": {}, "evidence": {"final_status": "INCONCLUSIVE"},
			"certificate": {}, "error": None, "worker_pid": 123,
			"state_history": [
				{"sequence": 1, "state": "PENDING", "timestamp": "2026-01-01T00:00:00Z", "message": "Job accepted.", "progress": None},
				{"sequence": 2, "state": "INCONCLUSIVE", "timestamp": "2026-01-01T00:00:02Z", "message": "Done.", "progress": None},
			],
		})

	gateway = RemoteLocalAgentGateway(
		"http://local-agent.test",
		transport=httpx.MockTransport(handler),
		poll_interval=0,
	)
	result = gateway.dispatch(target="/dev/sdz", authorization={"approved": False}, dry_run=True)

	assert paths == ["/health", "/jobs/sanitize", "/jobs/async-1"]
	assert result["job_state"] == "INCONCLUSIVE"
	assert result["state_history"] == ["PENDING", "INCONCLUSIVE"]
