from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from fastapi.testclient import TestClient

from agent.agent import OrchestrationJobResult, _ObservableStateHistory
from agent.common import JobState
from agent.discovery import DiscoveredDevice
from local_agent.jobs import LocalJobWorker, result_payload
from local_agent.main import create_app
from local_agent.storage import LocalJobStore


@dataclass
class StubDiscovery:
	devices: list[DiscoveredDevice]

	def discover(self):
		return self.devices


class DeferredExecutor:
	def __init__(self):
		self.calls = []

	def submit(self, function, *args):
		self.calls.append((function, args))
		return SimpleNamespace()

	def run_next(self):
		function, args = self.calls.pop(0)
		function(*args)


def test_result_payload_flattens_observable_state_history():
	result = OrchestrationJobResult(
		job_state=JobState.CANCELLED,
		state_history=_ObservableStateHistory([JobState.PENDING, JobState.CANCELLED], None),
		target="/dev/mock",
	)
	payload = result_payload(result)
	assert payload["job_state"] == "CANCELLED"
	assert payload["state_history"] == ["PENDING", "CANCELLED"]


@pytest.mark.parametrize(("state", "dry_run", "terminal"), [
	("VERIFIED", False, "VERIFIED"),
	("FAILED", False, "FAILED"),
	("INCONCLUSIVE", False, "INCONCLUSIVE"),
	("CANCELLED", True, "INCONCLUSIVE"),
])
def test_terminal_payload_scopes_raw_execution_status(state, dry_run, terminal):
	payload = result_payload(_result("/dev/mock", state, dry_run=dry_run, verified=state == "VERIFIED"))
	assert payload["orchestration_terminal_status"] == terminal
	assert payload["execution"]["status"] == terminal
	assert payload["execution"]["raw_status"] == "RUNNING"
	assert payload["execution"]["status_scope"] == "orchestration_terminal"
	assert payload["evidence"]["execution"]["status"] == "RUNNING"
	assert payload["execution_status_semantics"]["evidence.execution.status"] == "raw_pathway_historical"


def test_terminal_payload_normalizes_cancelled_inconclusive_mismatch_without_losing_fields(tmp_path):
	worker = LocalJobWorker(store=LocalJobStore(tmp_path / "terminal.db"), agent=object())
	payload = {
		"job_state": "CANCELLED", "final_status": "INCONCLUSIVE", "message": "Outcome is inconclusive.",
		"profile": {"serial_number": "SER-TEST"}, "policy": {"selected_pathway": "HDD_OVERWRITE"},
		"execution": {"status": "CANCELLED", "metadata": {"method": "HDD_OVERWRITE"}},
		"verification": {"status": "INCONCLUSIVE", "verified": False},
		"evidence": {"final_status": "INCONCLUSIVE", "integrity_hash": "fixture-hash"},
		"certificate": {"successful_sanitization_claim": False}, "error": None,
	}
	original = json.loads(json.dumps(payload))
	terminal = worker._terminal_payload(payload, dry_run=False)
	assert terminal["job_state"] == terminal["final_status"] == "INCONCLUSIVE"
	for field in ("message", "profile", "policy", "execution", "verification", "evidence", "certificate", "error"):
		assert terminal[field] == original[field]
	assert payload == original


def _result(target, state="VERIFIED", *, method="HDD_OVERWRITE", dry_run=False, verified=True):
	final_status = "VERIFIED" if state == "VERIFIED" else state
	if state == "CANCELLED":
		final_status = "INCONCLUSIVE"
	return {
		"target": target,
		"job_state": state,
		"state_history": ["PENDING", "PROFILING", "POLICY_SELECTED", "RUNNING", "VERIFYING", state],
		"profile": {"device_path": target, "device_type": "HDD"},
		"policy": {"selected_pathway": method},
		"execution": {"status": "RUNNING", "dry_run": dry_run, "metadata": {"method": method}},
		"verification": {"status": final_status, "verified": verified},
		"evidence": {"final_status": final_status, "execution": {"status": "RUNNING"}},
		"certificate": {
			"certificate_id": f"cert-{final_status.lower()}",
			"certificate_hash": "a" * 64,
			"final_status": final_status,
			"outcome_kind": "sanitization_certificate" if final_status == "VERIFIED" else "outcome_report",
			"successful_sanitization_claim": final_status == "VERIFIED",
			"execution": {"status": "RUNNING"},
		},
		"message": "Workflow completed.",
	}


class StubAgent:
	def __init__(self, state="VERIFIED", *, method="HDD_OVERWRITE", verified=True):
		self.state = state
		self.method = method
		self.verified = verified
		self.calls = []

	def sanitize_device(self, target, authorization, dry_run=None, *, event_callback=None, progress_callback=None):
		self.calls.append({"target": target, "authorization": dict(authorization), "dry_run": dry_run})
		for state in ["PROFILING", "POLICY_SELECTED", "RUNNING"]:
			if event_callback:
				event_callback(state)
		if progress_callback and self.method == "HDD_OVERWRITE":
			progress_callback(SimpleNamespace(bytes_written=512, total_bytes=1024))
		if event_callback:
			event_callback("VERIFYING")
		result = _result(
			target,
			"CANCELLED" if dry_run else self.state,
			method=self.method,
			dry_run=bool(dry_run),
			verified=False if dry_run else self.verified,
		)
		if authorization.get("ata_password"):
			result["execution"]["metadata"]["diagnostic"] = f"device said {authorization['ata_password']}"
		return result


class BlockingAgent(StubAgent):
	def __init__(self, *, method="ATA_ERASE"):
		super().__init__(method=method)
		self.started = threading.Event()
		self.release = threading.Event()

	def sanitize_device(self, target, authorization, dry_run=None, *, event_callback=None, progress_callback=None):
		if event_callback:
			event_callback("PROFILING")
			event_callback("POLICY_SELECTED")
			event_callback("RUNNING")
		if progress_callback and self.method == "HDD_OVERWRITE":
			progress_callback(SimpleNamespace(bytes_written=512, total_bytes=1024))
		self.started.set()
		self.release.wait(timeout=5)
		if event_callback:
			event_callback("VERIFYING")
		return _result(target, method=self.method)


def _discovery():
	return StubDiscovery([
		DiscoveredDevice(
			device_path="/dev/sdz",
			device_type="HDD",
			model="Mock disk",
			serial_number=None,
			size_bytes=1024,
			is_system_device=False,
			eligible_for_sanitization=True,
		)
	])


def _client(tmp_path, *, agent=None, executor=None, database_name="jobs.db"):
	agent = agent or StubAgent()
	executor = executor or DeferredExecutor()
	app = create_app(
		agent=agent,
		discovery=_discovery(),
		database_path=tmp_path / database_name,
		executor=executor,
	)
	return TestClient(app), agent, executor


def _submit(client, target="/dev/sdz", *, dry_run=True, password=None):
	return client.post(
		"/jobs/sanitize",
		json={
			"target": target,
			"authorization": {"approved": not dry_run, "ata_password": password},
			"dry_run": dry_run,
		},
	)


def test_packaged_console_origin_has_credentialed_cors_access(tmp_path):
	client, _, _ = _client(tmp_path)
	response = client.options(
		"/health",
		headers={
			"Origin": "http://127.0.0.1:8787",
			"Access-Control-Request-Method": "GET",
			"Access-Control-Request-Headers": "X-VYPER-API-Key",
		},
	)
	assert response.status_code == 200
	assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:8787"
	assert response.headers["access-control-allow-credentials"] == "true"


def test_tauri_origins_have_narrow_credentialed_cors_access(tmp_path):
	client, _, _ = _client(tmp_path)
	for origin in ("tauri://localhost", "http://tauri.localhost"):
		response = client.options(
			"/health",
			headers={
				"Origin": origin,
				"Access-Control-Request-Method": "GET",
				"Access-Control-Request-Headers": "X-VYPER-API-Key",
			},
		)
		assert response.status_code == 200
		assert response.headers["access-control-allow-origin"] == origin
		assert response.headers["access-control-allow-credentials"] == "true"


def test_health_devices_and_cors(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		assert client.get("/health").json() == {"status": "ok", "service": "local-agent", "api_version": "2"}
		devices = client.get("/devices")
		cors = client.options(
			"/devices",
			headers={"Origin": "http://127.0.0.1:3000", "Access-Control-Request-Method": "GET"},
		)
	assert devices.json()[0]["serial_number"] is None
	assert cors.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"


def test_remote_requests_alias_exposes_new_pending_request_ahead_of_older_submitted(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		base = {
			"target_identity": "fixture-identity", "requested_target": "/dev/sdb", "dry_run": False,
			"authorization_policy": {"central_approved": True}, "expires_at": "2999-01-01T00:00:00Z",
			"nonce": "fixture-nonce",
		}
		client.app.state.job_store.save_remote_request({
			**base, "central_job_id": "older-submitted", "idempotency_key": "older-request",
		})
		client.app.state.job_store.map_remote_job("older-submitted", "local-old", local_approved=True)
		client.app.state.job_store.save_remote_request({
			**base, "central_job_id": "new-pending", "idempotency_key": "new-request", "nonce": "new-nonce",
		})
		response = client.get("/remote-requests")
	assert response.status_code == 200
	assert [item["central_job_id"] for item in response.json()] == ["new-pending", "older-submitted"]
	assert response.json()[0]["status"] == "WAITING_LOCAL_APPROVAL"
	assert response.json()[0]["local_approved"] is False


def test_remote_request_rejection_api_records_decision_without_approval_or_execution(tmp_path):
	class SyncClientStub:
		def __init__(self):
			self.rejections = []

		def reject_remote_job(self, central_job_id):
			self.rejections.append(central_job_id)
			return "local-rejected"

	client, _agent, executor = _client(tmp_path)
	sync_client = SyncClientStub()
	with client:
		client.app.state.sync_client = sync_client
		response = client.post(
			"/remote-jobs/central-rejected/approve",
			json={"approved": False, "ata_password": None},
		)

	assert response.status_code == 200
	assert response.json() == {
		"central_job_id": "central-rejected", "local_job_id": "local-rejected", "status": "REJECTED",
	}
	assert sync_client.rejections == ["central-rejected"]
	assert executor.calls == []


def test_post_returns_202_and_persists_pending_before_execution(tmp_path):
	client, agent, executor = _client(tmp_path)
	with client:
		response = _submit(client)
		job_id = response.json()["local_job_id"]
		current = client.get(f"/jobs/{job_id}").json()
	assert response.status_code == 202
	assert response.json()["api_version"] == "2"
	assert current["job_state"] == "PENDING"
	assert current["final_status"] is None
	assert agent.calls == []
	assert len(executor.calls) == 1


def test_lifecycle_events_are_durable_monotonic_and_dry_run_preserved(tmp_path):
	client, _agent, executor = _client(tmp_path)
	with client:
		accepted = _submit(client).json()
		executor.run_next()
		job = client.get(f"/jobs/{accepted['local_job_id']}").json()
		history = client.get("/jobs").json()
	assert job["job_state"] == "INCONCLUSIVE"
	assert job["final_status"] == "INCONCLUSIVE"
	assert [event["sequence"] for event in job["state_history"]] == list(range(1, len(job["state_history"]) + 1))
	states = [event["state"] for event in job["state_history"]]
	assert [state for index, state in enumerate(states) if index == 0 or state != states[index - 1]] == [
		"PENDING", "PROFILING", "POLICY_SELECTED", "RUNNING", "VERIFYING", "INCONCLUSIVE"
	]
	assert history[0]["local_job_id"] == accepted["local_job_id"]


def test_pipeline_stage_events_persist_once_without_replacing_job_state(tmp_path):
	store = LocalJobStore(tmp_path / "pipeline-events.db")
	store.create_job(
		local_job_id="pipeline-job", api_version="2", target="/dev/mock", dry_run=False,
		authorization_metadata={"approved": True},
	)
	assert store.start_job("pipeline-job", 1234) is True
	for event in (
		"STAGE_PROFILING_STARTED", "STAGE_PROFILING_COMPLETED", "STAGE_POLICY_STARTED",
	):
		store.record_event_once("pipeline-job", event, f"Recorded {event}.")
	store.record_event_once("pipeline-job", "STAGE_POLICY_STARTED", "Duplicate retry.")

	job = LocalJobStore(tmp_path / "pipeline-events.db").get_job("pipeline-job")
	states = [event["state"] for event in job["state_history"]]
	assert job["job_state"] == "PROFILING"
	assert states == [
		"PENDING", "PROFILING", "STAGE_PROFILING_STARTED",
		"STAGE_PROFILING_COMPLETED", "STAGE_POLICY_STARTED",
	]
	assert [event["sequence"] for event in job["state_history"]] == [1, 2, 3, 4, 5]


def test_every_pipeline_milestone_wakes_sync_but_byte_progress_does_not(tmp_path):
	store = LocalJobStore(tmp_path / "milestone-wakeup.db")
	store.create_job(
		local_job_id="wake-job", api_version="2", target="/dev/mock", dry_run=False,
		authorization_metadata={"approved": True},
	)
	wakeups = []

	def observe_committed_milestone():
		wakeups.append(store.get_job("wake-job")["state_history"][-1]["state"])

	worker = LocalJobWorker(store=store, agent=object(), milestone_notifier=observe_committed_milestone)
	milestones = [
		f"STAGE_{stage}_{outcome}"
		for stage in ("PROFILING", "POLICY", "EXECUTION", "VERIFICATION", "EVIDENCE", "CERTIFICATE")
		for outcome in ("STARTED", "COMPLETED", "FAILED")
	]
	for milestone in milestones:
		worker._stage_event("wake-job", milestone)
	worker._progress_event("wake-job", {"bytes_written": 512, "total_bytes": 1024})

	job = store.get_job("wake-job")
	assert wakeups == milestones
	assert [event["state"] for event in job["state_history"]][1:] == milestones
	assert job["progress"] == {"kind": "bytes", "bytes_completed": 512, "bytes_total": 1024}


def test_worker_wakes_after_durable_start_transitions_and_terminal_result(tmp_path):
	store = LocalJobStore(tmp_path / "terminal-wakeup.db")
	store.create_job(
		local_job_id="terminal-wake-job", api_version="2", target="/dev/mock", dry_run=False,
		authorization_metadata={"approved": True},
	)
	wakeups = []

	def observe_committed_state():
		job = store.get_job("terminal-wake-job")
		wakeups.append((job["job_state"], job["state_history"][-1]["state"]))

	LocalJobWorker(
		store=store, agent=StubAgent(), milestone_notifier=observe_committed_state,
	).run("terminal-wake-job", "/dev/mock", {"approved": True}, False)

	assert wakeups == [
		("PROFILING", "PROFILING"),
		("POLICY_SELECTED", "POLICY_SELECTED"),
		("RUNNING", "RUNNING"),
		("VERIFYING", "VERIFYING"),
		("VERIFIED", "VERIFIED"),
	]


def test_verified_requires_verified_result_and_other_terminals_persist(tmp_path):
	for index, (state, verified, expected) in enumerate([
		("VERIFIED", True, "VERIFIED"),
		("VERIFIED", False, "INCONCLUSIVE"),
		("FAILED", False, "FAILED"),
		("INCONCLUSIVE", False, "INCONCLUSIVE"),
		("UNSUPPORTED", False, "UNSUPPORTED"),
	]):
		client, _agent, executor = _client(
			tmp_path,
			agent=StubAgent(state=state, verified=verified),
			database_name=f"terminal-{index}.db",
		)
		with client:
			accepted = _submit(client, dry_run=False).json()
			executor.run_next()
			job = client.get(f"/jobs/{accepted['local_job_id']}").json()
		assert job["job_state"] == expected


def test_local_certificate_api_projects_authoritative_job_certificates_without_duplicates(tmp_path):
	client, _agent, executor = _client(tmp_path)
	with client:
		verified_id = _submit(client, dry_run=False).json()["local_job_id"]
		executor.run_next()
		first = client.get("/certificates").json()
		second = client.get("/certificates").json()
		verified_job = client.get(f"/jobs/{verified_id}").json()
	assert first == second
	assert len(first) == 1
	certificate = first[0]
	assert certificate["local_job_id"] == certificate["job_id"] == verified_id
	assert certificate["certificate_id"] == verified_job["certificate"]["certificate_id"]
	assert certificate["certificate_hash"] == verified_job["certificate"]["certificate_hash"]
	assert certificate["certificate_json"] == verified_job["certificate"]
	assert certificate["target"] == "/dev/sdz"
	assert certificate["final_status"] == "VERIFIED"
	assert certificate["outcome_kind"] == "sanitization_certificate"
	assert certificate["successful_sanitization_claim"] is True


def test_local_dry_run_outcome_report_is_not_presented_as_successful_certificate(tmp_path):
	client, _agent, executor = _client(tmp_path)
	with client:
		job_id = _submit(client, dry_run=True).json()["local_job_id"]
		executor.run_next()
		certificates = client.get("/certificates").json()
	assert len(certificates) == 1
	assert certificates[0]["local_job_id"] == job_id
	assert certificates[0]["final_status"] == "INCONCLUSIVE"
	assert certificates[0]["outcome_kind"] == "outcome_report"
	assert certificates[0]["successful_sanitization_claim"] is False


def test_local_audit_api_projects_ordered_job_events_and_filters_unrelated_jobs(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		store = client.app.state.job_store
		store.create_job(local_job_id="local-a", api_version="2", target="/dev/sda", dry_run=True, authorization_metadata={})
		store.transition("local-a", "PROFILING", "Profiling target device.")
		store.transition("local-a", "POLICY_SELECTED", "Policy selected.")
		store.create_job(local_job_id="local-b", api_version="2", target="/dev/sdb", dry_run=True, authorization_metadata={})
		all_events = client.get("/audit-logs").json()
		filtered = client.get("/audit-logs", params={"job_id": "local-a"}).json()
	assert {event["local_job_id"] for event in all_events} == {"local-a", "local-b"}
	assert [event["sequence"] for event in filtered] == [1, 2, 3]
	assert [event["state"] for event in filtered] == ["PENDING", "PROFILING", "POLICY_SELECTED"]
	assert all(event["local_job_id"] == "local-a" for event in filtered)
	assert all(event["actor"] == "local-agent" for event in filtered)
	assert all(event["resource"] == "local-job:local-a" for event in filtered)
	assert all(not event["action"].startswith(("RESULT_ACCEPTED", "JOB_EVENT_ACCEPTED")) for event in filtered)


def test_real_hdd_bytes_and_firmware_indeterminate_progress(tmp_path):
	blocking_hdd = BlockingAgent(method="HDD_OVERWRITE")
	client, _agent, _executor = _client(tmp_path, agent=blocking_hdd, executor=None)
	client.app.state.worker_executor = ThreadExecutorAdapter()
	with client:
		accepted = _submit(client, dry_run=False).json()
		assert blocking_hdd.started.wait(timeout=2)
		hdd = client.get(f"/jobs/{accepted['local_job_id']}").json()
		blocking_hdd.release.set()
		_wait_terminal(client, accepted["local_job_id"])
	assert hdd["progress"] == {"kind": "bytes", "bytes_completed": 512, "bytes_total": 1024}
	assert {"kind": "bytes", "bytes_completed": 512, "bytes_total": 1024} not in [
		event["progress"] for event in hdd["state_history"]
	]

	for method in ["ATA_ERASE", "CRYPTO_ERASE"]:
		blocking = BlockingAgent(method=method)
		client, _agent, _executor = _client(
			tmp_path,
			agent=blocking,
			executor=None,
			database_name=f"{method}.db",
		)
		# Use the app-owned executor for an actual asynchronous polling observation.
		client.app.state.worker_executor = ThreadExecutorAdapter()
		with client:
			accepted = _submit(client, dry_run=False).json()
			assert blocking.started.wait(timeout=2)
			running = client.get(f"/jobs/{accepted['local_job_id']}").json()
			blocking.release.set()
			_wait_terminal(client, accepted["local_job_id"])
		assert running["job_state"] == "RUNNING"
		assert running["progress"] == {"kind": "indeterminate"}


class ThreadExecutorAdapter:
	def submit(self, function, *args):
		thread = threading.Thread(target=function, args=args, daemon=True)
		thread.start()
		return thread


def _wait_terminal(client, job_id):
	for _ in range(100):
		job = client.get(f"/jobs/{job_id}").json()
		if job["final_status"] is not None:
			return job
		time.sleep(0.01)
	raise AssertionError("job did not reach a terminal state")


def test_same_destructive_target_is_locked_but_different_target_is_allowed(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		first = _submit(client, dry_run=False)
		duplicate = _submit(client, dry_run=False)
		different = _submit(client, target="/dev/sdy", dry_run=False)
	assert first.status_code == 202
	assert duplicate.status_code == 409
	assert different.status_code == 202


def test_pending_cancel_succeeds_and_active_cancel_is_rejected(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		pending_id = _submit(client).json()["local_job_id"]
		cancelled = client.post(f"/jobs/{pending_id}/cancel")
		active_id = _submit(client, target="/dev/sdy").json()["local_job_id"]
		client.app.state.job_store.transition(active_id, "RUNNING", "Firmware command running.", progress={"kind": "indeterminate"})
		unsafe = client.post(f"/jobs/{active_id}/cancel")
	assert cancelled.json()["job_state"] == "CANCELLED"
	assert unsafe.status_code == 409


def test_restart_preserves_completed_and_recovers_interrupted_without_verified_claim(tmp_path):
	database = tmp_path / "restart.db"
	store = LocalJobStore(database)
	store.create_job(local_job_id="complete", api_version="2", target="/dev/sdx", dry_run=True, authorization_metadata={})
	store.complete("complete", {**_empty_terminal(), "job_state": "FAILED", "final_status": "FAILED"})
	store.create_job(local_job_id="interrupted", api_version="2", target="/dev/sdy", dry_run=False, authorization_metadata={"approved": True})
	store.transition("interrupted", "RUNNING", "Running.", progress={"kind": "indeterminate"})

	client, _agent, _executor = _client(tmp_path, database_name="restart.db")
	with client:
		complete = client.get("/jobs/complete").json()
		interrupted = client.get("/jobs/interrupted").json()
	assert complete["job_state"] == "FAILED"
	assert interrupted["job_state"] == "INCONCLUSIVE"
	assert interrupted["final_status"] == "INCONCLUSIVE"
	assert "restarted before terminal verification" in interrupted["state_history"][-1]["message"]


def _empty_terminal():
	return {
		"message": "Done.", "progress": None, "profile": None, "policy": None,
		"execution": None, "verification": None, "evidence": None,
		"certificate": None, "error": None,
	}


def test_secret_absent_from_database_api_history_and_worker_failure(tmp_path):
	secret = "top-secret-password"
	client, _agent, executor = _client(tmp_path, agent=StubAgent(state="FAILED"))
	with client:
		accepted = _submit(client, dry_run=False, password=secret).json()
		executor.run_next()
		job = client.get(f"/jobs/{accepted['local_job_id']}")
	with sqlite3.connect(tmp_path / "jobs.db") as connection:
		database_dump = " ".join(str(value) for row in connection.execute("SELECT * FROM local_jobs") for value in row)
		database_dump += " ".join(str(value) for row in connection.execute("SELECT * FROM local_job_events") for value in row)
	assert secret not in job.text
	assert secret not in database_dump
	assert secret not in json.dumps(job.json()["state_history"])


def test_validation_unknown_job_and_no_command_endpoint(tmp_path):
	client, _agent, _executor = _client(tmp_path)
	with client:
		malformed = client.post("/jobs/sanitize", json={"target": "not-a-device", "authorized": True})
		unknown = client.get("/jobs/missing")
		command = client.post("/commands", json={"command": "anything"})
	assert malformed.status_code == 422
	assert unknown.status_code == 404
	assert command.status_code == 404
