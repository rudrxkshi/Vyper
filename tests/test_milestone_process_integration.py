from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from agent.discovery import DiscoveredDevice
from local_agent.process_worker import ProcessJobExecutor
from local_agent.storage import LocalJobStore
from local_agent.sync import AgentCredentialStore, CentralSyncClient, SyncLoop
from tests.test_stage4_sync import DiscoveryStub, _central_client, _prepare_agent_asset_job


def _send_frame(connection: socket.socket, payload: dict) -> None:
	connection.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")


def _executor_fixture_server(
	socket_path: str,
	ready: threading.Event,
	execution_started: threading.Event,
	release_execution: threading.Event,
	execution_completed: threading.Event,
	release_terminal: threading.Event,
	server_errors: list[BaseException],
) -> None:
	path = Path(socket_path)
	try:
		if path.exists():
			path.unlink()
		with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
			server.bind(socket_path)
			server.listen(1)
			ready.set()
			connection, _ = server.accept()
			with connection:
				request = bytearray()
				while b"\n" not in request:
					request.extend(connection.recv(8192))
				request_id = json.loads(bytes(request).split(b"\n", 1)[0])["request_id"]
				for kind, value in (
					("stage", "STAGE_PROFILING_STARTED"),
					("stage", "STAGE_PROFILING_COMPLETED"),
					("stage", "STAGE_POLICY_STARTED"),
					("stage", "STAGE_POLICY_COMPLETED"),
					("state", "POLICY_SELECTED"),
					("stage", "STAGE_EXECUTION_STARTED"),
					("state", "RUNNING"),
				):
					_send_frame(connection, {"version": "1", "event": {"kind": kind, "value": value}})
				execution_started.set()
				if not release_execution.wait(timeout=10):
					raise TimeoutError("Test did not release the execution fixture.")
				for kind, value in (
					("stage", "STAGE_EXECUTION_COMPLETED"),
					("state", "VERIFYING"),
					("stage", "STAGE_VERIFICATION_STARTED"),
				):
					_send_frame(connection, {"version": "1", "event": {"kind": kind, "value": value}})
				execution_completed.set()
				if not release_terminal.wait(timeout=10):
					raise TimeoutError("Test did not release the terminal fixture.")
				_send_frame(connection, {
					"version": "1",
					"request_id": request_id,
					"result": {
						"target": "/dev/sdb",
						"job_state": "FAILED",
						"final_status": "FAILED",
						"state_history": ["PENDING", "PROFILING", "POLICY_SELECTED", "RUNNING", "VERIFYING", "FAILED"],
						"profile": {"device_path": "/dev/sdb", "device_type": "HDD"},
						"policy": {"selected_pathway": "HDD_OVERWRITE"},
						"execution": {"status": "FAILED", "metadata": {"method": "HDD_OVERWRITE"}},
						"verification": {"status": "FAILED", "verified": False},
						"evidence": None,
						"certificate": None,
						"message": "Controlled non-destructive process fixture completed.",
					},
				})
	except BaseException as exc:  # pragma: no cover - surfaced in the parent assertion
		server_errors.append(exc)
		ready.set()
	finally:
		if path.exists():
			path.unlink()


def _wait_for(predicate, *, timeout: float = 4.0):
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		value = predicate()
		if value:
			return value
		time.sleep(0.02)
	raise AssertionError("Timed out waiting for the production milestone path.")


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="The production executor transport requires AF_UNIX.")
def test_spawned_worker_delivers_execution_milestones_before_terminal_result(tmp_path, monkeypatch):
	socket_path = str(Path.cwd() / f".vyper-process-test-{os.getpid()}-{uuid4().hex[:8]}.sock")
	ready = threading.Event()
	execution_started = threading.Event()
	release_execution = threading.Event()
	execution_completed = threading.Event()
	release_terminal = threading.Event()
	server_errors: list[BaseException] = []
	server = threading.Thread(
		target=_executor_fixture_server,
		args=(
			socket_path, ready, execution_started, release_execution,
			execution_completed, release_terminal, server_errors,
		),
		daemon=True,
	)
	server.start()
	assert ready.wait(timeout=3)
	assert not server_errors
	monkeypatch.setenv("VYPER_EXECUTOR_SOCKET", socket_path)
	monkeypatch.setenv("VYPER_EXECUTOR_DRY_RUN", "false")

	with _central_client(tmp_path) as central:
		enrolled, _headers, _asset, central_job = _prepare_agent_asset_job(central)
		credential_store = AgentCredentialStore(tmp_path / "credential.json")
		credential_store.save(enrolled)
		store = LocalJobStore(tmp_path / "local.db")
		executor = ProcessJobExecutor(tmp_path / "local.db", max_workers=1)
		device = DiscoveredDevice(
			device_path="/dev/sdb", device_type="HDD", model="Mock Disk", serial_number="SER-1",
			size_bytes=1000, interface="ATA/SATA", transport="SATA", rotational=True,
			mounted=False, is_system_device=False, eligible_for_sanitization=True,
		)

		def submit_local_job(**kwargs):
			store.create_job(
				local_job_id=kwargs["local_job_id"], api_version="2", target=kwargs["target"],
				dry_run=kwargs["dry_run"], authorization_metadata={"approved": kwargs["authorized"]},
			)
			if kwargs.get("initial_event"):
				store.record_event_once(kwargs["local_job_id"], *kwargs["initial_event"])
			executor.submit_job(
				kwargs["local_job_id"], kwargs["target"], {"approved": kwargs["authorized"]}, kwargs["dry_run"],
			)
			return kwargs["local_job_id"]

		def forward(request: httpx.Request) -> httpx.Response:
			response = central.request(
				request.method, request.url.raw_path.decode("ascii"), headers=dict(request.headers), content=request.content,
			)
			return httpx.Response(response.status_code, headers=dict(response.headers), content=response.content)

		sync = CentralSyncClient(
			central_url="http://central.test", credential_store=credential_store, job_store=store,
			discovery=DiscoveryStub([device]), submit_local_job=submit_local_job,
			transport=httpx.MockTransport(forward),
		)
		assert sync.poll_job()["central_job_id"] == central_job["central_job_id"]
		loop = SyncLoop(
			sync, interval_seconds=5, job_sync_interval_seconds=30,
			heartbeat_interval_seconds=30, inventory_interval_seconds=60,
			wakeup_event=executor.sync_wakeup_event,
		)
		loop.start()
		local_job_id = sync.approve_remote_job(central_job["central_job_id"], local_approved=True)
		try:
			assert execution_started.wait(timeout=4)

			def central_has_execution_started():
				detail = central.get(f"/central-jobs/{central_job['central_job_id']}").json()
				states = [event["state"] for event in detail["events"]]
				return detail if "STAGE_EXECUTION_STARTED" in states else None

			started_detail = _wait_for(central_has_execution_started)
			assert store.get_job(local_job_id)["final_status"] is None
			assert started_detail["result"] is None

			release_execution.set()
			assert execution_completed.wait(timeout=4)

			def central_has_execution_completed():
				detail = central.get(f"/central-jobs/{central_job['central_job_id']}").json()
				states = [event["state"] for event in detail["events"]]
				return detail if {
					"STAGE_EXECUTION_COMPLETED", "STAGE_VERIFICATION_STARTED",
				}.issubset(states) else None

			completed_detail = _wait_for(central_has_execution_completed)
			assert store.get_job(local_job_id)["final_status"] is None
			assert completed_detail["result"] is None
		finally:
			release_execution.set()
			release_terminal.set()
			_wait_for(lambda: store.get_job(local_job_id)["final_status"] == "FAILED")
			_wait_for(lambda: central.get(f"/central-jobs/{central_job['central_job_id']}").json()["final_status"] == "FAILED")
			loop.stop()
			executor.shutdown(wait=True)

	server.join(timeout=3)
	assert not server.is_alive()
	assert not server_errors
