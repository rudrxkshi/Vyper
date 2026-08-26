from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agent.discovery import DiscoveredDevice
from agent.certificate import CertificateBuilder
from agent.common import SanitizationResult, SanitizationStatus
from agent.evidence import EvidenceCollector
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult
from backend.app.main import create_app as create_central_app
from backend.app.models import AgentRecord, EnrollmentTokenRecord
from local_agent.storage import LocalJobStore
from local_agent.sync import AgentCredentialStore, CentralSyncClient, hardware_identity


class DiscoveryStub:
	def __init__(self, devices):
		self.devices = devices

	def discover(self):
		return self.devices


def _central_client(tmp_path):
	return TestClient(create_central_app(database_url=f"sqlite:///{tmp_path / 'central.db'}"))


def _enroll(client, *, token=None, hostname="host-a"):
	if token is None:
		token = client.post("/agents/enrollment-tokens", json={"ttl_seconds": 600}).json()["token"]
	response = client.post("/agents/enroll", json={
		"enrollment_token": token,
		"hostname": hostname,
		"platform": "Linux",
		"architecture": "x86_64",
		"agent_version": "4.0-test",
		"api_version": "2",
		"agent_protocol_version": "1",
	})
	return response


def _auth(enrollment):
	return {"Authorization": f"Bearer {enrollment['agent_token']}"}


def _device(path="/dev/sdb", *, serial="SER-1", system=False):
	return {
		"device_path": path, "device_type": "HDD", "model": "Mock Disk", "serial_number": serial,
		"size_bytes": 1000, "interface": "ATA/SATA", "transport": "SATA", "rotational": True,
		"mounted": False, "mounted_partitions": [], "is_system_device": system,
		"capabilities": {}, "warnings": [], "profile_error": None, "eligible_for_sanitization": not system,
	}


def _inventory(devices, version="inventory-1"):
	return {
		"agent_protocol_version": "1", "inventory_version": version,
		"observed_at": "2026-08-24T10:00:00Z", "devices": devices,
	}


def _prepare_agent_asset_job(client, *, hostname="host-a", dry_run=False, idempotency="job-key-0001"):
	enrolled = _enroll(client, hostname=hostname).json()
	headers = _auth(enrolled)
	assert client.put("/agent/inventory", headers=headers, json=_inventory([_device()])).status_code == 200
	asset = client.get(f"/agents/{enrolled['agent_id']}/assets").json()[0]
	job = client.post(f"/agents/{enrolled['agent_id']}/jobs", json={
		"asset_id": asset["id"], "dry_run": dry_run, "central_authorized": not dry_run,
		"destructive_confirmation": None if dry_run else "SANITIZE",
		"idempotency_key": idempotency, "expires_in_seconds": 3600,
	}).json()
	return enrolled, headers, asset, job


def test_one_time_enrollment_token_is_hashed_expiring_and_single_use(tmp_path):
	with _central_client(tmp_path) as client:
		issued = client.post("/agents/enrollment-tokens", json={"ttl_seconds": 600}).json()
		first = _enroll(client, token=issued["token"])
		second = _enroll(client, token=issued["token"])
		with client.app.state.session_factory() as db:
			record = db.execute(select(EnrollmentTokenRecord)).scalar_one()
			stored_hash = record.token_hash
	assert first.status_code == 200
	assert second.status_code == 409
	assert first.json()["agent_id"]
	assert first.json()["agent_token"] != issued["token"]
	assert issued["token"] not in stored_hash


def test_expired_enrollment_token_fails(tmp_path):
	with _central_client(tmp_path) as client:
		issued = client.post("/agents/enrollment-tokens", json={"ttl_seconds": 600}).json()
		with client.app.state.session_factory() as db:
			record = db.execute(select(EnrollmentTokenRecord)).scalar_one()
			record.expires_at = record.expires_at - timedelta(days=1)
			db.commit()
		response = _enroll(client, token=issued["token"])
	assert response.status_code == 410


def test_agent_heartbeat_auth_offline_derivation_and_revocation(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled = _enroll(client).json()
		heartbeat = {
			"agent_version": "4", "api_version": "2", "agent_protocol_version": "1",
			"hostname": "host-a", "platform": "Linux", "architecture": "x86_64",
			"local_status": "READY", "active_job_count": 0,
		}
		assert client.post("/agent/heartbeat", json=heartbeat).status_code == 401
		assert client.post("/agent/heartbeat", headers=_auth(enrolled), json=heartbeat).status_code == 200
		assert client.get("/agents").json()[0]["status"] == "ONLINE"
		with client.app.state.session_factory() as db:
			agent = db.get(AgentRecord, enrolled["agent_id"])
			agent.last_seen_at = agent.last_seen_at - timedelta(hours=1)
			db.commit()
		assert client.get("/agents").json()[0]["status"] == "OFFLINE"
		client.post(f"/agents/{enrolled['agent_id']}/revoke")
		assert client.post("/agent/heartbeat", headers=_auth(enrolled), json=heartbeat).status_code == 403


def test_inventory_is_agent_scoped_idempotent_and_tracks_path_observation(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled = _enroll(client).json()
		headers = _auth(enrolled)
		client.put("/agent/inventory", headers=headers, json=_inventory([_device()]))
		client.put("/agent/inventory", headers=headers, json=_inventory([_device()]))
		client.put("/agent/inventory", headers=headers, json=_inventory([_device("/dev/sdc")], "inventory-2"))
		assets = client.get(f"/agents/{enrolled['agent_id']}/assets").json()
	assert len(assets) == 1
	assert assets[0]["device_path"] == "/dev/sdc"
	assert len(assets[0]["observations_json"]) == 2


def test_inventory_missing_serial_has_safe_agent_scoped_fallback(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled = _enroll(client).json()
		response = client.put("/agent/inventory", headers=_auth(enrolled), json=_inventory([_device(serial=None)]))
		assets = client.get(f"/agents/{enrolled['agent_id']}/assets").json()
	assert response.status_code == 200
	assert len(assets[0]["hardware_identity"]) == 64
	assert assets[0]["identity_confidence"] == "LOW"


def test_replacement_hardware_at_same_path_is_a_new_high_confidence_asset(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled = _enroll(client).json()
		headers = _auth(enrolled)
		client.put("/agent/inventory", headers=headers, json=_inventory([_device(serial="SERIAL-A")]))
		client.put("/agent/inventory", headers=headers, json=_inventory([_device(serial="SERIAL-B")], "inventory-2"))
		assets = client.get(f"/agents/{enrolled['agent_id']}/assets").json()
	assert len(assets) == 2
	assert {asset["serial_number"] for asset in assets} == {"SERIAL-A", "SERIAL-B"}
	assert {asset["identity_confidence"] for asset in assets} == {"HIGH"}


def test_job_claim_is_assigned_atomic_idempotent_and_waits_for_local_approval(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled, headers, _asset, job = _prepare_agent_asset_job(client)
		duplicate = client.post(f"/agents/{enrolled['agent_id']}/jobs", json={
			"asset_id": job["asset_id"], "dry_run": False, "central_authorized": True,
			"destructive_confirmation": "SANITIZE",
			"idempotency_key": "job-key-0001", "expires_in_seconds": 3600,
		}).json()
		claim = client.get("/agent/jobs/next", headers=headers)
		second_claim = client.get("/agent/jobs/next", headers=headers)
	assert duplicate["central_job_id"] == job["central_job_id"]
	assert claim.status_code == 200
	assert claim.json()["status"] == "WAITING_LOCAL_APPROVAL"
	assert second_claim.status_code == 204


def test_system_disk_boot_dry_run_still_requires_local_boot_confirmation(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled = _enroll(client).json()
		headers = _auth(enrolled)
		assert client.put("/agent/inventory", headers=headers,
			json=_inventory([_device("/dev/sda", system=True)])).status_code == 200
		asset = client.get(f"/agents/{enrolled['agent_id']}/assets").json()[0]
		created = client.post(f"/agents/{enrolled['agent_id']}/jobs", json={
			"asset_id": asset["id"], "dry_run": True, "central_authorized": False,
			"destructive_confirmation": None, "idempotency_key": "boot-dry-run-0001",
			"expires_in_seconds": 3600, "execution_mode": "boot_sanitize",
		})
		claim = client.get("/agent/jobs/next", headers=headers)
	assert created.status_code == 201
	assert created.json()["execution_mode"] == "boot_sanitize"
	assert created.json()["request"]["execution_mode"] == "boot_sanitize"
	assert claim.json()["status"] == "WAITING_LOCAL_APPROVAL"
	assert claim.json()["authorization_policy"]["local_approval_required"] is True


def test_job_is_never_delivered_to_another_agent_and_expired_job_is_skipped(tmp_path):
	with _central_client(tmp_path) as client:
		first, first_headers, _asset, job = _prepare_agent_asset_job(client)
		second = _enroll(client, hostname="host-b").json()
		assert client.get("/agent/jobs/next", headers=_auth(second)).status_code == 204
		with client.app.state.session_factory() as db:
			row = db.get(__import__("backend.app.models", fromlist=["CentralJobRecord"]).CentralJobRecord, job["central_job_id"])
			row.expires_at = row.created_at - timedelta(seconds=1)
			db.commit()
		assert client.get("/agent/jobs/next", headers=first_headers).status_code == 204


def test_progress_events_are_monotonic_idempotent_and_do_not_create_verified(tmp_path):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		client.get("/agent/jobs/next", headers=headers)
		base = {
			"agent_protocol_version": "1", "local_job_id": "local-1", "state": "RUNNING",
			"timestamp": "2026-08-24T10:00:00Z", "message": "Measured.",
			"progress": {"kind": "bytes", "bytes_completed": 5, "bytes_total": 10},
		}
		first = client.post(f"/agent/jobs/{job['central_job_id']}/events", headers=headers, json={**base, "sequence": 1})
		duplicate = client.post(f"/agent/jobs/{job['central_job_id']}/events", headers=headers, json={**base, "sequence": 1})
		conflicting_duplicate = client.post(f"/agent/jobs/{job['central_job_id']}/events", headers=headers, json={**base, "sequence": 1, "message": "different"})
		out_of_order = client.post(f"/agent/jobs/{job['central_job_id']}/events", headers=headers, json={**base, "sequence": 3})
		stored = client.get("/central-jobs").json()[0]
	assert first.json()["duplicate"] is False
	assert duplicate.json()["duplicate"] is True
	assert conflicting_duplicate.status_code == 409
	assert out_of_order.status_code == 409
	assert stored["progress"] == base["progress"]
	assert stored["final_status"] is None


def _verified_result(local_job_id="local-1"):
	profile = DeviceProfile(device_path="/dev/sdb", device_type="HDD", model="Mock Disk",
		serial_number="SER-1", size_bytes=1000, interface="ATA", transport="SATA", is_system_device=False)
	policy = PolicyDecision(selected_pathway="HDD_OVERWRITE", device_type="HDD", reason="test", unsupported=False)
	execution = SanitizationResult(status=SanitizationStatus.RUNNING, target_device="/dev/sdb", dry_run=False,
		message="completed", metadata={"method": "HDD_OVERWRITE", "start_time": "2026-08-24T10:00:00Z",
			"end_time": "2026-08-24T10:00:01Z", "duration_seconds": 1.0})
	verification = VerificationResult(status=SanitizationStatus.VERIFIED, device="/dev/sdb",
		pathway="HDD_OVERWRITE", verified=True, message="verified", evidence={"source": "test"})
	evidence = EvidenceCollector(dry_run=False, agent_version="vyper-test").create_record(
		device_profile=profile, policy_decision=policy, execution_result=execution,
		verification_result=verification, started_at="2026-08-24T10:00:00Z", completed_at="2026-08-24T10:00:01Z")
	certificate = CertificateBuilder().build(evidence)
	return {
		"agent_protocol_version": "1", "idempotency_key": "result-key-1", "local_job_id": local_job_id,
		"job_state": "VERIFIED", "final_status": "VERIFIED",
		"profile": {"device_path": "/dev/sdb"}, "policy": {"selected_pathway": "HDD_OVERWRITE"},
		"execution": evidence.execution, "verification": evidence.verification,
		"evidence": evidence.to_dict(), "certificate": certificate.to_dict(), "state_history": [], "error": None,
	}


def test_final_result_is_structurally_checked_correlated_and_idempotent(tmp_path):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		payload = _verified_result()
		first = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=payload)
		duplicate = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=payload)
		stored = client.get("/central-jobs").json()[0]
	assert first.status_code == 200
	assert duplicate.json()["duplicate"] is True
	assert stored["local_job_id"] == "local-1"
	assert stored["final_status"] == "VERIFIED"


def test_bad_integrity_is_quarantined_and_revoked_agent_cannot_upload(tmp_path):
	with _central_client(tmp_path) as client:
		enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		bad = _verified_result()
		bad["evidence"]["integrity_hash"] = "0" * 64
		bad["evidence"]["integrity_algorithm"] = "sha256"
		response = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=bad)
		stored = client.get("/central-jobs").json()[0]
		client.post(f"/agents/{enrolled['agent_id']}/revoke")
		revoked = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=_verified_result("local-2"))
	assert response.status_code == 422
	assert stored["integrity_status"] == "QUARANTINED"
	assert stored["final_status"] == "INCONCLUSIVE"
	assert revoked.status_code == 403


def test_verified_result_without_integrity_hashes_is_quarantined(tmp_path):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		payload = _verified_result()
		payload["evidence"].pop("integrity_hash", None)
		payload["certificate"].pop("certificate_hash", None)
		response = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=payload)
		stored = client.get("/central-jobs").json()[0]
	assert response.status_code == 422
	assert stored["integrity_status"] == "QUARANTINED"
	assert stored["final_status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("final_status", ["FAILED", "INCONCLUSIVE"])
def test_non_verified_terminal_results_persist_without_success_claim(tmp_path, final_status):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		payload = _verified_result()
		payload.update({"job_state": final_status, "final_status": final_status})
		payload["verification"] = {"verified": False, "status": final_status}
		payload["evidence"] = {"final_status": final_status}
		payload["certificate"] = {"successful_sanitization_claim": False}
		response = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=payload)
		stored = client.get("/central-jobs").json()[0]
	assert response.status_code == 200
	assert stored["final_status"] == final_status
	assert stored["result"]["certificate"]["successful_sanitization_claim"] is False


def test_certificate_hash_mismatch_is_quarantined(tmp_path):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		payload = _verified_result()
		payload["certificate"].update({"certificate_hash_algorithm": "sha256", "certificate_hash": "0" * 64})
		response = client.post(f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=payload)
		stored = client.get("/central-jobs").json()[0]
	assert response.status_code == 422
	assert stored["integrity_status"] == "QUARANTINED"
	assert stored["final_status"] == "INCONCLUSIVE"


def test_final_result_cannot_change_existing_local_job_mapping(tmp_path):
	with _central_client(tmp_path) as client:
		_enrolled, headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		event = {
			"agent_protocol_version": "1", "local_job_id": "local-1", "sequence": 1,
			"state": "RUNNING", "timestamp": "2026-08-24T10:00:00Z", "message": "started",
		}
		assert client.post(f"/agent/jobs/{job['central_job_id']}/events", headers=headers, json=event).status_code == 200
		response = client.post(
			f"/agent/jobs/{job['central_job_id']}/result", headers=headers, json=_verified_result("local-2"),
		)
	assert response.status_code == 409


def test_caller_cannot_spoof_another_agent_job(tmp_path):
	with _central_client(tmp_path) as client:
		_first, _headers, _asset, job = _prepare_agent_asset_job(client, dry_run=True)
		second = _enroll(client, hostname="host-b").json()
		response = client.post(
			f"/agent/jobs/{job['central_job_id']}/events", headers=_auth(second),
			json={"agent_protocol_version": "1", "local_job_id": "x", "sequence": 1, "state": "RUNNING", "timestamp": "now", "message": "x"},
		)
	assert response.status_code == 404


def test_local_credential_permissions_and_offline_outbox_retry(tmp_path):
	credential_store = AgentCredentialStore(tmp_path / "credential.json")
	credential_store.save({"agent_id": "agent-1", "agent_token": "never-log-this", "agent_protocol_version": "1"})
	if os.name != "nt":
		assert oct((tmp_path / "credential.json").stat().st_mode & 0o777) == "0o600"
	store = LocalJobStore(tmp_path / "local.db")
	responses = {"available": False, "calls": 0}

	def handler(request):
		responses["calls"] += 1
		if not responses["available"]:
			return httpx.Response(503, json={"detail": "offline"})
		return httpx.Response(200, json={"ok": True})

	sync = CentralSyncClient(
		central_url="http://central.test", credential_store=credential_store, job_store=store,
		discovery=DiscoveryStub([]), submit_local_job=lambda **kwargs: "local", transport=httpx.MockTransport(handler),
	)
	assert sync.queue_heartbeat() is True
	assert sync.flush_outbox() == 0
	assert len(store.due_outbox(now="9999-12-31T00:00:00Z")) == 1
	# A new store instance demonstrates restart durability.
	restarted = LocalJobStore(tmp_path / "local.db")
	with sqlite3.connect(tmp_path / "local.db") as connection:
		connection.execute("UPDATE outbox SET next_attempt_at = '2000-01-01T00:00:00Z'")
		connection.commit()
	sync.job_store = restarted
	responses["available"] = True
	assert sync.flush_outbox() == 1
	assert restarted.due_outbox(now="9999-12-31T00:00:00Z") == []
	assert "never-log-this" not in json.dumps(restarted.due_outbox(now="9999-12-31T00:00:00Z"))


def test_queued_job_result_payload_and_outbox_share_result_idempotency_key(tmp_path):
	store = LocalJobStore(tmp_path / "local.db")
	local_job_id = "local-result-1"
	central_job_id = "central-result-1"
	store.create_job(local_job_id=local_job_id, api_version="2", target="/dev/mock", dry_run=True,
		authorization_metadata={"approved": False})
	store.complete(local_job_id, {
		"job_state": "INCONCLUSIVE", "final_status": "INCONCLUSIVE", "message": "Dry run complete.",
		"progress": None, "profile": {}, "policy": {}, "execution": {}, "verification": {},
		"evidence": {"final_status": "INCONCLUSIVE"}, "certificate": {"successful_sanitization_claim": False},
		"error": None,
	})
	store.save_remote_request({
		"central_job_id": central_job_id, "target_identity": "fixture-identity", "requested_target": "/dev/mock",
		"dry_run": True, "authorization_policy": {"central_approved": False},
		"expires_at": "2999-01-01T00:00:00Z", "idempotency_key": "remote-result-1", "nonce": "fixture-nonce",
	})
	assert store.map_remote_job(central_job_id, local_job_id, local_approved=False) is True
	credential_store = AgentCredentialStore(tmp_path / "credential.json")
	credential_store.save({"agent_id": "agent-1", "agent_token": "fixture-token", "agent_protocol_version": "1"})
	sync = CentralSyncClient(
		central_url="http://central.test", credential_store=credential_store, job_store=store,
		discovery=DiscoveryStub([]), submit_local_job=lambda **kwargs: local_job_id,
	)
	assert sync.queue_job_updates() > 0
	result = next(item for item in store.due_outbox(now="9999-12-31T00:00:00Z") if item["kind"] == "job_result")
	expected = f"result:{central_job_id}"
	assert result["idempotency_key"] == expected
	assert result["payload"]["idempotency_key"] == expected


def test_remote_destructive_request_requires_local_approval_and_revalidates_identity(tmp_path):
	credential_store = AgentCredentialStore(tmp_path / "credential.json")
	credential_store.save({"agent_id": "agent-1", "agent_token": "agent-token", "agent_protocol_version": "1"})
	store = LocalJobStore(tmp_path / "local.db")
	device = DiscoveredDevice(
		device_path="/dev/sdb", device_type="HDD", model="Mock Disk", serial_number="SER-1", size_bytes=1000,
		is_system_device=False, eligible_for_sanitization=True,
	)
	discovery = DiscoveryStub([device])
	submissions = []
	sync = CentralSyncClient(
		central_url="http://central.test", credential_store=credential_store, job_store=store, discovery=discovery,
		submit_local_job=lambda **kwargs: submissions.append(kwargs) or "local-1",
	)
	request = {
		"central_job_id": "central-1", "target_identity": hardware_identity(device.to_dict(), "agent-1"),
		"requested_target": "/dev/sdb", "dry_run": False,
		"authorization_policy": {"central_approved": True}, "expires_at": "2999-01-01T00:00:00Z",
		"idempotency_key": "remote-key", "nonce": "nonce", "status": "WAITING_LOCAL_APPROVAL",
	}
	store.save_remote_request(request)
	with pytest.raises(PermissionError):
		sync.approve_remote_job("central-1", local_approved=False)
	assert sync.approve_remote_job("central-1", local_approved=True) == "local-1"
	assert submissions[0]["authorized"] is True
	assert sync.approve_remote_job("central-1", local_approved=True) == "local-1"
	assert len(submissions) == 1


def test_remote_identity_or_system_state_change_blocks_execution(tmp_path):
	credential_store = AgentCredentialStore(tmp_path / "credential.json")
	credential_store.save({"agent_id": "agent-1", "agent_token": "agent-token", "agent_protocol_version": "1"})
	for index, changed in enumerate([
		DiscoveredDevice(device_path="/dev/sdb", device_type="HDD", model="Other", serial_number="OTHER", size_bytes=1000, is_system_device=False),
		DiscoveredDevice(device_path="/dev/sdb", device_type="HDD", model="Mock Disk", serial_number="SER-1", size_bytes=1000, is_system_device=True),
	]):
		store = LocalJobStore(tmp_path / f"local-{index}.db")
		original = _device()
		store.save_remote_request({
			"central_job_id": f"central-{index}", "target_identity": hardware_identity(original, "agent-1"),
			"requested_target": "/dev/sdb", "dry_run": False, "authorization_policy": {"central_approved": True},
			"expires_at": "2999-01-01T00:00:00Z", "idempotency_key": f"remote-{index}", "nonce": "nonce",
		})
		sync = CentralSyncClient(
			central_url="http://central.test", credential_store=credential_store, job_store=store,
			discovery=DiscoveryStub([changed]), submit_local_job=lambda **kwargs: "should-not-run",
		)
		with pytest.raises(RuntimeError):
			sync.approve_remote_job(f"central-{index}", local_approved=True)


def test_remote_local_job_id_is_deterministic_across_post_submit_retry(tmp_path):
	credential_store = AgentCredentialStore(tmp_path / "credential.json")
	credential_store.save({"agent_id": "agent-1", "agent_token": "agent-token", "agent_protocol_version": "1"})
	store = LocalJobStore(tmp_path / "local.db")
	device = DiscoveredDevice(
		device_path="/dev/sdb", device_type="HDD", model="Mock Disk", serial_number="SER-1", size_bytes=1000,
		is_system_device=False, eligible_for_sanitization=True,
	)
	store.save_remote_request({
		"central_job_id": "central-retry", "target_identity": hardware_identity(device.to_dict(), "agent-1"),
		"requested_target": "/dev/sdb", "dry_run": False, "authorization_policy": {"central_approved": True},
		"expires_at": "2999-01-01T00:00:00Z", "idempotency_key": "remote-retry", "nonce": "nonce",
	})
	calls = []

	def submit(**kwargs):
		calls.append(kwargs["local_job_id"])
		if len(calls) == 1:
			raise RuntimeError("simulated crash after durable local submission")
		return kwargs["local_job_id"]

	sync = CentralSyncClient(
		central_url="http://central.test", credential_store=credential_store, job_store=store,
		discovery=DiscoveryStub([device]), submit_local_job=submit,
	)
	with pytest.raises(RuntimeError):
		sync.approve_remote_job("central-retry", local_approved=True)
	local_job_id = sync.approve_remote_job("central-retry", local_approved=True)
	assert calls == [local_job_id, local_job_id]
	assert store.get_remote_request("central-retry")["local_job_id"] == local_job_id
