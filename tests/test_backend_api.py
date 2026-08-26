from __future__ import annotations

from dataclasses import dataclass

from fastapi.testclient import TestClient

from agent.agent import OrchestrationJobResult
from agent.certificate import CertificateBuilder
from agent.common import JobState, SanitizationResult, SanitizationStatus
from agent.credentials import AgentCredentialStore
from agent.evidence import EvidenceCollector
from agent.policy import PolicyDecision
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult

from backend.app.main import create_app


@dataclass
class StubGateway:
    result: OrchestrationJobResult

    def dispatch(self, *, target, authorization, dry_run=None):
        return {
            "job_state": self.result.job_state.value,
            "state_history": [state.value for state in self.result.state_history],
            "target": self.result.target,
            "profile": self.result.profile,
            "policy": self.result.policy,
            "execution": self.result.execution,
            "verification": self.result.verification,
            "evidence": self.result.evidence,
            "certificate": self.result.certificate,
            "message": self.result.message,
        }


def _orchestration_result() -> OrchestrationJobResult:
    profile = DeviceProfile(
        device_path="/dev/sdz",
        device_type="HDD",
        model="demo",
        serial_number="serial-1",
        size_bytes=1024,
        interface="ATA",
        transport="SATA",
        is_system_device=False,
        capabilities={"type": "ATA/SATA"},
    )
    policy = PolicyDecision(selected_pathway="HDD_OVERWRITE", device_type="HDD", reason="demo", unsupported=False)
    execution = SanitizationResult(
        status=SanitizationStatus.RUNNING,
        target_device="/dev/sdz",
        dry_run=True,
        message="planned",
        metadata={"method": "HDD_OVERWRITE", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T00:00:01Z", "duration_seconds": 1.0},
    )
    verification = VerificationResult(
        status=SanitizationStatus.VERIFIED,
        device="/dev/sdz",
        pathway="HDD_OVERWRITE",
        verified=True,
        evidence={"source": "demo", "status": "verified"},
    )
    evidence = EvidenceCollector(dry_run=False, agent_version="vyper-test").create_record(
        device_profile=profile, policy_decision=policy, execution_result=execution,
        verification_result=verification, started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
    )
    certificate = CertificateBuilder(certificate_version="1.0.0").build(evidence)
    return OrchestrationJobResult(
        job_state=JobState.VERIFIED,
        state_history=[JobState.PENDING, JobState.PROFILING, JobState.POLICY_SELECTED, JobState.RUNNING, JobState.VERIFYING, JobState.VERIFIED],
        target="/dev/sdz",
        profile=profile,
        policy=policy,
        execution=execution,
        verification=verification,
        evidence=evidence,
        certificate=certificate,
        message="Workflow completed.",
    )


def test_backend_persists_jobs_devices_and_certificates(tmp_path, monkeypatch):
    monkeypatch.delenv("VYPER_API_KEY", raising=False)
    monkeypatch.setenv("VYPER_AGENT_CREDENTIALS_PATH", str(tmp_path / "missing_credentials.json"))
    result = _orchestration_result()
    app = create_app(database_url=f"sqlite:///{tmp_path / 'vyper.db'}", agent_gateway=StubGateway(result))

    with TestClient(app) as client:
        response = client.post(
            "/jobs/sanitize",
            json={"target": "/dev/sdz", "authorization": {"approved": True}, "dry_run": True},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["job_state"] == "VERIFIED"
        assert body["certificate_id"] == result.certificate.certificate_id

        jobs = client.get("/jobs").json()
        assets = client.get("/assets").json()
        results = client.get("/results").json()
        certificates = client.get("/certificates").json()
        audit_logs = client.get("/audit-logs").json()

        assert len(jobs) == 1
        assert jobs[0]["target"] == "/dev/sdz"
        assert jobs[0]["asset"]["device_path"] == "/dev/sdz"
        assert len(assets) == 1
        assert assets[0]["device_path"] == "/dev/sdz"
        assert len(results) == 1
        assert results[0]["job_id"] == jobs[0]["id"]
        assert len(certificates) == 1
        assert certificates[0]["certificate_id"] == result.certificate.certificate_id
        assert len(audit_logs) == 1
        assert audit_logs[0]["action"] == "sanitize_device"


def test_backend_accepts_gui_generated_agent_key(tmp_path, monkeypatch):
    credentials_path = tmp_path / "agent_credentials.json"
    monkeypatch.delenv("VYPER_API_KEY", raising=False)
    monkeypatch.setenv("VYPER_DEV_ANONYMOUS_OPERATOR", "false")
    monkeypatch.setenv("VYPER_AGENT_CREDENTIALS_PATH", str(credentials_path))
    credentials = AgentCredentialStore(path=credentials_path).generate()
    app = create_app(database_url=f"sqlite:///{tmp_path / 'vyper.db'}", agent_gateway=StubGateway(_orchestration_result()))

    with TestClient(app) as client:
        rejected = client.post(
            "/jobs/sanitize",
            json={"target": "/dev/sdz", "authorization": {"approved": True}, "dry_run": True},
        )
        accepted = client.post(
            "/jobs/sanitize",
            headers={"X-VYPER-API-Key": credentials.api_key},
            json={"target": "/dev/sdz", "authorization": {"approved": True}, "dry_run": True},
        )

        assert rejected.status_code == 401
        assert accepted.status_code == 201
        assert accepted.json()["authorization_json"]["agent_api_key"] == "<redacted>"


def test_backend_rejects_verified_result_without_integrity_hashes(tmp_path):
    result = _orchestration_result()
    result.evidence.integrity_hash = ""
    result.certificate.certificate_hash = ""
    app = create_app(database_url=f"sqlite:///{tmp_path / 'invalid.db'}", agent_gateway=StubGateway(result))
    with TestClient(app) as client:
        response = client.post("/jobs/sanitize", json={
            "target": "/dev/sdz", "authorization": {"approved": True}, "dry_run": False,
        })
    assert response.status_code == 422
    assert "integrity hashes" in response.json()["detail"]


def test_backend_rejects_legacy_flat_sanitize_request(tmp_path):
    app = create_app(database_url=f"sqlite:///{tmp_path / 'vyper.db'}", agent_gateway=StubGateway(_orchestration_result()))

    with TestClient(app) as client:
        response = client.post(
            "/jobs/sanitize",
            json={
                "target": "/dev/sdz",
                "authorized": True,
                "ata_password": "legacy-password",
                "dry_run": True,
            },
        )

        assert response.status_code == 422
        detail = response.json()["detail"]
        invalid_fields = {item["loc"][-1] for item in detail}
        assert {"authorized", "ata_password"} <= invalid_fields
        assert client.get("/jobs").json() == []
