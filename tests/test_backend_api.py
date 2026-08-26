from __future__ import annotations

from dataclasses import dataclass

from fastapi.testclient import TestClient

from agent.agent import OrchestrationJobResult
from agent.certificate import SanitizationCertificate
from agent.common import JobState, SanitizationResult, SanitizationStatus
from agent.credentials import AgentCredentialStore
from agent.evidence import EvidenceRecord
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
    evidence = EvidenceRecord(
        job_id="job-1",
        device="/dev/sdz",
        device_profile=profile,
        policy_decision=policy,
        pathway={"selected_pathway": "HDD_OVERWRITE", "executed_pathway": "HDD_OVERWRITE", "sanitization_method": "HDD_OVERWRITE"},
        execution=execution,
        verification=verification,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_seconds=1.0,
        final_status="VERIFIED",
        warnings=[],
        errors=[],
        limitations=[],
        agent_version="vyper-test",
        integrity_algorithm="sha256",
        integrity_hash="hash-1",
    )
    certificate = SanitizationCertificate(
        certificate_id="cert-1",
        certificate_version="1.0.0",
        issued_at="2026-01-01T00:00:02Z",
        job_id="job-1",
        device={"device_path": "/dev/sdz", "device_type": "HDD", "model": "demo", "serial": "serial-1", "capacity_bytes": 1024, "interface": "ATA", "transport": "SATA"},
        sanitization={"selected_pathway": "HDD_OVERWRITE", "executed_pathway": "HDD_OVERWRITE", "sanitization_method": "HDD_OVERWRITE", "policy_reason": "demo"},
        execution={"status": "RUNNING", "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z", "duration_seconds": 1.0},
        verification={"status": "VERIFIED", "verified": True, "evidence": {"source": "demo", "status": "verified"}, "limitations": []},
        final_status="VERIFIED",
        evidence_integrity={"algorithm": "sha256", "hash": "hash-1"},
        agent={"version": "vyper-test"},
        certificate_hash_algorithm="sha256",
        certificate_hash="cert-hash-1",
        outcome_kind="sanitization_certificate",
        successful_sanitization_claim=True,
    )
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
    app = create_app(database_url=f"sqlite:///{tmp_path / 'vyper.db'}", agent_gateway=StubGateway(_orchestration_result()))

    with TestClient(app) as client:
        response = client.post(
            "/jobs/sanitize",
            json={"target": "/dev/sdz", "authorization": {"approved": True}, "dry_run": True},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["job_state"] == "VERIFIED"
        assert body["certificate_id"] == "cert-1"

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
        assert certificates[0]["certificate_id"] == "cert-1"
        assert len(audit_logs) == 1
        assert audit_logs[0]["action"] == "sanitize_device"


def test_backend_accepts_gui_generated_agent_key(tmp_path, monkeypatch):
    credentials_path = tmp_path / "agent_credentials.json"
    monkeypatch.delenv("VYPER_API_KEY", raising=False)
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
