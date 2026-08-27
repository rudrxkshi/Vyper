from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from agent.agent import VYPERAgent
from agent.discovery import DeviceDiscovery, DeviceDiscoveryError

from .jobs import LocalJobWorker, log_job
from .process_worker import ProcessJobExecutor
from .schemas import (
	DiscoveredDeviceRead, LocalJobAccepted, LocalJobResponse, RemoteJobApproval,
	SanitizeJobRequest, SyncEnrollmentRequest,
)
from .storage import DuplicateActiveTargetError, LocalJobStore
from .sync import AgentCredentialStore, CentralSyncClient, SyncLoop
from .identity import Ed25519IdentityStore


API_VERSION = "2"
_api_key_header = APIKeyHeader(name="X-VYPER-API-Key", auto_error=False)


def _require_local_api_key(api_key: str | None = Security(_api_key_header)) -> None:
	expected = os.getenv("VYPER_LOCAL_AGENT_API_KEY")
	if expected and api_key != expected:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid local agent API key.")


def _default_database_path() -> Path:
	configured = os.getenv("VYPER_LOCAL_AGENT_DATABASE_PATH")
	return Path(configured) if configured else Path(__file__).resolve().parent / "vyper_local.db"


def create_app(
	*,
	agent: VYPERAgent | None = None,
	discovery: DeviceDiscovery | None = None,
	database_path: str | Path | None = None,
	executor: Any | None = None,
) -> FastAPI:
	owned_executor = executor is None
	resolved_database_path = Path(database_path or _default_database_path())
	worker_executor = executor or ProcessJobExecutor(
		resolved_database_path, max_workers=max(1, int(os.getenv("VYPER_LOCAL_AGENT_WORKERS", "2"))),
	)

	@asynccontextmanager
	async def lifespan(app: FastAPI):
		store = LocalJobStore(resolved_database_path)
		app.state.job_store = store
		central_url = os.getenv("VYPER_CENTRAL_URL", "").strip()
		sync_enabled = os.getenv("VYPER_SYNC_ENABLED", "true").lower() in {"1", "true", "yes"}
		app.state.sync_client = None
		app.state.sync_loop = None
		if central_url and sync_enabled:
			credential_path = Path(os.getenv("VYPER_AGENT_CREDENTIAL_PATH") or Path(__file__).resolve().parent / "agent_credentials.json")
			sync_client = CentralSyncClient(
				central_url=central_url,
				credential_store=AgentCredentialStore(credential_path),
				identity_store=Ed25519IdentityStore(Path(os.getenv("VYPER_AGENT_IDENTITY_PATH") or credential_path.with_name("agent_identity.pem"))),
				job_store=store,
				discovery=app.state.device_discovery,
				submit_local_job=lambda **kwargs: dispatch_local_job(**kwargs).local_job_id,
				auto_run_dry_run=os.getenv("VYPER_REMOTE_DRY_RUN_AUTO", "true").lower() in {"1", "true", "yes"},
			)
			app.state.sync_client = sync_client
			app.state.sync_loop = SyncLoop(
				sync_client,
				interval_seconds=float(os.getenv("VYPER_CENTRAL_POLL_SECONDS", "5")),
				heartbeat_interval_seconds=float(os.getenv("VYPER_HEARTBEAT_INTERVAL", "30")),
				inventory_interval_seconds=float(os.getenv("VYPER_INVENTORY_INTERVAL", "60")),
			)
		recovered = store.recover_interrupted()
		if recovered:
			log_job("recovery", recovered_jobs=recovered, job_state="INCONCLUSIVE")
		if app.state.sync_loop is not None:
			app.state.sync_loop.start()
		try:
			yield
		finally:
			if app.state.sync_loop is not None:
				app.state.sync_loop.stop()
			if owned_executor:
				worker_executor.shutdown(wait=False)

	app = FastAPI(title="VYPER Local Agent API", version=API_VERSION, lifespan=lifespan)
	configured_origins = os.getenv(
		"VYPER_LOCAL_AGENT_CORS_ORIGINS",
		"tauri://localhost,http://tauri.localhost,http://127.0.0.1:8787,http://localhost:8787,http://127.0.0.1:3000,http://localhost:3000",
	)
	allowed_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
	app.add_middleware(
		CORSMiddleware,
		allow_origins=allowed_origins,
		allow_credentials=True,
		allow_methods=["GET", "POST"],
		allow_headers=["Content-Type", "X-VYPER-API-Key"],
	)
	app.state.vyper_agent = agent or VYPERAgent(dry_run=True)
	app.state.device_discovery = discovery or DeviceDiscovery()
	app.state.worker_executor = worker_executor
	app.state.job_store = None
	app.state.sync_client = None
	app.state.sync_loop = None

	def store() -> LocalJobStore:
		if app.state.job_store is None:
			raise HTTPException(status_code=503, detail="Local job store is not initialized.")
		return app.state.job_store

	def dispatch_local_job(
		*, target: str, dry_run: bool, authorized: bool, ata_password: str | None = None,
		local_job_id: str | None = None,
	) -> LocalJobAccepted:
		local_job_id = local_job_id or str(uuid4())
		existing = store().get_job(local_job_id)
		if existing is not None:
			if existing["target"] != target or bool(existing["dry_run"]) != bool(dry_run):
				raise HTTPException(status_code=409, detail="Local job idempotency key conflicts with an existing request.")
			return LocalJobAccepted(local_job_id=local_job_id, target=target)
		authorization_metadata = {"approved": bool(authorized), "has_ata_password": bool(ata_password)}
		try:
			store().create_job(
				local_job_id=local_job_id, api_version=API_VERSION, target=target,
				dry_run=dry_run, authorization_metadata=authorization_metadata,
			)
		except DuplicateActiveTargetError as exc:
			raise HTTPException(status_code=409, detail="A destructive job is already active for this physical target.") from exc
		authorization = {"approved": bool(authorized)}
		if ata_password:
			authorization["ata_password"] = ata_password
		try:
			if hasattr(app.state.worker_executor, "submit_job"):
				app.state.worker_executor.submit_job(local_job_id, target, authorization, dry_run)
				authorization.clear()
			else:
				worker = LocalJobWorker(store=store(), agent=app.state.vyper_agent)
				app.state.worker_executor.submit(worker.run, local_job_id, target, authorization, dry_run)
		except Exception as exc:
			authorization.clear()
			store().complete(local_job_id, {
				"job_state": "FAILED", "final_status": "FAILED", "message": "Local worker dispatch failed.",
				"progress": None, "profile": None, "policy": None, "execution": None,
				"verification": None, "evidence": None, "certificate": None,
				"error": {"code": "DISPATCH_FAILURE", "message": "Local worker dispatch failed."},
			})
			raise HTTPException(status_code=503, detail="Local worker dispatch failed.") from exc
		log_job("accepted", local_job_id=local_job_id, target=target, job_state="PENDING", event_sequence=1)
		return LocalJobAccepted(local_job_id=local_job_id, target=target)

	@app.get("/health", tags=["health"])
	def health() -> dict[str, str]:
		return {"status": "ok", "service": "local-agent", "api_version": API_VERSION}

	@app.get(
		"/devices",
		response_model=list[DiscoveredDeviceRead],
		tags=["devices"],
		dependencies=[Depends(_require_local_api_key)],
	)
	def list_devices():
		try:
			return [device.to_dict() for device in app.state.device_discovery.discover()]
		except DeviceDiscoveryError as exc:
			raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

	@app.post(
		"/jobs/sanitize",
		response_model=LocalJobAccepted,
		status_code=status.HTTP_202_ACCEPTED,
		tags=["jobs"],
		dependencies=[Depends(_require_local_api_key)],
	)
	def create_sanitize_job(request: SanitizeJobRequest):
		target = request.target.strip()
		if not target.startswith("/dev/") or target == "/dev/":
			raise HTTPException(status_code=422, detail="Target must be an explicit /dev device path.")
		dry_run = True if request.dry_run is None else bool(request.dry_run)
		if not dry_run and not request.authorization.approved:
			raise HTTPException(
				status_code=status.HTTP_403_FORBIDDEN,
				detail="Explicit authorization is required for non-dry-run execution.",
			)

		return dispatch_local_job(
			target=target, dry_run=dry_run, authorized=request.authorization.approved,
			ata_password=request.authorization.ata_password,
		)

	@app.get(
		"/jobs",
		response_model=list[LocalJobResponse],
		tags=["jobs"],
		dependencies=[Depends(_require_local_api_key)],
	)
	def list_jobs(
		state: str | None = None,
		target: str | None = None,
		limit: int = Query(default=100, ge=1, le=500),
	):
		return store().list_jobs(state=state, target=target, limit=limit)

	@app.get(
		"/jobs/{local_job_id}",
		response_model=LocalJobResponse,
		tags=["jobs"],
		dependencies=[Depends(_require_local_api_key)],
	)
	def get_job(local_job_id: str):
		job = store().get_job(local_job_id)
		if job is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Local job not found.")
		return job

	@app.get("/certificates", tags=["certificates"], dependencies=[Depends(_require_local_api_key)])
	def list_certificates(limit: int = Query(default=100, ge=1, le=500)):
		return store().list_certificates(limit=limit)

	@app.get("/audit-logs", tags=["audit"], dependencies=[Depends(_require_local_api_key)])
	def list_audit_logs(
		job_id: str | None = None,
		limit: int = Query(default=500, ge=1, le=1000),
	):
		return store().list_audit_events(local_job_id=job_id, limit=limit)

	@app.post(
		"/jobs/{local_job_id}/cancel",
		response_model=LocalJobResponse,
		tags=["jobs"],
		dependencies=[Depends(_require_local_api_key)],
	)
	def cancel_job(local_job_id: str):
		outcome = store().cancel_pending(local_job_id)
		if outcome == "missing":
			raise HTTPException(status_code=404, detail="Local job not found.")
		if outcome == "unsafe":
			raise HTTPException(
				status_code=409,
				detail="Cancellation is only supported before execution starts; the active pathway cannot be safely interrupted.",
			)
		return store().get_job(local_job_id)

	@app.post("/sync/enroll", dependencies=[Depends(_require_local_api_key)])
	def enroll_sync(payload: SyncEnrollmentRequest):
		if app.state.sync_client is None:
			raise HTTPException(status_code=503, detail="VYPER_CENTRAL_URL is not configured.")
		try:
			return app.state.sync_client.enroll(payload.enrollment_token, display_name=payload.display_name)
		except Exception as exc:
			raise HTTPException(status_code=502, detail="Central enrollment failed.") from exc

	@app.get("/sync/status", dependencies=[Depends(_require_local_api_key)])
	def sync_status():
		if app.state.sync_client is None:
			return {
				"configured": False, "enrolled": False, "agent_id": None,
				"central_url": None, "outbox_pending": 0, "outbox_abandoned": 0, "last_heartbeat": None,
				"agent_protocol_version": "1",
			}
		return app.state.sync_client.status()

	@app.get("/remote-requests", dependencies=[Depends(_require_local_api_key)], include_in_schema=False)
	@app.get("/remote-jobs", dependencies=[Depends(_require_local_api_key)])
	def list_remote_jobs():
		return store().list_remote_requests()

	@app.post("/remote-jobs/{central_job_id}/approve", dependencies=[Depends(_require_local_api_key)])
	def approve_remote_job(central_job_id: str, payload: RemoteJobApproval):
		if app.state.sync_client is None:
			raise HTTPException(status_code=503, detail="Central synchronization is not configured.")
		if not payload.approved:
			raise HTTPException(status_code=403, detail="Explicit local approval is required.")
		try:
			local_job_id = app.state.sync_client.approve_remote_job(
				central_job_id, local_approved=True, ata_password=payload.ata_password,
			)
		except PermissionError as exc:
			raise HTTPException(status_code=403, detail=str(exc)) from exc
		except (KeyError, RuntimeError) as exc:
			raise HTTPException(status_code=409, detail=str(exc)) from exc
		return {"central_job_id": central_job_id, "local_job_id": local_job_id, "status": "SUBMITTED"}

	return app


def _configured_bind_host() -> str:
	host = os.getenv("VYPER_LOCAL_AGENT_HOST", "127.0.0.1").strip() or "127.0.0.1"
	is_loopback = host in {"127.0.0.1", "::1", "localhost"}
	allow_public = os.getenv("VYPER_LOCAL_AGENT_ALLOW_PUBLIC", "").lower() in {"1", "true", "yes"}
	if not is_loopback and not allow_public:
		raise RuntimeError(
			"Refusing to bind the local agent publicly. Set "
			"VYPER_LOCAL_AGENT_ALLOW_PUBLIC=true only in an explicitly secured deployment."
		)
	return host


def main() -> None:
	host = _configured_bind_host()
	port = int(os.getenv("VYPER_LOCAL_AGENT_PORT", "8765"))
	uvicorn.run("local_agent.main:app", host=host, port=port, reload=False)


app = create_app()


if __name__ == "__main__":
	main()
