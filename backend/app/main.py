from __future__ import annotations

from contextlib import asynccontextmanager
import json
import logging
import os
import threading
import time
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from vyper_version import __version__

from .agent_gateway import build_agent_gateway
from .auth import require_api_key
from .db import create_engine_and_session_factory, default_database_url, init_db
from .security import production_mode, redact
from .routers.auth import router as auth_router
from .routers.audit_logs import router as audit_logs_router
from .routers.agents import router as agents_router
from .routers.certificates import router as certificates_router
from .routers.devices import router as devices_router
from .routers.downloads import router as downloads_router
from .routers.jobs import router as jobs_router
from .routers.results import router as results_router
from .routers.security_events import router as security_events_router

SUPPORTED_ALEMBIC_HEAD = "0004_organization_policy_approvals"


def require_supported_schema(engine) -> None:
	with engine.connect() as connection:
		try:
			current = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
		except Exception as exc:
			raise RuntimeError("Production database schema is unavailable; run Alembic migrations.") from exc
	if current != SUPPORTED_ALEMBIC_HEAD:
		raise RuntimeError(f"Production database schema must be at supported Alembic head {SUPPORTED_ALEMBIC_HEAD}.")


def create_app(*, database_url: str | None = None, agent_gateway=None) -> FastAPI:
	metrics_mode = os.getenv("VYPER_METRICS_MODE", "single-worker")
	if production_mode() and metrics_mode != "single-worker":
		raise RuntimeError("Production process-local metrics require VYPER_METRICS_MODE=single-worker.")
	resolved_database_url = database_url or default_database_url()
	engine, session_factory = create_engine_and_session_factory(resolved_database_url)
	app_state = {
		"engine": engine,
		"session_factory": session_factory,
		"agent_gateway": agent_gateway or build_agent_gateway(),
		"database_url": resolved_database_url,
	}

	@asynccontextmanager
	async def lifespan(app: FastAPI):
		app.state.engine = app_state["engine"]
		app.state.session_factory = app_state["session_factory"]
		app.state.agent_gateway = app_state["agent_gateway"]
		app.state.database_url = app_state["database_url"]
		if production_mode():
			require_supported_schema(app.state.engine)
		elif os.getenv("VYPER_AUTO_CREATE_SCHEMA", "true").lower() in {"1", "true", "yes"}:
			init_db(app.state.engine)
		yield

	app = FastAPI(title="VYPER API", version=__version__, lifespan=lifespan)
	default_origins = "" if production_mode() else "http://127.0.0.1:3000,http://localhost:3000"
	configured_origins = os.getenv("VYPER_CORS_ORIGINS", default_origins)
	allowed_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
	allow_credentials = os.getenv("VYPER_CORS_ALLOW_CREDENTIALS", "true").lower() in {"1", "true", "yes"}
	if "*" in allowed_origins and allow_credentials:
		raise RuntimeError("Wildcard CORS origins cannot be combined with credentials.")
	app.add_middleware(
		CORSMiddleware,
		allow_origins=allowed_origins,
		allow_credentials=allow_credentials,
		allow_methods=["*"],
		allow_headers=["*"],
	)

	request_logger = logging.getLogger("vyper.central.requests")
	metrics_lock = threading.Lock()
	metrics = {"requests_total": 0, "errors_total": 0, "latency_seconds_total": 0.0}

	@app.middleware("http")
	async def request_context(request: Request, call_next):
		started = time.perf_counter()
		supplied = request.headers.get("X-Request-ID", "")
		request_id = supplied if supplied and len(supplied) <= 64 and supplied.replace("-", "").isalnum() else str(uuid4())
		request.state.request_id = request_id
		try:
			response = await call_next(request)
		except Exception:
			with metrics_lock:
				metrics["requests_total"] += 1
				metrics["errors_total"] += 1
				metrics["latency_seconds_total"] += time.perf_counter() - started
			request_logger.exception(json.dumps(redact({"request_id": request_id, "route": request.url.path, "error_category": "unhandled"})))
			raise
		principal = getattr(request.state, "operator", None)
		latency_seconds = time.perf_counter() - started
		with metrics_lock:
			metrics["requests_total"] += 1
			metrics["errors_total"] += int(response.status_code >= 500)
			metrics["latency_seconds_total"] += latency_seconds
		request_logger.info(json.dumps({"request_id": request_id, "route": request.url.path, "method": request.method,
			"actor": principal.audit_identity if principal else None, "response_status": response.status_code,
			"latency_ms": round(latency_seconds * 1000, 2)}, separators=(",", ":")))
		response.headers["X-Request-ID"] = request_id
		return response

	@app.get("/health", tags=["health"])
	def health() -> dict[str, str]:
		return {"status": "ok", "service": "central", "api_version": "1"}

	@app.get("/readiness", tags=["health"])
	def readiness():
		try:
			with app.state.engine.connect() as connection:
				connection.execute(text("SELECT 1"))
		except Exception as exc:
			raise HTTPException(status_code=503, detail="Database is unavailable.") from exc
		return {"status": "ready", "dependencies": {"database": "ready"}}

	@app.get("/metrics", response_class=PlainTextResponse, tags=["health"], dependencies=[Depends(require_api_key)])
	def metrics_endpoint():
		with metrics_lock:
			snapshot = dict(metrics)
		return "\n".join([
			f'# VYPER metrics_mode={metrics_mode}; process-local counters require one backend worker',
			"# TYPE vyper_http_requests_total counter",
			f"vyper_http_requests_total {snapshot['requests_total']}",
			"# TYPE vyper_http_errors_total counter",
			f"vyper_http_errors_total {snapshot['errors_total']}",
			"# TYPE vyper_http_request_latency_seconds_total counter",
			f"vyper_http_request_latency_seconds_total {snapshot['latency_seconds_total']:.6f}",
		]) + "\n"

	app.include_router(jobs_router, prefix="/jobs")
	app.include_router(devices_router, prefix="/assets")
	app.include_router(devices_router, prefix="/devices")
	app.include_router(results_router, prefix="/results")
	app.include_router(certificates_router, prefix="/certificates")
	app.include_router(audit_logs_router, prefix="/audit-logs")
	app.include_router(security_events_router, prefix="/security-events")
	app.include_router(auth_router)
	app.include_router(agents_router)
	app.include_router(downloads_router)
	return app


app = create_app()
