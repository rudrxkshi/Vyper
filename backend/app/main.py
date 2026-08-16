from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .agent_gateway import build_agent_gateway
from .db import create_engine_and_session_factory, init_db
from .routers.audit_logs import router as audit_logs_router
from .routers.certificates import router as certificates_router
from .routers.devices import router as devices_router
from .routers.jobs import router as jobs_router
from .routers.results import router as results_router


def _default_database_url() -> str:
	backend_root = Path(__file__).resolve().parents[2] / "backend"
	backend_root.mkdir(parents=True, exist_ok=True)
	return os.getenv("VYPER_DATABASE_URL") or f"sqlite:///{backend_root / 'vyper.db'}"


def create_app(*, database_url: str | None = None, agent_gateway=None) -> FastAPI:
	resolved_database_url = database_url or _default_database_url()
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
		init_db(app.state.engine)
		yield

	app = FastAPI(title="VYPER API", version="0.1.0", lifespan=lifespan)
	app.add_middleware(
		CORSMiddleware,
		allow_origins=["*"],
		allow_credentials=True,
		allow_methods=["*"],
		allow_headers=["*"],
	)

	@app.get("/health", tags=["health"])
	def health() -> dict[str, str]:
		return {"status": "ok"}

	app.include_router(jobs_router, prefix="/jobs")
	app.include_router(devices_router, prefix="/assets")
	app.include_router(devices_router, prefix="/devices")
	app.include_router(results_router, prefix="/results")
	app.include_router(certificates_router, prefix="/certificates")
	app.include_router(audit_logs_router, prefix="/audit-logs")
	return app


app = create_app()

