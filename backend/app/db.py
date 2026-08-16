from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
	pass


def default_database_url() -> str:
	env_url = os.getenv("VYPER_DATABASE_URL")
	if env_url:
		return env_url

	postgres_host = os.getenv("VYPER_POSTGRES_HOST") or os.getenv("POSTGRES_HOST")
	postgres_db = os.getenv("VYPER_POSTGRES_DB") or os.getenv("POSTGRES_DB")
	postgres_user = os.getenv("VYPER_POSTGRES_USER") or os.getenv("POSTGRES_USER")
	postgres_password = os.getenv("VYPER_POSTGRES_PASSWORD") or os.getenv("POSTGRES_PASSWORD")
	postgres_port = os.getenv("VYPER_POSTGRES_PORT") or os.getenv("POSTGRES_PORT", "5432")
	if postgres_host and postgres_db and postgres_user and postgres_password:
		return f"postgresql+psycopg2://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"

	database_path = Path(__file__).resolve().parents[2] / "backend" / "vyper.db"
	database_path.parent.mkdir(parents=True, exist_ok=True)
	return f"sqlite:///{database_path}"


def create_engine_and_session_factory(database_url: str | None = None):
	resolved_url = database_url or default_database_url()
	connect_args = {"check_same_thread": False} if resolved_url.startswith("sqlite") else {}
	engine = create_engine(resolved_url, connect_args=connect_args, future=True)
	session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
	return engine, session_factory


def init_db(engine) -> None:
	from . import models  # noqa: F401 - ensure model registration before create_all

	Base.metadata.create_all(bind=engine)


def get_db(request: Request) -> Iterator[Session]:
	session_factory = request.app.state.session_factory
	db = session_factory()
	try:
		yield db
	finally:
		db.close()
