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
	url_file = os.getenv("VYPER_DATABASE_URL_FILE")
	if url_file:
		try:
			value = Path(url_file).read_text(encoding="utf-8").strip()
		except OSError as exc:
			raise RuntimeError("VYPER_DATABASE_URL_FILE could not be read.") from exc
		if not value:
			raise RuntimeError("VYPER_DATABASE_URL_FILE is empty.")
		return value
	env_url = os.getenv("VYPER_DATABASE_URL")
	if env_url:
		return env_url
	if os.getenv("VYPER_ENV", "development").strip().lower() == "production":
		raise RuntimeError("VYPER_DATABASE_URL is required in production and must point to PostgreSQL.")

	database_path = Path(__file__).resolve().parents[2] / "backend" / "vyper.db"
	database_path.parent.mkdir(parents=True, exist_ok=True)
	return f"sqlite:///{database_path}"


def create_engine_and_session_factory(database_url: str | None = None):
	resolved_url = database_url or default_database_url()
	if os.getenv("VYPER_ENV", "development").strip().lower() == "production" and not resolved_url.startswith("postgresql"):
		raise RuntimeError("Production central deployments require a PostgreSQL VYPER_DATABASE_URL.")
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
