from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"users", "operator_sessions", "agents", "agent_assets", "central_jobs", "assets", "jobs",
	"results", "certificates", "audit_logs", "agent_enrollment_tokens"}


def validate(url: str) -> dict:
	if not url.startswith("postgresql"):
		raise ValueError("The Stage 13 production database harness requires PostgreSQL.")
	config = Config(str(ROOT / "alembic.ini")); config.set_main_option("sqlalchemy.url", url); command.upgrade(config, "head")
	engine = create_engine(url, pool_pre_ping=True)
	with engine.begin() as connection:
		connection.execute(text("SELECT 1"))
		tables = set(inspect(connection).get_table_names())
		missing = sorted(REQUIRED - tables)
		if missing: raise RuntimeError(f"PostgreSQL schema is missing: {', '.join(missing)}")
		revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
	engine.dispose()
	return {"database": "postgresql", "migration": revision, "schema": "PASS", "required_tables": sorted(REQUIRED),
		"rollback_policy": "FORWARD_ONLY_RESTORE_TESTED_BACKUP", "connection_pre_ping": True}


def main() -> None:
	parser = argparse.ArgumentParser(); parser.add_argument("--url", default=os.getenv("VYPER_TEST_POSTGRES_URL")); args = parser.parse_args()
	if not args.url: raise SystemExit("VYPER_TEST_POSTGRES_URL or --url is required.")
	print(json.dumps(validate(args.url), indent=2, sort_keys=True))


if __name__ == "__main__": main()
