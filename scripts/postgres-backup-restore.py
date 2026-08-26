from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy import create_engine, text


def run_drill(source_url: str, restore_url: str, *, execute: bool) -> dict:
	if not execute: return {"status": "PLAN_ONLY", "commands": ["pg_dump --format=custom", "pg_restore --clean --if-exists"]}
	if not source_url.startswith("postgresql") or not restore_url.startswith("postgresql"):
		raise ValueError("Backup/restore drill requires PostgreSQL URLs.")
	with tempfile.TemporaryDirectory(prefix="vyper-backup-drill-") as temporary:
		backup = Path(temporary) / "vyper.dump"
		subprocess.run(["pg_dump", "--format=custom", "--file", str(backup), source_url], check=True, timeout=300)
		subprocess.run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--dbname", restore_url, str(backup)], check=True, timeout=300)
	engine = create_engine(restore_url, pool_pre_ping=True)
	with engine.connect() as connection:
		counts = {table: connection.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
			for table in ("users", "operator_sessions", "agents", "agent_assets", "central_jobs", "assets", "jobs", "results", "certificates", "audit_logs")}
		chain_rows = connection.execute(text("SELECT count(*) FROM audit_logs WHERE event_hash IS NOT NULL")).scalar_one()
	engine.dispose()
	return {"status": "PASS", "record_counts": counts, "audit_hash_rows": chain_rows,
		"private_signing_keys_included": False, "scope": "database only"}


def main() -> None:
	parser = argparse.ArgumentParser(); parser.add_argument("--source-url", default=os.getenv("VYPER_TEST_POSTGRES_URL"));
	parser.add_argument("--restore-url", default=os.getenv("VYPER_TEST_POSTGRES_RESTORE_URL")); parser.add_argument("--execute", action="store_true")
	args = parser.parse_args(); print(json.dumps(run_drill(args.source_url or "", args.restore_url or "", execute=args.execute), indent=2, sort_keys=True))


if __name__ == "__main__": main()
