from __future__ import annotations

import argparse
import getpass
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from .auth import OperatorRole
from .db import create_engine_and_session_factory
from .models import UserRecord
from .security import hash_password


def main() -> None:
	parser = argparse.ArgumentParser(description="VYPER central operator administration")
	parser.add_argument("username")
	parser.add_argument("--display-name")
	parser.add_argument("--role", choices=[role.value for role in OperatorRole], default="ADMIN")
	args = parser.parse_args()
	password = getpass.getpass("Password: ")
	_, factory = create_engine_and_session_factory()
	with factory() as db:
		username = args.username.strip().lower()
		if db.execute(select(UserRecord).where(UserRecord.username == username)).scalar_one_or_none():
			raise SystemExit("User already exists.")
		now = datetime.now(timezone.utc)
		db.add(UserRecord(id=str(uuid4()), username=username, display_name=args.display_name or username,
			password_hash=hash_password(password), role=args.role, password_changed_at=now))
		db.commit()
	print(f"Created {args.role} operator {username}.")


if __name__ == "__main__":
	main()
