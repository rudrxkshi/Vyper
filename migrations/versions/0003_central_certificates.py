"""Index accepted remote sanitization certificates.

Revision ID: 0003_central_certificates
Revises: 0002_stage13_mfa_sessions
"""
from alembic import op
from sqlalchemy import inspect

from backend.app.db import Base
from backend.app import models  # noqa: F401

revision = "0003_central_certificates"
down_revision = "0002_stage13_mfa_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind()
	if "central_certificates" not in inspect(bind).get_table_names():
		Base.metadata.tables["central_certificates"].create(bind=bind)


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade.")
