"""Stage 6 production baseline schema.

Revision ID: 0001_stage6_baseline
Revises: None
"""
from alembic import op

from backend.app.db import Base
from backend.app import models  # noqa: F401

revision = "0001_stage6_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
	# This baseline is intentionally generated from the versioned SQLAlchemy schema.
	# Later revisions must use explicit incremental operations.
	Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
	# A baseline downgrade is destructive and intentionally unsupported. Restore a
	# tested backup instead; forward-only production migrations are the policy.
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
