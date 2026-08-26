"""Preserve disabled organization memberships for auditability.

Revision ID: 0008_organization_membership_lifecycle
Revises: 0007_remote_policy_lifecycle
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0008_organization_membership_lifecycle"
down_revision = "0007_remote_policy_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
	inspector = inspect(op.get_bind())
	existing = {column["name"] for column in inspector.get_columns("organization_memberships")}
	if "disabled_at" not in existing:
		op.add_column("organization_memberships", sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))
		op.create_index("ix_organization_memberships_disabled_at", "organization_memberships", ["disabled_at"])


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
