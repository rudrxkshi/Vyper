"""Scope central audit and security records to organizations.

Revision ID: 0006_organization_event_scope
Revises: 0005_organization_memberships
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0006_organization_event_scope"
down_revision = "0005_organization_memberships"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind()
	inspector = inspect(bind)
	for table in ("audit_logs", "security_events"):
		existing = {column["name"] for column in inspector.get_columns(table)}
		if "organization_id" not in existing:
			op.add_column(table, sa.Column("organization_id", sa.String(36), nullable=True))
			op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
			if bind.dialect.name != "sqlite":
				op.create_foreign_key(f"fk_{table}_organization_id", table, "organizations", ["organization_id"], ["id"])


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
