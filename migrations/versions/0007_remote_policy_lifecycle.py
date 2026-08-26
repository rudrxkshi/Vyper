"""Add version and revocation state to remote policies.

Revision ID: 0007_remote_policy_lifecycle
Revises: 0006_organization_event_scope
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0007_remote_policy_lifecycle"
down_revision = "0006_organization_event_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
	inspector = inspect(op.get_bind())
	existing = {column["name"] for column in inspector.get_columns("remote_policies")}
	if "version" not in existing:
		op.add_column("remote_policies", sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
	if "revoked_at" not in existing:
		op.add_column("remote_policies", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
