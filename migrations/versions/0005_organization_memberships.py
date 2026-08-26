"""Explicit operator membership for organization-scoped central resources.

Revision ID: 0005_organization_memberships
Revises: 0004_organization_policy_approvals
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0005_organization_memberships"
down_revision = "0004_organization_policy_approvals"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind()
	inspector = inspect(bind)
	if "organization_memberships" not in inspector.get_table_names():
		op.create_table(
			"organization_memberships",
			sa.Column("id", sa.String(36), primary_key=True),
			sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
			sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
			sa.Column("role", sa.String(32), nullable=False, server_default="MEMBER"),
			sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
			sa.UniqueConstraint("organization_id", "user_id", name="uq_organization_membership"),
		)
		op.create_index("ix_organization_memberships_organization_id", "organization_memberships", ["organization_id"])
		op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
