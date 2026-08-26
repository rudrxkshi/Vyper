"""Organization-scoped remote policies and immutable approvals.

Revision ID: 0004_organization_policy_approvals
Revises: 0003_remote_command_identity
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0004_organization_policy_approvals"
down_revision = "0003_remote_command_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind(); inspector = inspect(bind)
	if "organizations" not in inspector.get_table_names():
		op.create_table(
			"organizations", sa.Column("id", sa.String(36), primary_key=True),
			sa.Column("name", sa.String(255), nullable=False, unique=True),
			sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
		)
	if "remote_policies" not in inspector.get_table_names():
		op.create_table(
			"remote_policies", sa.Column("id", sa.String(36), primary_key=True),
			sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
			sa.Column("name", sa.String(128), nullable=False),
			sa.Column("remote_sanitization_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
			sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
			sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
			sa.Column("allow_system_disk", sa.Boolean(), nullable=False, server_default=sa.false()),
			sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
			sa.UniqueConstraint("organization_id", "name", name="uq_remote_policy_organization_name"),
		)
		op.create_index("ix_remote_policies_organization_id", "remote_policies", ["organization_id"])
	for table, columns in {
		"agents": [("organization_id", sa.String(36))],
		"agent_enrollment_tokens": [("organization_id", sa.String(36))],
		"central_jobs": [("organization_id", sa.String(36)), ("policy_id", sa.String(36)), ("required_approvals", sa.Integer())],
	}.items():
		existing = {item["name"] for item in inspector.get_columns(table)}
		for name, type_ in columns:
			if name not in existing:
				op.add_column(table, sa.Column(name, type_, nullable=True))
	if "central_job_approvals" not in inspector.get_table_names():
		op.create_table(
			"central_job_approvals", sa.Column("id", sa.String(36), primary_key=True),
			sa.Column("central_job_id", sa.String(36), sa.ForeignKey("central_jobs.central_job_id"), nullable=False),
			sa.Column("approver_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
			sa.Column("approver", sa.String(128), nullable=False), sa.Column("decision", sa.String(32), nullable=False),
			sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
			sa.UniqueConstraint("central_job_id", "approver_user_id", name="uq_central_job_approver"),
		)
		op.create_index("ix_central_job_approvals_central_job_id", "central_job_approvals", ["central_job_id"])


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade the baseline.")
