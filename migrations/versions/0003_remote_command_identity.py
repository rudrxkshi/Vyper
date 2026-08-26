"""Remote command identity and security events.

Revision ID: 0003_remote_command_identity
Revises: 0002_stage13_mfa_sessions
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0003_remote_command_identity"
down_revision = "0002_stage13_mfa_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind(); inspector = inspect(bind)
	agent_columns = {column["name"] for column in inspector.get_columns("agents")}
	for name, column in (
		("public_key_pem", sa.Column("public_key_pem", sa.Text(), nullable=True)),
		("public_key_id", sa.Column("public_key_id", sa.String(64), nullable=True)),
		("identity_fingerprint", sa.Column("identity_fingerprint", sa.String(64), nullable=True)),
	):
		if name not in agent_columns:
			op.add_column("agents", column)
	job_columns = {column["name"] for column in inspector.get_columns("central_jobs")}
	if "command_json" not in job_columns:
		op.add_column("central_jobs", sa.Column("command_json", sa.JSON(), nullable=True))
	if "security_events" not in inspector.get_table_names():
		op.create_table(
			"security_events",
			sa.Column("id", sa.String(36), primary_key=True),
			sa.Column("event_type", sa.String(128), nullable=False),
			sa.Column("severity", sa.String(32), nullable=False, server_default="INFO"),
			sa.Column("actor", sa.String(128), nullable=True),
			sa.Column("resource", sa.String(255), nullable=True),
			sa.Column("agent_id", sa.String(36), nullable=True),
			sa.Column("central_job_id", sa.String(36), nullable=True),
			sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
			sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
		)
		op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
		op.create_index("ix_security_events_resource", "security_events", ["resource"])
		op.create_index("ix_security_events_agent_id", "security_events", ["agent_id"])
		op.create_index("ix_security_events_central_job_id", "security_events", ["central_job_id"])


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade.")
