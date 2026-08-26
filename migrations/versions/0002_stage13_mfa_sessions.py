"""Stage 13 MFA and hardened sessions.

Revision ID: 0002_stage13_mfa_sessions
Revises: 0001_stage6_baseline
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0002_stage13_mfa_sessions"
down_revision = "0001_stage6_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
	bind = op.get_bind(); inspector = inspect(bind)
	user_columns = {column["name"] for column in inspector.get_columns("users")}
	session_columns = {column["name"] for column in inspector.get_columns("operator_sessions")}
	for name, column in (
		("mfa_enabled", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false())),
		("mfa_secret_encrypted", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True)),
		("mfa_recovery_codes_json", sa.Column("mfa_recovery_codes_json", sa.JSON(), nullable=False, server_default="[]")),
	):
		if name not in user_columns: op.add_column("users", column)
	added_nullable = []
	for name, column in (
		("absolute_expires_at", sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=True)),
		("mfa_assurance", sa.Column("mfa_assurance", sa.String(32), nullable=False, server_default="PASSWORD")),
		("csrf_token_hash", sa.Column("csrf_token_hash", sa.String(64), nullable=True)),
	):
		if name not in session_columns:
			op.add_column("operator_sessions", column); added_nullable.append(name)
	if added_nullable:
		op.execute("UPDATE operator_sessions SET absolute_expires_at = expires_at, csrf_token_hash = token_hash WHERE absolute_expires_at IS NULL")
		with op.batch_alter_table("operator_sessions") as batch:
			if "absolute_expires_at" in added_nullable: batch.alter_column("absolute_expires_at", nullable=False)
			if "csrf_token_hash" in added_nullable: batch.alter_column("csrf_token_hash", nullable=False)


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade.")
