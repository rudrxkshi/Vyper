"""Merge the central-certificate and organization-lifecycle histories.

Revision ID: 0009_merge_migration_heads
Revises: 0003_central_certificates, 0008_organization_membership_lifecycle
"""

revision = "0009_merge_migration_heads"
down_revision = ("0003_central_certificates", "0008_organization_membership_lifecycle")
branch_labels = None
depends_on = None


def upgrade() -> None:
	pass


def downgrade() -> None:
	raise RuntimeError("VYPER production migrations are forward-only; restore a backup to downgrade.")
