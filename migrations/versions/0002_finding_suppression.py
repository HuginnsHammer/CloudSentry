"""Persist scanner suppression metadata on platform findings.

Revision ID: 0002_finding_suppression
Revises: 0001_enterprise_platform
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_finding_suppression"
down_revision = "0001_enterprise_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "findings",
        sa.Column("suppression_reason", sa.String(length=2000), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "suppression_reason")
    op.drop_column("findings", "suppressed")
