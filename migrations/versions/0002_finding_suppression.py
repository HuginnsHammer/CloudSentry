"""Persist complete scan diagnostics and finding evidence metadata.

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
        "scans",
        sa.Column("diagnostics", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "findings",
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "findings",
        sa.Column("category", sa.String(length=80), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "findings",
        sa.Column("confidence", sa.String(length=16), nullable=False, server_default="medium"),
    )
    op.add_column("findings", sa.Column("resource", sa.String(length=300), nullable=True))
    op.add_column(
        "findings",
        sa.Column("impact", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "findings",
        sa.Column("reference_urls", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "findings",
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "findings",
        sa.Column("suppression_reason", sa.String(length=2000), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "reference_urls")
    op.drop_column("findings", "impact")
    op.drop_column("findings", "resource")
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "category")
    op.drop_column("findings", "description")
    op.drop_column("scans", "diagnostics")
    op.drop_column("findings", "suppression_reason")
    op.drop_column("findings", "suppressed")
