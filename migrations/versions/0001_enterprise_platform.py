"""Initial tenant-aware CloudSentry platform schema.

Revision ID: 0001_enterprise_platform
Revises:
"""
from alembic import op

from scanner.platform.models import Base

revision = "0001_enterprise_platform"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Initial schema snapshot. Future revisions must use explicit Alembic operations
    # and must never mutate this historical revision.
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
