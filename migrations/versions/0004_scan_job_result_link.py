"""Link scan jobs to their persisted scan result.

Revision ID: 0004_scan_job_result_link
Revises: 0003_github_app_scan_jobs
"""
from alembic import op
import sqlalchemy as sa


revision = "0004_scan_job_result_link"
down_revision = "0003_github_app_scan_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("scan_id", sa.Uuid(), nullable=True))
    op.create_unique_constraint("uq_scan_jobs_scan_id", "scan_jobs", ["scan_id"])
    op.create_foreign_key(
        "fk_scan_jobs_scan_tenant",
        "scan_jobs",
        "scans",
        ["organization_id", "scan_id"],
        ["organization_id", "id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_scan_jobs_scan_tenant", "scan_jobs", type_="foreignkey")
    op.drop_constraint("uq_scan_jobs_scan_id", "scan_jobs", type_="unique")
    op.drop_column("scan_jobs", "scan_id")
