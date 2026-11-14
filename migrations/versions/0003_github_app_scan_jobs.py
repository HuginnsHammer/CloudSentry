"""Add GitHub App installations, webhook idempotency, and scan jobs.

Revision ID: 0003_github_app_scan_jobs
Revises: 0002_finding_suppression
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_github_app_scan_jobs"
down_revision = "0002_finding_suppression"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_installations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=False),
        sa.Column("account_login", sa.String(length=255), nullable=False),
        sa.Column("account_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="unclaimed"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('unclaimed', 'active', 'suspended', 'deleted')",
            name="ck_github_installations_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("installation_id", name="uq_github_installations_installation_id"),
        sa.UniqueConstraint(
            "organization_id", "installation_id",
            name="uq_github_installations_org_installation",
        ),
    )

    op.add_column("projects", sa.Column("github_installation_id", sa.BigInteger(), nullable=True))
    op.add_column("projects", sa.Column("github_repository_id", sa.BigInteger(), nullable=True))
    op.add_column("projects", sa.Column("github_repository_full_name", sa.String(length=255), nullable=True))
    op.add_column("projects", sa.Column("github_default_branch", sa.String(length=255), nullable=True))
    op.create_unique_constraint(
        "uq_projects_github_repository_id", "projects", ["github_repository_id"]
    )
    op.create_foreign_key(
        "fk_projects_github_installation_tenant",
        "projects",
        "github_installations",
        ["organization_id", "github_installation_id"],
        ["organization_id", "installation_id"],
    )

    op.create_table(
        "github_webhook_deliveries",
        sa.Column("delivery_id", sa.String(length=128), nullable=False),
        sa.Column("event", sa.String(length=80), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=True),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('processed', 'ignored')",
            name="ck_github_webhook_deliveries_status",
        ),
        sa.PrimaryKeyConstraint("delivery_id"),
    )
    op.create_index(
        "ix_github_webhook_deliveries_received",
        "github_webhook_deliveries",
        ["received_at"],
    )

    scan_status = sa.Enum(
        "queued", "running", "completed", "partial", "failed", "cancelled",
        name="scan_status", native_enum=False, create_constraint=True,
    )
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("source_revision", sa.String(length=64), nullable=False),
        sa.Column("ref", sa.String(length=255), nullable=False),
        sa.Column("dedupe_key", sa.String(length=64), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("available_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "attempts >= 0 AND max_attempts BETWEEN 1 AND 10",
            name="ck_scan_jobs_attempt_limits",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
            name="fk_scan_jobs_project_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id", "environment_id"],
            ["environments.organization_id", "environments.project_id", "environments.id"],
            name="fk_scan_jobs_environment_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "requested_by_user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_scan_jobs_requester_membership",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_scan_jobs_org_id"),
        sa.UniqueConstraint("organization_id", "dedupe_key", name="uq_scan_jobs_org_dedupe"),
    )
    op.create_index("ix_scan_jobs_claim", "scan_jobs", ["status", "available_at"])
    op.create_index(
        "ix_scan_jobs_org_project_created",
        "scan_jobs",
        ["organization_id", "project_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_org_project_created", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_claim", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_github_webhook_deliveries_received", table_name="github_webhook_deliveries")
    op.drop_table("github_webhook_deliveries")
    op.drop_constraint("fk_projects_github_installation_tenant", "projects", type_="foreignkey")
    op.drop_constraint("uq_projects_github_repository_id", "projects", type_="unique")
    op.drop_column("projects", "github_default_branch")
    op.drop_column("projects", "github_repository_full_name")
    op.drop_column("projects", "github_repository_id")
    op.drop_column("projects", "github_installation_id")
    op.drop_table("github_installations")
