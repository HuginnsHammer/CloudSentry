"""Initial tenant-aware CloudSentry platform schema.

Revision ID: 0001_enterprise_platform
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_enterprise_platform"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(160), nullable=True),
        sa.Column("identity_provider", sa.String(80), nullable=False),
        sa.Column("identity_subject", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("identity_provider", "identity_subject", name="uq_users_external_identity"),
    )
    op.create_table(
        "memberships",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'security_analyst', 'developer', 'viewer')",
            name="membership_role",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("organization_id", "user_id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("repository_url", sa.String(2048), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_projects_org_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
    )
    op.create_index("ix_projects_organization_id", "projects", ["organization_id"])
    op.create_table(
        "environments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("is_production", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_environments_project_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "project_id", "id", name="uq_environments_org_project_id"),
        sa.UniqueConstraint("project_id", "name", name="uq_environments_project_name"),
    )
    op.create_index("ix_environments_org_project", "environments", ["organization_id", "project_id"])
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=9), nullable=False),
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("scanner_version", sa.String(40), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')",
            name="scan_status",
        ),
        sa.CheckConstraint("completed_at IS NULL OR completed_at >= started_at", name="ck_scans_completion_after_start"),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_scans_project_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id", "environment_id"],
            ["environments.organization_id", "environments.project_id", "environments.id"],
            name="fk_scans_environment_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_scans_org_id"),
    )
    op.create_index("ix_scans_org_project_started", "scans", ["organization_id", "project_id", "started_at"])
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("rule_id", sa.String(160), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(length=14), nullable=False),
        sa.Column("file_path", sa.String(2048), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("assigned_to_user_id", sa.Uuid(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'triaged', 'in_progress', 'accepted_risk', 'resolved', 'false_positive')",
            name="finding_status",
        ),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_findings_severity"),
        sa.CheckConstraint("line_start IS NULL OR line_start > 0", name="ck_findings_line_start_positive"),
        sa.CheckConstraint("line_end IS NULL OR line_end > 0", name="ck_findings_line_end_positive"),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_findings_project_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "assigned_to_user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_findings_assignee_membership",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_findings_org_id"),
        sa.UniqueConstraint("organization_id", "project_id", "fingerprint", name="uq_findings_project_fingerprint"),
    )
    op.create_index("ix_findings_org_status_severity", "findings", ["organization_id", "status", "severity"])
    op.create_index("ix_findings_org_assignee", "findings", ["organization_id", "assigned_to_user_id"])
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_id"], ["scans.organization_id", "scans.id"],
            ondelete="CASCADE", name="fk_scan_findings_scan_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"], ["findings.organization_id", "findings.id"],
            ondelete="CASCADE", name="fk_scan_findings_finding_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_scan_findings_scan_finding"),
    )
    op.create_index("ix_scan_findings_org_scan", "scan_findings", ["organization_id", "scan_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("target_id", sa.String(80), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "actor_user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_audit_actor_membership",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_org_occurred", "audit_events", ["organization_id", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_occurred", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_scan_findings_org_scan", table_name="scan_findings")
    op.drop_table("scan_findings")
    op.drop_index("ix_findings_org_assignee", table_name="findings")
    op.drop_index("ix_findings_org_status_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_org_project_started", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_environments_org_project", table_name="environments")
    op.drop_table("environments")
    op.drop_index("ix_projects_organization_id", table_name="projects")
    op.drop_table("projects")
    op.drop_index("ix_memberships_user_id", table_name="memberships")
    op.drop_table("memberships")
    op.drop_table("users")
    op.drop_table("organizations")
