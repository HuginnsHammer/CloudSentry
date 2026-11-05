"""Tenant-aware persistence models for the CloudSentry platform."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Enum as SAEnum, ForeignKey,
    ForeignKeyConstraint, Index, JSON, String, Text, UniqueConstraint, Uuid, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base metadata for platform tables."""


class MembershipRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


def enum_type(enum_class: type[StrEnum], name: str) -> SAEnum:
    return SAEnum(
        enum_class, name=name, native_enum=False, create_constraint=True,
        values_callable=lambda values: [item.value for item in values],
        validate_strings=True,
    )


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("slug", name="uq_organizations_slug"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    """External identity reference; this foundation stores no local passwords."""
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("identity_provider", "identity_subject", name="uq_users_external_identity"),
        UniqueConstraint("email", name="uq_users_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(160))
    identity_provider: Mapped[str] = mapped_column(String(80), nullable=False)
    identity_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),
        Index("ix_memberships_user_id", "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[MembershipRole] = mapped_column(enum_type(MembershipRole, "membership_role"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_projects_org_id"),
        UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
        Index("ix_projects_organization_id", "organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    repository_url: Mapped[str | None] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Environment(Base):
    __tablename__ = "environments"
    __table_args__ = (
        UniqueConstraint("organization_id", "project_id", "id", name="uq_environments_org_project_id"),
        UniqueConstraint("project_id", "name", name="uq_environments_project_name"),
        ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_environments_project_tenant",
        ),
        Index("ix_environments_org_project", "organization_id", "project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    is_production: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_scans_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_scans_project_tenant",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id", "environment_id"],
            ["environments.organization_id", "environments.project_id", "environments.id"],
            name="fk_scans_environment_tenant",
        ),
        CheckConstraint("completed_at IS NULL OR completed_at >= started_at", name="ck_scans_completion_after_start"),
        Index("ix_scans_org_project_started", "organization_id", "project_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    status: Mapped[ScanStatus] = mapped_column(enum_type(ScanStatus, "scan_status"), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(40), nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    """Stable project-level issue identity, retained across repeated scans."""
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_findings_org_id"),
        UniqueConstraint("organization_id", "project_id", "fingerprint", name="uq_findings_project_fingerprint"),
        ForeignKeyConstraint(
            ["organization_id", "project_id"], ["projects.organization_id", "projects.id"],
            ondelete="CASCADE", name="fk_findings_project_tenant",
        ),
        ForeignKeyConstraint(
            ["organization_id", "assigned_to_user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_findings_assignee_membership",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_severity",
        ),
        CheckConstraint("line_start IS NULL OR line_start > 0", name="ck_findings_line_start_positive"),
        CheckConstraint("line_end IS NULL OR line_end > 0", name="ck_findings_line_end_positive"),
        Index("ix_findings_org_status_severity", "organization_id", "status", "severity"),
        Index("ix_findings_org_assignee", "organization_id", "assigned_to_user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        enum_type(FindingStatus, "finding_status"), nullable=False, default=FindingStatus.OPEN
    )
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    line_start: Mapped[int | None] = mapped_column()
    line_end: Mapped[int | None] = mapped_column()
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanFinding(Base):
    """Immutable observation linking a scan run to a stable project finding."""
    __tablename__ = "scan_findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", name="uq_scan_findings_scan_finding"),
        ForeignKeyConstraint(
            ["organization_id", "scan_id"], ["scans.organization_id", "scans.id"],
            ondelete="CASCADE", name="fk_scan_findings_scan_tenant",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_id"], ["findings.organization_id", "findings.id"],
            ondelete="CASCADE", name="fk_scan_findings_finding_tenant",
        ),
        Index("ix_scan_findings_org_scan", "organization_id", "scan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "actor_user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_audit_actor_membership",
        ),
        Index("ix_audit_events_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
