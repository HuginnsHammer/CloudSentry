"""Tests for tenant-aware platform persistence constraints."""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.platform.database import build_engine, build_session_factory
from scanner.platform.models import (
    AuditEvent, Base, Environment, Finding, FindingStatus, Membership,
    MembershipRole, Organization, Project, Scan, ScanStatus, User,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    event.listen(engine, "connect", lambda connection, _record: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    factory = build_session_factory(engine)
    with factory() as value:
        yield value
    engine.dispose()


def seed_project(session: Session, suffix: str):
    organization = Organization(name=f"Org {suffix}", slug=f"org-{suffix}")
    user = User(email=f"{suffix}@example.test", identity_provider="test-oidc", identity_subject=f"sub-{suffix}")
    session.add_all([organization, user])
    session.flush()
    session.add(Membership(organization_id=organization.id, user_id=user.id, role=MembershipRole.OWNER))
    project = Project(organization_id=organization.id, name=f"Project {suffix}", slug=f"project-{suffix}")
    session.add(project)
    session.flush()
    return organization, user, project


def test_database_configuration_requires_explicit_postgres_or_test_sqlite():
    with pytest.raises(RuntimeError, match="CLOUDSENTRY_DATABASE_URL"):
        build_engine(None)
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        build_engine("sqlite+pysqlite:///:memory:")
    build_engine("sqlite+pysqlite:///:memory:", allow_sqlite=True).dispose()


def test_environment_cannot_reference_another_tenant_project(session):
    org_a, _, _ = seed_project(session, "a")
    _, _, project_b = seed_project(session, "b")
    session.commit()
    session.add(Environment(organization_id=org_a.id, project_id=project_b.id, name="production"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_cannot_reference_another_tenant_scan(session):
    org_a, _, project_a = seed_project(session, "a")
    org_b, _, _ = seed_project(session, "b")
    scan = Scan(
        organization_id=org_a.id, project_id=project_a.id, status=ScanStatus.COMPLETED,
        target="repository", scanner_version="0.2.0", summary={},
    )
    session.add(scan)
    session.commit()
    session.add(Finding(
        organization_id=org_b.id, scan_id=scan.id, fingerprint="f" * 64, rule_id="TEST-001",
        title="Cross-tenant finding", severity="high", status=FindingStatus.OPEN,
        file_path="main.tf", evidence="public ingress", remediation="restrict ingress",
    ))
    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_assignee_must_be_member_of_same_tenant(session):
    org_a, _, project_a = seed_project(session, "a")
    _, user_b, _ = seed_project(session, "b")
    scan = Scan(
        organization_id=org_a.id, project_id=project_a.id, status=ScanStatus.COMPLETED,
        target="repository", scanner_version="0.2.0", summary={},
    )
    session.add(scan)
    session.commit()
    session.add(Finding(
        organization_id=org_a.id, scan_id=scan.id, fingerprint="a" * 64, rule_id="TEST-002",
        title="Cross-tenant assignment", severity="medium", status=FindingStatus.OPEN,
        file_path="Dockerfile", evidence="root user", remediation="use a non-root user",
        assigned_to_user_id=user_b.id,
    ))
    with pytest.raises(IntegrityError):
        session.commit()


def test_audit_actor_must_belong_to_recorded_tenant(session):
    org_a, _, _ = seed_project(session, "a")
    _, user_b, _ = seed_project(session, "b")
    session.commit()
    session.add(AuditEvent(
        organization_id=org_a.id, actor_user_id=user_b.id, action="project.updated",
        target_type="project", details={},
    ))
    with pytest.raises(IntegrityError):
        session.commit()


def test_membership_role_is_explicit(session):
    organization, user, _ = seed_project(session, "a")
    membership = session.get(Membership, (organization.id, user.id))
    assert membership is not None
    assert membership.role is MembershipRole.OWNER
