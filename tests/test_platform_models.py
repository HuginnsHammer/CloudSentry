"""Tests for tenant-aware platform persistence constraints."""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.platform.database import build_engine, build_session_factory
from scanner.platform.models import (
    AuditEvent, Base, Environment, Finding, FindingStatus, Membership,
    MembershipRole, Organization, Project, Scan, ScanFinding, ScanStatus, User,
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


def create_scan(session: Session, organization: Organization, project: Project) -> Scan:
    scan = Scan(
        organization_id=organization.id, project_id=project.id, status=ScanStatus.COMPLETED,
        target="repository", scanner_version="0.1.0", summary={},
    )
    session.add(scan)
    session.flush()
    return scan


def create_finding(session: Session, organization: Organization, project: Project, **overrides) -> Finding:
    values = {
        "organization_id": organization.id, "project_id": project.id,
        "fingerprint": "f" * 64, "rule_id": "TEST-001", "title": "Test finding",
        "severity": "high", "status": FindingStatus.OPEN, "file_path": "main.tf",
        "evidence": "public ingress", "remediation": "restrict ingress",
    }
    values.update(overrides)
    finding = Finding(**values)
    session.add(finding)
    session.flush()
    return finding


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


def test_scan_finding_link_cannot_cross_tenant_boundary(session):
    org_a, _, project_a = seed_project(session, "a")
    org_b, _, project_b = seed_project(session, "b")
    scan_a = create_scan(session, org_a, project_a)
    finding_b = create_finding(session, org_b, project_b)
    session.commit()
    session.add(ScanFinding(organization_id=org_a.id, scan_id=scan_a.id, finding_id=finding_b.id))
    with pytest.raises(IntegrityError):
        session.commit()


def test_finding_assignee_must_be_member_of_same_tenant(session):
    org_a, _, project_a = seed_project(session, "a")
    _, user_b, _ = seed_project(session, "b")
    with pytest.raises(IntegrityError):
        create_finding(session, org_a, project_a, assigned_to_user_id=user_b.id)


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


def test_finding_identity_is_stable_across_multiple_scans(session):
    organization, _, project = seed_project(session, "a")
    finding = create_finding(session, organization, project)
    first_scan = create_scan(session, organization, project)
    second_scan = create_scan(session, organization, project)
    session.add_all([
        ScanFinding(organization_id=organization.id, scan_id=first_scan.id, finding_id=finding.id),
        ScanFinding(organization_id=organization.id, scan_id=second_scan.id, finding_id=finding.id),
    ])
    session.commit()
    assert session.query(ScanFinding).count() == 2
    assert session.query(Finding).count() == 1


def test_membership_role_is_explicit(session):
    organization, user, _ = seed_project(session, "a")
    membership = session.get(Membership, (organization.id, user.id))
    assert membership is not None
    assert membership.role is MembershipRole.OWNER
