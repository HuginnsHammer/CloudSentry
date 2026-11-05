from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.api.platform_app import app
from scanner.platform.dependencies import get_current_user, get_db_session
from scanner.platform.models import (
    AuditEvent,
    Base,
    Finding,
    FindingStatus,
    Membership,
    MembershipRole,
    Organization,
    Project,
    User,
)


@pytest.fixture
def finding_client():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    org_a = Organization(id=uuid4(), name="Tenant A", slug="tenant-a")
    org_b = Organization(id=uuid4(), name="Tenant B", slug="tenant-b")
    analyst = User(
        id=uuid4(), email="analyst@example.test", display_name="Analyst",
        identity_provider="https://identity.example.test/", identity_subject="analyst",
    )
    developer = User(
        id=uuid4(), email="developer@example.test", display_name="Developer",
        identity_provider="https://identity.example.test/", identity_subject="developer",
    )
    viewer = User(
        id=uuid4(), email="viewer@example.test", display_name="Viewer",
        identity_provider="https://identity.example.test/", identity_subject="viewer",
    )
    project_a = Project(id=uuid4(), organization_id=org_a.id, name="Alpha", slug="alpha")
    project_b = Project(id=uuid4(), organization_id=org_b.id, name="Bravo", slug="bravo")
    finding_a = Finding(
        id=uuid4(), organization_id=org_a.id, project_id=project_a.id,
        fingerprint="fingerprint-a", rule_id="CS001", title="Public storage",
        severity="high", status=FindingStatus.OPEN, file_path="infra/main.tf",
        evidence="bucket is public", remediation="Restrict public access",
    )
    with factory() as session:
        session.add_all([org_a, org_b, analyst, developer, viewer])
        session.flush()
        session.add_all([
            Membership(organization_id=org_a.id, user_id=analyst.id, role=MembershipRole.SECURITY_ANALYST),
            Membership(organization_id=org_a.id, user_id=developer.id, role=MembershipRole.DEVELOPER),
            Membership(organization_id=org_a.id, user_id=viewer.id, role=MembershipRole.VIEWER),
            project_a, project_b, finding_a,
        ])
        session.commit()

    active_user_id = {"value": analyst.id}

    def override_session():
        with factory() as session:
            yield session

    def override_user():
        with factory() as session:
            return session.get(User, active_user_id["value"])

    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_current_user] = override_user
    client = TestClient(app)
    try:
        yield client, factory, active_user_id, org_a.id, org_b.id, project_a.id, finding_a.id, developer.id, viewer.id
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def endpoint(org_id, project_id, finding_id):
    return f"/api/v1/organizations/{org_id}/projects/{project_id}/findings/{finding_id}"


def test_member_can_list_only_findings_in_their_project(finding_client):
    client, _, _, org_a, org_b, project_a, finding_a, _, _ = finding_client
    response = client.get(f"/api/v1/organizations/{org_a}/projects/{project_a}/findings")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [str(finding_a)]
    foreign = client.get(f"/api/v1/organizations/{org_b}/projects/{project_a}/findings")
    assert foreign.status_code == 404


def test_analyst_can_assign_and_triage_with_audit_event(finding_client):
    client, factory, _, org_a, _, project_a, finding_id, developer_id, _ = finding_client
    response = client.patch(
        endpoint(org_a, project_a, finding_id),
        json={"status": "triaged", "assigned_to_user_id": str(developer_id), "note": "Reviewed"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "triaged"
    assert response.json()["assigned_to_user_id"] == str(developer_id)
    with factory() as session:
        events = session.scalars(select(AuditEvent)).all()
        assert len(events) == 1
        assert events[0].action == "finding.updated"
        assert events[0].details["changes"]["status"]["to"] == "triaged"


def test_developer_can_start_and_resolve_but_not_accept_risk(finding_client):
    client, _, active, org_a, _, project_a, finding_id, developer_id, _ = finding_client
    active["value"] = developer_id
    url = endpoint(org_a, project_a, finding_id)
    started = client.patch(url, json={"status": "in_progress"})
    assert started.status_code == 200
    resolved = client.patch(url, json={"status": "resolved"})
    assert resolved.status_code == 200
    assert resolved.json()["resolved_at"] is not None
    forbidden = client.patch(url, json={"status": "accepted_risk", "note": "Business decision"})
    assert forbidden.status_code == 403


def test_viewer_cannot_change_findings(finding_client):
    client, _, active, org_a, _, project_a, finding_id, _, viewer_id = finding_client
    active["value"] = viewer_id
    response = client.patch(endpoint(org_a, project_a, finding_id), json={"status": "triaged"})
    assert response.status_code == 403


def test_risk_acceptance_requires_a_reason(finding_client):
    client, _, _, org_a, _, project_a, finding_id, _, _ = finding_client
    response = client.patch(endpoint(org_a, project_a, finding_id), json={"status": "accepted_risk"})
    assert response.status_code == 422


def test_assignee_must_be_a_member_of_same_organization(finding_client):
    client, _, _, org_a, org_b, project_a, finding_id, _, _ = finding_client
    foreign_user = User(
        id=uuid4(), email="outsider@example.test", display_name="Outsider",
        identity_provider="https://identity.example.test/", identity_subject="outsider",
    )
    response = client.patch(
        endpoint(org_a, project_a, finding_id),
        json={"assigned_to_user_id": str(foreign_user.id)},
    )
    assert response.status_code == 422


def test_invalid_status_payload_is_rejected(finding_client):
    client, _, _, org_a, _, project_a, finding_id, _, _ = finding_client
    response = client.patch(endpoint(org_a, project_a, finding_id), json={"status": "ignored"})
    assert response.status_code == 422
