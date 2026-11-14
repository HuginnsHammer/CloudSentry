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
    Membership,
    MembershipRole,
    Organization,
    Project,
    User,
)


@pytest.fixture
def resource_client():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    org_a = Organization(id=uuid4(), name="Tenant A", slug="tenant-a")
    org_b = Organization(id=uuid4(), name="Tenant B", slug="tenant-b")
    user = User(
        id=uuid4(),
        email="owner@example.test",
        display_name="Owner",
        identity_provider="https://identity.example.test/",
        identity_subject="owner-subject",
    )
    project_a = Project(id=uuid4(), organization_id=org_a.id, name="Alpha", slug="alpha")
    with factory() as session:
        session.add_all([org_a, org_b, user])
        session.flush()
        session.add_all([
            Membership(
                organization_id=org_a.id,
                user_id=user.id,
                role=MembershipRole.SECURITY_ANALYST,
            ),
            project_a,
        ])
        session.commit()

    def override_session():
        with factory() as session:
            yield session

    def override_user():
        with factory() as session:
            return session.get(User, user.id)

    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_current_user] = override_user
    client = TestClient(app)
    try:
        yield client, factory, org_a.id, org_b.id, project_a.id
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_authenticated_user_can_create_an_organization_and_become_owner(resource_client):
    client, _, _, _, _ = resource_client
    response = client.post(
        "/api/v1/organizations",
        json={"name": "Platform Security", "slug": "Platform-Security"},
    )
    assert response.status_code == 201, response.text
    organization = response.json()
    assert organization["slug"] == "platform-security"
    assert organization["role"] == "owner"

    detail = client.get(f"/api/v1/organizations/{organization['id']}")
    assert detail.status_code == 200
    assert detail.json()["name"] == "Platform Security"
    memberships = client.get("/api/v1/organizations")
    assert any(
        item["id"] == organization["id"] and item["role"] == "owner"
        for item in memberships.json()
    )


def test_organization_slug_conflicts_return_409(resource_client):
    client, _, _, _, _ = resource_client
    payload = {"name": "New Organization", "slug": "new-organization"}
    assert client.post("/api/v1/organizations", json=payload).status_code == 201
    conflict = client.post("/api/v1/organizations", json=payload)
    assert conflict.status_code == 409


def test_owner_can_create_project_and_production_environment(resource_client):
    client, _, _, _, _ = resource_client
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Infrastructure Team", "slug": "infrastructure-team"},
    ).json()
    organization_id = organization["id"]

    project_response = client.post(
        f"/api/v1/organizations/{organization_id}/projects",
        json={
            "name": "Payments Platform",
            "slug": "payments-platform",
            "repository_url": "https://github.com/example/payments.git",
        },
    )
    assert project_response.status_code == 201, project_response.text
    project = project_response.json()
    assert project["repository_url"] == "https://github.com/example/payments"

    detail = client.get(
        f"/api/v1/organizations/{organization_id}/projects/{project['id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["slug"] == "payments-platform"

    environment_response = client.post(
        f"/api/v1/organizations/{organization_id}/projects/{project['id']}/environments",
        json={"name": "production", "is_production": True},
    )
    assert environment_response.status_code == 201, environment_response.text
    assert environment_response.json()["is_production"] is True

    environments = client.get(
        f"/api/v1/organizations/{organization_id}/projects/{project['id']}/environments"
    )
    assert environments.status_code == 200
    assert [item["name"] for item in environments.json()] == ["production"]


def test_project_and_environment_writes_require_owner_or_admin(resource_client):
    client, _, org_a, _, project_a = resource_client
    project = client.post(
        f"/api/v1/organizations/{org_a}/projects",
        json={"name": "Denied", "slug": "denied"},
    )
    environment = client.post(
        f"/api/v1/organizations/{org_a}/projects/{project_a}/environments",
        json={"name": "staging"},
    )
    assert project.status_code == 403
    assert environment.status_code == 403


def test_non_member_cannot_create_project_in_another_organization(resource_client):
    client, _, _, org_b, _ = resource_client
    response = client.post(
        f"/api/v1/organizations/{org_b}/projects",
        json={"name": "Unauthorized", "slug": "unauthorized"},
    )
    assert response.status_code == 404


@pytest.mark.parametrize(
    "repository_url",
    [
        "http://github.com/example/repo",
        "https://127.0.0.1/private",
        "https://github.com@127.0.0.1/example/repo",
        "https://github.com/example/repo?redirect=http://127.0.0.1",
        "https://github.com/example/../secrets",
        "https://evil.example/example/repo",
    ],
)
def test_repository_url_rejects_non_github_and_ssrf_shaped_values(resource_client, repository_url):
    client, _, _, _, _ = resource_client
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "URL Validation", "slug": f"url-validation-{uuid4().hex[:8]}"},
    ).json()
    response = client.post(
        f"/api/v1/organizations/{organization['id']}/projects",
        json={"name": "Invalid URL", "slug": "invalid-url", "repository_url": repository_url},
    )
    assert response.status_code == 422


def test_duplicate_project_and_environment_names_return_409(resource_client):
    client, _, _, _, _ = resource_client
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Duplicate Tests", "slug": "duplicate-tests"},
    ).json()
    org_id = organization["id"]
    project = client.post(
        f"/api/v1/organizations/{org_id}/projects",
        json={"name": "Project", "slug": "project"},
    ).json()
    project_url = f"/api/v1/organizations/{org_id}/projects/{project['id']}"
    payload = {"name": "staging"}
    assert client.post(f"{project_url}/environments", json=payload).status_code == 201
    assert client.post(f"{project_url}/environments", json=payload).status_code == 409
    assert client.post(
        f"/api/v1/organizations/{org_id}/projects",
        json={"name": "Other Project", "slug": "project"},
    ).status_code == 409


def test_resource_creation_writes_audit_events(resource_client):
    client, factory, _, _, _ = resource_client
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Audited Org", "slug": "audited-org"},
    ).json()
    project = client.post(
        f"/api/v1/organizations/{organization['id']}/projects",
        json={"name": "Audited Project", "slug": "audited-project"},
    ).json()
    client.post(
        f"/api/v1/organizations/{organization['id']}/projects/{project['id']}/environments",
        json={"name": "test"},
    )
    with factory() as session:
        actions = session.scalars(
            select(AuditEvent.action).where(
                AuditEvent.organization_id == organization["id"]
            )
        ).all()
    assert set(actions) == {
        "organization.created",
        "project.created",
        "environment.created",
    }
