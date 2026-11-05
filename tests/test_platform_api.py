from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.api.platform_app import app
from scanner.platform.dependencies import get_current_user, get_db_session
from scanner.platform.models import Base, Membership, MembershipRole, Organization, Project, User


@pytest.fixture
def platform_client():
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
        email="analyst@example.test",
        display_name="Analyst",
        identity_provider="https://identity.example.test/",
        identity_subject="subject-123",
    )
    project_a = Project(id=uuid4(), organization_id=org_a.id, name="Alpha", slug="alpha")
    project_b = Project(id=uuid4(), organization_id=org_b.id, name="Bravo", slug="bravo")
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
            project_b,
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
        yield client, org_a.id, org_b.id
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_platform_health_is_public(platform_client):
    client, _, _ = platform_client
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "authenticated-platform-api"


def test_platform_routes_require_authentication_by_default(platform_client):
    client, _, _ = platform_client
    app.dependency_overrides.pop(get_current_user)
    response = client.get("/api/v1/organizations")
    assert response.status_code == 401


def test_user_sees_only_organizations_they_belong_to(platform_client):
    client, org_a_id, org_b_id = platform_client
    response = client.get("/api/v1/organizations")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [str(org_a_id)]
    assert response.json()[0]["role"] == "security_analyst"
    assert str(org_b_id) not in response.text


def test_project_list_is_tenant_scoped(platform_client):
    client, org_a_id, org_b_id = platform_client
    allowed = client.get(f"/api/v1/organizations/{org_a_id}/projects")
    denied = client.get(f"/api/v1/organizations/{org_b_id}/projects")
    assert allowed.status_code == 200
    assert [item["slug"] for item in allowed.json()] == ["alpha"]
    assert denied.status_code == 404


def test_invalid_organization_identifier_is_rejected(platform_client):
    client, _, _ = platform_client
    response = client.get("/api/v1/organizations/not-a-uuid/projects")
    assert response.status_code == 422
