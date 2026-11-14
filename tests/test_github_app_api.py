import hashlib
import hmac
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.api.github import get_github_app_client
from scanner.api.platform_app import app
from scanner.platform.dependencies import get_current_user, get_db_session
from scanner.platform.models import (
    AuditEvent,
    Base,
    GitHubInstallation,
    GitHubWebhookDelivery,
    Membership,
    MembershipRole,
    Organization,
    Project,
    ScanJob,
    ScanStatus,
    User,
)


WEBHOOK_SECRET = "cloudsentry-test-webhook-secret-32-characters-minimum"


class FakeGitHubAppClient:
    def __init__(self):
        self.installation = {
            "id": 12345,
            "account": {"id": 67890, "login": "acme-security", "type": "Organization"},
        }
        self.repository = {
            "id": 98765,
            "full_name": "acme-security/payments",
            "html_url": "https://github.com/acme-security/payments",
            "default_branch": "main",
        }

    def get_installation(self, installation_id):
        result = dict(self.installation)
        result["id"] = installation_id
        return result

    def get_installation_repository(self, installation_id, repository_id):
        if self.repository is None:
            return None
        result = dict(self.repository)
        result["id"] = repository_id
        return result


@pytest.fixture
def github_client(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    organization = Organization(id=uuid4(), name="Acme", slug="acme")
    user = User(
        id=uuid4(),
        email="owner@example.test",
        display_name="Owner",
        identity_provider="https://identity.example.test/",
        identity_subject="owner-subject",
    )
    project = Project(
        id=uuid4(),
        organization_id=organization.id,
        name="Payments",
        slug="payments",
    )
    with factory() as session:
        session.add_all([organization, user])
        session.flush()
        session.add_all([
            Membership(
                organization_id=organization.id,
                user_id=user.id,
                role=MembershipRole.OWNER,
            ),
            project,
        ])
        session.commit()

    def override_session():
        with factory() as session:
            yield session

    def override_user():
        with factory() as session:
            return session.get(User, user.id)

    fake = FakeGitHubAppClient()
    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_github_app_client] = lambda: fake
    monkeypatch.setenv("CLOUDSENTRY_GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    client = TestClient(app)
    try:
        yield client, factory, organization.id, project.id, user.id, fake
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def add_installation(factory, organization_id=None, status="unclaimed"):
    installation = GitHubInstallation(
        id=uuid4(),
        organization_id=organization_id,
        installation_id=12345,
        account_id=67890,
        account_login="acme-security",
        account_type="Organization",
        status=status,
    )
    with factory() as session:
        session.add(installation)
        session.commit()
    return installation


def bind_project_record(factory, project_id, organization_id):
    with factory() as session:
        project = session.get(Project, project_id)
        project.github_installation_id = 12345
        project.github_repository_id = 98765
        project.github_repository_full_name = "acme-security/payments"
        project.github_default_branch = "main"
        project.repository_url = "https://github.com/acme-security/payments"
        session.commit()


def send_webhook(client, event, payload, delivery_id=None, *, secret=WEBHOOK_SECRET):
    delivery_id = delivery_id or str(uuid4())
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return client.post(
        "/api/v1/integrations/github/webhook",
        content=raw,
        headers={
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery_id,
            "X-Hub-Signature-256": f"sha256={signature}",
            "Content-Type": "application/json",
        },
    ), delivery_id


def installation_payload(action="created"):
    return {
        "action": action,
        "installation": {
            "id": 12345,
            "account": {"id": 67890, "login": "acme-security", "type": "Organization"},
        },
    }


def push_payload(ref="refs/heads/main", revision="a" * 40):
    return {
        "ref": ref,
        "after": revision,
        "deleted": False,
        "installation": {"id": 12345},
        "repository": {"id": 98765, "full_name": "acme-security/payments"},
    }


def test_installation_created_webhook_is_verified_and_stored_unclaimed(github_client):
    client, factory, _, _, _, _ = github_client
    response, delivery_id = send_webhook(client, "installation", installation_payload())
    assert response.status_code == 202
    assert response.json()["result"] == "processed"
    with factory() as session:
        installation = session.scalar(
            select(GitHubInstallation).where(GitHubInstallation.installation_id == 12345)
        )
        delivery = session.get(GitHubWebhookDelivery, delivery_id)
        assert installation.organization_id is None
        assert installation.status == "unclaimed"
        assert delivery.status == "processed"
        assert delivery.payload_sha256 == hashlib.sha256(
            json.dumps(installation_payload(), separators=(",", ":")).encode()
        ).hexdigest()


def test_webhook_delivery_is_idempotent(github_client):
    client, factory, _, _, _, _ = github_client
    payload = installation_payload()
    first, delivery_id = send_webhook(client, "installation", payload)
    second, _ = send_webhook(client, "installation", payload, delivery_id)
    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["duplicate"] is True
    with factory() as session:
        assert len(session.scalars(select(GitHubWebhookDelivery)).all()) == 1
        assert len(session.scalars(select(GitHubInstallation)).all()) == 1


def test_missing_or_invalid_webhook_signature_is_rejected(github_client, monkeypatch):
    client, _, _, _, _, _ = github_client
    raw = json.dumps(installation_payload()).encode()
    missing = client.post(
        "/api/v1/integrations/github/webhook",
        content=raw,
        headers={"X-GitHub-Event": "installation", "X-GitHub-Delivery": str(uuid4())},
    )
    invalid = client.post(
        "/api/v1/integrations/github/webhook",
        content=raw,
        headers={
            "X-GitHub-Event": "installation",
            "X-GitHub-Delivery": str(uuid4()),
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
        },
    )
    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_webhook_fails_closed_when_secret_is_not_configured(github_client, monkeypatch):
    client, _, _, _, _, _ = github_client
    monkeypatch.delenv("CLOUDSENTRY_GITHUB_WEBHOOK_SECRET")
    response, _ = send_webhook(client, "installation", installation_payload())
    assert response.status_code == 503


def test_webhook_rejects_oversized_declared_body(github_client):
    client, _, _, _, _, _ = github_client
    response = client.post(
        "/api/v1/integrations/github/webhook",
        content=b"{}",
        headers={
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": str(uuid4()),
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "Content-Length": str(1024 * 1024 + 1),
        },
    )
    assert response.status_code == 413


def test_claim_requires_owner_or_admin(github_client):
    client, factory, organization_id, _, _, _ = github_client
    add_installation(factory)
    with factory() as session:
        membership = session.get(Membership, (organization_id, session.scalar(select(User.id))))
        membership.role = MembershipRole.SECURITY_ANALYST
        session.commit()
    response = client.post(
        f"/api/v1/organizations/{organization_id}/github/installations/12345/claim"
    )
    assert response.status_code == 403


def test_owner_can_claim_a_verified_installation(github_client):
    client, factory, organization_id, _, _, _ = github_client
    add_installation(factory)
    response = client.post(
        f"/api/v1/organizations/{organization_id}/github/installations/12345/claim"
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "active"
    with factory() as session:
        installation = session.scalar(select(GitHubInstallation))
        assert installation.organization_id == organization_id
        assert session.scalar(select(AuditEvent.action)) == "github.installation_claimed"


def test_installation_claim_rejects_account_mismatch(github_client):
    client, factory, organization_id, _, _, fake = github_client
    add_installation(factory)
    fake.installation["account"]["id"] = 11111
    response = client.post(
        f"/api/v1/organizations/{organization_id}/github/installations/12345/claim"
    )
    assert response.status_code == 409
    with factory() as session:
        assert session.scalar(select(GitHubInstallation)).organization_id is None


def test_owner_can_bind_only_a_repository_accessible_to_the_installation(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    response = client.post(
        f"/api/v1/organizations/{organization_id}/projects/{project_id}/github/repository",
        json={"installation_id": 12345, "repository_id": 98765},
    )
    assert response.status_code == 200, response.text
    assert response.json()["full_name"] == "acme-security/payments"
    with factory() as session:
        project = session.get(Project, project_id)
        assert project.github_installation_id == 12345
        assert project.github_repository_id == 98765
        assert project.github_default_branch == "main"


def test_repository_binding_rejects_repositories_not_installed(github_client):
    client, factory, organization_id, project_id, _, fake = github_client
    add_installation(factory, organization_id, status="active")
    fake.repository = None
    response = client.post(
        f"/api/v1/organizations/{organization_id}/projects/{project_id}/github/repository",
        json={"installation_id": 12345, "repository_id": 99999},
    )
    assert response.status_code == 404


def test_repository_binding_requires_owner_or_admin(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    with factory() as session:
        membership = session.get(Membership, (organization_id, session.scalar(select(User.id))))
        membership.role = MembershipRole.DEVELOPER
        session.commit()
    response = client.post(
        f"/api/v1/organizations/{organization_id}/projects/{project_id}/github/repository",
        json={"installation_id": 12345, "repository_id": 98765},
    )
    assert response.status_code == 403


def test_push_to_default_branch_queues_one_immutable_scan_job(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    bind_project_record(factory, project_id, organization_id)
    response, _ = send_webhook(client, "push", push_payload())
    assert response.status_code == 202
    assert response.json()["result"] == "queued"
    with factory() as session:
        jobs = session.scalars(select(ScanJob)).all()
        assert len(jobs) == 1
        assert jobs[0].status == ScanStatus.QUEUED
        assert jobs[0].source_revision == "a" * 40
        assert jobs[0].ref == "refs/heads/main"
        assert session.scalar(select(AuditEvent.action)) == "github.push_scan_queued"


def test_push_to_non_default_branch_does_not_queue_a_job(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    bind_project_record(factory, project_id, organization_id)
    response, _ = send_webhook(client, "push", push_payload(ref="refs/heads/feature/test"))
    assert response.status_code == 202
    assert response.json()["result"] == "ignored"
    with factory() as session:
        assert session.scalar(select(ScanJob)) is None


def test_duplicate_push_revision_with_new_delivery_does_not_duplicate_job(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    bind_project_record(factory, project_id, organization_id)
    first, _ = send_webhook(client, "push", push_payload())
    second, _ = send_webhook(client, "push", push_payload())
    assert first.json()["result"] == "queued"
    assert second.json()["result"] == "duplicate_job"
    with factory() as session:
        assert len(session.scalars(select(ScanJob)).all()) == 1


def test_suspended_installation_cannot_queue_scans(github_client):
    client, factory, organization_id, project_id, _, _ = github_client
    add_installation(factory, organization_id, status="suspended")
    bind_project_record(factory, project_id, organization_id)
    response, _ = send_webhook(client, "push", push_payload())
    assert response.json()["result"] == "ignored"
    with factory() as session:
        assert session.scalar(select(ScanJob)) is None


def test_deleted_installation_webhook_disables_existing_installation(github_client):
    client, factory, organization_id, _, _, _ = github_client
    add_installation(factory, organization_id, status="active")
    response, _ = send_webhook(client, "installation", installation_payload("deleted"))
    assert response.status_code == 202
    with factory() as session:
        installation = session.scalar(select(GitHubInstallation))
        assert installation.organization_id == organization_id
        assert installation.status == "deleted"
