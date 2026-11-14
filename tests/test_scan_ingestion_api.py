from datetime import datetime, timezone
from uuid import UUID, uuid4

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
    Environment,
    Finding,
    FindingStatus,
    Membership,
    MembershipRole,
    Organization,
    Project,
    Scan,
    ScanFinding,
    ScanStatus,
    User,
)


@pytest.fixture
def scan_client():
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
    viewer = User(
        id=uuid4(), email="viewer@example.test", display_name="Viewer",
        identity_provider="https://identity.example.test/", identity_subject="viewer",
    )
    project_a = Project(id=uuid4(), organization_id=org_a.id, name="Alpha", slug="alpha")
    project_b = Project(id=uuid4(), organization_id=org_b.id, name="Bravo", slug="bravo")
    environment_a = Environment(
        id=uuid4(), organization_id=org_a.id, project_id=project_a.id,
        name="production", is_production=True,
    )
    environment_b = Environment(
        id=uuid4(), organization_id=org_b.id, project_id=project_b.id,
        name="production", is_production=True,
    )
    with factory() as session:
        session.add_all([org_a, org_b, analyst, viewer])
        session.flush()
        session.add_all([
            Membership(organization_id=org_a.id, user_id=analyst.id, role=MembershipRole.SECURITY_ANALYST),
            Membership(organization_id=org_a.id, user_id=viewer.id, role=MembershipRole.VIEWER),
            project_a, project_b, environment_a, environment_b,
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
        yield (
            client, factory, active_user_id, org_a.id, org_b.id,
            project_a.id, project_b.id, environment_a.id, environment_b.id, viewer.id,
        )
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def scan_endpoint(org_id, project_id):
    return f"/api/v1/organizations/{org_id}/projects/{project_id}/scans/ingest"


def finding_payload(*, fingerprint="fingerprint-001", suppressed=False, title="Public storage"):
    return {
        "rule_id": "CS-TF-001",
        "title": title,
        "description": "A storage resource may be publicly accessible.",
        "severity": "high",
        "confidence": "high",
        "category": "terraform",
        "file_path": "infra/main.tf",
        "line_start": 10,
        "line_end": 12,
        "resource": "aws_s3_bucket.example",
        "evidence": "acl = \"public-read\"",
        "impact": "Untrusted parties may access stored objects.",
        "remediation": "Restrict public access and review bucket policies.",
        "references": [],
        "fingerprint": fingerprint,
        "suppressed": suppressed,
        "suppression_reason": "Approved exception CS-42" if suppressed else None,
    }


def report(*findings, status="ok", files_scanned=1, errors=None):
    return {
        "scanner_version": "0.1.0",
        "status": status,
        "files_scanned": files_scanned,
        "findings": list(findings),
        "errors": errors or [],
        "warnings": [],
        "risk_score": 100,  # Deliberately untrusted; the platform recomputes it.
        "severity_counts": {"critical": 99},
    }


def test_analyst_can_ingest_findings_and_platform_records_observation_and_audit(scan_client):
    client, factory, _, org_a, _, project_a, _, env_a, _, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={
            "target": "payments-service",
            "environment_id": str(env_a),
            "source_revision": "a1b2c3d4",
            "result": report(finding_payload()),
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["findings_created"] == 1
    assert body["findings_updated"] == 0
    assert body["findings_observed"] == 1

    with factory() as session:
        scan = session.get(Scan, UUID(body["scan_id"]))
        findings = session.scalars(select(Finding)).all()
        observations = session.scalars(select(ScanFinding)).all()
        events = session.scalars(select(AuditEvent)).all()
        assert scan.status == ScanStatus.COMPLETED
        assert scan.summary["risk_score"] == 7
        assert scan.summary["severity_counts"] == {
            "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0,
        }
        assert scan.summary["ingestion_provenance"] == "client_supplied_report_unverified"
        assert scan.summary["timestamp_semantics"] == "platform_ingestion_time_only"
        assert len(findings) == len(observations) == len(events) == 1
        assert findings[0].description == "A storage resource may be publicly accessible."
        assert findings[0].category == "terraform"
        assert findings[0].confidence == "high"
        assert findings[0].impact == "Untrusted parties may access stored objects."
        assert findings[0].reference_urls == []
        assert scan.diagnostics == {"errors": [], "warnings": []}
        assert events[0].action == "scan.result_ingested"


def test_rescan_updates_stable_finding_and_reopens_a_resolved_issue(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    first = client.post(url, json={"target": "repo", "result": report(finding_payload())})
    assert first.status_code == 201
    with factory() as session:
        finding = session.scalar(select(Finding))
        finding.status = FindingStatus.RESOLVED
        finding.resolved_at = datetime.now(timezone.utc)
        session.commit()

    second = client.post(
        url,
        json={"target": "repo", "result": report(finding_payload(title="Updated title"))},
    )
    assert second.status_code == 201
    assert second.json()["findings_created"] == 0
    assert second.json()["findings_updated"] == 1
    with factory() as session:
        finding = session.scalar(select(Finding))
        assert finding.title == "Updated title"
        assert finding.status == FindingStatus.OPEN
        assert finding.resolved_at is None
        assert len(session.scalars(select(ScanFinding)).all()) == 2


def test_accepted_risk_is_not_overwritten_by_a_rescan(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    assert client.post(url, json={"target": "repo", "result": report(finding_payload())}).status_code == 201
    with factory() as session:
        finding = session.scalar(select(Finding))
        finding.status = FindingStatus.ACCEPTED_RISK
        session.commit()
    response = client.post(url, json={"target": "repo", "result": report(finding_payload(title="Still present"))})
    assert response.status_code == 201
    with factory() as session:
        assert session.scalar(select(Finding)).status == FindingStatus.ACCEPTED_RISK


def test_suppression_reason_is_persisted_and_excluded_from_risk(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(finding_payload(suppressed=True))},
    )
    assert response.status_code == 201
    assert response.json()["suppressed_observed"] == 1
    with factory() as session:
        finding = session.scalar(select(Finding))
        scan = session.scalar(select(Scan))
        assert finding.suppressed is True
        assert finding.suppression_reason == "Approved exception CS-42"
        assert scan.summary["risk_score"] == 0
        assert scan.summary["active_findings"] == 0


def test_partial_scan_is_retained_without_resolving_absent_findings(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    assert client.post(url, json={"target": "repo", "result": report(finding_payload())}).status_code == 201
    with factory() as session:
        finding = session.scalar(select(Finding))
        finding.status = FindingStatus.IN_PROGRESS
        session.commit()
    partial = report(
        status="partial",
        files_scanned=1,
        errors=[{"file_path": "infra/broken.tf", "kind": "parse", "message": "Invalid HCL"}],
    )
    response = client.post(url, json={"target": "repo", "result": partial})
    assert response.status_code == 201
    assert response.json()["status"] == "partial"
    with factory() as session:
        assert session.scalar(select(Finding)).status == FindingStatus.IN_PROGRESS
        assert session.scalar(select(Scan).where(Scan.status == ScanStatus.PARTIAL)) is not None


def test_failed_scan_is_recorded_but_does_not_update_findings(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    assert client.post(url, json={"target": "repo", "result": report(finding_payload())}).status_code == 201
    with factory() as session:
        finding = session.scalar(select(Finding))
        previous_seen = finding.last_seen_at
    failed = report(
        status="error",
        files_scanned=0,
        errors=[{"file_path": "repo", "kind": "discovery", "message": "No supported files"}],
    )
    response = client.post(url, json={"target": "repo", "result": failed})
    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json()["findings_updated"] == 0
    with factory() as session:
        assert session.scalar(select(Finding)).last_seen_at == previous_seen
        assert session.scalar(select(Scan).where(Scan.status == ScanStatus.FAILED)) is not None


def test_other_tenant_project_is_not_disclosed(scan_client):
    client, _, _, org_a, _, _, project_b, _, _, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_b),
        json={"target": "repo", "result": report()},
    )
    assert response.status_code == 404


def test_viewer_cannot_ingest_scan_results(scan_client):
    client, _, active, org_a, _, project_a, _, _, _, viewer_id = scan_client
    active["value"] = viewer_id
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report()},
    )
    assert response.status_code == 403


def test_environment_must_belong_to_the_same_project_and_tenant(scan_client):
    client, _, _, org_a, _, project_a, _, _, env_b, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "environment_id": str(env_b), "result": report()},
    )
    assert response.status_code == 404


@pytest.mark.parametrize("path", ["/etc/passwd", "../secrets.tf", "C:/private/main.tf", "."])
def test_absolute_and_traversal_paths_are_rejected(scan_client, path):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    item = finding_payload()
    item["file_path"] = path
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(item)},
    )
    assert response.status_code == 422


def test_duplicate_fingerprints_are_rejected(scan_client):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(finding_payload(), finding_payload())},
    )
    assert response.status_code == 422


def test_invalid_line_range_is_rejected(scan_client):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    item = finding_payload()
    item["line_start"] = 20
    item["line_end"] = 10
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(item)},
    )
    assert response.status_code == 422


def test_scan_history_is_scoped_and_paginated(scan_client):
    client, _, _, org_a, org_b, project_a, project_b, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    created = client.post(url, json={"target": "repo", "result": report(finding_payload())})
    assert created.status_code == 201
    scan_id = created.json()["scan_id"]
    listing = client.get(url.rsplit("/scans/ingest", 1)[0] + "/scans?limit=1")
    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert listing.json()[0]["id"] == scan_id
    detail = client.get(url.rsplit("/scans/ingest", 1)[0] + f"/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["summary"]["ingestion_provenance"] == "client_supplied_report_unverified"
    foreign = client.get(
        f"/api/v1/organizations/{org_b}/projects/{project_b}/scans/{scan_id}"
    )
    assert foreign.status_code == 404


def test_suppressed_findings_are_hidden_by_default_but_auditable(scan_client):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    url = scan_endpoint(org_a, project_a)
    created = client.post(
        url,
        json={"target": "repo", "result": report(finding_payload(suppressed=True))},
    )
    assert created.status_code == 201
    base = f"/api/v1/organizations/{org_a}/projects/{project_a}/findings"
    default_view = client.get(base)
    audit_view = client.get(base, params={"include_suppressed": "true"})
    assert default_view.status_code == 200
    assert default_view.json() == []
    assert audit_view.status_code == 200
    assert len(audit_view.json()) == 1
    assert audit_view.json()[0]["suppression_reason"] == "Approved exception CS-42"



def test_partial_scan_diagnostics_are_preserved(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    partial = report(
        status="partial",
        files_scanned=1,
        errors=[{"file_path": "infra/broken.tf", "kind": "parse", "message": "Invalid HCL syntax"}],
    )
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": partial},
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    detail = client.get(
        f"/api/v1/organizations/{org_a}/projects/{project_a}/scans/{scan_id}"
    )
    assert detail.status_code == 200
    assert detail.json()["diagnostics"]["errors"][0]["file_path"] == "infra/broken.tf"


def test_negative_finding_line_numbers_are_rejected(scan_client):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    item = finding_payload()
    item["line_start"] = -1
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(item)},
    )
    assert response.status_code == 422


def test_oversized_declared_ingestion_body_is_rejected(scan_client):
    client, _, _, org_a, _, project_a, _, _, _, _ = scan_client
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report()},
        headers={"Content-Length": str(32 * 1024 * 1024 + 1)},
    )
    assert response.status_code == 413


def test_dot_prefixed_relative_paths_are_normalized(scan_client):
    client, factory, _, org_a, _, project_a, _, _, _, _ = scan_client
    item = finding_payload()
    item["file_path"] = "./infra/./main.tf"
    response = client.post(
        scan_endpoint(org_a, project_a),
        json={"target": "repo", "result": report(item)},
    )
    assert response.status_code == 201
    with factory() as session:
        assert session.scalar(select(Finding)).file_path == "infra/main.tf"
