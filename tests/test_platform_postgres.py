"""PostgreSQL integration checks for database-enforced tenant boundaries."""
from datetime import datetime, timezone
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.platform.models import (
    AuditEvent,
    Environment,
    Finding,
    Membership,
    MembershipRole,
    Organization,
    Project,
    Scan,
    ScanFinding,
    ScanStatus,
    User,
)


DATABASE_URL = os.getenv("CLOUDSENTRY_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="CLOUDSENTRY_DATABASE_URL is required for PostgreSQL integration tests",
)


def test_postgres_rejects_cross_tenant_relationships():
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    organization_a = Organization(id=uuid4(), name="Tenant A", slug=f"pg-a-{uuid4().hex}")
    organization_b = Organization(id=uuid4(), name="Tenant B", slug=f"pg-b-{uuid4().hex}")
    user_a = User(
        id=uuid4(), email=f"a-{uuid4().hex}@example.test",
        identity_provider="https://issuer.example.test/", identity_subject=f"a-{uuid4()}",
    )
    user_b = User(
        id=uuid4(), email=f"b-{uuid4().hex}@example.test",
        identity_provider="https://issuer.example.test/", identity_subject=f"b-{uuid4()}",
    )
    project_a = Project(
        id=uuid4(), organization_id=organization_a.id, name="Project A", slug=f"a-{uuid4().hex}",
    )
    project_b = Project(
        id=uuid4(), organization_id=organization_b.id, name="Project B", slug=f"b-{uuid4().hex}",
    )
    now = datetime.now(timezone.utc)

    try:
        with Session(engine) as session:
            session.add_all([organization_a, organization_b, user_a, user_b])
            session.flush()
            session.add_all([
                Membership(
                    organization_id=organization_a.id,
                    user_id=user_a.id,
                    role=MembershipRole.OWNER,
                ),
                project_a,
                project_b,
            ])
            session.flush()
            environment_a = Environment(
                id=uuid4(), organization_id=organization_a.id,
                project_id=project_a.id, name="production", is_production=True,
            )
            session.add(environment_a)
            scan_a = Scan(
                id=uuid4(), organization_id=organization_a.id, project_id=project_a.id,
                environment_id=environment_a.id, status=ScanStatus.COMPLETED,
                target="tenant-a", scanner_version="0.1.0", summary={}, diagnostics={},
                started_at=now, completed_at=now,
            )
            finding_b = Finding(
                id=uuid4(), organization_id=organization_b.id, project_id=project_b.id,
                fingerprint=uuid4().hex, rule_id="CS-TEST-001", title="Test finding",
                severity="high", file_path="infra/main.tf", evidence="test evidence",
                remediation="test remediation",
            )
            session.add_all([scan_a, finding_b])
            session.commit()

        def must_reject(record):
            with Session(engine) as session:
                session.add(record)
                with pytest.raises(IntegrityError):
                    session.flush()
                session.rollback()

        must_reject(Environment(
            id=uuid4(), organization_id=organization_a.id,
            project_id=project_b.id, name="cross-tenant", is_production=False,
        ))
        must_reject(Scan(
            id=uuid4(), organization_id=organization_a.id, project_id=project_b.id,
            status=ScanStatus.COMPLETED, target="invalid", scanner_version="0.1.0",
            summary={}, diagnostics={}, started_at=now, completed_at=now,
        ))
        must_reject(Finding(
            id=uuid4(), organization_id=organization_a.id, project_id=project_b.id,
            fingerprint=uuid4().hex, rule_id="CS-TEST-002", title="Cross-tenant finding",
            severity="high", file_path="infra/main.tf", evidence="test evidence",
            remediation="test remediation",
        ))
        must_reject(Finding(
            id=uuid4(), organization_id=organization_a.id, project_id=project_a.id,
            fingerprint=uuid4().hex, rule_id="CS-TEST-003", title="Foreign assignee",
            severity="high", file_path="infra/main.tf", evidence="test evidence",
            remediation="test remediation", assigned_to_user_id=user_b.id,
        ))
        must_reject(AuditEvent(
            id=uuid4(), organization_id=organization_a.id, actor_user_id=user_b.id,
            action="test.invalid_actor", target_type="test", target_id=None, details={},
        ))
        must_reject(ScanFinding(
            id=uuid4(), organization_id=organization_a.id,
            scan_id=scan_a.id, finding_id=finding_b.id,
        ))
    finally:
        with Session(engine) as session:
            session.execute(
                Organization.__table__.delete().where(
                    Organization.id.in_([organization_a.id, organization_b.id])
                )
            )
            session.execute(
                User.__table__.delete().where(User.id.in_([user_a.id, user_b.id]))
            )
            session.commit()
        engine.dispose()
