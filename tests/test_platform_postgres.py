"""PostgreSQL integration checks for database-enforced tenant boundaries."""
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.platform.worker import claim_next_job

from scanner.platform.models import (
    AuditEvent,
    Environment,
    Finding,
    GitHubInstallation,
    Membership,
    MembershipRole,
    Organization,
    Project,
    Scan,
    ScanFinding,
    ScanJob,
    ScanStatus,
    User,
)
from scanner.platform.worker import claim_next_job


DATABASE_URL = os.getenv("CLOUDSENTRY_DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
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
    installation_id = uuid4().int % 9000000000 + 1

    try:
        with Session(engine, expire_on_commit=False) as session:
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
            installation_a = GitHubInstallation(
                id=uuid4(), organization_id=organization_a.id,
                installation_id=installation_id,
                account_id=uuid4().int % 9000000000 + 1,
                account_login="tenant-a-app", account_type="Organization", status="active",
            )
            session.add(installation_a)
            session.flush()
            project_a.github_installation_id = installation_a.installation_id
            project_a.github_repository_id = uuid4().int % 9000000000 + 1
            project_a.github_repository_full_name = "tenant-a/repository"
            project_a.github_default_branch = "main"
            valid_job = ScanJob(
                id=uuid4(), organization_id=organization_a.id, project_id=project_a.id,
                source_revision="a" * 40, ref="refs/heads/main",
                dedupe_key=uuid4().hex + uuid4().hex, status=ScanStatus.QUEUED,
                attempts=0, max_attempts=3,
            )
            second_job = ScanJob(
                id=uuid4(), organization_id=organization_a.id, project_id=project_a.id,
                source_revision="b" * 40, ref="refs/heads/main",
                dedupe_key=uuid4().hex + uuid4().hex, status=ScanStatus.QUEUED,
                attempts=0, max_attempts=3, available_at=now,
            )
            session.add_all([scan_a, finding_b, valid_job, second_job])
            session.commit()

        # Hold worker A's row lock while worker B claims. PostgreSQL SKIP LOCKED
        # must hand B a different job rather than blocking or double-claiming.
        claim_time = now + timedelta(seconds=10)
        with Session(engine, expire_on_commit=False) as worker_a:
            first_claim = claim_next_job(worker_a, "pg-worker-a", now=claim_time)
            assert first_claim is not None
            with Session(engine, expire_on_commit=False) as worker_b:
                second_claim = claim_next_job(worker_b, "pg-worker-b", now=claim_time)
                assert second_claim is not None
                assert first_claim.id != second_claim.id
                worker_b.commit()
            worker_a.commit()

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
        must_reject(ScanJob(
            id=uuid4(), organization_id=organization_a.id, project_id=project_b.id,
            source_revision="b" * 40, ref="refs/heads/main",
            dedupe_key=uuid4().hex + uuid4().hex, status=ScanStatus.QUEUED,
            attempts=0, max_attempts=3,
        ))
        with Session(engine) as session:
            cross_tenant_project = session.get(Project, project_b.id)
            cross_tenant_project.github_installation_id = installation_id
            with pytest.raises(IntegrityError):
                session.flush()
            session.rollback()
    finally:
        with Session(engine, expire_on_commit=False) as session:
            session.execute(
                Organization.__table__.delete().where(
                    Organization.id.in_([organization_a.id, organization_b.id])
                )
            )
            session.execute(
                GitHubInstallation.__table__.delete().where(
                    GitHubInstallation.installation_id == installation_id
                )
            )
            session.execute(
                User.__table__.delete().where(User.id.in_([user_a.id, user_b.id]))
            )
            session.commit()
        engine.dispose()



def test_postgres_workers_skip_locked_jobs_without_double_claiming():
    """A locked first job is skipped so a second worker can claim another job."""
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    organization = Organization(name="Queue tenant", slug=f"queue-{uuid4().hex}")
    project = Project(
        id=uuid4(), organization_id=organization.id,
        name="Queue project", slug=f"queue-{uuid4().hex}",
    )
    now = datetime.now(timezone.utc)
    try:
        with Session(engine) as setup:
            setup.add(organization)
            setup.flush()
            setup.add(project)
            setup.flush()
            jobs = [
                ScanJob(
                    organization_id=organization.id,
                    project_id=project.id,
                    source_revision=f"{index:040x}",
                    ref="refs/heads/main",
                    dedupe_key=uuid4().hex + uuid4().hex,
                    status=ScanStatus.QUEUED,
                    attempts=0,
                    max_attempts=3,
                    available_at=now,
                )
                for index in range(2)
            ]
            setup.add_all(jobs)
            setup.commit()

        first_session = Session(engine)
        second_session = Session(engine)
        try:
            first_claim = claim_next_job(first_session, "postgres-worker-a", now=now)
            assert first_claim is not None

            # The first transaction deliberately remains open and holds the
            # selected row lock. PostgreSQL SKIP LOCKED must return the other job.
            second_claim = claim_next_job(second_session, "postgres-worker-b", now=now)
            assert second_claim is not None
            assert second_claim.id != first_claim.id
            assert first_claim.lease_owner == "postgres-worker-a"
            assert second_claim.lease_owner == "postgres-worker-b"
            first_session.commit()
            second_session.commit()
        finally:
            first_session.close()
            second_session.close()

        with Session(engine) as verify:
            claimed = verify.query(ScanJob).filter(
                ScanJob.organization_id == organization.id,
                ScanJob.status == ScanStatus.RUNNING,
            ).all()
            assert len(claimed) == 2
            assert {job.lease_owner for job in claimed} == {
                "postgres-worker-a", "postgres-worker-b",
            }
    finally:
        with Session(engine) as cleanup:
            cleanup.execute(
                Organization.__table__.delete().where(Organization.id == organization.id)
            )
            cleanup.commit()
        engine.dispose()
