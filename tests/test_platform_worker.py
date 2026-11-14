from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from scanner.platform.models import Base, Organization, Project, ScanJob, ScanStatus
from scanner.platform.worker import (
    claim_next_job,
    complete_job,
    fail_job,
    renew_job_lease,
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        organization = Organization(name="Acme", slug="acme")
        session.add(organization)
        session.flush()
        project = Project(
            organization_id=organization.id,
            name="Payments",
            slug="payments",
        )
        session.add(project)
        session.commit()
        yield session, organization.id, project.id
    engine.dispose()


def add_job(session, organization_id, project_id, *, status=ScanStatus.QUEUED,
            attempts=0, max_attempts=3, available_at=None, lease_owner=None,
            lease_expires_at=None):
    job = ScanJob(
        organization_id=organization_id,
        project_id=project_id,
        source_revision="a" * 40,
        ref="refs/heads/main",
        dedupe_key=str(uuid4()),
        status=status,
        attempts=attempts,
        max_attempts=max_attempts,
        available_at=available_at or datetime.now(timezone.utc) - timedelta(seconds=1),
        lease_owner=lease_owner,
        lease_expires_at=lease_expires_at,
    )
    session.add(job)
    session.commit()
    return job


def test_claim_sets_owner_and_bounded_lease(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id)
    claimed = claim_next_job(session, "worker-a", lease_seconds=60, now=now)
    assert claimed.id == job.id
    assert claimed.status == ScanStatus.RUNNING
    assert claimed.attempts == 1
    assert claimed.lease_owner == "worker-a"
    assert claimed.lease_expires_at == now + timedelta(seconds=60)
    session.commit()


def test_claim_ignores_future_jobs_and_returns_none(db):
    session, org_id, project_id = db
    add_job(session, org_id, project_id, available_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert claim_next_job(session, "worker-a") is None


def test_expired_lease_is_reclaimed_and_attempt_count_increments(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(
        session, org_id, project_id,
        status=ScanStatus.RUNNING, attempts=1,
        lease_owner="dead-worker", lease_expires_at=now - timedelta(seconds=1),
    )
    claimed = claim_next_job(session, "worker-b", now=now)
    assert claimed.id == job.id
    assert claimed.attempts == 2
    assert claimed.lease_owner == "worker-b"


def test_exhausted_expired_lease_becomes_failed(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(
        session, org_id, project_id,
        status=ScanStatus.RUNNING, attempts=3, max_attempts=3,
        lease_owner="dead-worker", lease_expires_at=now - timedelta(seconds=1),
    )
    assert claim_next_job(session, "worker-b", now=now) is None
    session.refresh(job)
    assert job.status == ScanStatus.FAILED
    assert job.lease_owner is None
    assert job.finished_at.replace(tzinfo=timezone.utc) == now


def test_only_current_worker_can_renew_or_complete(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id)
    claim_next_job(session, "worker-a", now=now)
    assert not renew_job_lease(session, job.id, "worker-b", now=now)
    assert not complete_job(session, job.id, "worker-b", now=now)
    assert renew_job_lease(session, job.id, "worker-a", now=now)
    assert complete_job(session, job.id, "worker-a", now=now)
    session.refresh(job)
    assert job.status == ScanStatus.COMPLETED
    assert job.lease_owner is None


def test_expired_worker_cannot_complete_job(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id)
    claim_next_job(session, "worker-a", now=now)
    assert not complete_job(session, job.id, "worker-a", now=now + timedelta(minutes=6))


def test_failure_requeues_with_backoff_then_fails_at_attempt_limit(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id, max_attempts=2)
    claim_next_job(session, "worker-a", now=now)
    assert fail_job(session, job.id, "worker-a", "temporary checkout failure", now=now)
    session.refresh(job)
    assert job.status == ScanStatus.QUEUED
    assert job.available_at.replace(tzinfo=timezone.utc) == now + timedelta(seconds=30)
    assert job.lease_owner is None

    claim_next_job(session, "worker-b", now=now + timedelta(seconds=31))
    assert fail_job(session, job.id, "worker-b", "second attempt failed", now=now + timedelta(seconds=31))
    session.refresh(job)
    assert job.status == ScanStatus.FAILED
    assert job.finished_at.replace(tzinfo=timezone.utc) == now + timedelta(seconds=31)


@pytest.mark.parametrize("lease_seconds", [0, 29, 3601, True])
def test_invalid_lease_duration_is_rejected(db, lease_seconds):
    session, _, _ = db
    with pytest.raises(ValueError):
        claim_next_job(session, "worker-a", lease_seconds=lease_seconds)


def test_naive_timestamps_are_rejected(db):
    session, _, _ = db
    with pytest.raises(ValueError):
        claim_next_job(session, "worker-a", now=datetime(2026, 1, 1))


def test_running_job_without_lease_expiry_is_recoverable(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(
        session, org_id, project_id,
        status=ScanStatus.RUNNING, attempts=1,
        lease_owner="worker-with-broken-lease", lease_expires_at=None,
    )
    claimed = claim_next_job(session, "worker-recovery", now=now)
    assert claimed.id == job.id
    assert claimed.lease_owner == "worker-recovery"
    assert claimed.attempts == 2


@pytest.mark.parametrize("worker_id", ["", " worker ", "worker\nname", "x" * 129])
def test_worker_identity_must_be_printable_and_bounded(db, worker_id):
    session, _, _ = db
    with pytest.raises(ValueError):
        claim_next_job(session, worker_id)


def test_job_operations_reject_non_uuid_identifiers(db):
    session, _, _ = db
    with pytest.raises(ValueError):
        complete_job(session, "not-a-uuid", "worker-a")


def test_retry_delay_is_validated_even_when_no_retries_remain(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id, max_attempts=1)
    claim_next_job(session, "worker-a", now=now)
    with pytest.raises(ValueError):
        fail_job(
            session, job.id, "worker-a", "failed",
            retry_delay_seconds=-1, now=now,
        )
    session.refresh(job)
    assert job.status == ScanStatus.RUNNING


def test_failure_summary_is_single_line_and_bounded(db):
    session, org_id, project_id = db
    now = datetime.now(timezone.utc)
    job = add_job(session, org_id, project_id)
    claim_next_job(session, "worker-a", now=now)
    assert fail_job(session, job.id, "worker-a", "checkout\nfailed", now=now)
    session.refresh(job)
    assert job.error_summary == "checkout failed"
