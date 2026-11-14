"""Transactional lease operations for durable platform scan jobs.

The worker process is deliberately separate from the authenticated API. These
functions only manage queue ownership; they do not fetch repositories or execute
untrusted source. Callers own the SQLAlchemy transaction and must commit.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from scanner.platform.models import ScanJob, ScanStatus

MIN_LEASE_SECONDS = 30
MAX_LEASE_SECONDS = 3600
MAX_RETRY_DELAY_SECONDS = 3600
MAX_ERROR_SUMMARY_LENGTH = 500


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _validate_worker(worker_id: str) -> None:
    if (
        not isinstance(worker_id, str)
        or not worker_id
        or worker_id != worker_id.strip()
        or len(worker_id) > 128
        or any(ord(char) < 32 or ord(char) == 127 for char in worker_id)
    ):
        raise ValueError("worker_id must be 1-128 printable characters without surrounding whitespace")


def _validate_job_id(job_id: UUID) -> None:
    if not isinstance(job_id, UUID):
        raise ValueError("job_id must be a UUID")


def _validate_time(instant: datetime) -> None:
    if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("now must be timezone-aware")


def _validate_lease(lease_seconds: int) -> None:
    if type(lease_seconds) is not int or not MIN_LEASE_SECONDS <= lease_seconds <= MAX_LEASE_SECONDS:
        raise ValueError(
            f"lease_seconds must be an integer between {MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS}"
        )


def claim_next_job(
    session: Session,
    worker_id: str,
    *,
    lease_seconds: int = 300,
    now: datetime | None = None,
) -> ScanJob | None:
    """Atomically claim the oldest available job, reclaiming expired leases.

    PostgreSQL workers use FOR UPDATE SKIP LOCKED so concurrent workers cannot
    claim the same row. The transaction must be committed before doing work.
    """
    _validate_worker(worker_id)
    _validate_lease(lease_seconds)
    instant = now or _utcnow()
    _validate_time(instant)

    # Expired jobs that have exhausted their retry budget must not remain stuck
    # in RUNNING forever.
    session.execute(
        update(ScanJob)
        .where(
            ScanJob.status == ScanStatus.RUNNING,
            or_(ScanJob.lease_expires_at.is_(None), ScanJob.lease_expires_at <= instant),
            ScanJob.attempts >= ScanJob.max_attempts,
        )
        .values(
            status=ScanStatus.FAILED,
            lease_owner=None,
            lease_expires_at=None,
            finished_at=instant,
            error_summary="Worker lease expired after the maximum number of attempts",
            updated_at=instant,
        )
    )
    candidate = session.scalar(
        select(ScanJob)
        .where(
            ScanJob.attempts < ScanJob.max_attempts,
            or_(
                (ScanJob.status == ScanStatus.QUEUED) & (ScanJob.available_at <= instant),
                (ScanJob.status == ScanStatus.RUNNING)
                & or_(ScanJob.lease_expires_at.is_(None), ScanJob.lease_expires_at <= instant),
            ),
        )
        .order_by(ScanJob.available_at, ScanJob.created_at, ScanJob.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if candidate is None:
        return None

    candidate.status = ScanStatus.RUNNING
    candidate.attempts += 1
    candidate.lease_owner = worker_id
    candidate.lease_expires_at = instant + timedelta(seconds=lease_seconds)
    candidate.started_at = candidate.started_at or instant
    candidate.finished_at = None
    candidate.error_summary = None
    candidate.updated_at = instant
    session.flush()
    return candidate


def renew_job_lease(
    session: Session,
    job_id: UUID,
    worker_id: str,
    *,
    lease_seconds: int = 300,
    now: datetime | None = None,
) -> bool:
    """Extend a still-valid lease held by this worker; never resurrect an expired lease."""
    _validate_worker(worker_id)
    _validate_job_id(job_id)
    _validate_lease(lease_seconds)
    instant = now or _utcnow()
    _validate_time(instant)
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == ScanStatus.RUNNING,
            ScanJob.lease_owner == worker_id,
            ScanJob.lease_expires_at > instant,
        )
        .values(lease_expires_at=instant + timedelta(seconds=lease_seconds), updated_at=instant)
    )
    return result.rowcount == 1


def complete_job(
    session: Session,
    job_id: UUID,
    worker_id: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Complete a job only while the caller still owns a non-expired lease."""
    _validate_worker(worker_id)
    _validate_job_id(job_id)
    instant = now or _utcnow()
    _validate_time(instant)
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == ScanStatus.RUNNING,
            ScanJob.lease_owner == worker_id,
            ScanJob.lease_expires_at > instant,
        )
        .values(
            status=ScanStatus.COMPLETED,
            lease_owner=None,
            lease_expires_at=None,
            finished_at=instant,
            error_summary=None,
            updated_at=instant,
        )
    )
    return result.rowcount == 1


def fail_job(
    session: Session,
    job_id: UUID,
    worker_id: str,
    error_summary: str,
    *,
    retry_delay_seconds: int | None = None,
    now: datetime | None = None,
) -> bool:
    """Release a worker-owned job for bounded retry, or fail it permanently.

    Error summaries are bounded and intended for operator diagnosis. Callers
    must not pass credentials, tokens, source contents, or stack traces.
    """
    _validate_worker(worker_id)
    _validate_job_id(job_id)
    instant = now or _utcnow()
    _validate_time(instant)
    if not isinstance(error_summary, str) or not error_summary.strip():
        raise ValueError("error_summary must be non-empty")
    if retry_delay_seconds is not None and (
        type(retry_delay_seconds) is not int
        or not 0 <= retry_delay_seconds <= MAX_RETRY_DELAY_SECONDS
    ):
        raise ValueError(f"retry_delay_seconds must be between 0 and {MAX_RETRY_DELAY_SECONDS}")
    summary = " ".join(error_summary.split())[:MAX_ERROR_SUMMARY_LENGTH]
    job = session.scalar(
        select(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.status == ScanStatus.RUNNING,
            ScanJob.lease_owner == worker_id,
            ScanJob.lease_expires_at > instant,
        )
        .with_for_update()
    )
    if job is None:
        return False

    if job.attempts >= job.max_attempts:
        job.status = ScanStatus.FAILED
        job.finished_at = instant
    else:
        if retry_delay_seconds is None:
            delay = min(30 * (2 ** max(job.attempts - 1, 0)), MAX_RETRY_DELAY_SECONDS)
        else:
            delay = retry_delay_seconds
        job.status = ScanStatus.QUEUED
        job.available_at = instant + timedelta(seconds=delay)
        job.finished_at = None

    job.lease_owner = None
    job.lease_expires_at = None
    job.error_summary = summary
    job.updated_at = instant
    session.flush()
    return True
