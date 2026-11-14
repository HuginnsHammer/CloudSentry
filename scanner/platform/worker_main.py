"""Control-plane worker: fetch verified source, delegate isolated scanning, persist atomically."""
from __future__ import annotations

import argparse
import logging
import os
import re
import socket
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from scanner.api.scan_schemas import ScanIngestRequest
from scanner.platform.database import build_engine, build_session_factory
from scanner.platform.executor_client import ScanExecutorClient
from scanner.platform.github_app import GitHubAppClient
from scanner.platform.models import GitHubInstallation, Project, ScanJob, ScanStatus
from scanner.platform.scan_persistence import ScanPersistenceError, persist_scan_report
from scanner.platform.worker import claim_next_job, complete_job, fail_job


logger = logging.getLogger("cloudsentry.worker")
_SHA = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_LEASE_SECONDS = 900
MIN_POLL_SECONDS = 0.5
MAX_POLL_SECONDS = 60.0


class PermanentJobError(RuntimeError):
    """A job cannot succeed without changing its repository or project configuration."""


class LeaseLost(RuntimeError):
    """The worker no longer owns the job lease and must not publish a result."""


@dataclass(frozen=True)
class JobContext:
    organization_id: UUID
    project_id: UUID
    environment_id: UUID | None
    installation_id: int
    repository_id: int
    repository_full_name: str
    revision: str
    ref: str
    started_at: datetime


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _load_job_context(
    session_factory: sessionmaker,
    job_id: UUID,
    worker_id: str,
) -> JobContext:
    now = _utcnow()
    with session_factory() as session:
        job = session.get(ScanJob, job_id)
        if (
            job is None
            or job.status != ScanStatus.RUNNING
            or job.lease_owner != worker_id
            or job.lease_expires_at is None
            or job.lease_expires_at <= now
        ):
            raise LeaseLost("Worker no longer owns the scan job lease")
        project = session.scalar(
            select(Project).where(
                Project.id == job.project_id,
                Project.organization_id == job.organization_id,
            )
        )
        if (
            project is None
            or project.github_installation_id is None
            or project.github_repository_id is None
            or not project.github_repository_full_name
            or not project.github_default_branch
        ):
            raise PermanentJobError("Project has no verified GitHub repository binding")
        if job.ref != f"refs/heads/{project.github_default_branch}":
            raise PermanentJobError("Queued ref is no longer the project's configured default branch")
        if not _SHA.fullmatch(job.source_revision):
            raise PermanentJobError("Queued source revision is not a full commit SHA")
        installation = session.scalar(
            select(GitHubInstallation).where(
                GitHubInstallation.installation_id == project.github_installation_id,
                GitHubInstallation.organization_id == job.organization_id,
                GitHubInstallation.status == "active",
            )
        )
        if installation is None:
            raise PermanentJobError("GitHub App installation is no longer active for this organization")
        return JobContext(
            organization_id=job.organization_id,
            project_id=job.project_id,
            environment_id=job.environment_id,
            installation_id=project.github_installation_id,
            repository_id=project.github_repository_id,
            repository_full_name=project.github_repository_full_name,
            revision=job.source_revision,
            ref=job.ref,
            started_at=job.updated_at or job.started_at or job.created_at,
        )


def process_claimed_job(
    session_factory: sessionmaker,
    job_id: UUID,
    worker_id: str,
    github: GitHubAppClient,
    executor: ScanExecutorClient,
) -> bool:
    """Run one claimed job; scan publication and job completion share a transaction."""
    context = _load_job_context(session_factory, job_id, worker_id)
    archive = github.download_repository_archive(
        context.installation_id,
        context.repository_id,
        context.revision,
        expected_full_name=context.repository_full_name,
    )
    result = executor.scan(
        archive,
        revision=context.revision,
        target=context.repository_full_name,
    )
    try:
        validated = ScanIngestRequest.model_validate(
            {
                "target": context.repository_full_name,
                "source_revision": context.revision,
                "environment_id": context.environment_id,
                "result": result.model_dump(mode="json"),
            }
        )
    except ValueError:
        raise PermanentJobError("Isolated scanner report failed platform validation") from None

    completed_at = _utcnow()
    with session_factory() as session:
        project = session.scalar(
            select(Project)
            .where(
                Project.id == context.project_id,
                Project.organization_id == context.organization_id,
            )
            .with_for_update()
        )
        installation = session.scalar(
            select(GitHubInstallation)
            .where(
                GitHubInstallation.installation_id == context.installation_id,
                GitHubInstallation.organization_id == context.organization_id,
                GitHubInstallation.status == "active",
            )
            .with_for_update()
        )
        if (
            project is None
            or installation is None
            or project.github_installation_id != context.installation_id
            or project.github_repository_id != context.repository_id
            or project.github_repository_full_name != context.repository_full_name
            or project.github_default_branch is None
            or context.ref != f"refs/heads/{project.github_default_branch}"
        ):
            raise PermanentJobError("Repository binding or GitHub installation changed during the scan")
        if not complete_job(session, job_id, worker_id, now=completed_at):
            session.rollback()
            return False
        try:
            persisted = persist_scan_report(
                session,
                organization_id=context.organization_id,
                project_id=context.project_id,
                environment_id=context.environment_id,
                result=validated.result,
                target=context.repository_full_name,
                source_revision=context.revision,
                actor_user_id=None,
                provenance="server_managed_worker",
                timestamp_semantics="worker_execution_window",
                started_at=context.started_at,
                completed_at=completed_at,
                audit_action="scan.result_worker_ingested",
            )
        except ScanPersistenceError as exc:
            raise PermanentJobError("Persisted scan report violated platform constraints") from exc
        job = session.get(ScanJob, job_id)
        if job is None:
            raise RuntimeError("Claimed scan job disappeared during result persistence")
        job.scan_id = persisted.scan_id
        session.commit()
    return True


def _record_failure(
    session_factory: sessionmaker,
    job_id: UUID,
    worker_id: str,
    error: Exception,
) -> None:
    retryable = not isinstance(error, PermanentJobError)
    summary = f"{type(error).__name__}: scan job processing failed"
    with session_factory() as session:
        fail_job(
            session,
            job_id,
            worker_id,
            summary,
            retryable=retryable,
        )
        session.commit()


def run_once(
    session_factory: sessionmaker,
    worker_id: str,
    github: GitHubAppClient,
    executor: ScanExecutorClient,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> bool:
    """Claim and process at most one job. Returns whether a job was claimed."""
    with session_factory() as session:
        job = claim_next_job(session, worker_id, lease_seconds=lease_seconds)
        job_id = job.id if job is not None else None
        session.commit()
    if job_id is None:
        return False

    try:
        completed = process_claimed_job(session_factory, job_id, worker_id, github, executor)
        if completed:
            logger.info("scan job %s completed", job_id)
        else:
            logger.info("scan job %s lost its lease before publication", job_id)
    except LeaseLost:
        logger.info("scan job %s is no longer owned by this worker", job_id)
    except Exception as exc:
        try:
            _record_failure(session_factory, job_id, worker_id, exc)
        except Exception as record_error:
            logger.error(
                "scan job %s failed (%s); failure state could not be recorded (%s)",
                job_id,
                type(exc).__name__,
                type(record_error).__name__,
            )
        else:
            logger.error("scan job %s failed (%s)", job_id, type(exc).__name__)
    return True


def _worker_id() -> str:
    configured = os.getenv("CLOUDSENTRY_WORKER_ID")
    return configured or f"{socket.gethostname()}-{uuid4().hex[:12]}"


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudSentry isolated scan worker")
    parser.add_argument("--once", action="store_true", help="claim and process at most one job")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("CLOUDSENTRY_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    poll_seconds = float(os.getenv("CLOUDSENTRY_WORKER_POLL_SECONDS", "2"))
    lease_seconds = int(os.getenv("CLOUDSENTRY_WORKER_LEASE_SECONDS", str(DEFAULT_LEASE_SECONDS)))
    if not MIN_POLL_SECONDS <= poll_seconds <= MAX_POLL_SECONDS:
        raise SystemExit("CLOUDSENTRY_WORKER_POLL_SECONDS must be between 0.5 and 60")
    if not 120 <= lease_seconds <= 3600:
        raise SystemExit("CLOUDSENTRY_WORKER_LEASE_SECONDS must be between 120 and 3600")

    engine = build_engine()
    session_factory = build_session_factory(engine)
    github = GitHubAppClient.from_environment()
    # Fail at startup rather than accepting jobs with an unusable App key.
    github._app_jwt()
    executor = ScanExecutorClient.from_environment()
    worker_id = _worker_id()
    logger.info("worker %s started", worker_id)

    def _stop_worker(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop_worker)
    try:
        while True:
            claimed = run_once(
                session_factory,
                worker_id,
                github,
                executor,
                lease_seconds=lease_seconds,
            )
            if args.once:
                break
            if not claimed:
                time.sleep(poll_seconds)
    except KeyboardInterrupt:
        logger.info("worker %s stopping", worker_id)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
