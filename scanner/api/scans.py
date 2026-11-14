"""Tenant-scoped ingestion of completed scanner results.

This API persists reports; it does not clone repositories, execute files, or run scans.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.scan_schemas import ScanIngestRequest, ScanIngestResponse, ScanJobResponse, ScanResponse
from scanner.platform.dependencies import get_current_user, get_db_session, require_membership
from scanner.platform.scan_persistence import ScanPersistenceError, persist_scan_report
from scanner.platform.models import (
    Membership,
    MembershipRole,
    Project,
    Scan,
    ScanJob,
    User,
)

router = APIRouter(tags=["scans"])
INGEST_ROLES = {
    MembershipRole.OWNER,
    MembershipRole.ADMIN,
    MembershipRole.SECURITY_ANALYST,
}


@router.post(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/scans/ingest",
    response_model=ScanIngestResponse,
    status_code=201,
)
def ingest_scan_result(
    organization_id: UUID,
    project_id: UUID,
    payload: ScanIngestRequest,
    membership: Membership = Depends(require_membership),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> ScanIngestResponse:
    """Persist a bounded client report and stable finding observations atomically."""
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    if membership.role not in INGEST_ROLES:
        raise HTTPException(status_code=403, detail="Your role cannot ingest scan results")

    try:
        response = persist_scan_report(
            session,
            organization_id=organization_id,
            project_id=project_id,
            environment_id=payload.environment_id,
            result=payload.result,
            target=payload.target,
            source_revision=payload.source_revision,
            actor_user_id=user.id,
            provenance="client_supplied_report_unverified",
            timestamp_semantics="platform_ingestion_time_only",
            audit_action="scan.result_ingested",
        )
        session.commit()
    except ScanPersistenceError as exc:
        session.rollback()
        if str(exc) in {"project_not_found", "environment_not_found"}:
            raise HTTPException(status_code=404, detail=str(exc).replace("_", " ").title()) from None
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception:
        session.rollback()
        raise
    return response



@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/scans",
    response_model=list[ScanResponse],
)
def list_project_scans(
    organization_id: UUID,
    project_id: UUID,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> list[Scan]:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    statement = (
        select(Scan)
        .where(Scan.organization_id == organization_id, Scan.project_id == project_id)
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(session.scalars(statement).all())


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/scans/{scan_id}",
    response_model=ScanResponse,
)
def get_project_scan(
    organization_id: UUID,
    project_id: UUID,
    scan_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> Scan:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = session.scalar(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == organization_id,
            Scan.project_id == project_id,
        )
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan



@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/scan-jobs",
    response_model=list[ScanJobResponse],
)
def list_project_scan_jobs(
    organization_id: UUID,
    project_id: UUID,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> list[ScanJob]:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    statement = (
        select(ScanJob)
        .where(ScanJob.organization_id == organization_id, ScanJob.project_id == project_id)
        .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(session.scalars(statement).all())


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/scan-jobs/{job_id}",
    response_model=ScanJobResponse,
)
def get_project_scan_job(
    organization_id: UUID,
    project_id: UUID,
    job_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> ScanJob:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Scan job not found")
    job = session.scalar(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.organization_id == organization_id,
            ScanJob.project_id == project_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job
