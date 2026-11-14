"""Tenant-scoped ingestion of completed scanner results.

This API persists reports; it does not clone repositories, execute files, or run scans.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.scan_schemas import ScanIngestRequest, ScanIngestResponse, ScanJobResponse, ScanResponse
from scanner.platform.dependencies import get_current_user, get_db_session, require_membership
from scanner.scoring import summarize
from scanner.platform.models import (
    AuditEvent,
    Environment,
    Finding,
    FindingStatus,
    Membership,
    MembershipRole,
    Project,
    Scan,
    ScanFinding,
    ScanJob,
    ScanStatus,
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
    """Persist a bounded scanner report and stable finding observations atomically."""
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    if membership.role not in INGEST_ROLES:
        raise HTTPException(status_code=403, detail="Your role cannot ingest scan results")

    # Lock the tenant-owned project row to serialize concurrent fingerprint upserts.
    project = session.scalar(
        select(Project)
        .where(Project.id == project_id, Project.organization_id == organization_id)
        .with_for_update()
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if payload.environment_id is not None:
        environment = session.scalar(
            select(Environment).where(
                Environment.id == payload.environment_id,
                Environment.organization_id == organization_id,
                Environment.project_id == project_id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="Environment not found")

    result = payload.result
    status_map = {
        "ok": ScanStatus.COMPLETED,
        "partial": ScanStatus.PARTIAL,
        "error": ScanStatus.FAILED,
    }
    now = datetime.now(timezone.utc)
    verified_risk_score, verified_severity_counts = summarize(result.findings)
    summary = {
        "files_scanned": result.files_scanned,
        "findings_total": len(result.findings),
        "active_findings": sum(not item.suppressed for item in result.findings),
        "suppressed_findings": sum(item.suppressed for item in result.findings),
        "errors_count": len(result.errors),
        "warnings_count": len(result.warnings),
        # Recompute from ingested findings; never trust a client-supplied aggregate.
        "risk_score": verified_risk_score,
        "severity_counts": verified_severity_counts,
        "source_revision": payload.source_revision,
        "ingestion_provenance": "client_supplied_report_unverified",
        "timestamp_semantics": "platform_ingestion_time_only",
    }
    scan = Scan(
        organization_id=organization_id,
        project_id=project_id,
        environment_id=payload.environment_id,
        status=status_map[result.status],
        target=payload.target,
        scanner_version=result.scanner_version,
        summary=summary,
        diagnostics={
            "errors": [
                {**item.model_dump(mode="json"), "file_path": PurePosixPath(item.file_path).as_posix()}
                for item in result.errors
            ],
            "warnings": [
                {**item.model_dump(mode="json"), "file_path": PurePosixPath(item.file_path).as_posix()}
                for item in result.warnings
            ],
        },
        started_at=now,
        completed_at=now,
    )
    session.add(scan)
    session.flush()

    created = 0
    updated = 0
    observed = 0
    suppressed = 0

    # Failed scans are retained for operational visibility but never change finding state.
    if result.status != "error":
        for item in result.findings:
            normalized_file_path = PurePosixPath(item.file_path).as_posix()
            finding = session.scalar(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.project_id == project_id,
                    Finding.fingerprint == item.fingerprint,
                )
            )
            if finding is None:
                finding = Finding(
                    organization_id=organization_id,
                    project_id=project_id,
                    fingerprint=item.fingerprint,
                    rule_id=item.rule_id,
                    title=item.title,
                    description=item.description,
                    category=item.category,
                    confidence=item.confidence,
                    resource=item.resource,
                    impact=item.impact,
                    reference_urls=item.references,
                    severity=item.severity.value,
                    status=FindingStatus.OPEN,
                    file_path=normalized_file_path,
                    line_start=item.line_start,
                    line_end=item.line_end,
                    evidence=item.evidence,
                    remediation=item.remediation,
                    suppressed=item.suppressed,
                    suppression_reason=item.suppression_reason,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(finding)
                created += 1
            else:
                finding.rule_id = item.rule_id
                finding.title = item.title
                finding.description = item.description
                finding.category = item.category
                finding.confidence = item.confidence
                finding.resource = item.resource
                finding.impact = item.impact
                finding.reference_urls = item.references
                finding.severity = item.severity.value
                finding.file_path = normalized_file_path
                finding.line_start = item.line_start
                finding.line_end = item.line_end
                finding.evidence = item.evidence
                finding.remediation = item.remediation
                finding.suppressed = item.suppressed
                finding.suppression_reason = item.suppression_reason
                finding.last_seen_at = now
                # A genuinely reappearing resolved issue becomes open again. Explicit
                # risk acceptance and false-positive decisions remain human-controlled.
                if finding.status == FindingStatus.RESOLVED and not item.suppressed:
                    finding.status = FindingStatus.OPEN
                    finding.resolved_at = None
                updated += 1

            session.flush()
            session.add(
                ScanFinding(
                    organization_id=organization_id,
                    scan_id=scan.id,
                    finding_id=finding.id,
                    observed_at=now,
                )
            )
            observed += 1
            if item.suppressed:
                suppressed += 1

    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="scan.result_ingested",
            target_type="scan",
            target_id=str(scan.id),
            details={
                "project_id": str(project_id),
                "status": scan.status.value,
                "findings_created": created,
                "findings_updated": updated,
                "findings_observed": observed,
                "suppressed_observed": suppressed,
                "errors_count": len(result.errors),
                "warnings_count": len(result.warnings),
            },
        )
    )
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise

    return ScanIngestResponse(
        scan_id=scan.id,
        project_id=project_id,
        status={
            ScanStatus.COMPLETED: "completed",
            ScanStatus.PARTIAL: "partial",
            ScanStatus.FAILED: "failed",
        }[scan.status],
        findings_created=created,
        findings_updated=updated,
        findings_observed=observed,
        suppressed_observed=suppressed,
        errors_count=len(result.errors),
        warnings_count=len(result.warnings),
    )



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
