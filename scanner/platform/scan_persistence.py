"""Atomic persistence of scanner reports from API ingestion and trusted workers."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.scan_schemas import ScanIngestRequest, ScanIngestResponse
from scanner.models import ScanResult
from scanner.platform.models import (
    AuditEvent,
    Environment,
    Finding,
    FindingStatus,
    Project,
    Scan,
    ScanFinding,
    ScanStatus,
)
from scanner.scoring import summarize


class ScanPersistenceError(ValueError):
    """The report cannot be attached to the requested tenant resources."""


def persist_scan_report(
    session: Session,
    *,
    organization_id: UUID,
    project_id: UUID,
    result: ScanResult,
    target: str,
    environment_id: UUID | None = None,
    source_revision: str | None = None,
    actor_user_id: UUID | None = None,
    provenance: str = "client_supplied_report_unverified",
    timestamp_semantics: str = "platform_ingestion_time_only",
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    audit_action: str = "scan.result_ingested",
) -> ScanIngestResponse:
    """Persist one bounded report without committing the caller's transaction."""
    project = session.scalar(
        select(Project)
        .where(Project.id == project_id, Project.organization_id == organization_id)
        .with_for_update()
    )
    if project is None:
        raise ScanPersistenceError("project_not_found")

    if environment_id is not None:
        environment = session.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == organization_id,
                Environment.project_id == project_id,
            )
        )
        if environment is None:
            raise ScanPersistenceError("environment_not_found")

    status_map = {
        "ok": ScanStatus.COMPLETED,
        "partial": ScanStatus.PARTIAL,
        "error": ScanStatus.FAILED,
    }
    if result.status not in status_map:
        raise ScanPersistenceError("invalid_scan_status")
    try:
        validated = ScanIngestRequest.model_validate(
            {
                "target": target,
                "environment_id": environment_id,
                "source_revision": source_revision,
                "result": result.model_dump(mode="json"),
            }
        )
    except ValueError as exc:
        raise ScanPersistenceError("invalid_scan_report") from exc
    target = validated.target
    environment_id = validated.environment_id
    source_revision = validated.source_revision
    result = validated.result

    now = completed_at or datetime.now(timezone.utc)
    started = started_at or now
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or started.tzinfo is None
        or started.utcoffset() is None
        or now < started
    ):
        raise ScanPersistenceError("invalid_scan_timestamps")

    findings = result.findings
    fingerprints = [item.fingerprint for item in findings]
    if len(fingerprints) != len(set(fingerprints)):
        raise ScanPersistenceError("duplicate_finding_fingerprint")

    verified_risk_score, verified_severity_counts = summarize(findings)
    summary = {
        "files_scanned": result.files_scanned,
        "findings_total": len(findings),
        "active_findings": sum(not item.suppressed for item in findings),
        "suppressed_findings": sum(item.suppressed for item in findings),
        "errors_count": len(result.errors),
        "warnings_count": len(result.warnings),
        "risk_score": verified_risk_score,
        "severity_counts": verified_severity_counts,
        "source_revision": source_revision,
        "ingestion_provenance": provenance,
        "timestamp_semantics": timestamp_semantics,
    }
    scan = Scan(
        organization_id=organization_id,
        project_id=project_id,
        environment_id=environment_id,
        status=status_map[result.status],
        target=target,
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
        started_at=started,
        completed_at=now,
    )
    session.add(scan)
    session.flush()

    created = 0
    updated = 0
    observed = 0
    suppressed = 0

    # Failed scans are retained for visibility but never change finding state.
    if result.status != "error":
        for item in findings:
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
            actor_user_id=actor_user_id,
            action=audit_action,
            target_type="scan",
            target_id=str(scan.id),
            details={
                "project_id": str(project_id),
                "status": scan.status.value,
                "provenance": provenance,
                "findings_created": created,
                "findings_updated": updated,
                "findings_observed": observed,
                "suppressed_observed": suppressed,
                "errors_count": len(result.errors),
                "warnings_count": len(result.warnings),
            },
        )
    )
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
