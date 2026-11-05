"""Tenant-scoped finding queries and controlled lifecycle updates."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.api.finding_schemas import FindingResponse, FindingUpdate
from scanner.platform.dependencies import get_current_user, get_db_session, require_membership
from scanner.platform.models import (
    AuditEvent,
    Finding,
    FindingStatus,
    Membership,
    MembershipRole,
    Project,
    User,
)

router = APIRouter(tags=["findings"])

PRIVILEGED_ROLES = {
    MembershipRole.OWNER,
    MembershipRole.ADMIN,
    MembershipRole.SECURITY_ANALYST,
}
DEVELOPER_STATUSES = {FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED}


def _require_project(organization_id: UUID, project_id: UUID, session: Session) -> None:
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")


def _require_project(organization_id: UUID, project_id: UUID, session: Session) -> None:
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")


def _get_project_finding(
    organization_id: UUID,
    project_id: UUID,
    finding_id: UUID,
    session: Session,
) -> Finding:
    finding = session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.project_id == project_id,
            Finding.organization_id == organization_id,
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/findings",
    response_model=list[FindingResponse],
)
def list_project_findings(
    organization_id: UUID,
    project_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    assigned_to_me: bool = False,
) -> list[Finding]:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_project(organization_id, project_id, session)
    statement = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.project_id == project_id,
    )
    if finding_status is not None:
        statement = statement.where(Finding.status == finding_status)
    if severity is not None:
        statement = statement.where(Finding.severity == severity)
    if assigned_to_me:
        statement = statement.where(Finding.assigned_to_user_id == membership.user_id)
    return list(session.scalars(statement.order_by(Finding.first_seen_at.desc())).all())


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/findings/{finding_id}",
    response_model=FindingResponse,
)
def get_project_finding(
    organization_id: UUID,
    project_id: UUID,
    finding_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> Finding:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _get_project_finding(organization_id, project_id, finding_id, session)


@router.patch(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/findings/{finding_id}",
    response_model=FindingResponse,
)
def update_project_finding(
    organization_id: UUID,
    project_id: UUID,
    finding_id: UUID,
    payload: FindingUpdate,
    membership: Membership = Depends(require_membership),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Finding:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    changed_fields = payload.model_fields_set - {"note"}
    if not changed_fields:
        raise HTTPException(status_code=422, detail="Provide at least one field to update")

    role = membership.role
    if role not in PRIVILEGED_ROLES and role != MembershipRole.DEVELOPER:
        raise HTTPException(status_code=403, detail="Your role cannot modify findings")
    if "assigned_to_user_id" in changed_fields and role not in PRIVILEGED_ROLES:
        raise HTTPException(status_code=403, detail="Your role cannot assign findings")

    finding = _get_project_finding(organization_id, project_id, finding_id, session)
    changes: dict[str, object] = {}

    if "status" in changed_fields:
        new_status = payload.status
        if new_status is None:
            raise HTTPException(status_code=422, detail="Status cannot be null")
        if role == MembershipRole.DEVELOPER and new_status not in DEVELOPER_STATUSES:
            raise HTTPException(status_code=403, detail="Developers may only start or resolve findings")
        if new_status in {FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE}:
            if not payload.note or not payload.note.strip():
                raise HTTPException(
                    status_code=422,
                    detail="A non-empty note is required for risk acceptance or false-positive decisions",
                )
        if finding.status != new_status:
            changes["status"] = {"from": finding.status.value, "to": new_status.value}
            finding.status = new_status
            finding.resolved_at = (
                datetime.now(timezone.utc)
                if new_status in {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}
                else None
            )

    if "assigned_to_user_id" in changed_fields:
        assignee_id = payload.assigned_to_user_id
        if assignee_id is not None:
            assignee_membership = session.get(Membership, (organization_id, assignee_id))
            if assignee_membership is None:
                raise HTTPException(status_code=422, detail="Assignee must belong to this organization")
        if finding.assigned_to_user_id != assignee_id:
            changes["assigned_to_user_id"] = {
                "from": str(finding.assigned_to_user_id) if finding.assigned_to_user_id else None,
                "to": str(assignee_id) if assignee_id else None,
            }
            finding.assigned_to_user_id = assignee_id

    if payload.note and payload.note.strip():
        changes["note"] = payload.note.strip()

    if not changes:
        return finding

    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="finding.updated",
            target_type="finding",
            target_id=str(finding.id),
            details={"project_id": str(project_id), "changes": changes},
        )
    )
    session.commit()
    session.refresh(finding)
    return finding
