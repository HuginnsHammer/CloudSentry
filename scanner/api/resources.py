"""Authenticated organization, project, and environment management."""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.api.resource_schemas import (
    EnvironmentCreate,
    EnvironmentResponse,
    OrganizationCreate,
    OrganizationCreatedResponse,
    OrganizationResponse,
    ProjectCreate,
    ProjectResponse,
)
from scanner.platform.dependencies import get_current_user, get_db_session, require_membership
from scanner.platform.models import (
    AuditEvent,
    Environment,
    Membership,
    MembershipRole,
    Organization,
    Project,
    User,
)

router = APIRouter(tags=["organization resources"])
ADMIN_ROLES = {MembershipRole.OWNER, MembershipRole.ADMIN}


def _require_admin(membership: Membership) -> None:
    if membership.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Organization owner or admin role is required")


def _require_project(
    organization_id: UUID,
    project_id: UUID,
    session: Session,
) -> Project:
    project = session.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post(
    "/api/v1/organizations",
    response_model=OrganizationCreatedResponse,
    status_code=201,
)
def create_organization(
    payload: OrganizationCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> OrganizationCreatedResponse:
    """Create a tenant and make its creator the initial owner."""
    organization = Organization(name=payload.name, slug=payload.slug)
    try:
        session.add(organization)
        session.flush()
        session.add(
            Membership(
                organization_id=organization.id,
                user_id=user.id,
                role=MembershipRole.OWNER,
            )
        )
        session.flush()
        session.add(
            AuditEvent(
                organization_id=organization.id,
                actor_user_id=user.id,
                action="organization.created",
                target_type="organization",
                target_id=str(organization.id),
                details={"slug": organization.slug},
            )
        )
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        if "UNIQUE constraint failed" in str(exc.orig) or getattr(
            getattr(exc.orig, "diag", None), "constraint_name", None
        ) == "uq_organizations_slug":
            raise HTTPException(status_code=409, detail="Organization slug is already in use") from None
        raise
    return OrganizationCreatedResponse(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        role=MembershipRole.OWNER.value,
    )


@router.get(
    "/api/v1/organizations/{organization_id}",
    response_model=OrganizationResponse,
)
def get_organization(
    organization_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> Organization:
    organization = session.get(Organization, membership.organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return organization


@router.post(
    "/api/v1/organizations/{organization_id}/projects",
    response_model=ProjectResponse,
    status_code=201,
)
def create_project(
    organization_id: UUID,
    payload: ProjectCreate,
    membership: Membership = Depends(require_membership),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Project:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    _require_admin(membership)
    if session.scalar(
        select(Project.id).where(
            Project.organization_id == organization_id,
            Project.slug == payload.slug,
        )
    ) is not None:
        raise HTTPException(status_code=409, detail="Project slug is already in use")
    project = Project(
        organization_id=organization_id,
        name=payload.name,
        slug=payload.slug,
        repository_url=payload.repository_url,
    )
    try:
        session.add(project)
        session.flush()
        session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=user.id,
                action="project.created",
                target_type="project",
                target_id=str(project.id),
                details={"slug": project.slug, "repository_url": project.repository_url},
            )
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Project conflicts with an existing resource") from None
    session.refresh(project)
    return project


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}",
    response_model=ProjectResponse,
)
def get_project(
    organization_id: UUID,
    project_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> Project:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return _require_project(organization_id, project_id, session)


@router.get(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/environments",
    response_model=list[EnvironmentResponse],
)
def list_environments(
    organization_id: UUID,
    project_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> list[Environment]:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_project(organization_id, project_id, session)
    statement = (
        select(Environment)
        .where(
            Environment.organization_id == organization_id,
            Environment.project_id == project_id,
        )
        .order_by(Environment.name)
    )
    return list(session.scalars(statement).all())


@router.post(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/environments",
    response_model=EnvironmentResponse,
    status_code=201,
)
def create_environment(
    organization_id: UUID,
    project_id: UUID,
    payload: EnvironmentCreate,
    membership: Membership = Depends(require_membership),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Environment:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_admin(membership)
    _require_project(organization_id, project_id, session)
    if session.scalar(
        select(Environment.id).where(
            Environment.organization_id == organization_id,
            Environment.project_id == project_id,
            Environment.name == payload.name,
        )
    ) is not None:
        raise HTTPException(status_code=409, detail="Environment name is already in use")
    environment = Environment(
        organization_id=organization_id,
        project_id=project_id,
        name=payload.name,
        is_production=payload.is_production,
    )
    try:
        session.add(environment)
        session.flush()
        session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=user.id,
                action="environment.created",
                target_type="environment",
                target_id=str(environment.id),
                details={
                    "project_id": str(project_id),
                    "name": environment.name,
                    "is_production": environment.is_production,
                },
            )
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Environment conflicts with an existing resource") from None
    session.refresh(environment)
    return environment
