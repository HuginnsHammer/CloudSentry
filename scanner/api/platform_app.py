"""Authenticated hosted API; intentionally separate from the local scanner API."""
from uuid import UUID

from fastapi import Depends, FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.platform.dependencies import (
    get_current_user,
    get_db_session,
    require_membership,
)
from scanner.platform.models import Membership, Organization, Project, User

app = FastAPI(
    title="CloudSentry Platform API",
    version="0.2.0",
    description="Authenticated organization and project API. Scanning is not exposed here.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "authenticated-platform-api"}


@app.get("/api/v1/me")
def current_identity(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> dict[str, object]:
    memberships = session.scalars(
        select(Membership).where(Membership.user_id == user.id)
    ).all()
    organizations = []
    for membership in memberships:
        organization = session.get(Organization, membership.organization_id)
        if organization is not None:
            organizations.append({
                "id": str(organization.id),
                "name": organization.name,
                "slug": organization.slug,
                "role": membership.role.value,
            })
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": user.display_name,
        "organizations": organizations,
    }


@app.get("/api/v1/organizations")
def list_organizations(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> list[dict[str, str]]:
    memberships = session.scalars(
        select(Membership).where(Membership.user_id == user.id)
    ).all()
    result = []
    for membership in memberships:
        organization = session.get(Organization, membership.organization_id)
        if organization is not None:
            result.append({
                "id": str(organization.id),
                "name": organization.name,
                "slug": organization.slug,
                "role": membership.role.value,
            })
    return result


@app.get("/api/v1/organizations/{organization_id}/projects")
def list_projects(
    organization_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> list[dict[str, str]]:
    projects = session.scalars(
        select(Project)
        .where(Project.organization_id == membership.organization_id)
        .order_by(Project.name)
    ).all()
    return [
        {"id": str(project.id), "name": project.name, "slug": project.slug}
        for project in projects
    ]
