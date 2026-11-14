"""Authenticated hosted API; intentionally separate from the local scanner API."""
from uuid import UUID

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from scanner.api.findings import router as findings_router
from scanner.api.github import router as github_router
from scanner.api.resources import router as resources_router
from scanner.api.scans import router as scans_router
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
    version="0.4.0",
    description="Authenticated tenant platform API. It imports reports but never executes scans.",
)


app.include_router(findings_router)
app.include_router(github_router)
app.include_router(resources_router)
app.include_router(scans_router)


@app.middleware("http")
async def limit_scan_ingest_content_length(request: Request, call_next):
    """Reject oversized declared report bodies before JSON parsing."""
    if request.method == "POST" and request.url.path.endswith("/scans/ingest"):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared_size < 0:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared_size > 32 * 1024 * 1024:
                return JSONResponse(status_code=413, content={"detail": "Scan report exceeds the 32 MiB limit"})
    return await call_next(request)


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
) -> list[dict[str, object]]:
    projects = session.scalars(
        select(Project)
        .where(Project.organization_id == membership.organization_id)
        .order_by(Project.name)
    ).all()
    return [
        {
            "id": str(project.id),
            "name": project.name,
            "slug": project.slug,
            "repository_url": project.repository_url,
        }
        for project in projects
    ]
