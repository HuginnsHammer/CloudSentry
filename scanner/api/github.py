"""GitHub App installation management and signed webhook ingestion."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.api.github_schemas import (
    GitHubInstallationResponse,
    GitHubRepositoryBindRequest,
    GitHubRepositoryBindingResponse,
)
from scanner.platform.dependencies import get_current_user, get_db_session, require_membership
from scanner.platform.github_app import (
    GitHubAppClient,
    GitHubAppConfigurationError,
    GitHubAppError,
)
from scanner.platform.models import (
    AuditEvent,
    GitHubInstallation,
    GitHubWebhookDelivery,
    Membership,
    MembershipRole,
    Project,
    ScanJob,
    ScanStatus,
    User,
)

router = APIRouter(tags=["GitHub integration"])
ADMIN_ROLES = {MembershipRole.OWNER, MembershipRole.ADMIN}
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_WEBHOOK_BYTES = 1024 * 1024


def get_github_app_client() -> GitHubAppClient:
    try:
        client = GitHubAppClient.from_environment()
        client._app_jwt()
        return client
    except GitHubAppConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="GitHub App integration is not configured",
        ) from None


def _require_admin(membership: Membership) -> None:
    if membership.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Organization owner or admin role is required")


def _installation_response(installation: GitHubInstallation) -> GitHubInstallationResponse:
    return GitHubInstallationResponse(
        installation_id=installation.installation_id,
        account_id=installation.account_id,
        account_login=installation.account_login,
        account_type=installation.account_type,
        status=installation.status,
    )


@router.get(
    "/api/v1/organizations/{organization_id}/github/installations",
    response_model=list[GitHubInstallationResponse],
)
def list_github_installations(
    organization_id: UUID,
    membership: Membership = Depends(require_membership),
    session: Session = Depends(get_db_session),
) -> list[GitHubInstallationResponse]:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    installations = session.scalars(
        select(GitHubInstallation)
        .where(GitHubInstallation.organization_id == organization_id)
        .order_by(GitHubInstallation.account_login)
    ).all()
    return [_installation_response(item) for item in installations]


@router.post(
    "/api/v1/organizations/{organization_id}/github/installations/{installation_id}/claim",
    response_model=GitHubInstallationResponse,
)
def claim_github_installation(
    organization_id: UUID,
    installation_id: int,
    membership: Membership = Depends(require_membership),
    client: GitHubAppClient = Depends(get_github_app_client),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> GitHubInstallationResponse:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    _require_admin(membership)
    installation = session.scalar(
        select(GitHubInstallation)
        .where(GitHubInstallation.installation_id == installation_id)
        .with_for_update()
    )
    if installation is None:
        raise HTTPException(status_code=404, detail="GitHub installation not found")
    if installation.status in {"deleted", "suspended"}:
        raise HTTPException(status_code=409, detail="GitHub installation is not active")
    if installation.organization_id not in {None, organization_id}:
        raise HTTPException(status_code=409, detail="GitHub installation is already claimed")

    try:
        remote = client.get_installation(installation_id)
    except GitHubAppError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    account = remote.get("account", {})
    if account.get("id") != installation.account_id:
        raise HTTPException(status_code=409, detail="GitHub installation account does not match its signed webhook")
    login = account.get("login")
    account_type = account.get("type")
    if not isinstance(login, str) or not isinstance(account_type, str):
        raise HTTPException(status_code=502, detail="GitHub installation account metadata is incomplete")

    installation.organization_id = organization_id
    installation.account_login = login
    installation.account_type = account_type
    installation.status = "active"
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="github.installation_claimed",
            target_type="github_installation",
            target_id=str(installation_id),
            details={"account_login": login, "account_type": account_type},
        )
    )
    session.commit()
    return _installation_response(installation)


@router.post(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/github/repository",
    response_model=GitHubRepositoryBindingResponse,
)
def bind_github_repository(
    organization_id: UUID,
    project_id: UUID,
    payload: GitHubRepositoryBindRequest,
    membership: Membership = Depends(require_membership),
    client: GitHubAppClient = Depends(get_github_app_client),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> GitHubRepositoryBindingResponse:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_admin(membership)
    project = session.scalar(
        select(Project)
        .where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
        .with_for_update()
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    installation = session.scalar(
        select(GitHubInstallation).where(
            GitHubInstallation.installation_id == payload.installation_id,
            GitHubInstallation.organization_id == organization_id,
            GitHubInstallation.status == "active",
        )
    )
    if installation is None:
        raise HTTPException(status_code=404, detail="Active GitHub installation not found")
    try:
        repository = client.get_installation_repository(
            payload.installation_id,
            payload.repository_id,
        )
    except GitHubAppError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    if repository is None:
        raise HTTPException(status_code=404, detail="Repository is not accessible to this installation")
    parsed = urlsplit(repository["html_url"])
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(status_code=502, detail="GitHub returned an unexpected repository URL")

    project.github_installation_id = payload.installation_id
    project.github_repository_id = payload.repository_id
    project.github_repository_full_name = repository["full_name"]
    project.github_default_branch = repository["default_branch"]
    project.repository_url = repository["html_url"]
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="github.repository_bound",
            target_type="project",
            target_id=str(project_id),
            details={
                "installation_id": payload.installation_id,
                "repository_id": payload.repository_id,
                "repository_full_name": repository["full_name"],
            },
        )
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="GitHub repository is already linked to another project",
        ) from None
    return GitHubRepositoryBindingResponse(
        project_id=project_id,
        repository_id=payload.repository_id,
        full_name=repository["full_name"],
        default_branch=repository["default_branch"],
        html_url=repository["html_url"],
    )


@router.delete(
    "/api/v1/organizations/{organization_id}/projects/{project_id}/github/repository",
    status_code=204,
)
def unbind_github_repository(
    organization_id: UUID,
    project_id: UUID,
    membership: Membership = Depends(require_membership),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> None:
    if membership.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Project not found")
    _require_admin(membership)
    project = session.scalar(
        select(Project)
        .where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
        .with_for_update()
    )
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.github_repository_id is None:
        return
    project.github_installation_id = None
    project.github_repository_id = None
    project.github_repository_full_name = None
    project.github_default_branch = None
    project.repository_url = None
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="github.repository_unbound",
            target_type="project",
            target_id=str(project_id),
            details={},
        )
    )
    session.commit()


def _installation_webhook(
    payload: dict,
    action: str | None,
    session: Session,
) -> bool:
    data = payload.get("installation")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Installation webhook is missing installation data")
    installation_id = data.get("id")
    account = data.get("account")
    if (
        type(installation_id) is not int
        or installation_id <= 0
        or not isinstance(account, dict)
        or type(account.get("id")) is not int
        or account.get("id") <= 0
        or not isinstance(account.get("login"), str)
        or not account.get("login")
        or len(account.get("login")) > 255
        or not isinstance(account.get("type"), str)
        or not account.get("type")
        or len(account.get("type")) > 40
    ):
        raise HTTPException(status_code=400, detail="Installation webhook contains invalid account metadata")
    if action not in {"created", "deleted", "suspend", "unsuspend"}:
        return False

    installation = session.scalar(
        select(GitHubInstallation)
        .where(GitHubInstallation.installation_id == installation_id)
        .with_for_update()
    )
    if installation is None:
        installation = GitHubInstallation(
            installation_id=installation_id,
            account_id=account["id"],
            account_login=account["login"],
            account_type=account["type"],
            status="unclaimed",
        )
        session.add(installation)
    else:
        installation.account_id = account["id"]
        installation.account_login = account["login"]
        installation.account_type = account["type"]

    if action == "deleted":
        installation.status = "deleted"
    elif action == "suspend":
        installation.status = "suspended"
    elif action in {"created", "unsuspend"}:
        installation.status = "active" if installation.organization_id else "unclaimed"

    if installation.organization_id is not None:
        session.add(
            AuditEvent(
                organization_id=installation.organization_id,
                actor_user_id=None,
                action=f"github.installation_{action}",
                target_type="github_installation",
                target_id=str(installation_id),
                details={"account_login": account["login"]},
            )
        )
    return True


def _push_webhook(payload: dict, session: Session) -> str:
    repository = payload.get("repository")
    installation_data = payload.get("installation")
    if not isinstance(repository, dict) or not isinstance(installation_data, dict):
        raise HTTPException(status_code=400, detail="Push webhook is missing repository or installation data")
    repository_id = repository.get("id")
    installation_id = installation_data.get("id")
    ref = payload.get("ref")
    revision = payload.get("after")
    if (
        type(repository_id) is not int
        or repository_id <= 0
        or type(installation_id) is not int
        or installation_id <= 0
        or not isinstance(ref, str)
        or len(ref) > 255
        or not isinstance(revision, str)
    ):
        raise HTTPException(status_code=400, detail="Push webhook contains invalid repository metadata")
    if payload.get("deleted") is True or not _SHA.fullmatch(revision) or set(revision) == {"0"}:
        return "ignored"

    project = session.scalar(
        select(Project)
        .where(
            Project.github_repository_id == repository_id,
            Project.github_installation_id == installation_id,
        )
        .with_for_update()
    )
    if project is None or not project.github_default_branch:
        return "ignored"
    if ref != f"refs/heads/{project.github_default_branch}":
        return "ignored"
    installation = session.scalar(
        select(GitHubInstallation).where(
            GitHubInstallation.installation_id == installation_id,
            GitHubInstallation.organization_id == project.organization_id,
            GitHubInstallation.status == "active",
        )
    )
    if installation is None:
        return "ignored"

    normalized_revision = revision.lower()
    dedupe_key = hashlib.sha256(
        f"{project.organization_id}:{project.id}:{ref}:{normalized_revision}".encode()
    ).hexdigest()
    existing = session.scalar(
        select(ScanJob.id).where(
            ScanJob.organization_id == project.organization_id,
            ScanJob.dedupe_key == dedupe_key,
        )
    )
    if existing is not None:
        return "duplicate_job"

    job = ScanJob(
        organization_id=project.organization_id,
        project_id=project.id,
        source_revision=normalized_revision,
        ref=ref,
        dedupe_key=dedupe_key,
        status=ScanStatus.QUEUED,
        attempts=0,
        max_attempts=3,
    )
    session.add(job)
    session.flush()
    session.add(
        AuditEvent(
            organization_id=project.organization_id,
            actor_user_id=None,
            action="github.push_scan_queued",
            target_type="scan_job",
            target_id=str(job.id),
            details={
                "project_id": str(project.id),
                "repository_id": repository_id,
                "ref": ref,
                "source_revision": normalized_revision,
            },
        )
    )
    return "queued"


@router.post("/api/v1/integrations/github/webhook", status_code=202)
async def github_webhook(
    request: Request,
    session: Session = Depends(get_db_session),
) -> dict[str, object]:
    secret = os.getenv("CLOUDSENTRY_GITHUB_WEBHOOK_SECRET")
    if not secret or len(secret) < 32:
        raise HTTPException(status_code=503, detail="GitHub webhook verification requires a 32-character secret")
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) < 0 or int(declared_length) > MAX_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="GitHub webhook payload exceeds 1 MiB")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="GitHub webhook payload exceeds 1 MiB")
    signature = request.headers.get("x-hub-signature-256", "")
    if not re.fullmatch(r"sha256=[0-9a-fA-F]{64}", signature):
        raise HTTPException(status_code=401, detail="GitHub webhook signature is required or malformed")
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature[7:], expected):
        raise HTTPException(status_code=401, detail="GitHub webhook signature is invalid")

    event = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")
    if not re.fullmatch(r"[a-z_]{1,80}", event) or len(delivery_id) != 36:
        raise HTTPException(status_code=400, detail="GitHub webhook headers are invalid")
    try:
        UUID(delivery_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="GitHub delivery ID must be a UUID") from None
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="GitHub webhook body must be valid JSON") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="GitHub webhook body must be a JSON object")

    existing_delivery = session.get(GitHubWebhookDelivery, delivery_id)
    payload_digest = hashlib.sha256(raw).hexdigest()
    if existing_delivery is not None:
        if not hmac.compare_digest(existing_delivery.payload_sha256, payload_digest):
            raise HTTPException(status_code=409, detail="GitHub delivery ID was reused with a different payload")
        return {"accepted": True, "duplicate": True, "result": "already_processed"}
    action = payload.get("action") if isinstance(payload.get("action"), str) else None
    if action is not None and len(action) > 80:
        raise HTTPException(status_code=400, detail="GitHub webhook action is invalid")
    delivery = GitHubWebhookDelivery(
        delivery_id=delivery_id,
        event=event,
        action=action,
        payload_sha256=payload_digest,
        status="ignored",
    )
    session.add(delivery)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        existing_delivery = session.get(GitHubWebhookDelivery, delivery_id)
        if existing_delivery is None or not hmac.compare_digest(
            existing_delivery.payload_sha256, payload_digest
        ):
            raise
        return {"accepted": True, "duplicate": True, "result": "already_processed"}

    result = "ignored"
    if event == "installation":
        processed = _installation_webhook(payload, action, session)
        result = "processed" if processed else "ignored"
    elif event == "push":
        result = _push_webhook(payload, session)
    delivery.status = "processed" if result in {"processed", "queued", "duplicate_job"} else "ignored"
    delivery.processed_at = datetime.now(timezone.utc)
    session.commit()
    return {"accepted": True, "duplicate": False, "result": result}
