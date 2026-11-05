"""Request dependencies for authenticated, tenant-scoped platform access."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Generator
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.platform.auth import verify_access_token
from scanner.platform.database import build_engine, build_session_factory
from scanner.platform.models import Membership, User

bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def _session_factory():
    database_url = os.getenv("CLOUDSENTRY_DATABASE_URL")
    if not database_url:
        raise RuntimeError("CLOUDSENTRY_DATABASE_URL must be configured")
    return build_session_factory(build_engine(database_url))


def get_db_session() -> Generator[Session, None, None]:
    try:
        factory = _session_factory()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Platform database is not configured") from exc
    with factory() as session:
        yield session


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: Session = Depends(get_db_session),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = verify_access_token(credentials.credentials)
    except (ValueError, RuntimeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token is invalid or OIDC is not configured",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    user = session.scalar(
        select(User).where(
            User.identity_provider == claims["iss"],
            User.identity_subject == claims["sub"],
        )
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This identity has not been provisioned for CloudSentry",
        )
    return user


def require_membership(
    organization_id: UUID,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Membership:
    membership = session.get(Membership, (organization_id, user.id))
    if membership is None:
        # Deliberately do not disclose whether the organization exists.
        raise HTTPException(status_code=404, detail="Organization not found")
    return membership
