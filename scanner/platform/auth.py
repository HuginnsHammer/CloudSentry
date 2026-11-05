"""OIDC access-token verification for the hosted platform API.

Only asymmetric RS256 access tokens from the configured issuer are accepted.
Users must be provisioned and belong to an organization before they can access
tenant data; this module never creates accounts from untrusted token claims.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_url: str

    @classmethod
    def from_env(cls) -> "OIDCSettings":
        values = {
            "CLOUDSENTRY_OIDC_ISSUER": os.getenv("CLOUDSENTRY_OIDC_ISSUER", "").strip(),
            "CLOUDSENTRY_OIDC_AUDIENCE": os.getenv("CLOUDSENTRY_OIDC_AUDIENCE", "").strip(),
            "CLOUDSENTRY_OIDC_JWKS_URL": os.getenv("CLOUDSENTRY_OIDC_JWKS_URL", "").strip(),
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError(f"OIDC configuration is incomplete: {', '.join(missing)}")
        return cls(
            issuer=values["CLOUDSENTRY_OIDC_ISSUER"],
            audience=values["CLOUDSENTRY_OIDC_AUDIENCE"],
            jwks_url=values["CLOUDSENTRY_OIDC_JWKS_URL"],
        )


@lru_cache(maxsize=8)
def _jwks_client(url: str) -> PyJWKClient:
    return PyJWKClient(url, cache_jwk_set=True, cache_keys=True)


def verify_access_token(token: str, settings: OIDCSettings | None = None) -> dict:
    """Verify signature and required OIDC access-token claims."""
    config = settings or OIDCSettings.from_env()
    try:
        signing_key = _jwks_client(config.jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.audience,
            issuer=config.issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except (InvalidTokenError, jwt.PyJWKClientError, ValueError) as exc:
        raise ValueError("Bearer token is invalid or could not be verified") from exc

    if not isinstance(claims.get("sub"), str) or not claims["sub"].strip():
        raise ValueError("Bearer token has no valid subject")
    if not isinstance(claims.get("iss"), str):
        raise ValueError("Bearer token has no valid issuer")
    return claims
