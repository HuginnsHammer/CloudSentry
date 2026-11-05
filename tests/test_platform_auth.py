from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from scanner.platform.auth import OIDCSettings, verify_access_token


@pytest.fixture
def signing_keys(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        "scanner.platform.auth._jwks_client",
        lambda _url: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=private_key.public_key())
        ),
    )
    return private_key


def make_token(private_key, *, issuer="https://identity.example.test/", audience="cloudsentry"):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )


def test_access_token_requires_expected_signature_and_claims(signing_keys):
    settings = OIDCSettings(
        issuer="https://identity.example.test/",
        audience="cloudsentry",
        jwks_url="https://identity.example.test/.well-known/jwks.json",
    )
    claims = verify_access_token(make_token(signing_keys), settings)
    assert claims["sub"] == "user-123"


@pytest.mark.parametrize(
    ("issuer", "audience"),
    [
        ("https://attacker.example/", "cloudsentry"),
        ("https://identity.example.test/", "another-api"),
    ],
)
def test_access_token_rejects_wrong_issuer_or_audience(signing_keys, issuer, audience):
    settings = OIDCSettings(
        issuer="https://identity.example.test/",
        audience="cloudsentry",
        jwks_url="https://identity.example.test/.well-known/jwks.json",
    )
    with pytest.raises(ValueError, match="invalid or could not be verified"):
        verify_access_token(make_token(signing_keys, issuer=issuer, audience=audience), settings)
