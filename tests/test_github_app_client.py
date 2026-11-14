import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scanner.platform.github_app import (
    GitHubAppClient,
    GitHubAppConfigurationError,
    GitHubAppError,
)


def make_key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return private, private_pem


def test_app_jwt_is_rs256_signed_and_short_lived():
    private, private_pem = make_key_pair()
    client = GitHubAppClient("123456", private_pem)
    token = client._app_jwt()
    claims = jwt.decode(
        token,
        private.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims["iss"] == "123456"
    assert claims["exp"] - claims["iat"] == 600


def test_environment_supports_escaped_private_key_newlines(monkeypatch):
    _, private_pem = make_key_pair()
    monkeypatch.setenv("CLOUDSENTRY_GITHUB_APP_ID", "123456")
    monkeypatch.setenv(
        "CLOUDSENTRY_GITHUB_APP_PRIVATE_KEY",
        private_pem.replace("\n", "\\n"),
    )
    client = GitHubAppClient.from_environment()
    assert client.private_key == private_pem.strip()


def test_missing_app_credentials_fail_closed(monkeypatch):
    monkeypatch.delenv("CLOUDSENTRY_GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("CLOUDSENTRY_GITHUB_APP_PRIVATE_KEY", raising=False)
    with pytest.raises(GitHubAppConfigurationError):
        GitHubAppClient.from_environment()


def test_invalid_private_key_fails_as_configuration_error():
    client = GitHubAppClient("123456", "not-a-valid-private-key")
    with pytest.raises(GitHubAppConfigurationError):
        client._app_jwt()


def test_client_rejects_unexpected_api_paths():
    client = GitHubAppClient("123456", "unused")
    with pytest.raises(GitHubAppError):
        client._request("GET", "//attacker.example/path", token="unused")
