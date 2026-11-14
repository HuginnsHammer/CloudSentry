"""Minimal GitHub App client with short-lived installation tokens."""
from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import jwt


API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class GitHubAppConfigurationError(RuntimeError):
    """The GitHub App is not configured correctly."""


class GitHubAppError(RuntimeError):
    """A GitHub API operation failed safely."""


class GitHubAppClient:
    def __init__(self, app_id: str, private_key: str, *, timeout: float = 10.0):
        self.app_id = app_id
        self.private_key = private_key
        self.timeout = timeout

    @classmethod
    def from_environment(cls) -> "GitHubAppClient":
        app_id = os.getenv("CLOUDSENTRY_GITHUB_APP_ID", "").strip()
        private_key = os.getenv("CLOUDSENTRY_GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n").strip()
        if not app_id.isdigit() or not private_key.startswith("-----BEGIN"):
            raise GitHubAppConfigurationError("GitHub App ID and private key must be configured")
        return cls(app_id, private_key)

    def _app_jwt(self) -> str:
        now = int(time.time())
        try:
            return jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.app_id},
                self.private_key,
                algorithm="RS256",
            )
        except (TypeError, ValueError) as exc:
            raise GitHubAppConfigurationError("GitHub App private key could not sign a token") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise GitHubAppError("Invalid GitHub API path")
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "CloudSentry",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(f"{API_ROOT}{path}", data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise GitHubAppError(f"GitHub API rejected the request (HTTP {exc.code})") from None
        except (URLError, TimeoutError, OSError):
            raise GitHubAppError("GitHub API is temporarily unreachable") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise GitHubAppError("GitHub API response exceeded the configured size limit")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubAppError("GitHub API returned an invalid JSON response") from None
        if not isinstance(value, dict):
            raise GitHubAppError("GitHub API returned an unexpected response")
        return value

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        if installation_id <= 0:
            raise GitHubAppError("Invalid GitHub installation ID")
        result = self._request(
            "GET",
            f"/app/installations/{installation_id}",
            token=self._app_jwt(),
        )
        if result.get("id") != installation_id or not isinstance(result.get("account"), dict):
            raise GitHubAppError("GitHub installation response did not match the requested installation")
        return result

    def create_installation_token(self, installation_id: int) -> str:
        if installation_id <= 0:
            raise GitHubAppError("Invalid GitHub installation ID")
        result = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            token=self._app_jwt(),
            body={},
        )
        token = result.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub did not issue an installation token")
        return token

    def get_installation_repository(
        self,
        installation_id: int,
        repository_id: int,
    ) -> dict[str, Any] | None:
        if repository_id <= 0:
            raise GitHubAppError("Invalid GitHub repository ID")
        token = self.create_installation_token(installation_id)
        for page in range(1, 101):
            result = self._request(
                "GET",
                f"/installation/repositories?per_page=100&page={page}",
                token=token,
            )
            repositories = result.get("repositories")
            if not isinstance(repositories, list):
                raise GitHubAppError("GitHub returned an invalid installation repository list")
            for repository in repositories:
                if isinstance(repository, dict) and repository.get("id") == repository_id:
                    if not all(
                        isinstance(repository.get(key), str)
                        for key in ("full_name", "html_url", "default_branch")
                    ):
                        raise GitHubAppError("GitHub repository response is missing required metadata")
                    return {
                        "id": repository_id,
                        "full_name": repository["full_name"],
                        "html_url": repository["html_url"],
                        "default_branch": repository["default_branch"],
                    }
            if len(repositories) < 100:
                return None
        raise GitHubAppError("GitHub installation has too many repositories to verify safely")
