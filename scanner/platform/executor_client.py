"""Authenticated client for the isolated, network-restricted scan executor."""
from __future__ import annotations

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scanner.models import ScanResult


DEFAULT_EXECUTOR_URL = "http://scan-executor:8081/internal/v1/scan"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_RESULT_BYTES = 20 * 1024 * 1024
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class ExecutorError(RuntimeError):
    """The isolated scanner could not return a validated report."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(newurl, code, "Executor redirects are not permitted", headers, fp)


class ScanExecutorClient:
    def __init__(self, url: str, shared_secret: str, *, timeout: float = 180.0):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "scan-executor"
            or parsed.port != 8081
            or parsed.path != "/internal/v1/scan"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("executor URL must use the private scan-executor service endpoint")
        if len(shared_secret) < 32:
            raise ValueError("executor shared secret must contain at least 32 characters")
        self.url = url
        self.shared_secret = shared_secret
        self.timeout = timeout
        self._opener = build_opener(_NoRedirectHandler())

    @classmethod
    def from_environment(cls) -> "ScanExecutorClient":
        url = os.getenv("CLOUDSENTRY_EXECUTOR_URL", DEFAULT_EXECUTOR_URL)
        secret = os.getenv("CLOUDSENTRY_EXECUTOR_SHARED_SECRET", "")
        return cls(url, secret)

    def scan(self, archive: bytes, *, revision: str, target: str) -> ScanResult:
        if not archive or len(archive) > MAX_ARCHIVE_BYTES:
            raise ExecutorError("Source archive is empty or exceeds the 50 MiB limit")
        if not _SHA.fullmatch(revision):
            raise ExecutorError("A full 40-character commit SHA is required")
        if not target or len(target) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in target):
            raise ExecutorError("Invalid scan target metadata")
        request = Request(
            self.url,
            data=archive,
            headers={
                "Authorization": f"Bearer {self.shared_secret}",
                "Content-Type": "application/gzip",
                "X-CloudSentry-Revision": revision.lower(),
                "X-CloudSentry-Target": target,
                "User-Agent": "CloudSentry-Worker",
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                if response.geturl() != self.url:
                    raise ExecutorError("Executor response URL did not match the configured endpoint")
                raw = response.read(MAX_RESULT_BYTES + 1)
        except HTTPError as exc:
            raise ExecutorError(f"Isolated scanner rejected the request (HTTP {exc.code})") from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise ExecutorError("Isolated scanner is unavailable or returned an invalid response") from None
        if len(raw) > MAX_RESULT_BYTES:
            raise ExecutorError("Isolated scanner result exceeded the 20 MiB limit")
        try:
            body = json.loads(raw)
            result = body["result"]
            return ScanResult.model_validate(result)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise ExecutorError("Isolated scanner returned an invalid scan report") from None
