"""Private scan executor; designed to run without database or GitHub credentials."""
from __future__ import annotations

import asyncio
import hmac
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from scanner.models import ScanError, ScanResult, ScanWarning, Severity
from scanner.scoring import summarize

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 5000
MAX_DIRECTORIES = 10000
MAX_FINDINGS = 1000
MAX_DIAGNOSTICS = 100
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_SCAN_SECONDS = 120
_SCAN_SEMAPHORE = asyncio.Semaphore(1)
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")

app = FastAPI(
    title="CloudSentry isolated scan executor",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class ArchiveError(ValueError):
    """An archive violated extraction safety limits."""


def _read_secret() -> str:
    secret = os.getenv("CLOUDSENTRY_EXECUTOR_SHARED_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Executor authentication is not configured")
    return secret


def _safe_extract(archive_bytes: bytes, workspace: Path) -> list[ScanError]:
    if not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ArchiveError("Archive is empty or exceeds the compressed size limit")
    workspace.mkdir(parents=True, exist_ok=True)
    root_name: str | None = None
    total_bytes = 0
    file_count = 0
    directory_count = 0
    skipped: list[ScanError] = []
    root = workspace.resolve()

    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            for member in tar:
                raw_name = member.name
                if (
                    not raw_name
                    or "\\" in raw_name
                    or "\x00" in raw_name
                    or len(raw_name) > 4096
                ):
                    raise ArchiveError("Archive contains an invalid path")
                stripped = raw_name.rstrip("/")
                if not stripped:
                    raise ArchiveError("Archive contains an empty path")
                if stripped.startswith("/") or PurePosixPath(stripped).is_absolute() or PureWindowsPath(stripped).drive:
                    raise ArchiveError("Archive contains an absolute path")
                parts = stripped.split("/")
                if len(parts) > 65 or any(part in {"", ".", ".."} for part in parts):
                    raise ArchiveError("Archive path traversal or excessive path depth detected")
                if root_name is None:
                    root_name = parts[0]
                if parts[0] != root_name:
                    raise ArchiveError("Archive contains multiple root directories")
                if len(parts) == 1:
                    if not member.isdir():
                        raise ArchiveError("Archive root entry must be a directory")
                    continue

                relative_parts = parts[1:]
                relative_path = "/".join(relative_parts)
                destination = workspace.joinpath(*relative_parts)
                if not destination.resolve().is_relative_to(root):
                    raise ArchiveError("Archive path escapes the extraction directory")

                if member.isdir():
                    directory_count += 1
                    if directory_count > MAX_DIRECTORIES:
                        raise ArchiveError("Archive contains too many directories")
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue

                if member.issym() or member.islnk():
                    if len(skipped) < MAX_DIAGNOSTICS:
                        skipped.append(
                            ScanError(
                                file_path=relative_path,
                                kind="archive",
                                message="Symbolic and hard links are skipped for safety.",
                            )
                        )
                    continue
                if getattr(member, "issparse", lambda: False)() or not member.isfile():
                    raise ArchiveError("Archive contains an unsupported special file")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise ArchiveError("Archive contains a file larger than the 10 MiB extraction limit")

                file_count += 1
                total_bytes += member.size
                if file_count > MAX_FILES or total_bytes > MAX_EXTRACTED_BYTES:
                    raise ArchiveError("Archive exceeds file-count or total extracted-size limits")

                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = tar.extractfile(member)
                if source is None:
                    raise ArchiveError("Archive file contents could not be read")
                written = 0
                with source, destination.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        written += len(chunk)
                        if written > member.size:
                            raise ArchiveError("Archive member exceeded its declared size")
                        output.write(chunk)
                if written != member.size:
                    raise ArchiveError("Archive member size did not match its header")
                destination.chmod(0o600)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveError("Source archive is malformed or could not be extracted safely") from exc

    if root_name is None:
        raise ArchiveError("Archive contains no repository root directory")
    return skipped


def _normalize_path(value: str) -> str:
    if not value or "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ArchiveError("Scanner returned an invalid diagnostic path")
    normalized = PurePosixPath(value).as_posix()
    if (
        normalized.startswith("/")
        or PureWindowsPath(value).drive
        or any(part == ".." for part in normalized.split("/"))
        or len(normalized) > 2048
    ):
        raise ArchiveError("Scanner returned a path outside the repository workspace")
    return normalized


def _bound_result(result: ScanResult, skipped: list[ScanError]) -> ScanResult:
    result.errors.extend(skipped)
    if len(result.findings) > MAX_FINDINGS:
        severity_order = {severity: index for index, severity in enumerate(Severity)}
        result.findings = sorted(
            result.findings,
            key=lambda item: (severity_order[item.severity], item.file_path, item.line_start or 0),
        )[:MAX_FINDINGS]
        result.errors.append(
            ScanError(
                file_path=".",
                kind="limit",
                message="Finding output was capped at 1000 entries; this report is incomplete.",
            )
        )
    if len(result.errors) > MAX_DIAGNOSTICS:
        result.errors = result.errors[: MAX_DIAGNOSTICS - 1] + [
            ScanError(
                file_path=".",
                kind="limit",
                message="Additional scan errors were omitted after the 100-entry diagnostic limit.",
            )
        ]
    if len(result.warnings) > MAX_DIAGNOSTICS:
        result.warnings = result.warnings[: MAX_DIAGNOSTICS - 1] + [
            ScanWarning(
                file_path=".",
                message="Additional scan warnings were omitted after the 100-entry diagnostic limit.",
            )
        ]

    for item in result.findings:
        item.file_path = _normalize_path(item.file_path)
        item.title = item.title[:300]
        item.description = item.description[:2000]
        item.category = item.category[:80]
        item.confidence = item.confidence if item.confidence in {"high", "medium", "low"} else "medium"
        item.resource = item.resource[:300] if item.resource else None
        item.impact = item.impact[:2000]
        item.evidence = item.evidence[:4096]
        item.remediation = item.remediation[:4096]
        item.references = [ref[:512] for ref in item.references[:10]]
        item.suppression_reason = item.suppression_reason[:2000] if item.suppression_reason else None
    for item in result.errors:
        item.file_path = _normalize_path(item.file_path)
        item.kind = item.kind[:80] or "scanner"
        item.message = item.message[:2048]
    for item in result.warnings:
        item.file_path = _normalize_path(item.file_path)
        item.message = item.message[:2048]

    if result.errors and result.files_scanned:
        result.status = "partial"
    elif result.errors:
        result.status = "error"
        result.findings = []
    result.risk_score, result.severity_counts = summarize(result.findings)
    return result


def _scan_archive(archive_bytes: bytes) -> ScanResult:
    with tempfile.TemporaryDirectory(prefix="cloudsentry-executor-") as temporary:
        root = Path(temporary)
        workspace = root / "source"
        report_path = root / "scan-result.json"
        skipped = _safe_extract(archive_bytes, workspace)
        command = [
            sys.executable,
            "-m",
            "scanner.cli",
            "scan",
            ".",
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
        environment = {
            "PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(root),
            "TMPDIR": str(root),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        }
        try:
            completed = subprocess.run(
                command,
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=MAX_SCAN_SECONDS + 10,
                check=False,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            raise ArchiveError("Static scan exceeded its execution time limit") from None
        if completed.returncode not in {0, 1, 2} or not report_path.is_file():
            raise ArchiveError("Static scanner failed before producing a valid report")
        if report_path.stat().st_size > MAX_REPORT_BYTES:
            raise ArchiveError("Static scanner report exceeded the 20 MiB output limit")
        try:
            result = ScanResult.model_validate_json(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ArchiveError("Static scanner produced an invalid report") from None
        return _bound_result(result, skipped)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/v1/scan")
async def scan_archive(request: Request) -> JSONResponse:
    secret = _read_secret()
    authorization = request.headers.get("authorization", "")
    expected = f"Bearer {secret}"
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Executor authentication failed")

    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) < 0 or int(declared_length) > MAX_ARCHIVE_BYTES:
                raise HTTPException(status_code=413, detail="Source archive exceeds 50 MiB")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None

    revision = request.headers.get("x-cloudsentry-revision", "")
    target = request.headers.get("x-cloudsentry-target", "")
    if not _SHA.fullmatch(revision):
        raise HTTPException(status_code=400, detail="A full commit SHA is required")
    if (
        not target
        or len(target) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in target)
    ):
        raise HTTPException(status_code=400, detail="Invalid scan target")

    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/gzip":
        raise HTTPException(status_code=415, detail="Content-Type must be application/gzip")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_ARCHIVE_BYTES:
            raise HTTPException(status_code=413, detail="Source archive exceeds 50 MiB")
    if not body:
        raise HTTPException(status_code=400, detail="Source archive is empty")

    try:
        async with _SCAN_SEMAPHORE:
            result = await asyncio.to_thread(_scan_archive, bytes(body))
    except ArchiveError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return JSONResponse({"source_revision": revision.lower(), "target": target, "result": result.model_dump(mode="json")})
