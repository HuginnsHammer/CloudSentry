"""Validated payloads for importing a completed local CloudSentry scan."""
from pathlib import PurePosixPath, PureWindowsPath
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scanner.models import ScanResult


class ScanIngestRequest(BaseModel):
    """A completed scanner result; this endpoint never executes submitted paths."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    environment_id: UUID | None = None
    source_revision: str | None = Field(default=None, min_length=7, max_length=64)
    result: ScanResult

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("target must be non-empty and contain no control characters")
        return value

    @field_validator("source_revision")
    @classmethod
    def validate_source_revision(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) < 7 or len(value) > 64
            or any(char not in "0123456789abcdefABCDEF" for char in value)
        ):
            raise ValueError("source_revision must be a 7-64 character hexadecimal commit SHA")
        return value

    @model_validator(mode="after")
    def validate_result_limits(self):
        result = self.result
        if result.status not in {"ok", "partial", "error"}:
            raise ValueError("result.status must be ok, partial, or error")
        if result.files_scanned < 0:
            raise ValueError("files_scanned cannot be negative")
        if result.status == "ok" and result.errors:
            raise ValueError("a complete scan cannot contain scan errors")
        if result.status == "partial" and (not result.errors or result.files_scanned == 0):
            raise ValueError("a partial scan must include errors and at least one inspected file")
        if result.status == "error" and (result.files_scanned != 0 or result.findings or not result.errors):
            raise ValueError("an error scan must contain errors and no inspected files or findings")
        if any(key not in {"critical", "high", "medium", "low", "info"} or value < 0
               for key, value in result.severity_counts.items()):
            raise ValueError("severity_counts contains an invalid severity or negative count")
        if not result.scanner_version or len(result.scanner_version) > 40:
            raise ValueError("scanner_version must be non-empty and at most 40 characters")
        if not 0 <= result.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if len(result.findings) > 1000 or len(result.errors) > 100 or len(result.warnings) > 100:
            raise ValueError("scan result exceeds the platform ingestion limits")
        fingerprints = [finding.fingerprint for finding in result.findings]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("scan result contains duplicate finding fingerprints")
        for finding in result.findings:
            if (not finding.fingerprint or len(finding.fingerprint) > 128
                    or not finding.rule_id or len(finding.rule_id) > 160):
                raise ValueError("finding fingerprint and rule ID must be non-empty and within platform limits")
            if not finding.title.strip() or not finding.evidence.strip() or not finding.remediation.strip():
                raise ValueError("finding title, evidence, and remediation must be non-empty")
            if not finding.category or len(finding.category) > 80:
                raise ValueError("finding category must be non-empty and at most 80 characters")
            if finding.confidence not in {"high", "medium", "low"}:
                raise ValueError("finding confidence must be high, medium, or low")
            if finding.resource is not None and len(finding.resource) > 300:
                raise ValueError("finding resource exceeds 300 characters")
            if len(finding.title) > 300 or len(finding.file_path) > 2048:
                raise ValueError("finding title or file path exceeds the platform limit")
            if len(finding.description) > 2000 or len(finding.impact) > 2000:
                raise ValueError("finding description or impact exceeds 2000 characters")
            if len(finding.references) > 10 or any(len(ref) > 512 for ref in finding.references):
                raise ValueError("finding references exceed the platform limits")
            if (finding.suppression_reason is not None and len(finding.suppression_reason) > 2000):
                raise ValueError("suppression reason exceeds 2000 characters")
            if len(finding.evidence) > 4096 or len(finding.remediation) > 4096:
                raise ValueError("finding evidence or remediation exceeds 4096 characters")
            path = finding.file_path
            if not path or "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
                raise ValueError("finding file paths must be normalized relative paths")
            normalized = PurePosixPath(path)
            if (
                normalized.is_absolute()
                or PureWindowsPath(path).is_absolute()
                or not normalized.parts
                or any(part in {".", ".."} for part in path.split("/"))
            ):
                raise ValueError("finding file paths must not be absolute or traverse directories")
            if len(path) > 2048:
                raise ValueError("finding file path exceeds 2048 characters")
            if finding.line_start is not None and finding.line_start < 1:
                raise ValueError("finding line_start must be positive")
            if finding.line_end is not None and finding.line_end < 1:
                raise ValueError("finding line_end must be positive")
            if finding.line_start is not None and finding.line_end is not None:
                if finding.line_end < finding.line_start:
                    raise ValueError("finding line_end cannot be before line_start")
        for diagnostic in [*result.errors, *result.warnings]:
            path = diagnostic.file_path
            if (
                not path
                or len(path) > 2048
                or "\\\\" in path
                or any(ord(char) < 32 or ord(char) == 127 for char in path)
            ):
                raise ValueError("diagnostic paths must be normalized relative paths")
            normalized = PurePosixPath(path)
            if (
                normalized.is_absolute()
                or PureWindowsPath(path).is_absolute()
                or any(part == ".." for part in path.split("/"))
            ):
                raise ValueError("diagnostic paths must not be absolute or traverse directories")
            if len(diagnostic.message) > 2048:
                raise ValueError("diagnostic message exceeds 2048 characters")
        return self


class ScanIngestResponse(BaseModel):
    scan_id: UUID
    project_id: UUID
    status: Literal["completed", "partial", "failed"]
    findings_created: int
    findings_updated: int
    findings_observed: int
    suppressed_observed: int
    errors_count: int
    warnings_count: int


class ScanResponse(BaseModel):
    id: UUID
    project_id: UUID
    environment_id: UUID | None
    status: str
    target: str
    scanner_version: str
    summary: dict[str, object]
    started_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)
