"""Validated payloads for importing a completed local CloudSentry scan."""
from pathlib import PurePosixPath
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
        if len(result.scanner_version) > 40:
            raise ValueError("scanner_version exceeds 40 characters")
        if not 0 <= result.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if len(result.findings) > 5000 or len(result.errors) > 500 or len(result.warnings) > 500:
            raise ValueError("scan result exceeds the platform ingestion limits")
        fingerprints = [finding.fingerprint for finding in result.findings]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("scan result contains duplicate finding fingerprints")
        if result.status == "error" and result.findings:
            raise ValueError("an error scan cannot contain findings; submit a partial result instead")
        for finding in result.findings:
            if len(finding.fingerprint) > 128 or len(finding.rule_id) > 160:
                raise ValueError("finding fingerprint or rule ID exceeds the platform limit")
            if len(finding.title) > 300 or len(finding.file_path) > 2048:
                raise ValueError("finding title or file path exceeds the platform limit")
            if len(finding.evidence) > 16384 or len(finding.remediation) > 8192:
                raise ValueError("finding evidence or remediation exceeds the platform limit")
            path = finding.file_path
            if not path or "\\" in path or "\x00" in path:
                raise ValueError("finding file paths must be normalized relative paths")
            normalized = PurePosixPath(path)
            if normalized.is_absolute() or any(part in {".", ".."} for part in normalized.parts):
                raise ValueError("finding file paths must not be absolute or traverse directories")
            if len(path) > 2048:
                raise ValueError("finding file path exceeds 2048 characters")
            if finding.line_start is not None and finding.line_end is not None:
                if finding.line_end < finding.line_start:
                    raise ValueError("finding line_end cannot be before line_start")
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
