"""Validated shared result models."""
from enum import StrEnum
from pydantic import BaseModel, Field
class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: str = "medium"
    category: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    resource: str | None = None
    evidence: str
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    fingerprint: str
    suppressed: bool = False
    suppression_reason: str | None = None
class ScanError(BaseModel):
    file_path: str
    kind: str
    message: str
class ScanWarning(BaseModel):
    """A non-fatal problem worth surfacing, such as a suppression directive that did nothing."""

    file_path: str
    line_start: int | None = None
    message: str
class ScanResult(BaseModel):
    scanner_version: str = "0.1.0"
    status: str
    files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    warnings: list[ScanWarning] = Field(default_factory=list)
    risk_score: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
