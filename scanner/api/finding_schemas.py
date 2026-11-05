"""Validated request and response shapes for finding management."""
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from scanner.platform.models import FindingStatus


class FindingUpdate(BaseModel):
    """Fields a member may change during finding triage."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus | None = None
    assigned_to_user_id: UUID | None = None
    note: str | None = Field(default=None, max_length=2000)


class FindingResponse(BaseModel):
    id: UUID
    project_id: UUID
    fingerprint: str
    rule_id: str
    title: str
    severity: str
    status: FindingStatus
    file_path: str
    line_start: int | None
    line_end: int | None
    evidence: str
    remediation: str
    assigned_to_user_id: UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None

    model_config = ConfigDict(from_attributes=True)
