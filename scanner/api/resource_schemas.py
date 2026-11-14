"""Request and response schemas for tenant resource management."""
import re
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$")


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("organization name must be non-empty and contain no control characters")
        return value

    @field_validator("slug")
    @classmethod
    def clean_slug(cls, value: str) -> str:
        value = value.strip().lower()
        if not _SLUG.fullmatch(value):
            raise ValueError("slug must contain lowercase letters, numbers and single hyphens")
        return value


class OrganizationCreatedResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    role: str


class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    slug: str

    model_config = ConfigDict(from_attributes=True)


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(min_length=1, max_length=80)
    repository_url: str | None = Field(default=None, max_length=2048)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("project name must be non-empty and contain no control characters")
        return value

    @field_validator("slug")
    @classmethod
    def clean_slug(cls, value: str) -> str:
        value = value.strip().lower()
        if not _SLUG.fullmatch(value):
            raise ValueError("slug must contain lowercase letters, numbers and single hyphens")
        return value

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("repository_url is not a valid URL") from exc
        segments = parsed.path.strip("/").split("/")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.query
            or parsed.fragment
            or len(segments) != 2
            or any(
                segment in {"", ".", ".."}
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", segment)
                for segment in segments
            )
        ):
            raise ValueError("repository_url must be an HTTPS GitHub repository URL")
        repository = segments[1][:-4] if segments[1].endswith(".git") else segments[1]
        if not repository:
            raise ValueError("repository_url must identify a repository")
        return f"https://github.com/{segments[0]}/{repository}"


class ProjectResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    slug: str
    repository_url: str | None

    model_config = ConfigDict(from_attributes=True)


class EnvironmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    is_production: bool = False

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not _ENVIRONMENT_NAME.fullmatch(value):
            raise ValueError("environment name contains unsupported characters")
        return value


class EnvironmentResponse(BaseModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    name: str
    is_production: bool

    model_config = ConfigDict(from_attributes=True)
