"""Request and response contracts for GitHub App integration."""
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from uuid import UUID


class GitHubRepositoryBindRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installation_id: StrictInt = Field(gt=0, le=9223372036854775807)
    repository_id: StrictInt = Field(gt=0, le=9223372036854775807)


class GitHubInstallationResponse(BaseModel):
    installation_id: int
    account_id: int
    account_login: str
    account_type: str
    status: str


class GitHubRepositoryBindingResponse(BaseModel):
    project_id: UUID
    repository_id: int
    full_name: str
    default_branch: str
    html_url: str
