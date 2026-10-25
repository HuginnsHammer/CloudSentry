"""Loopback-only API for local configuration scans."""

import ipaddress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from scanner.engine import scan_paths

app = FastAPI(
    title="CloudSentry API",
    version="0.1.0",
    description="Local static configuration audit API",
)


@app.middleware("http")
async def require_loopback_client(request: Request, call_next):
    """Reject network clients; the API is intended for local desktop use only."""
    client = request.client
    if client is None:
        return JSONResponse(
            status_code=403,
            content={"detail": "CloudSentry API is restricted to loopback clients"},
        )

    try:
        is_loopback = ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        is_loopback = False

    if not is_loopback:
        return JSONResponse(
            status_code=403,
            content={"detail": "CloudSentry API is restricted to loopback clients"},
        )

    return await call_next(request)


# Local development only; do not broaden this list without adding API authorization.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=50)

    @field_validator("paths")
    @classmethod
    def reject_blank_paths(cls, paths: list[str]) -> list[str]:
        if any(not path.strip() for path in paths):
            raise ValueError("paths must not contain empty or whitespace-only values")
        return paths


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-static-analysis"}


@app.post("/api/v1/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    paths = [Path(value).expanduser() for value in request.paths]
    if any(not path.exists() for path in paths):
        raise HTTPException(status_code=400, detail="One or more paths do not exist")
    return scan_paths(paths).model_dump(mode="json")
