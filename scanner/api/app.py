from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from scanner.engine import scan_paths
app = FastAPI(title="CloudSentry API", version="0.1.0", description="Local static configuration audit API")
# Local development only; do not broaden this list without adding API authorization.
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"], allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
class ScanRequest(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=50)
@app.get("/health")
def health() -> dict[str, str]: return {"status": "ok", "mode": "local-static-analysis"}
@app.post("/api/v1/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    paths = [Path(p).expanduser() for p in request.paths]
    if any(not p.exists() for p in paths): raise HTTPException(status_code=400, detail="One or more paths do not exist")
    return scan_paths(paths).model_dump(mode="json")
