import json
from pathlib import Path
from typing import Iterable
import hcl2
import yaml
from scanner.models import ScanError, ScanResult
from scanner.rules.compose import scan_compose
from scanner.rules.dockerfile import scan_dockerfile
from scanner.rules.terraform import scan_terraform
from scanner.scoring import summarize
MAX_FILE_BYTES = 2 * 1024 * 1024

def detect_kind(path: Path) -> str | None:
    if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."): return "dockerfile"
    if path.suffix.lower() == ".tf": return "terraform"
    if path.suffix.lower() in {".yaml", ".yml"}: return "yaml"
    return None

def discover(paths: Iterable[Path]) -> list[Path]:
    found: set[Path] = set()
    for item in paths:
        if item.is_file():
            if detect_kind(item): found.add(item)
        elif item.is_dir():
            for candidate in item.rglob("*"):
                if candidate.is_file() and detect_kind(candidate) and not any(part in {".git", ".venv", "node_modules"} for part in candidate.parts): found.add(candidate)
    return sorted(found)

def scan_paths(paths: Iterable[Path]) -> ScanResult:
    result = ScanResult(status="ok")
    for path in discover(paths):
        display = str(path)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                result.errors.append(ScanError(file_path=display, kind="input", message=f"File exceeds {MAX_FILE_BYTES} byte limit")); continue
            text = path.read_text(encoding="utf-8")
            kind = detect_kind(path)
            if kind == "dockerfile": result.findings.extend(scan_dockerfile(text, display))
            elif kind == "terraform":
                try: parsed = hcl2.loads(text)
                except Exception as exc:
                    result.errors.append(ScanError(file_path=display, kind="parse", message=f"Terraform parse failed: {exc}")); continue
                result.findings.extend(scan_terraform(text, display, parsed))
            elif kind == "yaml":
                try: data = yaml.safe_load(text)
                except yaml.YAMLError as exc:
                    result.errors.append(ScanError(file_path=display, kind="parse", message=f"YAML parse failed: {exc}")); continue
                if isinstance(data, dict) and "services" in data: result.findings.extend(scan_compose(data, display, text))
            result.files_scanned += 1
        except (OSError, UnicodeError) as exc:
            result.errors.append(ScanError(file_path=display, kind="input", message=str(exc)))
    result.findings = sorted({f.fingerprint: f for f in result.findings}.values(), key=lambda f: (f.file_path, f.line_start or 0, f.rule_id))
    result.risk_score, result.severity_counts = summarize(result.findings)
    if result.errors: result.status = "partial" if result.files_scanned else "error"
    return result

def result_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
