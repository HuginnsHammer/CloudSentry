"""File discovery, safe parsing, rule dispatch, and result normalization."""
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
from scanner.suppression import apply_suppressions, directive_warnings

MAX_FILE_BYTES = 2 * 1024 * 1024

def detect_kind(path: Path) -> str | None:
    if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
        return "dockerfile"
    if path.suffix.lower() == ".tf":
        return "terraform"
    if path.suffix.lower() in {".yaml", ".yml"}:
        return "yaml"
    return None

def discover(paths: Iterable[Path]) -> list[Path]:
    found: set[Path] = set()
    for item in paths:
        if item.is_file():
            if detect_kind(item):
                found.add(item)
        elif item.is_dir():
            for candidate in item.rglob("*"):
                excluded = {".git", ".venv", "node_modules"}
                if candidate.is_file() and detect_kind(candidate) and not any(p in excluded for p in candidate.parts):
                    found.add(candidate)
    return sorted(found)

def scan_paths(paths: Iterable[Path]) -> ScanResult:
    result = ScanResult(status="ok")
    requested = list(paths)
    discovered = discover(requested)

    # Never report a clean scan when the requested target contained no supported files.
    # Explicit unsupported files are errors; unsupported files inside a directory are
    # ignored unless the directory contains no supported configuration at all.
    if not requested:
        result.errors.append(
            ScanError(
                file_path=".",
                kind="discovery",
                message="No scan paths were provided.",
            )
        )
    for item in requested:
        if item.is_file() and detect_kind(item) is None:
            result.errors.append(
                ScanError(
                    file_path=str(item),
                    kind="unsupported",
                    message="Unsupported file type. Expected a Dockerfile, .tf, .yaml, or .yml Compose file.",
                )
            )
        elif item.is_dir() and not any(
            candidate == item or item in candidate.parents for candidate in discovered
        ):
            result.errors.append(
                ScanError(
                    file_path=str(item),
                    kind="discovery",
                    message="No supported configuration files found in this directory.",
                )
            )
    if not requested:
        result.status = "error"
        return result

    for path in discovered:
        display = str(path)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                result.errors.append(ScanError(file_path=display, kind="input", message=f"File exceeds {MAX_FILE_BYTES} byte limit"))
                continue
            source = path.read_text(encoding="utf-8")
            kind = detect_kind(path)
            current = []
            if kind == "dockerfile":
                current = scan_dockerfile(source, display)
            elif kind == "terraform":
                try:
                    parsed = hcl2.loads(source)
                except Exception as exc:
                    result.errors.append(ScanError(file_path=display, kind="parse", message=f"Terraform parse failed: {exc}"))
                    continue
                current = scan_terraform(source, display, parsed)
            elif kind == "yaml":
                try:
                    data = yaml.safe_load(source)
                except yaml.YAMLError as exc:
                    result.errors.append(ScanError(file_path=display, kind="parse", message=f"YAML parse failed: {exc}"))
                    continue
                if not isinstance(data, dict) or "services" not in data:
                    result.errors.append(
                        ScanError(
                            file_path=display,
                            kind="unsupported",
                            message="YAML file is not a Docker Compose document with a top-level services mapping",
                        )
                    )
                    continue
                if not isinstance(data["services"], dict):
                    result.errors.append(
                        ScanError(
                            file_path=display,
                            kind="parse",
                            message="Docker Compose 'services' must be a mapping",
                        )
                    )
                    continue
                current = scan_compose(data, display, source)
            result.findings.extend(apply_suppressions(current, source))
            result.warnings.extend(directive_warnings(current, source, display))
            result.files_scanned += 1
        except (OSError, UnicodeError) as exc:
            result.errors.append(ScanError(file_path=display, kind="input", message=str(exc)))
    result.findings = sorted(
        {finding.fingerprint: finding for finding in result.findings}.values(),
        key=lambda finding: (finding.file_path, finding.line_start or 0, finding.rule_id),
    )
    result.risk_score, result.severity_counts = summarize(result.findings)
    if result.errors:
        result.status = "partial" if result.files_scanned else "error"
    return result

def result_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
