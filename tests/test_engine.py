from pathlib import Path
from scanner.engine import scan_paths


def test_directory_scan_and_parse_error(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\n", encoding="utf-8")
    (tmp_path / "broken.tf").write_text('resource "x" {', encoding="utf-8")
    result = scan_paths([tmp_path])
    assert result.files_scanned == 1
    assert any(f.rule_id == "CS-DKR-002" for f in result.findings)
    assert result.errors and result.status == "partial"


def test_oversized_file_is_reported(tmp_path: Path):
    file = tmp_path / "Dockerfile"
    file.write_bytes(b"#" * (2 * 1024 * 1024 + 1))
    result = scan_paths([file])
    assert result.errors[0].kind == "input"
    assert result.files_scanned == 0


def test_suppressed_finding_is_kept_with_its_reason_and_excluded_from_the_score(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n# cloudsentry:ignore CS-DKR-001 -- build stage only\nUSER root\n",
        encoding="utf-8",
    )
    result = scan_paths([tmp_path])
    (finding,) = result.findings
    assert finding.rule_id == "CS-DKR-001"
    assert finding.suppressed
    assert finding.suppression_reason == "build stage only"
    assert result.risk_score == 0
    assert result.severity_counts["high"] == 0
    assert result.warnings == []


def test_unused_directive_becomes_a_warning_with_file_and_line(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\nUSER app\n# cloudsentry:ignore CS-DKR-001 -- stale\nRUN true\n",
        encoding="utf-8",
    )
    result = scan_paths([tmp_path])
    (warning,) = result.warnings
    assert warning.file_path == str(dockerfile)
    assert warning.line_start == 3
    assert result.status == "ok"



def test_directory_without_supported_files_is_an_error(tmp_path: Path):
    (tmp_path / "README.md").write_text("Nothing to scan here.\n", encoding="utf-8")

    result = scan_paths([tmp_path])

    assert result.status == "error"
    assert result.files_scanned == 0
    assert len(result.errors) == 1
    assert result.errors[0].kind == "discovery"
    assert "No supported configuration files" in result.errors[0].message


def test_unrelated_yaml_is_not_counted_as_a_successful_scan(tmp_path: Path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("apiVersion: v1\nkind: ConfigMap\n", encoding="utf-8")

    result = scan_paths([manifest])

    assert result.status == "error"
    assert result.files_scanned == 0
    assert result.errors[0].kind == "unsupported"
    assert "not a Docker Compose document" in result.errors[0].message


def test_explicit_unsupported_file_prevents_a_false_clean_result(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\nUSER app\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("Not a scan target.\n", encoding="utf-8")

    result = scan_paths([dockerfile, readme])

    assert result.status == "partial"
    assert result.files_scanned == 1
    assert any(error.kind == "unsupported" and error.file_path == str(readme) for error in result.errors)



def test_nonexistent_scan_path_is_an_error(tmp_path: Path):
    missing = tmp_path / "missing"

    result = scan_paths([missing])

    assert result.status == "error"
    assert result.files_scanned == 0
    assert result.errors[0].kind == "input"
    assert result.errors[0].file_path == str(missing)
