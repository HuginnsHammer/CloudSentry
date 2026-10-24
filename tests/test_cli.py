"""Exit-code contract: 0 clean, 1 findings, 2 anything that could not be scanned."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()

CLEAN_DOCKERFILE = "FROM python:3.12-slim\nUSER app\n"
LATEST_ONLY_DOCKERFILE = "FROM python:latest\nUSER app\n"  # one MEDIUM finding
ROOT_DOCKERFILE = "FROM python:3.12-slim\nUSER root\n"  # one HIGH finding
BROKEN_TERRAFORM = 'resource "aws_ebs_volume" "x" {'


def _run(*args: object):
    return runner.invoke(app, ["scan", *[str(arg) for arg in args]])


def test_clean_scan_exits_zero(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path).exit_code == 0


def test_findings_exit_one(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(ROOT_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path).exit_code == 1


def test_unparseable_file_alone_exits_two(tmp_path: Path):
    (tmp_path / "broken.tf").write_text(BROKEN_TERRAFORM, encoding="utf-8")
    assert _run(tmp_path).exit_code == 2


def test_unparseable_file_next_to_a_clean_file_still_exits_two(tmp_path: Path):
    """Regression: this used to exit 0, so a CI gate passed with part of the target unscanned."""
    (tmp_path / "broken.tf").write_text(BROKEN_TERRAFORM, encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path).exit_code == 2


def test_scan_errors_take_precedence_over_findings(tmp_path: Path):
    (tmp_path / "broken.tf").write_text(BROKEN_TERRAFORM, encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(ROOT_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path).exit_code == 2


def test_oversized_file_exits_two(tmp_path: Path):
    (tmp_path / "Dockerfile").write_bytes(b"#" * (2 * 1024 * 1024 + 1))
    assert _run(tmp_path).exit_code == 2


def test_json_report_lists_the_errors_that_caused_exit_two(tmp_path: Path):
    (tmp_path / "broken.tf").write_text(BROKEN_TERRAFORM, encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE, encoding="utf-8")
    report = tmp_path / "report.json"

    result = _run(tmp_path, "--format", "json", "--output", report)

    assert result.exit_code == 2
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["status"] == "partial"
    assert [error["kind"] for error in data["errors"]] == ["parse"]


@pytest.mark.parametrize(
    ("threshold", "expected_exit"),
    [("info", 1), ("medium", 1), ("high", 0), ("critical", 0)],
)
def test_severity_threshold_controls_exit_code(tmp_path: Path, threshold: str, expected_exit: int):
    (tmp_path / "Dockerfile").write_text(LATEST_ONLY_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path, "--severity", threshold).exit_code == expected_exit


def test_misuse_exits_two(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE, encoding="utf-8")
    assert _run(tmp_path, "--format", "xml").exit_code == 2
    assert _run(tmp_path, "--severity", "urgent").exit_code == 2
    assert _run(tmp_path / "does-not-exist").exit_code == 2


SUPPRESSED_ROOT_DOCKERFILE = (
    "FROM python:3.12-slim\n# cloudsentry:ignore CS-DKR-001 -- build stage only\nUSER root\n"
)


def test_suppressed_finding_does_not_fail_the_gate_but_stays_in_the_json_report(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(SUPPRESSED_ROOT_DOCKERFILE, encoding="utf-8")
    report = tmp_path / "report.json"

    result = _run(tmp_path, "--format", "json", "--output", report)

    assert result.exit_code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    (finding,) = data["findings"]
    assert finding["rule_id"] == "CS-DKR-001"
    assert finding["suppressed"] is True
    assert finding["suppression_reason"] == "build stage only"
    assert data["risk_score"] == 0
    assert data["severity_counts"]["high"] == 0


def test_text_report_counts_suppressed_findings_without_listing_them(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(SUPPRESSED_ROOT_DOCKERFILE, encoding="utf-8")
    result = _run(tmp_path)
    assert result.exit_code == 0
    assert "1 suppressed finding(s)" in result.stdout
    assert "CS-DKR-001" not in result.stdout


def test_unused_directive_is_a_warning_not_a_failure(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nUSER app\n# cloudsentry:ignore CS-DKR-001 -- stale\nRUN true\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.json"

    assert _run(tmp_path).stdout.count("warning:") == 1
    result = _run(tmp_path, "--format", "json", "--output", report)

    assert result.exit_code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert [warning["line_start"] for warning in data["warnings"]] == [3]



def test_directory_without_supported_files_exits_two(tmp_path: Path):
    (tmp_path / "README.md").write_text("Nothing to scan here.\n", encoding="utf-8")
    assert _run(tmp_path).exit_code == 2


def test_explicit_unsupported_file_exits_two(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text("Nothing to scan here.\n", encoding="utf-8")
    assert _run(readme).exit_code == 2
