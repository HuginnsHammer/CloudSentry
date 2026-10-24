import json
from pathlib import Path

from typer.testing import CliRunner

from scanner.cli import app
from scanner.models import ScanError, ScanResult, ScanWarning, Severity
from scanner.rules.shared import make_finding
from scanner.sarif import result_sarif

runner = CliRunner()


def _finding(*, severity: Severity = Severity.HIGH, file_path: str = "infra/main.tf"):
    return make_finding(
        rule_id="CS-TF-002",
        title="Public ingress",
        description="Ingress accepts traffic from any address.",
        severity=severity,
        category="network-exposure",
        file_path=file_path,
        line=8,
        evidence='cidr_blocks = ["0.0.0.0/0"]',
        impact="The service may be reachable from untrusted networks.",
        remediation="Restrict the source CIDR.",
        resource="aws_security_group.web",
        confidence="high",
    )


def test_sarif_contains_rule_metadata_location_and_remediation():
    result = ScanResult(status="ok", files_scanned=1, findings=[_finding()])

    document = json.loads(result_sarif(result))
    run = document["runs"][0]
    finding = run["results"][0]

    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "CloudSentry"
    assert run["tool"]["driver"]["rules"][0]["id"] == "CS-TF-002"
    assert finding["ruleId"] == "CS-TF-002"
    assert finding["level"] == "error"
    location = finding["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "infra/main.tf"
    assert location["region"]["startLine"] == 8
    assert finding["properties"]["evidence"] == 'cidr_blocks = ["0.0.0.0/0"]'
    assert finding["properties"]["remediation"] == "Restrict the source CIDR."
    assert finding["partialFingerprints"]["cloudsentry/fingerprint"]


def test_sarif_maps_medium_severity_to_warning_and_keeps_suppression_reason():
    finding = _finding(severity=Severity.MEDIUM)
    finding.suppressed = True
    finding.suppression_reason = "Public endpoint is approved for this environment"
    result = ScanResult(status="ok", files_scanned=1, findings=[finding])

    output = json.loads(result_sarif(result))["runs"][0]["results"][0]

    assert output["level"] == "warning"
    assert output["suppressions"] == [
        {
            "kind": "inSource",
            "status": "accepted",
            "justification": "Public endpoint is approved for this environment",
        }
    ]


def test_sarif_preserves_scan_errors_and_warnings():
    result = ScanResult(
        status="partial",
        files_scanned=1,
        errors=[ScanError(file_path="broken.tf", kind="parse", message="invalid HCL")],
        warnings=[ScanWarning(file_path="Dockerfile", line_start=3, message="unused suppression")],
    )

    invocation = json.loads(result_sarif(result))["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is False
    notifications = invocation["toolExecutionNotifications"]
    assert [item["level"] for item in notifications] == ["error", "warning"]
    assert notifications[0]["message"]["text"] == "parse: invalid HCL"
    assert notifications[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_clean_scan_produces_valid_empty_sarif_run():
    document = json.loads(result_sarif(ScanResult(status="ok", files_scanned=2)))
    run = document["runs"][0]

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert run["invocations"][0]["executionSuccessful"] is True


def test_cli_writes_sarif_report_and_keeps_findings_exit_code(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER root\n", encoding="utf-8"
    )
    report = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "sarif", "--output", str(report)],
    )

    assert result.exit_code == 1
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"
    assert {item["ruleId"] for item in document["runs"][0]["results"]} == {"CS-DKR-001"}



def test_cli_sarif_preserves_partial_scan_diagnostics_and_exit_code(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\\nUSER root\\n", encoding="utf-8"
    )
    (tmp_path / "broken.tf").write_text(
        'resource "aws_ebs_volume" "broken" {', encoding="utf-8"
    )
    report = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "sarif", "--output", str(report)],
    )

    assert result.exit_code == 2
    document = json.loads(report.read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["properties"]["scanStatus"] == "partial"
    assert {item["ruleId"] for item in run["results"]} == {"CS-DKR-001"}
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert any(
        notification["level"] == "error"
        and "parse" in notification["message"]["text"]
        for notification in invocation["toolExecutionNotifications"]
    )


def test_cli_sarif_keeps_suppressed_findings_and_justification(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\\n"
        "# cloudsentry:ignore CS-DKR-001 -- build stage only\\n"
        "USER root\\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "sarif", "--output", str(report)],
    )

    assert result.exit_code == 0
    finding = json.loads(report.read_text(encoding="utf-8"))["runs"][0]["results"][0]
    assert finding["ruleId"] == "CS-DKR-001"
    assert finding["suppressions"][0]["status"] == "accepted"
    assert finding["suppressions"][0]["justification"] == "build stage only"
