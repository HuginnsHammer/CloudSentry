"""SARIF 2.1.0 serialization for CloudSentry scan results."""

import json
from pathlib import Path
from urllib.parse import quote

from scanner.models import Finding, ScanResult, Severity

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _artifact_uri(file_path: str) -> str:
    """Return a repository-relative URI when possible, otherwise an absolute file URI."""
    path = Path(file_path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            return path.resolve().as_uri()
    return quote(path.as_posix(), safe="/-._~")


def _rule_descriptor(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _LEVELS[finding.severity]},
        "properties": {"category": finding.category},
    }


def _finding_result(finding: Finding, rule_index: int) -> dict[str, object]:
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": _artifact_uri(finding.file_path)}
    }
    if finding.line_start is not None and finding.line_start > 0:
        region: dict[str, int] = {"startLine": finding.line_start}
        if finding.line_end is not None and finding.line_end >= finding.line_start:
            region["endLine"] = finding.line_end
        physical_location["region"] = region

    properties: dict[str, object] = {
        "category": finding.category,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "impact": finding.impact,
        "remediation": finding.remediation,
    }
    if finding.resource:
        properties["resource"] = finding.resource

    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": f"{finding.title}: {finding.description}"},
        "locations": [{"physicalLocation": physical_location}],
        "partialFingerprints": {"cloudsentry/fingerprint": finding.fingerprint},
        "properties": properties,
    }
    if finding.suppressed:
        suppression: dict[str, str] = {"kind": "inSource", "status": "accepted"}
        if finding.suppression_reason:
            suppression["justification"] = finding.suppression_reason
        result["suppressions"] = [suppression]
    return result


def result_sarif(result: ScanResult) -> str:
    """Serialize scan findings and scan diagnostics as a SARIF 2.1.0 document."""
    unique_rules: dict[str, Finding] = {}
    for finding in sorted(result.findings, key=lambda item: (item.rule_id, item.title)):
        unique_rules.setdefault(finding.rule_id, finding)
    rules = list(unique_rules.values())
    rule_indices = {finding.rule_id: index for index, finding in enumerate(rules)}

    notifications: list[dict[str, object]] = []
    for error in result.errors:
        notification: dict[str, object] = {
            "level": "error",
            "message": {"text": f"{error.kind}: {error.message}"},
            "properties": {"kind": error.kind},
        }
        if error.file_path:
            notification["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": _artifact_uri(error.file_path)}}}
            ]
        notifications.append(notification)
    for warning in result.warnings:
        notification: dict[str, object] = {
            "level": "warning",
            "message": {"text": warning.message},
            "properties": {"kind": "scan-warning"},
        }
        location: dict[str, object] = {
            "artifactLocation": {"uri": _artifact_uri(warning.file_path)}
        }
        if warning.line_start is not None and warning.line_start > 0:
            location["region"] = {"startLine": warning.line_start}
        notification["locations"] = [{"physicalLocation": location}]
        notifications.append(notification)

    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "CloudSentry",
                "version": result.scanner_version,
                "informationUri": "https://github.com/HuginnsHammer/CloudSentry",
                "rules": [_rule_descriptor(finding) for finding in rules],
            }
        },
        "results": [
            _finding_result(finding, rule_indices[finding.rule_id])
            for finding in result.findings
        ],
        "invocations": [
            {
                "executionSuccessful": not result.errors,
                "toolExecutionNotifications": notifications,
            }
        ],
        "properties": {
            "scanStatus": result.status,
            "filesScanned": result.files_scanned,
            "riskScore": result.risk_score,
            "severityCounts": result.severity_counts,
        },
    }
    document = {"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(document, indent=2, sort_keys=True)
