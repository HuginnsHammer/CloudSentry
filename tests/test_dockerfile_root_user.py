from scanner.models import Severity
from scanner.rules.dockerfile import scan_dockerfile


def test_root_username_and_uid_group_forms_are_detected():
    for instruction in ("USER root", "USER root:root", "USER 0", "USER 0:0"):
        findings = scan_dockerfile(
            f"FROM alpine:3.20\n{instruction}\n",
            "Dockerfile",
        )
        root_findings = [finding for finding in findings if finding.rule_id == "CS-DKR-001"]

        assert len(root_findings) == 1, instruction
        assert root_findings[0].severity == Severity.HIGH
        assert root_findings[0].line_start == 2


def test_non_root_user_with_group_is_not_reported_as_root():
    findings = scan_dockerfile(
        "FROM alpine:3.20\nUSER app:app\n",
        "Dockerfile",
    )

    assert not any(finding.rule_id == "CS-DKR-001" for finding in findings)
    assert not any(finding.rule_id == "CS-DKR-003" for finding in findings)
