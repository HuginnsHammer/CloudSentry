import hcl2
import yaml

from scanner.rules.compose import scan_compose
from scanner.rules.dockerfile import scan_dockerfile
from scanner.rules.terraform import scan_terraform
from scanner.suppression import apply_suppressions, directive_warnings


def _dockerfile(source: str):
    findings = scan_dockerfile(source, "Dockerfile")
    return apply_suppressions(findings, source)


def _by_rule(findings):
    return {finding.rule_id: finding for finding in findings}


def test_suppression_requires_reason_and_matches_adjacent_line():
    source = "# cloudsentry:ignore CS-DKR-001 -- accepted in isolated build image\nUSER root\n"
    finding = _by_rule(_dockerfile(source))["CS-DKR-001"]
    assert finding.suppressed is True
    assert finding.suppression_reason == "accepted in isolated build image"


def test_suppression_does_not_hide_other_rules_on_the_same_line():
    # CS-DKR-002 (latest tag) and CS-DKR-003 (no USER) are both reported on the FROM line.
    source = (
        "# cloudsentry:ignore CS-DKR-002 -- pinned by the registry mirror\nFROM ubuntu:latest\n"
    )
    findings = _by_rule(_dockerfile(source))
    assert findings["CS-DKR-002"].suppressed
    assert not findings["CS-DKR-003"].suppressed


def test_suppression_without_reason_is_ignored_and_reported():
    source = "# cloudsentry:ignore CS-DKR-001\nUSER root\n"
    findings = scan_dockerfile(source, "Dockerfile")
    assert not _by_rule(apply_suppressions(findings, source))["CS-DKR-001"].suppressed
    warnings = directive_warnings(findings, source, "Dockerfile")
    assert [(w.line_start, "reason is required" in w.message) for w in warnings] == [(1, True)]


def test_directive_does_not_reach_past_intervening_code():
    """Regression: a directive used to suppress the next matching finding at any distance."""
    source = (
        "# cloudsentry:ignore CS-DKR-001 -- documented exception\nFROM ubuntu:latest\nUSER root\n"
    )
    findings = scan_dockerfile(source, "Dockerfile")
    by_rule = _by_rule(apply_suppressions(findings, source))
    assert not by_rule["CS-DKR-001"].suppressed
    assert not by_rule["CS-DKR-002"].suppressed
    (warning,) = directive_warnings(findings, source, "Dockerfile")
    assert warning.line_start == 1
    assert "no matching finding on line 2" in warning.message


def test_blank_and_comment_lines_between_directive_and_code_are_skipped():
    source = (
        "FROM python:3.12\n"
        "# cloudsentry:ignore CS-DKR-001 -- build stage only\n"
        "\n"
        "# an ordinary comment\n"
        "USER root\n"
    )
    assert _by_rule(_dockerfile(source))["CS-DKR-001"].suppressed


def test_stacked_directives_apply_to_the_same_line():
    source = (
        "# cloudsentry:ignore CS-DKR-002 -- mirror pins the tag\n"
        "# cloudsentry:ignore CS-DKR-003 -- user set by entrypoint\n"
        "FROM ubuntu:latest\n"
    )
    findings = _dockerfile(source)
    assert {f.rule_id for f in findings} == {"CS-DKR-002", "CS-DKR-003"}
    assert all(f.suppressed for f in findings)


def test_trailing_directive_applies_to_its_own_line():
    source = "FROM python:3.12\nUSER root  # cloudsentry:ignore CS-DKR-001 -- build stage only\n"
    finding = _by_rule(_dockerfile(source))["CS-DKR-001"]
    assert finding.suppressed
    assert finding.suppression_reason == "build stage only"


def test_all_suppresses_every_rule_reported_on_the_target_line():
    source = "# cloudsentry:ignore ALL -- legacy image, tracked in TICKET-1\nFROM ubuntu:latest\n"
    assert all(f.suppressed for f in _dockerfile(source))


def test_directive_text_inside_a_string_is_not_a_directive():
    source = 'FROM python:3.12\nRUN echo "# cloudsentry:ignore CS-DKR-001 -- nope"\nUSER root\n'
    assert not _by_rule(_dockerfile(source))["CS-DKR-001"].suppressed


def test_unused_directive_is_reported_with_its_line():
    source = "FROM python:3.12\nUSER app\n# cloudsentry:ignore CS-DKR-001 -- stale\nRUN true\n"
    findings = scan_dockerfile(source, "Dockerfile")
    (warning,) = directive_warnings(findings, source, "Dockerfile")
    assert warning.line_start == 3
    assert "Unused cloudsentry:ignore CS-DKR-001" in warning.message


def test_directive_with_no_code_after_it_is_reported():
    source = "FROM python:3.12\nUSER app\n# cloudsentry:ignore CS-DKR-001 -- trailing\n"
    (warning,) = directive_warnings([], source, "Dockerfile")
    assert "no code follows it" in warning.message


def test_used_directive_produces_no_warning():
    source = "# cloudsentry:ignore CS-DKR-001 -- ok\nUSER root\n"
    findings = scan_dockerfile(source, "Dockerfile")
    assert directive_warnings(findings, source, "Dockerfile") == []


def test_terraform_directive_suppresses_only_the_group_it_sits_above():
    source = """resource "aws_security_group" "web" {
  ingress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "ssh" {
  ingress {
    protocol    = "tcp"
    # cloudsentry:ignore CS-TF-002 -- bastion reachable only through the VPN gateway
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    findings = apply_suppressions(scan_terraform(source, "main.tf", hcl2.loads(source)), source)
    assert {f.resource: f.suppressed for f in findings} == {
        "aws_security_group.web": False,
        "aws_security_group.ssh": True,
    }


def test_compose_directive_suppresses_only_the_service_it_sits_above():
    source = """services:
  web:
    image: nginx
    privileged: true
  worker:
    image: busybox
    # cloudsentry:ignore CS-CMP-001 -- needs raw device access for the lab
    privileged: true
"""
    findings = apply_suppressions(scan_compose(yaml.safe_load(source), "c.yml", source), source)
    assert {f.resource: f.suppressed for f in findings} == {"web": False, "worker": True}
