import hcl2

from scanner.models import Severity
from scanner.rules.compose import scan_compose
from scanner.rules.dockerfile import scan_dockerfile
from scanner.rules.terraform import scan_terraform


def test_dockerfile_root_and_latest():
    findings = scan_dockerfile("FROM ubuntu:latest\nUSER root\n", "Dockerfile")
    assert {"CS-DKR-001", "CS-DKR-002"} <= {f.rule_id for f in findings}
    assert all(f.fingerprint for f in findings)


def test_secure_dockerfile_has_no_findings():
    assert scan_dockerfile("FROM python:3.12-slim\nUSER app\n", "Dockerfile") == []


def test_compose_privileged_socket_and_wildcard_port():
    source = (
        "services:\n  app:\n    privileged: true\n    ports:\n"
        '      - "0.0.0.0:8080:80"\n    volumes:\n'
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
    )
    data = {
        "services": {
            "app": {
                "privileged": True,
                "ports": ["0.0.0.0:8080:80"],
                "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
            }
        }
    }
    findings = scan_compose(data, "compose.yml", source)
    assert {f.rule_id for f in findings} == {"CS-CMP-001", "CS-CMP-003", "CS-CMP-004"}
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_terraform_public_acl():
    parsed = {"resource": [{"aws_s3_bucket_acl": [{"assets": {"acl": "public-read"}}]}]}
    findings = scan_terraform(
        'resource "aws_s3_bucket_acl" "assets" { acl = "public-read" }', "main.tf", parsed
    )
    assert [f.rule_id for f in findings] == ["CS-TF-001"]


def test_secure_terraform_acl_does_not_trigger():
    parsed = {"resource": [{"aws_s3_bucket_acl": [{"assets": {"acl": "private"}}]}]}
    assert (
        scan_terraform(
            'resource "aws_s3_bucket_acl" "assets" { acl = "private" }', "main.tf", parsed
        )
        == []
    )


def test_inline_security_group_ingress_world_open_is_detected():
    source = '''resource "aws_security_group" "test" {
  name = "cloudsentry-test"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    parsed = hcl2.loads(source)
    findings = scan_terraform(source, "main.tf", parsed)
    matches = [finding for finding in findings if finding.rule_id == "CS-TF-002"]
    assert len(matches) == 1
    assert matches[0].resource == "aws_security_group.test"
    assert matches[0].severity == Severity.HIGH
    assert matches[0].line_start == 7
    assert "0.0.0.0/0" in matches[0].evidence


def test_restricted_inline_security_group_ingress_is_not_reported():
    source = '''resource "aws_security_group" "test" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    assert not any(finding.rule_id == "CS-TF-002" for finding in findings)


def test_world_open_egress_is_not_reported_as_ingress_exposure():
    source = '''resource "aws_security_group_rule" "egress" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    assert not any(finding.rule_id == "CS-TF-002" for finding in findings)


def test_legacy_standalone_ingress_rule_is_detected():
    source = '''resource "aws_security_group_rule" "public" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    assert [finding.rule_id for finding in findings] == ["CS-TF-002"]


def test_modern_ipv6_ingress_rule_is_detected():
    source = '''resource "aws_vpc_security_group_ingress_rule" "public" {
  security_group_id = "sg-example"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv6          = "::/0"
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    matches = [finding for finding in findings if finding.rule_id == "CS-TF-002"]
    assert len(matches) == 1
    assert "::/0" in matches[0].evidence



def test_compose_port_without_host_ip_is_reported_as_wildcard_binding():
    source = 'services:\n  app:\n    ports:\n      - "8080:80"\n'
    data = {"services": {"app": {"ports": ["8080:80"]}}}
    findings = scan_compose(data, "compose.yml", source)
    matches = [finding for finding in findings if finding.rule_id == "CS-CMP-004"]
    assert len(matches) == 1
    assert matches[0].line_start == 4
    assert matches[0].evidence == "8080:80"


def test_compose_loopback_port_binding_is_not_reported():
    source = 'services:\n  app:\n    ports:\n      - "127.0.0.1:8080:80"\n'
    data = {"services": {"app": {"ports": ["127.0.0.1:8080:80"]}}}
    findings = scan_compose(data, "compose.yml", source)
    assert not any(finding.rule_id == "CS-CMP-004" for finding in findings)


def test_compose_container_port_only_is_not_reported_as_host_published():
    source = 'services:\n  app:\n    ports:\n      - "80"\n'
    data = {"services": {"app": {"ports": ["80"]}}}
    findings = scan_compose(data, "compose.yml", source)
    assert not any(finding.rule_id == "CS-CMP-004" for finding in findings)



def test_terraform_bucket_resource_public_acl_is_detected_at_acl_line():
    source = '''resource "aws_s3_bucket" "assets" {
  bucket = "cloudsentry-example-assets"
  acl    = "public-read"
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    matches = [finding for finding in findings if finding.rule_id == "CS-TF-001"]
    assert len(matches) == 1
    assert matches[0].resource == "aws_s3_bucket.assets"
    assert matches[0].line_start == 3
    assert matches[0].severity == Severity.CRITICAL


def test_terraform_bucket_resource_private_acl_is_not_reported():
    source = '''resource "aws_s3_bucket" "assets" {
  bucket = "cloudsentry-example-assets"
  acl    = "private"
}
'''
    findings = scan_terraform(source, "main.tf", hcl2.loads(source))
    assert not any(finding.rule_id == "CS-TF-001" for finding in findings)



def test_compose_long_port_mapping_without_host_ip_is_reported():
    source = '''services:
  app:
    ports:
      - target: 80
        published: "8080"
'''
    data = {
        "services": {
            "app": {"ports": [{"target": 80, "published": "8080"}]}
        }
    }

    findings = scan_compose(data, "compose.yml", source)
    matches = [finding for finding in findings if finding.rule_id == "CS-CMP-004"]

    assert len(matches) == 1
    assert matches[0].line_start == 5
    assert "published=8080" in matches[0].evidence
    assert "default (all interfaces)" in matches[0].evidence


def test_compose_long_port_mapping_explicit_wildcard_is_reported_at_host_ip():
    source = '''services:
  app:
    ports:
      - target: 80
        published: "8080"
        host_ip: "0.0.0.0"
'''
    data = {
        "services": {
            "app": {
                "ports": [
                    {"target": 80, "published": "8080", "host_ip": "0.0.0.0"}
                ]
            }
        }
    }

    findings = scan_compose(data, "compose.yml", source)
    matches = [finding for finding in findings if finding.rule_id == "CS-CMP-004"]

    assert len(matches) == 1
    assert matches[0].line_start == 6
    assert "host_ip=0.0.0.0" in matches[0].evidence


def test_compose_long_port_mapping_loopback_is_not_reported():
    source = '''services:
  app:
    ports:
      - target: 80
        published: "8080"
        host_ip: "127.0.0.1"
'''
    data = {
        "services": {
            "app": {
                "ports": [
                    {"target": 80, "published": "8080", "host_ip": "127.0.0.1"}
                ]
            }
        }
    }

    findings = scan_compose(data, "compose.yml", source)
    assert not any(finding.rule_id == "CS-CMP-004" for finding in findings)


def test_compose_long_port_mapping_without_published_port_is_not_reported():
    source = '''services:
  app:
    ports:
      - target: 80
'''
    data = {"services": {"app": {"ports": [{"target": 80}]}}}

    findings = scan_compose(data, "compose.yml", source)
    assert not any(finding.rule_id == "CS-CMP-004" for finding in findings)
