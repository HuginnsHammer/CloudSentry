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
    source = "services:\n  app:\n    privileged: true\n    ports:\n      - \"0.0.0.0:8080:80\"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    data = {"services": {"app": {"privileged": True, "ports": ["0.0.0.0:8080:80"], "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}}}
    findings = scan_compose(data, "compose.yml", source)
    assert {f.rule_id for f in findings} == {"CS-CMP-001", "CS-CMP-003", "CS-CMP-004"}
    assert any(f.severity == Severity.CRITICAL for f in findings)

def test_terraform_public_acl():
    parsed = {"resource": [{"aws_s3_bucket_acl": [{"assets": {"acl": "public-read"}}]}]}
    findings = scan_terraform('resource "aws_s3_bucket_acl" "assets" { acl = "public-read" }', "main.tf", parsed)
    assert [f.rule_id for f in findings] == ["CS-TF-001"]

def test_secure_terraform_acl_does_not_trigger():
    parsed = {"resource": [{"aws_s3_bucket_acl": [{"assets": {"acl": "private"}}]}]}
    assert scan_terraform('resource "aws_s3_bucket_acl" "assets" { acl = "private" }', "main.tf", parsed) == []
