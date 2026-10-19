"""Findings must point at the line of the offending resource, not the first textual match."""

from pathlib import Path

import hcl2
import yaml

from scanner.engine import scan_paths
from scanner.rules.compose import scan_compose
from scanner.rules.terraform import scan_terraform

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _tf(source: str):
    return scan_terraform(source, "main.tf", hcl2.loads(source))


def _compose(source: str):
    return scan_compose(yaml.safe_load(source), "compose.yml", source)


def _lines(findings, rule_id: str) -> dict[str, int | None]:
    return {f.resource: f.line_start for f in findings if f.rule_id == rule_id}


def test_unencrypted_volume_reports_its_own_line_not_an_earlier_encrypted_one():
    source = """resource "aws_ebs_volume" "good" {
  size      = 8
  encrypted = true
}
resource "aws_ebs_volume" "bad" {
  size      = 8
  encrypted = false
}
"""
    assert _lines(_tf(source), "CS-TF-003") == {"aws_ebs_volume.bad": 7}


def test_commented_out_attribute_is_ignored_when_locating_a_finding():
    source = """resource "aws_ebs_volume" "bad" {
  # encrypted = true
  encrypted = false
}
"""
    assert _lines(_tf(source), "CS-TF-003") == {"aws_ebs_volume.bad": 3}


def test_each_security_group_reports_its_own_cidr_line():
    source = """resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    assert _lines(_tf(source), "CS-TF-002") == {
        "aws_security_group.web": 6,
        "aws_security_group.ssh": 14,
    }


def test_multiple_ingress_blocks_in_one_group_map_to_their_own_blocks():
    source = """resource "aws_security_group" "mixed" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
    findings = [f for f in _tf(source) if f.rule_id == "CS-TF-002"]
    assert [f.line_start for f in findings] == [12, 18]


def test_cidr_in_a_comment_does_not_attract_the_finding():
    source = """resource "aws_security_group_rule" "ssh" {
  # was "0.0.0.0/0" before the audit
  type        = "ingress"
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
"""
    assert _lines(_tf(source), "CS-TF-002") == {"aws_security_group_rule.ssh": 5}


def test_public_acl_reports_its_own_resource_header():
    source = """resource "aws_s3_bucket_acl" "private" {
  acl = "private"
}
resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}
"""
    assert _lines(_tf(source), "CS-TF-001") == {"aws_s3_bucket_acl.public": 4}


def test_braces_in_strings_and_comments_do_not_end_a_block_early():
    source = """resource "aws_ebs_volume" "tricky" {
  tags = { Name = "closing } brace in a string" } # } and another in a comment
  /* a block comment with } inside */
  encrypted = false
}
"""
    assert _lines(_tf(source), "CS-TF-003") == {"aws_ebs_volume.tricky": 4}


def test_compose_findings_point_at_the_right_service():
    source = """services:
  web:
    image: nginx
    privileged: true
    network_mode: host
  worker:
    image: busybox
    privileged: true
  db:
    image: postgres
    privileged: false
"""
    findings = _compose(source)
    assert _lines(findings, "CS-CMP-001") == {"web": 4, "worker": 8}
    assert _lines(findings, "CS-CMP-002") == {"web": 5}


def test_compose_socket_and_wildcard_ports_report_the_matching_list_item():
    source = """services:
  proxy:
    image: nginx
    ports:
      - "127.0.0.1:8080:80"
      - "0.0.0.0:8443:443"
    volumes:
      - ./conf:/etc/nginx
      - /var/run/docker.sock:/var/run/docker.sock
  agent:
    image: busybox
    ports:
      - "0.0.0.0:9000:9000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
"""
    findings = _compose(source)
    assert _lines(findings, "CS-CMP-004") == {"proxy": 6, "agent": 13}
    assert _lines(findings, "CS-CMP-003") == {"proxy": 9, "agent": 15}


def test_examples_have_exact_line_numbers():
    result = scan_paths([EXAMPLES])
    actual = {(Path(f.file_path).name, f.rule_id, f.line_start) for f in result.findings}
    assert actual == {
        ("docker-compose.vulnerable.yml", "CS-CMP-001", 4),
        ("docker-compose.vulnerable.yml", "CS-CMP-002", 5),
        ("docker-compose.vulnerable.yml", "CS-CMP-004", 7),
        ("docker-compose.vulnerable.yml", "CS-CMP-003", 9),
        ("Dockerfile.vulnerable", "CS-DKR-002", 1),
        ("Dockerfile.vulnerable", "CS-DKR-001", 2),
        ("storage.vulnerable.tf", "CS-TF-001", 1),
        ("storage.vulnerable.tf", "CS-TF-003", 8),
    }
