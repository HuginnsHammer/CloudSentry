from typing import Any
from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding

def _line(text: str, needle: str) -> int | None:
    return next((i for i, line in enumerate(text.splitlines(), 1) if needle in line), None)

def scan_terraform(text: str, path: str, parsed: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for block in parsed.get("resource", []) or []:
        if not isinstance(block, dict): continue
        for resource_type, instances in block.items():
            if not isinstance(instances, list): continue
            for instance in instances:
                if not isinstance(instance, dict): continue
                for name, attrs in instance.items():
                    if not isinstance(attrs, dict): continue
                    resource = f"{resource_type}.{name}"
                    if resource_type == "aws_s3_bucket_acl" and str(attrs.get("acl", "")).lower() in {"public-read", "public-read-write"}:
                        findings.append(make_finding(rule_id="CS-TF-001", title="S3 bucket ACL allows public access", description="An S3 ACL explicitly grants public read or write access.", severity=Severity.CRITICAL, category="cloud-storage", file_path=path, line=_line(text, "aws_s3_bucket_acl"), resource=resource, evidence=f"acl = {attrs.get('acl')}", impact="Objects may be exposed or modified publicly depending on effective bucket settings.", remediation="Remove public ACL grants and enforce S3 Block Public Access and least-privilege bucket policies."))
                    if resource_type == "aws_security_group_rule" and isinstance(attrs.get("cidr_blocks"), list) and "0.0.0.0/0" in attrs["cidr_blocks"]:
                        findings.append(make_finding(rule_id="CS-TF-002", title="Security group rule allows all IPv4 sources", description="Rule contains a world-open IPv4 CIDR; direction and port context need review.", severity=Severity.HIGH, category="network-exposure", file_path=path, line=_line(text, "0.0.0.0/0"), resource=resource, evidence=f"cidr_blocks = {attrs['cidr_blocks']}", impact="If this is ingress, services may be reachable from any IPv4 address.", remediation="Restrict source CIDRs and ports to the smallest justified set.", confidence="medium"))
                    if resource_type == "aws_ebs_volume" and attrs.get("encrypted") is False:
                        findings.append(make_finding(rule_id="CS-TF-003", title="EBS volume encryption explicitly disabled", description="The resource sets encrypted = false.", severity=Severity.HIGH, category="data-protection", file_path=path, line=_line(text, "encrypted"), resource=resource, evidence="encrypted = false", impact="Data at rest may not receive expected EBS encryption protections.", remediation="Enable encryption and define approved KMS key policy where required."))
    return findings
