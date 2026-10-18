"""Static checks for literal Terraform security misconfigurations."""

from typing import Any

from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding

_WORLD_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _line(text: str, needle: str) -> int | None:
    return next((i for i, line in enumerate(text.splitlines(), 1) if needle in line), None)


def _world_open_cidrs(attrs: dict[str, Any]) -> list[str]:
    """Return literal any-source CIDRs from supported AWS rule attributes."""
    found: list[str] = []
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        values = attrs.get(key)
        if isinstance(values, list):
            found.extend(value for value in values if isinstance(value, str) and value in _WORLD_OPEN_CIDRS)
    for key in ("cidr_ipv4", "cidr_ipv6"):
        value = attrs.get(key)
        if isinstance(value, str) and value in _WORLD_OPEN_CIDRS:
            found.append(value)
    return list(dict.fromkeys(found))


def _append_open_ingress_finding(
    findings: list[Finding],
    *,
    text: str,
    path: str,
    resource: str,
    attrs: dict[str, Any],
    context: str = "ingress",
) -> None:
    cidrs = _world_open_cidrs(attrs)
    if not cidrs:
        return

    cidr = cidrs[0]
    port_context = ", ".join(
        f"{key}={attrs[key]!r}"
        for key in ("protocol", "from_port", "to_port", "ip_protocol", "from_port", "to_port")
        if key in attrs
    )
    evidence_parts = [f"{context} allows source {', '.join(cidrs)}"]
    if port_context:
        evidence_parts.append(port_context)
    findings.append(
        make_finding(
            rule_id="CS-TF-002",
            title="Security group ingress allows traffic from any IP address",
            description="An AWS security group ingress rule includes a world-open IPv4 or IPv6 CIDR.",
            severity=Severity.HIGH,
            category="network-exposure",
            file_path=path,
            line=_line(text, cidr),
            resource=resource,
            evidence="; ".join(evidence_parts),
            impact="Services covered by this ingress rule may be reachable from any address in the specified IP family, subject to ports and other network controls.",
            remediation="Restrict ingress source CIDRs and exposed ports to the smallest justified set.",
            confidence="high",
        )
    )


def scan_terraform(text: str, path: str, parsed: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for block in parsed.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for resource_type, instances in block.items():
            if not isinstance(instances, list):
                continue
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                for name, attrs in instance.items():
                    if not isinstance(attrs, dict):
                        continue
                    resource = f"{resource_type}.{name}"

                    if (
                        resource_type == "aws_s3_bucket_acl"
                        and str(attrs.get("acl", "")).lower() in {"public-read", "public-read-write"}
                    ):
                        findings.append(
                            make_finding(
                                rule_id="CS-TF-001",
                                title="S3 bucket ACL allows public access",
                                description="An S3 ACL explicitly grants public read or write access.",
                                severity=Severity.CRITICAL,
                                category="cloud-storage",
                                file_path=path,
                                line=_line(text, "aws_s3_bucket_acl"),
                                resource=resource,
                                evidence=f"acl = {attrs.get('acl')}",
                                impact="Objects may be exposed or modified publicly depending on effective bucket settings.",
                                remediation="Remove public ACL grants and enforce S3 Block Public Access and least-privilege bucket policies.",
                            )
                        )

                    # Legacy standalone rule: direction is explicit, so only ingress is reported.
                    if resource_type == "aws_security_group_rule" and attrs.get("type") == "ingress":
                        _append_open_ingress_finding(
                            findings, text=text, path=path, resource=resource, attrs=attrs
                        )

                    # Newer AWS provider resource is ingress-only by definition.
                    if resource_type == "aws_vpc_security_group_ingress_rule":
                        _append_open_ingress_finding(
                            findings, text=text, path=path, resource=resource, attrs=attrs
                        )

                    # Inline ingress blocks are nested inside aws_security_group resources.
                    if resource_type == "aws_security_group":
                        ingress_blocks = attrs.get("ingress", [])
                        if isinstance(ingress_blocks, dict):
                            ingress_blocks = [ingress_blocks]
                        if isinstance(ingress_blocks, list):
                            for ingress in ingress_blocks:
                                if isinstance(ingress, dict):
                                    _append_open_ingress_finding(
                                        findings,
                                        text=text,
                                        path=path,
                                        resource=resource,
                                        attrs=ingress,
                                    )

                    if resource_type == "aws_ebs_volume" and attrs.get("encrypted") is False:
                        findings.append(
                            make_finding(
                                rule_id="CS-TF-003",
                                title="EBS volume encryption explicitly disabled",
                                description="The resource sets encrypted = false.",
                                severity=Severity.HIGH,
                                category="data-protection",
                                file_path=path,
                                line=_line(text, "encrypted"),
                                resource=resource,
                                evidence="encrypted = false",
                                impact="Data at rest may not receive expected EBS encryption protections.",
                                remediation="Enable encryption and define approved KMS key policy where required.",
                            )
                        )
    return findings
