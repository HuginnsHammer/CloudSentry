"""Static checks for literal Terraform security misconfigurations."""

import re
from typing import Any

from scanner.models import Finding, Severity
from scanner.rules.locate import Span, child_block_spans, find_line, find_resource_span
from scanner.rules.shared import make_finding

_WORLD_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _world_open_cidrs(attrs: dict[str, Any]) -> list[str]:
    """Return literal any-source CIDRs from supported AWS rule attributes."""
    found: list[str] = []
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        values = attrs.get(key)
        if isinstance(values, list):
            found.extend(
                value for value in values if isinstance(value, str) and value in _WORLD_OPEN_CIDRS
            )
    for key in ("cidr_ipv4", "cidr_ipv6"):
        value = attrs.get(key)
        if isinstance(value, str) and value in _WORLD_OPEN_CIDRS:
            found.append(value)
    return list(dict.fromkeys(found))


def _append_open_ingress_finding(
    findings: list[Finding],
    *,
    lines: list[str],
    span: Span | None,
    path: str,
    resource: str,
    attrs: dict[str, Any],
    context: str = "ingress",
) -> None:
    """Report a world-open ingress; ``span`` is the narrowest known block holding the CIDR."""
    cidrs = _world_open_cidrs(attrs)
    if not cidrs:
        return

    cidr = cidrs[0]
    line = None
    if span is not None:
        line = find_line(lines, span, rf'"{re.escape(cidr)}"') or span[0] + 1
    port_context = ", ".join(
        f"{key}={attrs[key]!r}"
        for key in ("protocol", "ip_protocol", "from_port", "to_port")
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
            line=line,
            resource=resource,
            evidence="; ".join(evidence_parts),
            impact="Services covered by this ingress rule may be reachable from any address in the specified IP family, subject to ports and other network controls.",
            remediation="Restrict ingress source CIDRs and exposed ports to the smallest justified set.",
            confidence="high",
        )
    )


def scan_terraform(text: str, path: str, parsed: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for block in parsed.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for resource_type, instances in block.items():
            # python-hcl2 7.x returns labeled blocks as {label: body}; retain
            # compatibility with the older list-of-singleton-dicts shape too.
            if isinstance(instances, dict):
                instances = [{label: body} for label, body in instances.items()]
            if not isinstance(instances, list):
                continue
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                for name, attrs in instance.items():
                    if not isinstance(attrs, dict):
                        continue
                    resource = f"{resource_type}.{name}"
                    # Restrict every line lookup to this resource's own block.
                    span = find_resource_span(lines, resource_type, str(name))
                    header_line = span[0] + 1 if span else None

                    if resource_type == "aws_s3_bucket_acl" and str(
                        attrs.get("acl", "")
                    ).lower() in {"public-read", "public-read-write"}:
                        findings.append(
                            make_finding(
                                rule_id="CS-TF-001",
                                title="S3 bucket ACL allows public access",
                                description="An S3 ACL explicitly grants public read or write access.",
                                severity=Severity.CRITICAL,
                                category="cloud-storage",
                                file_path=path,
                                line=header_line,
                                resource=resource,
                                evidence=f"acl = {attrs.get('acl')}",
                                impact="Objects may be exposed or modified publicly depending on effective bucket settings.",
                                remediation="Remove public ACL grants and enforce S3 Block Public Access and least-privilege bucket policies.",
                            )
                        )

                    # Legacy standalone rule: direction is explicit, so only ingress is reported.
                    if (
                        resource_type == "aws_security_group_rule"
                        and attrs.get("type") == "ingress"
                    ):
                        _append_open_ingress_finding(
                            findings,
                            lines=lines,
                            span=span,
                            path=path,
                            resource=resource,
                            attrs=attrs,
                        )

                    # Newer AWS provider resource is ingress-only by definition.
                    if resource_type == "aws_vpc_security_group_ingress_rule":
                        _append_open_ingress_finding(
                            findings,
                            lines=lines,
                            span=span,
                            path=path,
                            resource=resource,
                            attrs=attrs,
                        )

                    # Inline ingress blocks are nested inside aws_security_group resources.
                    if resource_type == "aws_security_group":
                        ingress_blocks = attrs.get("ingress", [])
                        if isinstance(ingress_blocks, dict):
                            ingress_blocks = [ingress_blocks]
                        if isinstance(ingress_blocks, list):
                            # Parsed ingress entries follow source order, so the nth entry
                            # maps to the nth `ingress { }` block; fall back to the resource.
                            block_spans = child_block_spans(lines, span, "ingress") if span else []
                            for position, ingress in enumerate(ingress_blocks):
                                if isinstance(ingress, dict):
                                    block_span = (
                                        block_spans[position]
                                        if position < len(block_spans)
                                        else span
                                    )
                                    _append_open_ingress_finding(
                                        findings,
                                        lines=lines,
                                        span=block_span,
                                        path=path,
                                        resource=resource,
                                        attrs=ingress,
                                    )

                    if resource_type == "aws_ebs_volume" and attrs.get("encrypted") is False:
                        encrypted_line = None
                        if span:
                            encrypted_line = (
                                find_line(lines, span, r"\bencrypted\s*=") or header_line
                            )
                        findings.append(
                            make_finding(
                                rule_id="CS-TF-003",
                                title="EBS volume encryption explicitly disabled",
                                description="The resource sets encrypted = false.",
                                severity=Severity.HIGH,
                                category="data-protection",
                                file_path=path,
                                line=encrypted_line,
                                resource=resource,
                                evidence="encrypted = false",
                                impact="Data at rest may not receive expected EBS encryption protections.",
                                remediation="Enable encryption and define approved KMS key policy where required.",
                            )
                        )
    return findings
