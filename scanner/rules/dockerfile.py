"""Static security checks for Dockerfile instructions."""

import re

from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding


def _instruction_lines(text: str) -> list[tuple[int, str]]:
    """Return numbered, non-empty, non-comment instruction lines."""
    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), 1)
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _stages(lines: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """Split instructions at FROM boundaries, retaining original line numbers."""
    stages: list[list[tuple[int, str]]] = []
    for item in lines:
        if re.match(r"^FROM\s+", item[1], re.IGNORECASE):
            stages.append([])
        if stages:
            stages[-1].append(item)
        else:
            # Preserve useful behavior for malformed or partial snippets with no FROM.
            stages.append([item])
    return stages


def _is_root_user(instruction: str) -> bool:
    """Recognize root by username or UID, including an optional group suffix."""
    return bool(
        re.match(r"^USER\s+(?:root|0+)(?::[^\s#]+)?\s*(?:#.*)?$", instruction, re.IGNORECASE)
    )


def scan_dockerfile(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = _instruction_lines(text)
    stages = _stages(lines)
    if not stages:
        return findings

    # The final stage is the default runtime image. USER instructions in earlier
    # build stages do not determine the runtime user's identity.
    runtime_stage = stages[-1]
    for number, line in lines:
        if line.upper().startswith("FROM ") and re.search(r":latest(?:\s|$)", line, re.I):
            findings.append(
                make_finding(
                    rule_id="CS-DKR-002",
                    title="Base image uses mutable latest tag",
                    description="The image tag can resolve to different content over time.",
                    severity=Severity.MEDIUM,
                    category="supply-chain",
                    file_path=path,
                    line=number,
                    evidence=line,
                    impact="Builds may be non-reproducible and receive unexpected upstream changes.",
                    remediation="Pin a reviewed version tag, preferably with an immutable image digest.",
                )
            )

    for number, line in runtime_stage:
        if _is_root_user(line):
            findings.append(
                make_finding(
                    rule_id="CS-DKR-001",
                    title="Container explicitly runs as root",
                    description="The final Dockerfile stage selects root as the runtime user.",
                    severity=Severity.HIGH,
                    category="container-hardening",
                    file_path=path,
                    line=number,
                    evidence=line,
                    impact="A process compromise can gain root privileges inside the container.",
                    remediation="Create or select a dedicated unprivileged user and use USER with that account.",
                )
            )

    if not any(re.match(r"^USER\s+", line, re.IGNORECASE) for _, line in runtime_stage):
        from_line = next(
            (number for number, line in runtime_stage if line.upper().startswith("FROM ")),
            runtime_stage[0][0] if runtime_stage else 1,
        )
        findings.append(
            make_finding(
                rule_id="CS-DKR-003",
                title="No USER instruction found in final stage",
                description="The final runtime stage does not declare an explicit runtime user.",
                severity=Severity.MEDIUM,
                category="container-hardening",
                file_path=path,
                line=from_line,
                evidence="No USER instruction found in final stage",
                impact="The final image may run as root depending on its base image and entrypoint.",
                remediation="Set a dedicated non-root USER in the final build stage and review the resulting image configuration.",
                confidence="medium",
            )
        )
    return findings
