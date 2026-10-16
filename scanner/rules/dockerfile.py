import re
from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding

def scan_dockerfile(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = [(i, line.strip()) for i, line in enumerate(text.splitlines(), 1) if line.strip() and not line.lstrip().startswith("#")]
    for number, line in lines:
        if re.match(r"^USER\s+(0|root)\s*(?:#.*)?$", line, re.I):
            findings.append(make_finding(rule_id="CS-DKR-001", title="Container explicitly runs as root", description="The Dockerfile selects root as the runtime user.", severity=Severity.HIGH, category="container-hardening", file_path=path, line=number, evidence=line, impact="A process compromise can gain root privileges inside the container.", remediation="Create or select a dedicated unprivileged user and use USER with that account."))
        if line.upper().startswith("FROM ") and re.search(r":latest(?:\s|$)", line, re.I):
            findings.append(make_finding(rule_id="CS-DKR-002", title="Base image uses mutable latest tag", description="The image tag can resolve to different content over time.", severity=Severity.MEDIUM, category="supply-chain", file_path=path, line=number, evidence=line, impact="Builds may be non-reproducible and receive unexpected upstream changes.", remediation="Pin a reviewed version tag, preferably with an immutable image digest."))
    if not any(re.match(r"^USER\s+", line, re.I) for _, line in lines):
        from_line = next((n for n, line in lines if line.upper().startswith("FROM ")), 1)
        findings.append(make_finding(rule_id="CS-DKR-003", title="No USER instruction found", description="No explicit runtime user is declared in this Dockerfile.", severity=Severity.MEDIUM, category="container-hardening", file_path=path, line=from_line, evidence="No USER instruction found", impact="The final image may run as root depending on its base image and entrypoint.", remediation="Set a dedicated non-root USER in the final build stage; review every stage.", confidence="medium"))
    return findings
