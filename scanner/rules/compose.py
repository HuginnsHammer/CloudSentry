from typing import Any
from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding

def _line(source: str, needle: str) -> int | None:
    return next((i for i, line in enumerate(source.splitlines(), 1) if needle in line), None)

def scan_compose(data: Any, path: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict): return findings
    for name, service in services.items():
        if not isinstance(service, dict): continue
        if service.get("privileged") is True:
            findings.append(make_finding(rule_id="CS-CMP-001", title="Privileged container enabled", description=f"Service {name!r} requests privileged mode.", severity=Severity.CRITICAL, category="container-isolation", file_path=path, line=_line(source, "privileged"), resource=str(name), evidence="privileged: true", impact="Privileged mode substantially weakens container isolation.", remediation="Remove privileged mode and grant only required capabilities and devices."))
        if service.get("network_mode") == "host":
            findings.append(make_finding(rule_id="CS-CMP-002", title="Host network namespace shared", description=f"Service {name!r} uses host networking.", severity=Severity.HIGH, category="network-exposure", file_path=path, line=_line(source, "network_mode"), resource=str(name), evidence="network_mode: host", impact="The container bypasses normal network namespace isolation.", remediation="Use an isolated Compose network and publish only required ports."))
        volumes = service.get("volumes", [])
        if isinstance(volumes, list) and any(isinstance(v, str) and "/var/run/docker.sock" in v for v in volumes):
            findings.append(make_finding(rule_id="CS-CMP-003", title="Docker socket mounted into service", description=f"Service {name!r} mounts the Docker daemon socket.", severity=Severity.CRITICAL, category="container-isolation", file_path=path, line=_line(source, "docker.sock"), resource=str(name), evidence="volume mount references /var/run/docker.sock", impact="Daemon access can permit control over other containers and potentially the host.", remediation="Remove the socket mount or use a tightly scoped broker."))
        ports = service.get("ports", [])
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, str) and (port.startswith("0.0.0.0:") or port.startswith(":::")):
                    findings.append(make_finding(rule_id="CS-CMP-004", title="Port published on all host interfaces", description=f"Service {name!r} publishes a port on a wildcard host address.", severity=Severity.MEDIUM, category="network-exposure", file_path=path, line=_line(source, port), resource=str(name), evidence=port, impact="The service may be reachable on other interfaces depending on firewall and routing.", remediation="Bind to 127.0.0.1 for local-only access or restrict exposure with network controls.", confidence="medium"))
    return findings
