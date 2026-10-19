"""Static checks for Docker Compose service configuration."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import yaml

from scanner.models import Finding, Severity
from scanner.rules.shared import make_finding

_DOCKER_SOCKET = "/var/run/docker.sock"


@dataclass(frozen=True)
class _ServiceNode:
    """Position information for one service, read from the YAML node tree."""

    line: int
    node: yaml.MappingNode

    def key_line(self, key: str) -> int:
        """Line of ``key`` within this service, or the service's own line if absent."""
        for key_node, _ in self.node.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
                return key_node.start_mark.line + 1
        return self.line

    def item_line(self, key: str, matches: Callable[[str], bool]) -> int:
        """Line of the first scalar list item under ``key`` accepted by ``matches``."""
        for key_node, value_node in self.node.value:
            if (
                isinstance(key_node, yaml.ScalarNode)
                and key_node.value == key
                and isinstance(value_node, yaml.SequenceNode)
            ):
                for item in value_node.value:
                    if isinstance(item, yaml.ScalarNode) and matches(str(item.value)):
                        return item.start_mark.line + 1
        return self.key_line(key)


def _locate_services(source: str) -> dict[str, _ServiceNode]:
    """Map service names to their YAML nodes so findings carry accurate line numbers."""
    try:
        root = yaml.compose(source, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}
    if not isinstance(root, yaml.MappingNode):
        return {}
    for key_node, value_node in root.value:
        if (
            isinstance(key_node, yaml.ScalarNode)
            and key_node.value == "services"
            and isinstance(value_node, yaml.MappingNode)
        ):
            return {
                str(name_node.value): _ServiceNode(name_node.start_mark.line + 1, service_node)
                for name_node, service_node in value_node.value
                if isinstance(name_node, yaml.ScalarNode)
                and isinstance(service_node, yaml.MappingNode)
            }
    return {}


def scan_compose(data: Any, path: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        return findings
    located = _locate_services(source)
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        where = located.get(str(name))

        if service.get("privileged") is True:
            findings.append(
                make_finding(
                    rule_id="CS-CMP-001",
                    title="Privileged container enabled",
                    description=f"Service {name!r} requests privileged mode.",
                    severity=Severity.CRITICAL,
                    category="container-isolation",
                    file_path=path,
                    line=where.key_line("privileged") if where else None,
                    resource=str(name),
                    evidence="privileged: true",
                    impact="Privileged mode substantially weakens container isolation.",
                    remediation=(
                        "Remove privileged mode and grant only required capabilities and devices."
                    ),
                )
            )

        if service.get("network_mode") == "host":
            findings.append(
                make_finding(
                    rule_id="CS-CMP-002",
                    title="Host network namespace shared",
                    description=f"Service {name!r} uses host networking.",
                    severity=Severity.HIGH,
                    category="network-exposure",
                    file_path=path,
                    line=where.key_line("network_mode") if where else None,
                    resource=str(name),
                    evidence="network_mode: host",
                    impact="The container bypasses normal network namespace isolation.",
                    remediation="Use an isolated Compose network and publish only required ports.",
                )
            )

        volumes = service.get("volumes", [])
        if isinstance(volumes, list) and any(
            isinstance(volume, str) and _DOCKER_SOCKET in volume for volume in volumes
        ):
            findings.append(
                make_finding(
                    rule_id="CS-CMP-003",
                    title="Docker socket mounted into service",
                    description=f"Service {name!r} mounts the Docker daemon socket.",
                    severity=Severity.CRITICAL,
                    category="container-isolation",
                    file_path=path,
                    line=(
                        where.item_line("volumes", lambda value: _DOCKER_SOCKET in value)
                        if where
                        else None
                    ),
                    resource=str(name),
                    evidence=f"volume mount references {_DOCKER_SOCKET}",
                    impact=(
                        "Daemon access can permit control over other containers and potentially "
                        "the host."
                    ),
                    remediation="Remove the socket mount or use a tightly scoped broker.",
                )
            )

        ports = service.get("ports", [])
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, str) and (
                    port.startswith("0.0.0.0:") or port.startswith(":::")
                ):
                    findings.append(
                        make_finding(
                            rule_id="CS-CMP-004",
                            title="Port published on all host interfaces",
                            description=(
                                f"Service {name!r} publishes a port on a wildcard host address."
                            ),
                            severity=Severity.MEDIUM,
                            category="network-exposure",
                            file_path=path,
                            line=(
                                where.item_line("ports", lambda value, port=port: value == port)
                                if where
                                else None
                            ),
                            resource=str(name),
                            evidence=port,
                            impact=(
                                "The service may be reachable on other interfaces depending on "
                                "firewall and routing."
                            ),
                            remediation=(
                                "Bind to 127.0.0.1 for local-only access or restrict exposure "
                                "with network controls."
                            ),
                            confidence="medium",
                        )
                    )
    return findings
