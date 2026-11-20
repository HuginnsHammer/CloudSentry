# Scanner coverage and validation contract

## Supported input formats

| Input | Current behavior | Important boundary |
|---|---|---|
| Dockerfile | Line-oriented checks for mutable `latest` tags and runtime root-user configuration | Does not build the image or resolve all Dockerfile/build-argument semantics |
| Terraform `.tf` | Parses HCL and checks selected literal AWS configuration patterns | Does not evaluate variables, locals, modules, provider defaults, dynamic blocks or deployed state |
| Docker Compose `.yaml` / `.yml` | Parses YAML and checks selected service configuration patterns | Only documents with a top-level `services` mapping are accepted; does not resolve runtime network policy |
| Other YAML | Reported as unsupported when explicitly targeted or as a diagnostic when discovered in a repository | Kubernetes and arbitrary YAML are not currently scanned |

## Scan result meanings

- **Complete / `ok`:** every supported file discovered for the request was read and parsed by the current scanner. This is not a claim that every security issue was detected.
- **Partial / `partial`:** at least one supported file was inspected, but one or more requested inputs could not be inspected.
- **Error / `error`:** no usable supported input was scanned, or the request itself was invalid.

A repository scan with no supported configuration files must not return a clean result. Explicit unsupported files, malformed supported files, unreadable files and oversized files must remain visible as diagnostics.

## Discovery policy

Recursive discovery excludes common version-control, virtual-environment, dependency, build and generated directories. It does not follow symlinked directories or files. Explicit symlink scan targets are rejected. This prevents a repository scan from silently traversing paths outside its selected workspace.

The scanner applies a per-file size limit. This is a resource guard, not a complete denial-of-service boundary; service deployments still need process and container resource limits.

## Evidence expectations

Every finding should include, where applicable:

- Stable rule identifier and severity.
- File path and source line.
- A short source excerpt or normalized evidence.
- The affected resource or service.
- Security impact and actionable remediation.
- Confidence appropriate to the evidence available.

Do not describe a heuristic finding as proof of exploitability. Do not describe zero findings as proof of security.

## Coverage expansion policy

New rules should ship with positive, negative and edge-case fixtures. Tests should cover literal and structurally equivalent configurations, false-positive boundaries, source attribution, suppression behavior and malformed input. Rule changes should preserve stable identifiers unless a documented breaking change is necessary.
