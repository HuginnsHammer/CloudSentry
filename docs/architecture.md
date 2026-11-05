# Architecture

## Local scanner

Pipeline: path discovery and size checks → file dispatch → safe parsing → independent rules → normalized findings → deterministic deduplication and scoring → CLI/API serialization.

The core engine does not depend on FastAPI. Terraform uses python-hcl2, YAML uses PyYAML safe_load, and Dockerfile checks inspect instruction lines without executing a build. Dynamic expressions are not evaluated. HCL line mapping is approximate because the decoded parser tree does not preserve source token locations.

## Enterprise platform boundary

The enterprise persistence layer lives under scanner/platform and is deliberately separate from the local scanner. The local CLI and loopback-only API do not require a database.

PostgreSQL is the production persistence target. SQLAlchemy models define organizations, external identity references, memberships, projects, environments, scans, stable project-level findings, scan-to-finding observations, and audit events. Composite foreign keys encode tenant ownership in the database so related records cannot cross organization boundaries by changing identifiers.

A finding has a stable identity within a project, keyed by its deterministic fingerprint. ScanFinding records which scan observed that finding. This separates the lifecycle of a security issue from an individual scan run and provides a foundation for first-seen/last-seen tracking, remediation assignment, and verified resolution.

Alembic owns schema evolution. Application startup must never call metadata.create_all. The platform package does not yet provide authentication, organization APIs, remote scanning, or production deployment. The existing path-based scan API remains loopback-only until a separately reviewed design replaces arbitrary client-supplied filesystem paths with isolated server-managed workspaces.
