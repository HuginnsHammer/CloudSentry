# Production-readiness checklist

This checklist is intentionally conservative. A checked application feature does not imply that its deployment or operations are ready.

## Scanner integrity

- [x] Supported-format discovery for Terraform, Dockerfiles and Compose.
- [x] Per-file size guard and parser diagnostics.
- [x] Partial/error outcomes for incomplete scans.
- [x] Stable finding identifiers and source evidence.
- [ ] Broader rule coverage with positive/negative fixtures and external validation.
- [ ] Rule confidence calibration and documented false-positive handling.
- [ ] Scan performance benchmarks on representative large repositories.

## Team platform

- [x] PostgreSQL persistence and migrations.
- [x] Organizations, memberships, roles, projects and environments.
- [x] Persistent scans, findings and audit events.
- [ ] Complete user provisioning, invitation and membership lifecycle.
- [ ] Organization dashboard and administrative UX.
- [ ] Tenant-level quotas, retention and export/deletion controls.
- [ ] Independent authorization review across all tenant-owned endpoints.

## GitHub managed scanning

- [x] GitHub App installation and repository binding.
- [x] Signed webhook validation and delivery deduplication.
- [x] Durable jobs and worker/executor process entry points.
- [x] Pinned source revision and result provenance checks.
- [ ] Executor OS/container sandbox enforced by deployment.
- [ ] Worker lease renewal and cancellation after lease loss.
- [ ] End-to-end worker/archive/executor/database tests.
- [ ] Revocation, unbinding and permission-change race tests.

## Production operations

- [ ] Reproducible deployment manifests and environment-specific configuration.
- [ ] TLS termination and trusted proxy configuration.
- [ ] Secret manager integration and documented rotation.
- [ ] Structured logs, metrics, dashboards and actionable alerts.
- [ ] Database backups and tested restoration.
- [ ] Capacity limits, quotas, rate limits and abuse protection.
- [ ] Incident response and disaster recovery procedures.
- [ ] Dependency, container and code security scanning.
- [ ] Branch protection, required CI checks and release approvals.

CloudSentry should not be marketed as production-ready for enterprise workloads while critical unchecked items remain open.
