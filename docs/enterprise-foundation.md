# Enterprise foundation — milestone 0.2

## Scope

This milestone introduced the tenant-aware persistence boundary. Subsequent
milestones added OIDC authentication, read-only organization/project access, finding
lifecycle management, audit events, and bounded scan-result ingestion. It remains
an early platform foundation, not a production-ready multi-user service.

The local scanner remains usable without a database. Platform persistence is a
separate package so deterministic analysis does not become coupled to HTTP,
authentication, or a hosted database.

## Data model

- Organization is the tenant boundary.
- User represents an external identity-provider subject; local passwords are not stored.
- Membership binds a user to an organization with owner, admin, security analyst,
  developer, or viewer role.
- Project and Environment organize repositories and deployment contexts.
- Scan stores an imported scan report, status, provenance and summary; it does not
  prove that the hosted platform executed the scan.
- Finding is a stable project-level issue identity with lifecycle state, evidence,
  remediation, assignee and scanner-suppression metadata.
- ScanFinding records each scan that observed a stable finding, preserving history across repeated scans.
- AuditEvent records an actor, action, target and structured details.

Tenant ownership is represented in composite foreign keys, not only application
conventions. A scan cannot point to another tenant's project; a finding cannot
point to another tenant's scan; and finding assignees and audit actors must be
members of the same organization.

## Database policy

Configure CLOUDSENTRY_DATABASE_URL with a PostgreSQL URL. Plain postgresql://
URLs are normalized to the psycopg 3 driver. SQLite is available only when code
explicitly opts in with allow_sqlite=True, primarily for tests. The application
must not create or mutate schema at startup: schema evolution belongs to Alembic.

No database URL, cloud credential, identity-provider secret, or signing key is
committed to the repository.

## Security boundary and deliberate omissions

The hosted platform API now verifies OIDC bearer tokens and scopes reads/writes to
organization memberships. The separate local path-based scanner API remains
loopback-only. Report ingestion accepts client-submitted JSON; it does not execute
remote scans or provide verified scan provenance. Do not deploy either API as a
company-facing service until the production controls below are complete.

Before enabling organization-facing endpoints, implement and test:

1. Complete identity provisioning, invitations and lifecycle management; keep
   external OIDC tokens as the sole authentication authority.
2. Add isolated, resource-limited scan workers with server-managed source checkouts.
3. Add signed scan provenance and idempotent ingestion/job processing.
4. Add per-tenant quotas, rate limits, concurrency limits and request-size controls.
5. Add production deployment, secrets management, TLS/proxy policy, monitoring,
   backup/restore drills and incident response procedures.
6. Run tenant-isolation and authorization integration tests against PostgreSQL,
   not only SQLite.

## Acceptance criteria

- Schema creates cleanly on SQLite with foreign-key enforcement for unit tests.
- PostgreSQL is the only accepted production database driver.
- Cross-tenant project/environment, scan/finding, assignee and audit-actor
  references are rejected by database constraints.
- Existing local CLI/API behavior remains independent of platform persistence.
- No feature is described as production-ready until authentication, authorization,
  migrations, isolated workers and PostgreSQL integration tests exist.

## Next implementation sequence

1. Expand PostgreSQL-backed tenant-isolation and API authorization tests.
2. Add a secure worker/job pipeline and server-managed repository checkouts.
3. Implement a least-privilege GitHub App and verified webhook-driven scans.
4. Add cloud inventory connectors and drift detection only after scan provenance
   and worker isolation are established.
