# Enterprise foundation — milestone 0.2

## Scope

This milestone introduces the first persistence boundary for CloudSentry's future
organization-aware platform. It is intentionally not a public multi-user API.

The local scanner remains usable without a database. Platform persistence is a
separate package so deterministic analysis does not become coupled to HTTP,
authentication, or a hosted database.

## Data model

- Organization is the tenant boundary.
- User represents an external identity-provider subject; local passwords are not stored.
- Membership binds a user to an organization with owner, admin, security analyst,
  developer, or viewer role.
- Project and Environment organize repositories and deployment contexts.
- Scan stores a scan execution and status/summary.
- Finding is a stable project-level issue identity with lifecycle state, evidence, remediation and assignee.
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

This change does not expose network endpoints, implement login, issue tokens,
or make the existing local path-based scan API safe for remote use. The current
API must remain loopback-only. Do not deploy it as a company-facing service.

Before enabling organization-facing endpoints, implement and test:

1. OIDC login with issuer, audience, signature, nonce and expiry validation.
2. A request-scoped authenticated principal and organization membership checks.
3. Authorization for every organization/project/environment resource.
4. Scan-worker isolation with server-controlled workspaces; never accept arbitrary
   filesystem paths from remote callers.
5. Per-tenant quotas, rate limits, concurrency limits and audit events.
6. Reviewed Alembic migrations and migration/rollback CI checks.
7. Tenant-isolation integration tests against PostgreSQL, not only SQLite.

## Acceptance criteria

- Schema creates cleanly on SQLite with foreign-key enforcement for unit tests.
- PostgreSQL is the only accepted production database driver.
- Cross-tenant project/environment, scan/finding, assignee and audit-actor
  references are rejected by database constraints.
- Existing local CLI/API behavior remains independent of platform persistence.
- No feature is described as production-ready until authentication, authorization,
  migrations, isolated workers and PostgreSQL integration tests exist.

## Next implementation sequence

1. Add a reviewed, immutable initial Alembic migration.
2. Add PostgreSQL-backed integration tests and CI service container.
3. Implement OIDC authentication and organization membership dependencies.
4. Add organization/project APIs only after authorization tests pass.
5. Move scanning to isolated background workers with server-managed source checkout.
