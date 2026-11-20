# Test strategy

## Scanner tests

For every rule, provide:

- A positive fixture that must produce the finding.
- A negative fixture that looks similar but should not match.
- Boundary fixtures for casing, whitespace, aliases, nested blocks and alternate supported syntax.
- Evidence and source-line assertions.
- Suppression and stale-suppression behavior.
- Malformed, oversized, unreadable and non-UTF-8 input behavior.

Repository discovery tests must cover nested paths, excluded directories, symlinks, duplicate/overlapping inputs and deterministic ordering.

## Platform tests

Use PostgreSQL integration tests for transaction, migration, uniqueness, concurrency and tenant-isolation behavior. SQLite-only tests are not sufficient evidence for PostgreSQL locking or constraint semantics.

For each tenant-owned endpoint, test:
- Same-tenant authorized access.
- Cross-tenant read and write denial.
- Missing and deleted resource behavior.
- Role-specific permission boundaries.
- Concurrent mutation and idempotency behavior.

## GitHub pipeline tests

Test webhook signature failures, replayed delivery IDs, altered payloads, installation suspension/revocation, repository unbinding and default-branch changes.

Exercise the full pipeline using a controlled test repository/archive:
webhook → durable job → lease → archive acquisition → archive validation → executor → response validation → transactionally persisted scan and job completion.

Inject worker termination and executor timeout at each stage. Confirm stale leases cannot publish and retries do not create duplicate findings or completed scans.

## CI expectations

CI should run supported Python versions, linting, PostgreSQL migrations and integration tests, and frontend type-check/build. Add dependency and static security scanning as separate jobs. A green unit-test suite is necessary but does not replace deployment security verification.
