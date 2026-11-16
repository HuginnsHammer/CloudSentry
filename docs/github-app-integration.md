# GitHub App integration and managed scan execution

## Current scope

CloudSentry can register a GitHub App installation, verify a repository belongs to
that installation, and turn pushes to the repository's configured default branch
into durable scan jobs. A separate worker can acquire the pinned source archive,
submit it to the private executor service, validate the returned report, and
persist the scan result and job completion transactionally.

This is an implemented execution path, not a production security boundary by
itself. The executor performs bounded archive extraction and runs the static
scanner in a subprocess with a timeout. Those controls do **not** replace an
OS/container sandbox. Do not expose this pipeline to untrusted repositories
until the deployment enforces the isolation requirements below.

## Required GitHub App configuration

Create a GitHub App owned by the account that will install it.

Use read-only permissions:

- Repository metadata: read-only.
- Contents: read-only.

Subscribe to these webhook events:

- Installation.
- Push.

Configure the webhook URL:

`https://YOUR_PLATFORM_HOST/api/v1/integrations/github/webhook`

Set a randomly generated webhook secret of at least 32 characters. Configure the
platform with:

- `CLOUDSENTRY_GITHUB_APP_ID`: numeric GitHub App ID.
- `CLOUDSENTRY_GITHUB_APP_PRIVATE_KEY`: PEM private key contents (escaped newlines
  are supported).
- `CLOUDSENTRY_GITHUB_WEBHOOK_SECRET`: the exact webhook secret configured in GitHub.

Keep the private key and webhook secret in a secret manager. Never commit them to
the repository, expose them to the dashboard, or log installation access tokens.

## Claim an installation

When the App is installed, GitHub sends an `installation.created` webhook. CloudSentry
verifies the HMAC-SHA256 signature and stores the installation as `unclaimed`.

An organization owner/admin can claim the installation:

`POST /api/v1/organizations/{organization_id}/github/installations/{installation_id}/claim`

The installation ID is available in the GitHub installation settings URL. Claiming
calls the GitHub App API using a short-lived App JWT and verifies that the installation
belongs to the account recorded by the signed webhook. An installation can be claimed
by only one CloudSentry organization.

List linked installations:

`GET /api/v1/organizations/{organization_id}/github/installations`

## Bind a repository to a project

An owner/admin submits the installation ID and numeric repository ID:

`POST /api/v1/organizations/{organization_id}/projects/{project_id}/github/repository`

Example JSON:

```json
{
  "installation_id": 12345678,
  "repository_id": 987654321
}
```

CloudSentry creates a short-lived installation access token and verifies the
repository against the installation's repository list. It stores the verified
repository ID, full name, default branch and canonical HTTPS URL. The token is
held only in process memory and is not persisted.

Unbind with:

`DELETE /api/v1/organizations/{organization_id}/projects/{project_id}/github/repository`

Only GitHub.com HTTPS repositories are supported in this milestone. GitHub Enterprise
hosts and user-supplied arbitrary repository URLs are not fetched.

## Push webhook behavior

For a signed `push` event, CloudSentry:

1. Checks the repository ID and installation ID against a project binding.
2. Requires the installation to remain active and linked to that organization.
3. Accepts pushes to the configured default branch only.
4. Requires a full 40-character commit SHA and ignores deleted branches/zero SHAs.
5. Creates one tenant-scoped `ScanJob` for the immutable commit/ref.
6. Writes an audit event and webhook-delivery record in the same transaction.

The GitHub delivery ID is stored with a SHA-256 payload digest. Exact replays are
acknowledged without repeating work; reusing a delivery ID with a different signed
payload is rejected. Raw webhook bodies and installation tokens are not stored.

Installation suspend/delete events disable future job creation. Unsuspend events
reactivate the installation. Non-default branches and unrelated events are ignored.

## Worker and executor configuration

The control-plane worker requires:

- `CLOUDSENTRY_DATABASE_URL`
- `CLOUDSENTRY_GITHUB_APP_ID`
- `CLOUDSENTRY_GITHUB_APP_PRIVATE_KEY`
- `CLOUDSENTRY_EXECUTOR_SHARED_SECRET`

The executor requires the same `CLOUDSENTRY_EXECUTOR_SHARED_SECRET`. Generate a
cryptographically random value of at least 32 characters and inject it through a
secret manager into only the worker and executor. Do not give the executor the
database URL, GitHub App private key, OIDC signing/verification configuration, or
other control-plane credentials.

The worker uses:

- `CLOUDSENTRY_WORKER_ID` (optional; generated if omitted)
- `CLOUDSENTRY_WORKER_POLL_SECONDS` (0.5–60 seconds)
- `CLOUDSENTRY_WORKER_LEASE_SECONDS` (120–3600 seconds; default 900)
- `CLOUDSENTRY_EXECUTOR_URL` (must be the private
  `http://scan-executor:8081/internal/v1/scan` service endpoint)

Start the processes using the installed package entry points:

```sh
uvicorn scanner.api.app:app --host 0.0.0.0 --port 8000
python -m scanner.platform.worker_main
uvicorn scanner.executor_app:app --host 0.0.0.0 --port 8081
```

These commands describe process roles, not a production deployment recipe. The
executor must be reachable only from the worker over a private network. The local
path-based scan API must remain separate and loopback-only.

The worker currently uses a bounded lease without a renewal heartbeat. Keep
executor timeouts below the configured lease duration and monitor for expired
leases and repeated retries. Lease renewal, cancellation when ownership is lost,
and a fully supervised deployment remain follow-up work.

## Mandatory deployment isolation

Before enabling scans of untrusted repositories, deploy the executor with all of
the following enforced outside the application process:

- Dedicated unprivileged UID/GID; no root execution.
- No Docker/container-runtime socket, host mounts, host PID namespace or host
  networking.
- Read-only root filesystem with a small, bounded writable temporary filesystem.
- No outbound network access; no DNS or metadata-service access.
- Drop all Linux capabilities and apply seccomp/AppArmor or an equivalent policy.
- Explicit CPU, memory, PID, file-size, open-file and wall-clock limits.
- Ephemeral per-job workspace, removed after each scan.
- Executor service authentication and network policy allowing only the worker.
- Separate secrets: the executor receives only its worker-shared authentication
  secret and never receives GitHub or database credentials.

The current repository does not include a deployment manifest proving these
controls. A separate service or subprocess alone is not a sandbox.

## Scan result and provenance

The worker binds a scan to the immutable commit SHA and verified repository
identity. The executor response must match the requested target and revision.
The worker validates the report against the same bounded ingestion schema used
for client imports, rechecks the project/repository/installation binding, and
persists the result and job completion in one database transaction.

Client-submitted reports remain marked as unverified imports. Worker-produced
reports use `server_managed_worker` provenance. Provenance identifies the
application execution path; it is not cryptographic attestation of the host or
container runtime.

## Operations and acceptance criteria

Before production use:

1. Add executor-specific API tests and an end-to-end worker → archive → executor →
   persistence integration test.
2. Implement lease renewal and terminate in-flight work when lease ownership is lost.
3. Enforce and test the deployment isolation controls above.
4. Add backlog, retry, lease-expiry, executor-health and scan-duration metrics/alerts.
5. Add quotas, rate limits, concurrency controls and per-tenant retention policy.
6. Test installation revocation, repository unbinding, webhook replay and
   permission changes during active scans.
7. Configure TLS, trusted proxy policy, secret rotation, backups and restore drills.

A queued job is a request for work, not evidence of a completed scan. A completed
scan records what the configured scanner inspected at a pinned revision; it does
not prove that all infrastructure risk was detected.
