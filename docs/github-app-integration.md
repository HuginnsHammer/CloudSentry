# GitHub App integration and push-triggered scan queue

## Current scope

CloudSentry can register a GitHub App installation, verify a repository belongs to
that installation, and turn pushes to the repository's configured default branch
into durable scan jobs.

**This milestone does not execute scans.** Jobs remain queued until a separately
deployed, isolated worker is implemented. Do not describe this as continuous
scanning or assume a repository has been inspected merely because a job was queued.

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

## Scan job status

List project jobs:

`GET /api/v1/organizations/{organization_id}/projects/{project_id}/scan-jobs`

Get one job:

`GET /api/v1/organizations/{organization_id}/projects/{project_id}/scan-jobs/{job_id}`

Jobs are deduplicated by organization, project, ref and commit SHA. The database
includes attempt limits, availability time and lease fields for a future worker.
No worker claim, heartbeat, cancellation, source checkout or sandbox execution
endpoint is enabled yet. A queued job is a request for work, not evidence of a scan.

## Webhook security and operations

- HMAC-SHA256 verification uses the exact raw request body.
- Declared and actual payload size is limited to 1 MiB.
- Delivery IDs must be UUIDs; payload digests detect delivery-ID reuse.
- Unknown event types are recorded as ignored.
- Database failures return an error so GitHub can retry.
- Installation tokens are short-lived and never stored.
- The App is granted read-only repository permissions.

Before production use, configure TLS, trusted proxy/network policy, secret rotation,
webhook monitoring, rate limits, job backlog alerts and a retention policy for
webhook delivery records. The scan worker must be implemented with server-managed
source acquisition, no scanner access to the control-plane secrets, resource limits,
network isolation and transactional result ingestion before any job is marked
completed.
