# Authenticated scan-result ingestion

CloudSentry can now accept a bounded report produced by the existing local CLI and
persist it against an organization, project, and optional environment.

This is **report ingestion, not remote scanning**. The hosted API does not clone a
repository, read a server filesystem path, execute configuration, or verify that a
client actually ran the reported scanner. Imported results are marked
`client_supplied_report_unverified`. Do not treat this provenance as equivalent to
a server-attested scan. A managed, isolated worker pipeline and signed provenance
are separate future milestones.

## Permissions and endpoint

Only organization owners, admins, and security analysts can ingest results.
Developers and viewers cannot submit scans. The authenticated identity must already
be provisioned and belong to the organization.

`POST /api/v1/organizations/{organization_id}/projects/{project_id}/scans/ingest`

The request contains:

- `target`: a human-readable target label, not a filesystem path to be opened.
- `environment_id`: optional environment belonging to the same project and organization.
- `source_revision`: optional 7-64 character hexadecimal Git commit identifier.
- `result`: the JSON document emitted by `cloudsentry scan --format json`.

Finding paths must be normalized relative paths. Run the CLI from the repository
root and pass relative targets (for example, `cloudsentry scan ./infra`) so local
absolute paths are not uploaded. Reports are limited to 32 MiB by declared
Content-Length and have bounded finding, error, warning, evidence and reference
sizes. Duplicate finding fingerprints, absolute/traversal paths, unjustified
suppressions and inconsistent scan states are rejected. Reverse proxies must also
enforce a request-body limit because chunked requests may omit Content-Length.

## Example

First create a JSON report locally:

```sh
cloudsentry scan ./infra --format json --output cloudsentry-report.json
```

Then submit it to the authenticated platform API. This example uses `jq` to wrap
the report without changing its contents:

```sh
jq -n --arg target "payments-service" \
  --slurpfile report cloudsentry-report.json \
  '{target: $target, result: $report[0]}' > scan-ingest.json

curl --fail-with-body \
  -H "Authorization: Bearer $CLOUDSENTRY_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @scan-ingest.json \
  "$CLOUDSENTRY_PLATFORM_URL/api/v1/organizations/$CLOUDSENTRY_ORG_ID/projects/$CLOUDSENTRY_PROJECT_ID/scans/ingest"
```

The response reports the scan ID, outcome, and counts of created, updated, and
observed findings. The platform recomputes the aggregate risk score from the
submitted findings rather than trusting the client-supplied score. Finding
context (description, category, confidence, affected resource, impact, evidence,
remediation and references) and partial-scan diagnostics are persisted.

## Scan history

- `GET /api/v1/organizations/{organization_id}/projects/{project_id}/scans?limit=25&offset=0`
- `GET /api/v1/organizations/{organization_id}/projects/{project_id}/scans/{scan_id}`

Both endpoints are tenant- and project-scoped. The list accepts a limit from 1 to
100 and an offset from 0 to 10,000.

## Finding lifecycle behavior

- Findings are stable within a project by scanner fingerprint. Later observations
  update evidence and last-seen metadata rather than creating duplicate records.
- Suppressed observations and their reasons are retained. Suppressed findings are
  excluded from the default platform findings list; request
  `?include_suppressed=true` for audit review.
- A resolved finding that reappears unsuppressed is reopened. Accepted-risk and
  false-positive decisions remain human-controlled.
- A partial scan is stored as partial and never resolves findings that were absent
  from that incomplete result.
- A failed scan is stored for operational visibility but does not update findings.
- Findings absent from a complete scan are **not** automatically resolved yet.
  Reliable auto-resolution requires a stable, verified scan scope and is intentionally
  deferred.

Scan persistence, finding observations, and the scan-ingestion audit event are
committed in one database transaction. PostgreSQL project-row locking serializes
concurrent ingestions for the same project. Audit events contain counts and target
identifiers, not raw finding evidence.
