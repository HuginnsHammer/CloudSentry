# OIDC platform API — milestone 0.5

## Separation of trust boundaries

CloudSentry now has two FastAPI entry points:

- `scanner.api.app:app` remains the local, loopback-only API. Its path-based
  scanner endpoint must not be exposed to the internet.
- `scanner.api.platform_app:app` is the authenticated platform API. It accepts
  bounded, client-submitted scan reports and exposes tenant-scoped scan history;
  it never clones repositories, opens server paths, or executes a scan.

Run the hosted API with:

```sh
uvicorn scanner.api.platform_app:app --host 127.0.0.1 --port 8001
```

Do not deploy it until TLS termination, trusted proxy configuration, network
policy, production PostgreSQL, and an OIDC provider are configured.

## Required configuration

- `CLOUDSENTRY_DATABASE_URL`: PostgreSQL connection URL.
- `CLOUDSENTRY_OIDC_ISSUER`: exact expected token issuer.
- `CLOUDSENTRY_OIDC_AUDIENCE`: API audience registered with the identity provider.
- `CLOUDSENTRY_OIDC_JWKS_URL`: trusted HTTPS JWKS endpoint for the issuer.

Only RS256 tokens are accepted. Signature, issuer, audience, expiration, issued-at,
subject and required claims are validated. No algorithm is selected from the
untrusted token header. JWKS retrieval uses PyJWT's JWK client cache.

The API does not implement a password database, issue tokens, accept unsigned
tokens, or automatically create users from token claims. An administrator must
provision the external identity subject in the `users` table and create the
appropriate organization membership through a trusted provisioning process.

## Initial endpoints

- `GET /health`: process health only; contains no tenant data.
- `GET /api/v1/me`: authenticated identity and its memberships.
- `GET /api/v1/organizations`: organizations where the caller is a member.
- `POST /api/v1/organizations`: create an organization; the creator becomes its owner.
- `GET /api/v1/organizations/{organization_id}`: organization details for a member.
- `GET /api/v1/organizations/{organization_id}/projects`: projects in an
  organization only when the caller has a membership there.
- `POST /api/v1/organizations/{organization_id}/projects`: create a project (owner/admin).
- `GET /api/v1/organizations/{organization_id}/projects/{project_id}`: project details.
- `GET /api/v1/organizations/{organization_id}/projects/{project_id}/environments`:
  list project environments.
- `POST .../projects/{project_id}/environments`: create an environment (owner/admin).
- `POST /api/v1/organizations/{organization_id}/projects/{project_id}/scans/ingest`:
  import a bounded CLI report (owner, admin, security analyst only).
- `GET /api/v1/organizations/{organization_id}/projects/{project_id}/scans` and
  `GET .../scans/{scan_id}`: tenant-scoped scan history and details.
- `GET .../projects/{project_id}/findings`: active findings by default; suppressed
  findings require `include_suppressed=true`.

Unknown and unauthorized organization IDs both return 404 to reduce tenant
enumeration. Organization, project and environment reads are available to members;
project/environment creation is restricted to owners and admins. Scan ingestion and
finding lifecycle updates enforce their own role policies. Project repository URLs
are validated HTTPS GitHub metadata only; this API does not fetch or clone them.
Invitations, membership administration, token refresh, SCIM, and automated identity
provisioning are not implemented yet.

## Security limitations

Scan ingestion stores client-submitted data and marks its provenance
`client_supplied_report_unverified`; it is not proof that CloudSentry ran or verified
the scan. Complete and partial reports update observed findings, while failed reports
do not mutate finding state. Missing findings are not automatically resolved. See
[scan-result ingestion](scan-result-ingestion.md).

This is an API foundation, not a complete production identity product. Before
launch, add provider-specific OIDC integration tests, key-rotation and outage
tests, rate limits, structured security audit events, role-specific write
policies, request correlation, security headers, and deployment hardening.
The hosted API must remain separate from the local filesystem scanner until
isolated workers and server-managed source acquisition are implemented.
