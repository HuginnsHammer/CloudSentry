# OIDC platform API — milestone 0.3

## Separation of trust boundaries

CloudSentry now has two FastAPI entry points:

- `scanner.api.app:app` remains the local, loopback-only API. Its path-based
  scanner endpoint must not be exposed to the internet.
- `scanner.api.platform_app:app` is the hosted platform API. It has no scan
  endpoint and requires OIDC bearer authentication for all tenant data.

Run the hosted API with:

```sh
uvicorn scanner.api.platform_app:app --host 0.0.0.0 --port 8001
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
- `GET /api/v1/organizations/{organization_id}/projects`: projects in an
  organization only when the caller has a membership there.

Unknown and unauthorized organization IDs both return 404 to reduce tenant
enumeration. These initial endpoints are read-only. Role-sensitive write
operations, invitations, token refresh, SCIM, and administrative provisioning
are not implemented yet.

## Security limitations

This is an API foundation, not a complete production identity product. Before
launch, add provider-specific OIDC integration tests, key-rotation and outage
tests, rate limits, structured security audit events, role-specific write
policies, request correlation, security headers, and deployment hardening.
The hosted API must remain separate from the local filesystem scanner until
isolated workers and server-managed source acquisition are implemented.
