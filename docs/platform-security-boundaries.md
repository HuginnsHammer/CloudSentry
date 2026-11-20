# Platform security boundaries

## Trust zones

| Zone | Responsibilities | Credentials allowed |
|---|---|---|
| Browser/dashboard | Display organization data and submit authorized actions | User session/token only |
| API/control plane | Authentication, authorization, tenant scoping, webhooks, persistence | Database credentials, OIDC configuration, GitHub App credentials and webhook secret |
| Worker | Lease jobs, fetch verified GitHub archives, coordinate execution | Database access, GitHub App credentials, worker-to-executor secret |
| Executor | Inspect one bounded source archive and return a report | Worker-to-executor secret only |

Do not collapse these zones by passing control-plane credentials into the executor.

## Required controls

- Enforce tenant authorization on every organization-owned object lookup and mutation.
- Scope database queries and uniqueness constraints to the tenant where appropriate.
- Verify webhook HMAC signatures over the raw request body and deduplicate delivery IDs.
- Bind repository access to a claimed GitHub App installation and verified repository ID.
- Pin scans to immutable commit SHAs; never fetch arbitrary user-supplied URLs.
- Bound archive bytes, expanded bytes, file count, path depth and scan duration.
- Reject path traversal, links and special files in downloaded archives.
- Run the executor with no outbound network and no host/container-runtime access.
- Keep secrets out of source control, frontend bundles, logs and scan evidence.
- Apply rate limits, quotas, concurrency limits and retention policies before public multi-tenant use.

## Current status

The application implements several of these controls in its API, webhook, ingestion and archive-processing paths. The repository does not yet provide a deployment artifact that demonstrates the executor's OS/container isolation, and the worker lease heartbeat/cancellation path remains incomplete. Treat these as production blockers, not optional hardening.

## Security review rule

A control is considered complete only when it has:
1. An implementation.
2. A test for the security property and relevant failure cases.
3. A deployment configuration that enables the control.
4. Operational visibility for failures or bypass attempts.
