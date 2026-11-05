# Finding management and audit workflow

CloudSentry's authenticated platform API exposes a tenant-scoped finding workflow.

## Read findings

`GET /api/v1/organizations/{organization_id}/projects/{project_id}/findings`

Optional filters:

- `status`: open, triaged, in_progress, accepted_risk, resolved, false_positive
- `severity`: critical, high, medium, low, info
- `assigned_to_me=true`: only findings assigned to the authenticated user

Fetch one finding by appending `/{finding_id}`.

## Update a finding

`PATCH /api/v1/organizations/{organization_id}/projects/{project_id}/findings/{finding_id}`

Example:

```json
{
  "status": "triaged",
  "assigned_to_user_id": "00000000-0000-0000-0000-000000000000",
  "note": "Confirmed with the service owner; remediation is scheduled."
}
```

The API enforces roles server-side:

- owner, admin, security_analyst: may change status and assign organization members
- developer: may move findings to in_progress or resolved, but cannot assign or accept risk
- viewer: read-only

Risk acceptance and false-positive decisions require a non-empty note. Assignments must target a user who belongs to the same organization. A finding from another tenant or project is not disclosed.

Every effective update writes an `AuditEvent` in the same database transaction as the finding change. The event records the actor, target, changed values and optional note. It deliberately does not copy source evidence into the audit log. If validation or persistence fails, the update and its audit record roll back together.

## Current limitations

This is the first lifecycle API, not a full case-management system. Bulk updates, comments as separate records, SLA policies, notifications, evidence redaction controls, scan ingestion and richer transition policies are future work. Audit events are append-only by application convention; production deployments should additionally restrict database permissions and retention policies so application users cannot alter or erase audit history.
