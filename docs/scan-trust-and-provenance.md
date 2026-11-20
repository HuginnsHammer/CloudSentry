# Scan trust, evidence and provenance

## Three distinct questions

A scan record must keep separate:

1. **Who submitted the report?**
2. **How was the report produced?**
3. **What source revision and configuration scope were inspected?**

These are not interchangeable. A report accepted by an authenticated API is not automatically a report produced by CloudSentry's trusted worker. A worker-produced report is not a cryptographic attestation of the host, container runtime or scanner binary.

## Provenance labels

- `client_import` (or the equivalent unverified-import state): a client supplied the report. Treat its claims as unverified input.
- `server_managed_worker`: the platform worker requested the scan from the configured executor and validated the response before persistence. This identifies the application execution path, not independent runtime attestation.

Never promote client-imported data to server-managed provenance merely because it belongs to an authenticated organization.

## Evidence integrity

For GitHub-triggered scans, bind the job to the verified repository identity and immutable commit SHA. Validate that the executor response identifies the same target and revision. Re-check the project/repository/installation binding before publishing results.

Persist the scan result and successful job completion transactionally so a failed publication cannot leave a job marked complete without its result. Preserve scan diagnostics and partial status; never turn missing evidence into a clean result.

## Evidence limits

Evidence excerpts are useful for review but may contain secrets or personal data. Keep excerpts bounded, avoid logging raw configuration or webhook payloads, apply access controls to scan records, and define retention/deletion policies before production use.

A source SHA proves which revision was requested; it does not prove the repository content was safe, the worker host was uncompromised, or the scanner detected every issue.
