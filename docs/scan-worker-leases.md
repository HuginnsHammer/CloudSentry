# Scan job lease contract

This document describes the durable queue primitives in `scanner.platform.worker`.
They manage ownership and retries only. They do not clone a repository, execute a
scanner, or attest that a scan occurred.

## Transaction contract

A worker must use a unique, stable process identifier (1-128 printable characters,
without surrounding whitespace or control characters) and a dedicated PostgreSQL
database session for each queue operation.

1. Call `claim_next_job(session, worker_id)`.
2. Commit immediately. Do not hold the row lock while doing network or filesystem work.
3. Perform work outside the database transaction.
4. Renew a still-valid lease periodically with `renew_job_lease`.
5. Complete or fail only while the worker still owns an unexpired lease.
6. Commit each state transition.

Claims use `SELECT ... FOR UPDATE SKIP LOCKED` on databases that support it, so
multiple PostgreSQL workers can take different jobs without waiting on one another.
Queued jobs are eligible at `available_at`; running jobs become eligible again
only after their lease expires. Each claim consumes one attempt. Expired jobs at
their attempt limit transition to failed rather than remaining stuck in running.

## Lease and retry limits

- Lease duration: 30-3,600 seconds.
- Default lease: 300 seconds.
- Attempts: bounded by each job's `max_attempts` (database constraint: 1-10).
- Default retry delay: 30 seconds, then exponential backoff capped at one hour.
- A worker whose lease expired cannot renew, complete, or fail the job.
- A job that reaches its attempt limit becomes terminally failed.

## Required worker security before execution is enabled

These primitives are not a sandbox. A production executor must not run with
control-plane credentials or unrestricted network access. Before enabling source
checkout or scanner execution, implement and validate all of the following:

- Fetch only the repository ID already verified and bound to the tenant project.
- Use a short-lived, read-only GitHub installation token; never persist or log it.
- Pin checkout to the queued full commit SHA, verify the resulting HEAD, and reject
  redirects or hosts outside the configured GitHub API/archive endpoints.
- Use a fresh, private temporary workspace per job; reject symlinks and unsafe
  archive paths; enforce checkout size, file count, disk, CPU, memory and wall-time
  limits.
- Run the scanner as an unprivileged isolated process/container with no control-plane
  secrets, no Docker socket, no host mounts, and no outbound network.
- Ensure cancellation and lease loss terminate the subprocess; a stale worker must
  never publish results after losing its lease.
- Persist results through the existing bounded ingestion service in a transaction,
  associating the immutable source revision. Mark a job completed only after the
  scan record and observations have committed successfully.
- Treat partial/error scans as incomplete; never resolve findings from them.
- Record only bounded, redacted operator diagnostics. Never store source contents,
  access tokens, raw exception traces or webhook bodies in job error fields.

The PostgreSQL CI integration test also holds one worker transaction open while a
second worker claims another row, verifying that `SKIP LOCKED` avoids duplicate
claims. Until the source-acquisition and sandbox controls above exist, the queue
must remain a durable request-for-work mechanism, not a claim of continuous scanning.
