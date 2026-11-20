# Worker and executor operations

## Process responsibilities

- **API/control plane:** authenticates platform requests, receives signed GitHub webhooks, manages tenant records and queues durable jobs.
- **Worker:** leases jobs, obtains the pinned source archive using the GitHub App, submits bounded content to the private executor, validates the response and publishes results.
- **Executor:** performs static analysis on an ephemeral source workspace and returns a bounded report.

The executor must not receive the platform database URL, GitHub App private key, OIDC configuration or other control-plane credentials.

## Current limitations

The repository contains worker and executor process entry points, but does not yet provide a complete production deployment manifest or prove OS/container isolation. The worker lease does not currently have a renewal heartbeat. Keep the executor timeout below the configured lease duration and monitor for expired leases until heartbeat and cancellation behavior are implemented.

## Operational signals to add

Track at least:

- Queue depth and oldest queued-job age.
- Jobs leased, completed, failed, retried and dead-lettered.
- Lease expiry and lease ownership loss.
- Executor availability, latency and timeout count.
- Archive download failures and rejected archive limits.
- Scan duration, files inspected, findings count and partial/error outcomes.
- Per-tenant concurrency and quota utilization.

Metrics and logs must not include installation tokens, private keys, webhook secrets, raw source files or unredacted configuration excerpts.

## Recovery expectations

A worker restart must not lose queued jobs. Expired leases should be safely reclaimable. Repeatedly failing jobs need bounded retries and a visible terminal state. A stale worker must not publish after losing lease ownership. Add a recovery drill that terminates a worker during archive acquisition, execution and result publication.

## Deployment boundary

Expose the executor only on a private worker-to-executor network. Apply a non-root identity, read-only root filesystem, ephemeral bounded workspace, no host mounts, no runtime socket, no outbound network, syscall restrictions and CPU/memory/PID/file-size/time limits outside the application process. A subprocess timeout alone is not a sandbox.
