# Threat model

Scanned files are untrusted input. Controls include a 2 MiB per-file limit, UTF-8 decoding, YAML safe_load, structured parser errors, deterministic results, and no configuration execution or outbound calls.

The HTTP API accepts local filesystem paths and is unsafe to expose to untrusted clients in its current form. Keep it on loopback. Authentication, authorization, allowlisted scan roots, rate limiting, concurrency limits, and symlink/path hardening remain outstanding before multi-user deployment.
