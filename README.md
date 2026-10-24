# CloudSentry

**Find the misconfiguration before it becomes an incident.**

CloudSentry is a lightweight, local-first static configuration auditor for Terraform, Dockerfiles, and Docker Compose. It checks configuration files without cloud credentials, an account, an AI model, or a hosted security API.

> **Early development:** CloudSentry uses heuristic static analysis. Findings need to be reviewed in context, and a clean scan is not proof that a configuration is secure. See [docs/limitations.md](docs/limitations.md).

## What it does

- Scans Terraform, Dockerfiles, and Docker Compose YAML.
- Reports rule IDs, severity, confidence, evidence, impact, remediation, fingerprints, and source locations.
- Supports terminal, JSON, and SARIF 2.1.0 CLI reports, plus a local FastAPI API and React + TypeScript dashboard.
- Includes scan errors and warnings in SARIF invocation diagnostics, so incomplete scans are visible in machine-readable output.
- Supports reasoned suppressions and preserves suppression justifications in machine-readable reports.
- Does not apply Terraform, build images, start containers, or execute scanned files.

## Requirements

- Python 3.12 or newer
- Node.js and npm (for the dashboard)

## Quick start: CLI

From the repository root:

```sh
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'

# Human-readable report
.venv/bin/cloudsentry scan examples --format text

# JSON report written to report.json
.venv/bin/cloudsentry scan examples --format json --output report.json

# SARIF 2.1.0 report for compatible code-scanning tools
.venv/bin/cloudsentry scan examples --format sarif --output cloudsentry.sarif
```

These commands use the virtual environment directly, so activating it is optional and the commands work in Fish as well as common POSIX shells. Exit codes remain the same for all output formats: `0` means no qualifying active findings, `1` means qualifying findings were found, and `2` means the scan was incomplete or the command was misused.

## Run the dashboard locally

Run the API and frontend in **two separate terminals**. Start both from the repository checkout.

**Terminal 1 — API**

```sh
cd ~/CloudSentry
.venv/bin/uvicorn scanner.api.app:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — frontend**

```sh
cd ~/CloudSentry/frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) in your browser. Enter the path to a configuration file or directory on the **same machine running the API**, then select **Run scan**. The API health endpoint is available at [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).

**Security note:** Keep the API bound to loopback (`127.0.0.1`). The scan endpoint accepts local filesystem paths and is intended for local development; do not expose it to a network or untrusted clients.

## Try a small demo scan

This creates two deliberately insecure sample files in a temporary directory. Use `/tmp/cloudsentry-demo` as the dashboard target path after starting the API and frontend.

```sh
mkdir -p /tmp/cloudsentry-demo

printf '%s\n' \
  'FROM ubuntu:latest' \
  'USER root' \
  > /tmp/cloudsentry-demo/Dockerfile

printf '%s\n' \
  'resource "aws_security_group" "demo" {' \
  '  ingress {' \
  '    from_port   = 0' \
  '    to_port     = 65535' \
  '    protocol    = "tcp"' \
  '    cidr_blocks = ["0.0.0.0/0"]' \
  '  }' \
  '}' \
  > /tmp/cloudsentry-demo/main.tf
```

The demo is intentionally unsafe so the scanner has findings to display. Do not use these example settings in a real deployment.

## Development checks

From the repository root:

```sh
.venv/bin/pytest
.venv/bin/ruff check .
```

Build and type-check the frontend:

```sh
cd frontend
npm install
npm run build
```

## Exit codes

- `0` — no findings at or above the selected severity threshold.
- `1` — qualifying findings were reported.
- `2` — the scan is incomplete, no supported configuration files were found, an explicit input is unsupported, or the command was misused (for example, a parse error, unreadable input, or oversized input).

Exit code `2` takes precedence over `1`, so a CI gate cannot pass when part of the target went unscanned.

## Responsible use

Scan configurations you own or are authorized to assess. Review findings against your deployment context and current provider guidance. See [SECURITY.md](SECURITY.md) for reporting instructions.

MIT License; see [LICENSE](LICENSE).
