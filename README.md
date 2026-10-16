# CloudSentry

**Find the misconfiguration before it becomes an incident.**

CloudSentry is a lightweight, local-first static configuration auditor for Terraform, Dockerfiles, and Docker Compose. It works without cloud credentials, an account, an AI model, or a hosted security API.

> Early development: checks are heuristic static analysis, not a guarantee of security. See docs/limitations.md.

## Features
- CLI with terminal and JSON reports.
- Terraform HCL, Dockerfile, and Docker Compose YAML checks.
- Stable rule IDs, severity, confidence, evidence, impact, remediation, fingerprints, source locations, and reasoned suppressions.
- FastAPI endpoint and React + TypeScript dashboard for local scanning.
- No applying Terraform, building images, starting containers, or executing scanned files.

## Quick start
Requires Python 3.12+.

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -e '.[dev]'
    cloudsentry scan examples --format text
    cloudsentry scan examples --format json --output report.json
    pytest

## Run API and dashboard

    uvicorn scanner.api.app:app --host 127.0.0.1 --port 8000
    cd frontend && npm install && npm run dev

Open http://127.0.0.1:5173. Keep the API bound to loopback: its endpoint accepts local filesystem paths and is not safe to expose to untrusted clients.

## Exit codes
0 = no findings at or above the selected severity threshold; 1 = qualifying findings; 2 = input/parser/usage error. A clean scan is not proof that a configuration is secure.

## Development

    pytest
    ruff check .

The initial Ruff gate checks for undefined names. Formatting and broader style rules are follow-up hardening work; see the development notes.

## Responsible use
Scan configurations you own or are authorized to assess. Verify findings against deployment context and current provider guidance. See SECURITY.md for reporting.

MIT License; see LICENSE.
