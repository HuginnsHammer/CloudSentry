# API

Run locally: uvicorn scanner.api.app:app --host 127.0.0.1 --port 8000.

- GET /health — health check.
- POST /api/v1/scan — JSON body such as {"paths":["./examples"]}; returns normalized scan results.

Security warning: this endpoint accepts local filesystem paths. Do not expose it to untrusted users. Authentication, allowlisted roots, rate limits, and resource controls are required before network deployment.
