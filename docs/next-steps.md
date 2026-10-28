# CloudSentry development checklist

A small, practical checklist for the next development sessions. Keep this list tied to tested behavior rather than treating planned work as completed features.

## Scanner correctness

- [ ] Add regression tests for each rule's positive case, safe counterexample, and expected source location.
- [ ] Verify malformed, unreadable, oversized, and unsupported inputs produce an incomplete-scan result rather than a clean result.
- [ ] Test that exit code `2` takes precedence over findings (exit code `1`) when a scan is incomplete.
- [ ] Confirm finding fingerprints stay stable when unrelated lines are added to a file.

## Suppressions and reports

- [ ] Test valid suppressions, missing reasons, and expired or malformed suppression entries (where supported).
- [ ] Check that text, JSON, and SARIF reports agree on finding identity, severity, and suppression state.
- [ ] Validate SARIF output against representative findings and scan warnings.

## Dashboard reliability

- [ ] Verify Complete, Partial, and Error states against real API responses.
- [ ] Check loading, empty, API-unavailable, and invalid-target-path states.
- [ ] Confirm the suppressed-findings toggle exposes suppression reasons without mixing suppressed items into the default active-risk view.
- [ ] Run `npm ci` and `npm run build` from `frontend/` on a clean checkout.

## Release hygiene

- [ ] Run `.venv/bin/pytest` and `.venv/bin/ruff check .` from the repository root.
- [ ] Review every new rule for evidence quality, confidence, impact, and actionable remediation.
- [ ] Update the README and limitations document when observable behavior or supported inputs change.
- [ ] Keep the API bound to `127.0.0.1` unless a separate, reviewed network security design is implemented.

## Working rule

Pick one unchecked item per session, add or update a test where possible, run the relevant checks, and only then mark it complete. A passing test suite is evidence for the covered cases—not proof that every configuration is secure.
