# Changelog

## Unreleased
- Initial local static scanner for Terraform, Dockerfiles, and Compose.
- Added CLI, API, initial deterministic rules, fixtures, tests, and security documentation.

### Fixed
- Findings now report the line of the offending resource, ingress block, or Compose service. Previously the first textual match anywhere in the file was used, so a second unencrypted volume, open security group, or privileged service was attributed to an earlier, unrelated line. Because fingerprints include the line, fingerprints of affected Terraform and Compose findings change.
- `cloudsentry scan` now exits 2 whenever any file could not be scanned. Previously a parse or input error next to otherwise clean files exited 0 (or 1 with findings), contradicting the documented exit codes and letting a CI gate pass with part of the target unscanned. A one-line notice is also written to stderr.
- The JSON report no longer drops suppressed findings. They are kept with `suppressed: true` and their reason as an audit trail, and are excluded from the risk score and exit status. The text report prints a count of suppressed findings.

### Changed
- **Suppression scope is narrower (behavior change).** A `cloudsentry:ignore` directive previously applied to the next matching finding below it at any distance, so a comment near the top of a file could silence an unrelated finding many lines later. It now applies only to the next line of code (skipping blank lines and comments, with several directives stackable), or to its own line when it trails code. Existing directives that sat above a different line than the one the finding is reported on must be moved directly above that line or to its end.
- Directives must now be real comments (`#` or `//` after whitespace), so directive-like text inside strings is ignored.

### Added
- `warnings` in the scan result and a `warning:` line in the text report for suppression directives that matched nothing or were ignored for lacking a reason. Warnings do not change the exit status.
