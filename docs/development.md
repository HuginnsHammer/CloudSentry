# Development

Use Python 3.12+. Install with python -m pip install -e '.[dev]'. Run pytest and ruff check .. The current lint gate checks for undefined names; formatting and broader style checks remain follow-up hardening work.

Every rule change should include vulnerable and secure examples, stable IDs, remediation, and limitations. Never execute scanned configuration files. Suppression directives must include a reason and should be narrowly scoped.
