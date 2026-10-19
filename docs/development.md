# Development

Use Python 3.12+. Install with python -m pip install -e '.[dev]'. Run pytest and ruff check .. The current lint gate checks for undefined names; formatting and broader style checks remain follow-up hardening work.

Every rule change should include vulnerable and secure examples, stable IDs, remediation, and limitations. Never execute scanned configuration files. Suppression directives must include a reason and are deliberately narrow: they apply only to the next line of code (or the line they trail), matched against the line a finding is reported at. When changing a rule, keep its reported line stable and cover it with a line-number test so suppressions keep working.
