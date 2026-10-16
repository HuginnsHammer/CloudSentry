"""Source-comment suppressions requiring an explicit justification."""
import re
from scanner.models import Finding

_DIRECTIVE = re.compile(r"cloudsentry:ignore\s+([A-Z0-9_, -]+?)\s+--\s*(\S.*)$", re.IGNORECASE)

def apply_suppressions(findings: list[Finding], source: str) -> list[Finding]:
    directives: list[tuple[int, set[str], str]] = []
    for number, line in enumerate(source.splitlines(), 1):
        match = _DIRECTIVE.search(line)
        if not match:
            continue
        ids = {item.strip().upper() for item in re.split(r"[, ]+", match.group(1)) if item.strip()}
        reason = match.group(2).strip()
        if ids and reason:
            directives.append((number, ids, reason))
    for finding in findings:
        if finding.line_start is None:
            continue
        # A directive applies to the next matching rule finding below it, even if
        # unrelated instructions occur between the comment and the source line.
        preceding = [item for item in directives if item[0] < finding.line_start]
        if not preceding:
            continue
        number, ids, reason = preceding[-1]
        if finding.rule_id.upper() in ids or "ALL" in ids:
            finding.suppressed = True
            finding.suppression_reason = reason
            directives.remove((number, ids, reason))
    return findings
