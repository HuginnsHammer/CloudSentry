"""Source-comment suppressions requiring an explicit justification."""
import re
from scanner.models import Finding

_DIRECTIVE = re.compile(r"cloudsentry:ignore\s+([A-Z0-9_, -]+?)\s+--\s*(\S.*)$", re.IGNORECASE)

def apply_suppressions(findings: list[Finding], source: str) -> list[Finding]:
    directives: dict[int, tuple[set[str], str]] = {}
    for number, line in enumerate(source.splitlines(), 1):
        match = _DIRECTIVE.search(line)
        if not match:
            continue
        ids = {item.strip().upper() for item in re.split(r"[, ]+", match.group(1)) if item.strip()}
        reason = match.group(2).strip()
        if ids and reason:
            directives[number] = (ids, reason)
    for finding in findings:
        candidates = [finding.line_start, (finding.line_start - 1 if finding.line_start else None)]
        for number in candidates:
            if number is None or number not in directives:
                continue
            ids, reason = directives[number]
            if finding.rule_id.upper() in ids or "ALL" in ids:
                finding.suppressed = True
                finding.suppression_reason = reason
                break
    return findings
