"""Source-comment suppressions requiring an explicit justification.

A directive is a comment of the form::

    # cloudsentry:ignore CS-DKR-001[, CS-DKR-002 | ALL] -- reason it is acceptable

(``//`` also works for Terraform). Scope is deliberately narrow:

* On a line of its own it applies to the next line of code, that is, the next line that is
  neither blank nor a comment. Several directives may be stacked above the same line.
* After code on the same line it applies to that line.

A directive never reaches past intervening code, so it cannot silently hide a different
finding further down the file. Findings are matched on the line they are reported at.
Directives that match nothing, or lack the mandatory reason, are reported as warnings so a
suppression that does not work is never mistaken for one that does.
"""

import re
from dataclasses import dataclass

from scanner.models import Finding, ScanWarning

# Require a comment marker preceded by whitespace (or line start) so text inside strings or
# URLs, such as `echo "# cloudsentry:ignore ..."`, is not treated as a directive.
_MARKER = r"(?:^|\s)(?:#|//)\s*cloudsentry:ignore\b"
_ANY_DIRECTIVE = re.compile(_MARKER, re.IGNORECASE)
_DIRECTIVE = re.compile(_MARKER + r"\s+([A-Z0-9_, -]+?)\s+--\s*(\S.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class Directive:
    line: int  # 1-based line holding the comment
    target: int | None  # 1-based line it applies to; None if no code follows it
    ids: frozenset[str]  # upper-case rule IDs, or "ALL"
    reason: str

    def matches(self, finding: Finding) -> bool:
        return (
            finding.line_start is not None
            and finding.line_start == self.target
            and ("ALL" in self.ids or finding.rule_id.upper() in self.ids)
        )


def _is_comment_only(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith("//")


def _target_line(lines: list[str], index: int) -> int | None:
    if not _is_comment_only(lines[index]):
        return index + 1  # trailing directive: applies to its own line
    for later in range(index + 1, len(lines)):
        if lines[later].strip() and not _is_comment_only(lines[later]):
            return later + 1
    return None


def parse_directives(source: str) -> tuple[list[Directive], list[int]]:
    """Return (valid directives, 1-based line numbers of malformed directives)."""
    lines = source.splitlines()
    directives: list[Directive] = []
    malformed: list[int] = []
    for index, text in enumerate(lines):
        if not _ANY_DIRECTIVE.search(text):
            continue
        match = _DIRECTIVE.search(text)
        ids = (
            {item.strip().upper() for item in re.split(r"[, ]+", match.group(1)) if item.strip()}
            if match
            else set()
        )
        reason = match.group(2).strip() if match else ""
        if not (ids and reason):
            malformed.append(index + 1)
            continue
        directives.append(Directive(index + 1, _target_line(lines, index), frozenset(ids), reason))
    return directives, malformed


def apply_suppressions(findings: list[Finding], source: str) -> list[Finding]:
    """Mark findings covered by a directive; the first matching directive supplies the reason."""
    directives, _ = parse_directives(source)
    for finding in findings:
        for directive in directives:
            if directive.matches(finding):
                finding.suppressed = True
                finding.suppression_reason = directive.reason
                break
    return findings


def directive_warnings(findings: list[Finding], source: str, file_path: str) -> list[ScanWarning]:
    """Report malformed directives and directives that matched no finding."""
    directives, malformed = parse_directives(source)
    warnings = [
        ScanWarning(
            file_path=file_path,
            line_start=line,
            message=(
                "Ignored cloudsentry:ignore directive: expected "
                "'cloudsentry:ignore RULE_ID[, RULE_ID] -- reason'; a reason is required."
            ),
        )
        for line in malformed
    ]
    for directive in directives:
        if any(directive.matches(finding) for finding in findings):
            continue
        ids = ", ".join(sorted(directive.ids))
        where = (
            f"no matching finding on line {directive.target}"
            if directive.target is not None
            else "no code follows it"
        )
        warnings.append(
            ScanWarning(
                file_path=file_path,
                line_start=directive.line,
                message=(
                    f"Unused cloudsentry:ignore {ids}: {where}. "
                    "Place the directive directly above the line the finding is reported on, "
                    "or at the end of that line."
                ),
            )
        )
    return sorted(warnings, key=lambda warning: warning.line_start or 0)
