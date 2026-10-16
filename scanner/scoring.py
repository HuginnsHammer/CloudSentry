from scanner.models import Finding, Severity
WEIGHTS = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 1}
def summarize(findings: list[Finding]) -> tuple[int, dict[str, int]]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        if not finding.suppressed: counts[finding.severity.value] += 1
    points = sum(WEIGHTS[f.severity] for f in findings if not f.suppressed)
    return min(100, points), counts
