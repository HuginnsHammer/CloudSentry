import hashlib
from scanner.models import Finding, Severity

def make_finding(*, rule_id: str, title: str, description: str, severity: Severity, category: str, file_path: str, line: int | None, evidence: str, impact: str, remediation: str, resource: str | None = None, confidence: str = "high") -> Finding:
    raw = f"{rule_id}|{file_path}|{line}|{resource or ''}|{evidence.strip()}"
    return Finding(rule_id=rule_id, title=title, description=description, severity=severity, confidence=confidence, category=category, file_path=file_path, line_start=line, line_end=line, resource=resource, evidence=evidence.strip()[:500], impact=impact, remediation=remediation, fingerprint=hashlib.sha256(raw.encode()).hexdigest()[:24])
