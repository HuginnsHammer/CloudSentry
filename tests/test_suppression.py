from scanner.rules.dockerfile import scan_dockerfile
from scanner.suppression import apply_suppressions

def test_suppression_requires_reason_and_matches_adjacent_line():
    source = "# cloudsentry:ignore CS-DKR-001 -- accepted in isolated build image\nUSER root\n"
    findings = scan_dockerfile(source, "Dockerfile")
    result = apply_suppressions(findings, source)
    finding = next(item for item in result if item.rule_id == "CS-DKR-001")
    assert finding.suppressed is True
    assert finding.suppression_reason == "accepted in isolated build image"

def test_suppression_does_not_hide_other_rules():
    source = "# cloudsentry:ignore CS-DKR-001 -- documented exception\nFROM ubuntu:latest\nUSER root\n"
    result = apply_suppressions(scan_dockerfile(source, "Dockerfile"), source)
    assert next(f for f in result if f.rule_id == "CS-DKR-001").suppressed
    assert not next(f for f in result if f.rule_id == "CS-DKR-002").suppressed

def test_suppression_without_reason_is_ignored():
    source = "# cloudsentry:ignore CS-DKR-001\nUSER root\n"
    result = apply_suppressions(scan_dockerfile(source, "Dockerfile"), source)
    assert not next(f for f in result if f.rule_id == "CS-DKR-001").suppressed
