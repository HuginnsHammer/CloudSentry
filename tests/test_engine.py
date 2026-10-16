from pathlib import Path
from scanner.engine import scan_paths

def test_directory_scan_and_parse_error(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\n", encoding="utf-8")
    (tmp_path / "broken.tf").write_text('resource "x" {', encoding="utf-8")
    result = scan_paths([tmp_path])
    assert result.files_scanned == 1
    assert any(f.rule_id == "CS-DKR-002" for f in result.findings)
    assert result.errors and result.status == "partial"

def test_oversized_file_is_reported(tmp_path: Path):
    file = tmp_path / "Dockerfile"
    file.write_bytes(b"#" * (2 * 1024 * 1024 + 1))
    result = scan_paths([file])
    assert result.errors[0].kind == "input"
    assert result.files_scanned == 0
