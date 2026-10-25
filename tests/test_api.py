from pathlib import Path

from fastapi.testclient import TestClient

from scanner.api.app import app

client = TestClient(app, client=("127.0.0.1", 50000))


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "local-static-analysis"


def test_non_loopback_client_is_rejected():
    remote_client = TestClient(app, client=("192.0.2.10", 50000))

    response = remote_client.get("/health")

    assert response.status_code == 403
    assert response.json()["detail"] == "CloudSentry API is restricted to loopback clients"


def test_scan_rejects_missing_path():
    response = client.post(
        "/api/v1/scan",
        json={"paths": ["./definitely-not-a-cloudsentry-path"]},
    )
    assert response.status_code == 400


def test_scan_validates_path_list():
    response = client.post("/api/v1/scan", json={"paths": []})
    assert response.status_code == 422


def test_scan_rejects_blank_path_values():
    for value in ("", "   ", "\t"):
        response = client.post("/api/v1/scan", json={"paths": [value]})
        assert response.status_code == 422


def test_scan_reports_directory_without_supported_files(tmp_path: Path):
    (tmp_path / "README.md").write_text("Nothing to scan here.\n", encoding="utf-8")

    response = client.post("/api/v1/scan", json={"paths": [str(tmp_path)]})

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "error"
    assert result["files_scanned"] == 0
    assert result["errors"][0]["kind"] == "discovery"


def test_scan_reports_unrelated_yaml_as_unsupported(tmp_path: Path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("apiVersion: v1\nkind: ConfigMap\n", encoding="utf-8")

    response = client.post("/api/v1/scan", json={"paths": [str(manifest)]})

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "error"
    assert result["errors"][0]["kind"] == "unsupported"
