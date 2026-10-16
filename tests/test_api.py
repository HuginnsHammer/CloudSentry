from fastapi.testclient import TestClient
from scanner.api.app import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "local-static-analysis"

def test_scan_rejects_missing_path():
    response = client.post("/api/v1/scan", json={"paths": ["./definitely-not-a-cloudsentry-path"]})
    assert response.status_code == 400

def test_scan_validates_path_list():
    response = client.post("/api/v1/scan", json={"paths": []})
    assert response.status_code == 422
