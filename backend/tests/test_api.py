from fastapi.testclient import TestClient

from dpn_ds.app import create_app
from dpn_ds.config import Settings
from dpn_ds.directory import DemoDirectory


def client(token="test-key", mode="demo") -> TestClient:
    return TestClient(create_app(
        Settings(api_token=token, mode=mode, realm="corp.example.com", controller="dc01"),
        directory=DemoDirectory(),
    ))


def test_health_is_non_sensitive():
    response = client().get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_token_required_for_every_directory_route():
    c = client()
    for route in ("overview", "users", "groups", "devices", "diagnostics", "advanced-health"):
        assert c.get(f"/api/v1/{route}").status_code == 401
        wrong = c.get(f"/api/v1/{route}", headers={"Authorization": "Bearer wrong"})
        assert wrong.status_code == 401


def test_missing_configuration_fails_closed():
    response = client(token="").get(
        "/api/v1/overview", headers={"Authorization": "Bearer anything"}
    )
    assert response.status_code == 503


def test_demo_overview_is_explicitly_simulated():
    response = client().get(
        "/api/v1/overview", headers={"Authorization": "Bearer test-key"}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "demo"
    assert payload["controller_status"] == "simulated"
    assert payload["counts"] == {"users": 5, "groups": 4, "devices": 4}


def test_read_only_api():
    c = client()
    response = c.post("/api/v1/users", headers={"Authorization": "Bearer test-key"})
    assert response.status_code == 405
