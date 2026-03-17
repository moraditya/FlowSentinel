"""Tests for GET /api/health."""

from __future__ import annotations

from starlette.testclient import TestClient


class TestHealthEndpoint:
    """Verify the health-check endpoint returns the expected payload."""

    def test_health_status_code(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_response_shape(self, client: TestClient) -> None:
        data = client.get("/api/health").json()
        assert "status" in data
        assert "model_loaded" in data
        assert "model_type" in data

    def test_health_status_valid(self, client: TestClient) -> None:
        data = client.get("/api/health").json()
        assert data["status"] in ("healthy", "degraded")

    def test_health_model_loaded_type(self, client: TestClient) -> None:
        data = client.get("/api/health").json()
        assert isinstance(data["model_loaded"], bool)

    def test_health_model_type(self, client: TestClient) -> None:
        data = client.get("/api/health").json()
        assert data["model_type"] == "xgboost"

    def test_health_no_extra_keys(self, client: TestClient) -> None:
        data = client.get("/api/health").json()
        assert set(data.keys()) == {"status", "model_loaded", "model_type", "mode"}

    def test_health_content_type(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.headers["content-type"] == "application/json"
