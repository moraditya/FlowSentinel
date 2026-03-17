"""
Smoke test — verify the app boots and core routes respond.

Uses a lifespan-backed TestClient so startup/shutdown hooks run.
Does NOT require model artifacts on disk.
"""

from __future__ import annotations

from starlette.testclient import TestClient


class TestSmoke:
    """Minimal end-to-end checks that the app is alive."""

    def test_health_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")

    def test_feature_names_returns_28(self, client: TestClient) -> None:
        resp = client.get("/api/feature-names")
        assert resp.status_code == 200
        assert len(resp.json()) == 28

    def test_capture_status_not_capturing(self, client: TestClient) -> None:
        resp = client.get("/api/capture/status")
        assert resp.status_code == 200
        assert resp.json()["is_capturing"] is False

    def test_baseline_status_valid(self, client: TestClient) -> None:
        resp = client.get("/api/baseline/status")
        assert resp.status_code == 200
        assert resp.json()["status"] in ("not_collected", "collecting", "ready")

    def test_replay_status_idle(self, client: TestClient) -> None:
        resp = client.get("/api/replay/status")
        assert resp.status_code == 200
        assert resp.json()["state"] in ("idle", "completed")

    def test_detection_stats_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/detection/stats")
        assert resp.status_code == 200

    def test_websocket_accepts(self, client: TestClient) -> None:
        with client.websocket_connect("/ws/live") as ws:
            # Connection accepted — read one heartbeat or event
            data = ws.receive_json(mode="text")
            assert "type" in data or "timestamp" in data
