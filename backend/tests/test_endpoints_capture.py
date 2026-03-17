"""
Integration tests for the capture and baseline endpoints.

These tests verify HTTP-level behaviour (status codes, response schemas,
auth requirements) using the FastAPI TestClient.  Actual packet capture
is NOT started — the tests validate the API contract only.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

# ══════════════════════════════════════════════════════════════════════
# Capture endpoints
# ══════════════════════════════════════════════════════════════════════


class TestCaptureEndpoints:
    """Verify /api/capture/* routes."""

    # ── GET /api/capture/status (public) ─────────────────────────────

    def test_status_no_auth_ok(self, client: TestClient) -> None:
        """GET /api/capture/status should be public."""
        resp = client.get("/api/capture/status")
        assert resp.status_code == 200

    def test_status_response_schema(self, client: TestClient) -> None:
        data = client.get("/api/capture/status").json()
        expected_keys = {
            "is_capturing",
            "interface",
            "packets_captured",
            "flows_analyzed",
            "threats_detected",
            "uptime_seconds",
            "error",
        }
        assert set(data.keys()) == expected_keys

    def test_status_not_capturing_after_stop(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """After stopping, capture status should reflect not capturing."""
        client.post("/api/capture/stop", headers=auth_headers)
        data = client.get("/api/capture/status").json()
        assert data["is_capturing"] is False

    # ── POST /api/capture/start (protected) ──────────────────────────

    def test_start_without_key_returns_422(self, client: TestClient) -> None:
        """POST /api/capture/start without API key should return 422."""
        resp = client.post("/api/capture/start", json={"interface": "lo0"})
        assert resp.status_code == 422

    def test_start_with_invalid_key_returns_401(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/api/capture/start",
            json={"interface": "lo0"},
            headers={"X-Api-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_start_with_valid_key_accepted(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """POST /api/capture/start with valid key returns 200 or 400.

        Returns 200 if capture starts, 400 if preflight fails (no root).
        Should never return 401 or 422 with a valid key.
        """
        resp = client.post(
            "/api/capture/start",
            json={"interface": "lo0", "bpf_filter": ""},
            headers=auth_headers,
        )
        assert resp.status_code in (200, 400)

    def test_start_response_has_detail_or_schema(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Start returns either a capture status or an error detail."""
        resp = client.post(
            "/api/capture/start",
            json={"interface": "lo0"},
            headers=auth_headers,
        )
        data = resp.json()
        # Either a capture status response or an error with detail
        assert "is_capturing" in data or "detail" in data

    # ── POST /api/capture/stop (protected) ───────────────────────────

    def test_stop_without_key_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/capture/stop")
        assert resp.status_code == 422

    def test_stop_with_valid_key_returns_200(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.post("/api/capture/stop", headers=auth_headers)
        assert resp.status_code == 200

    def test_stop_response_schema(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        data = client.post("/api/capture/stop", headers=auth_headers).json()
        assert "is_capturing" in data
        assert "packets_captured" in data

    def test_stop_cancels_baseline(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Stopping capture should cancel any in-progress baseline."""
        client.post("/api/capture/stop", headers=auth_headers)
        data = client.get("/api/baseline/status").json()
        assert data["status"] in ("not_collected", "ready")


# ══════════════════════════════════════════════════════════════════════
# Baseline endpoints
# ══════════════════════════════════════════════════════════════════════


class TestBaselineEndpoints:
    """Verify /api/baseline/* routes."""

    # ── GET /api/baseline/status (public) ────────────────────────────

    def test_status_no_auth_ok(self, client: TestClient) -> None:
        resp = client.get("/api/baseline/status")
        assert resp.status_code == 200

    def test_status_response_schema(self, client: TestClient) -> None:
        data = client.get("/api/baseline/status").json()
        assert "status" in data
        assert "samples_collected" in data
        assert "seconds_remaining" in data
        assert "duration_seconds" in data
        assert "message" in data

    def test_status_initial_state(self, client: TestClient) -> None:
        data = client.get("/api/baseline/status").json()
        assert data["status"] in ("not_collected", "collecting", "ready")

    # ── POST /api/baseline/collect (protected) ───────────────────────

    def test_collect_without_key_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/api/baseline/collect", json={"duration_seconds": 10}
        )
        assert resp.status_code == 422

    def test_collect_with_invalid_key_returns_401(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/api/baseline/collect",
            json={"duration_seconds": 10},
            headers={"X-Api-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_collect_without_capture_returns_400(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Collecting baseline requires capture to be running first."""
        # Make sure capture is stopped
        client.post("/api/capture/stop", headers=auth_headers)
        resp = client.post(
            "/api/baseline/collect",
            json={"duration_seconds": 10},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "Capture must be running" in resp.json()["detail"]

    def test_collect_duration_validation(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Duration must be between 10 and 1800 seconds."""
        resp = client.post(
            "/api/baseline/collect",
            json={"duration_seconds": 5},  # too short
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_collect_duration_max_validation(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.post(
            "/api/baseline/collect",
            json={"duration_seconds": 9999},  # too long
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_collect_1800_is_valid(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """30 min (1800s) should be accepted by the schema."""
        # Will 400 because capture isn't running, but not 422
        resp = client.post(
            "/api/baseline/collect",
            json={"duration_seconds": 1800},
            headers=auth_headers,
        )
        assert resp.status_code in (200, 400)


# ══════════════════════════════════════════════════════════════════════
# Simulate endpoint — graceful degradation
# ══════════════════════════════════════════════════════════════════════


class TestSimulateEndpoint:
    """Verify GET /api/simulate returns 200 or 503 (not crash)."""

    def test_simulate_returns_200_or_503(self, client: TestClient) -> None:
        """Simulate should return events or a clean error, never crash."""
        resp = client.get("/api/simulate?count=2")
        assert resp.status_code in (200, 503)

    def test_simulate_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/api/simulate")
        assert resp.status_code in (200, 503)


# ══════════════════════════════════════════════════════════════════════
# Auth enforcement on new endpoints
# ══════════════════════════════════════════════════════════════════════


class TestAuthOnNewEndpoints:
    """Verify that all protected endpoints reject requests without API key."""

    @pytest.mark.parametrize(
        "method,path,json_body",
        [
            ("post", "/api/capture/start", {"interface": "lo0"}),
            ("post", "/api/capture/stop", None),
            ("post", "/api/baseline/collect", {"duration_seconds": 10}),
            ("post", "/api/predict", {"features": {}}),
            ("post", "/api/predict/batch", {"samples": [{}]}),
        ],
    )
    def test_protected_endpoint_requires_key(
        self, client: TestClient, method: str, path: str, json_body
    ) -> None:
        """All POST endpoints should return 422 (missing header) without key."""
        func = getattr(client, method)
        kwargs = {}
        if json_body is not None:
            kwargs["json"] = json_body
        resp = func(path, **kwargs)
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "path",
        [
            "/api/health",
            "/api/feature-names",
            "/api/capture/status",
            "/api/baseline/status",
        ],
    )
    def test_public_endpoints_need_no_key(
        self, client: TestClient, path: str
    ) -> None:
        """These GET endpoints should always return 200."""
        resp = client.get(path)
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "path",
        [
            "/api/metrics",
            "/api/feature-importance",
            "/api/confusion-matrix",
            "/api/dataset/stats",
        ],
    )
    def test_model_endpoints_200_or_503(
        self, client: TestClient, path: str
    ) -> None:
        """Model-dependent endpoints return 200 if model loaded, 503 otherwise."""
        resp = client.get(path)
        assert resp.status_code in (200, 503)

    def test_simulate_public_and_degrades_gracefully(
        self, client: TestClient
    ) -> None:
        """GET /api/simulate should be public and return 200 or 503."""
        resp = client.get("/api/simulate")
        assert resp.status_code in (200, 503)


# ══════════════════════════════════════════════════════════════════════
# WebSocket /ws/live
# ══════════════════════════════════════════════════════════════════════


class TestWebSocketLive:
    """Verify the /ws/live WebSocket endpoint."""

    def test_websocket_connect(self, client: TestClient) -> None:
        """WebSocket should accept connections without error."""
        with client.websocket_connect("/ws/live"):
            pass  # connection accepted successfully
