"""Tests for the PCAP replay engine and API endpoints."""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from app.replay import DEMO_DIR, SCENARIOS, ReplayEngine

# ── Unit tests for ReplayEngine ──────────────────────────────────────


class TestReplayEngine:
    def test_initial_state(self):
        engine = ReplayEngine()
        assert not engine.is_replaying
        assert engine.status["state"] == "idle"

    def test_status_keys(self):
        engine = ReplayEngine()
        s = engine.status
        assert "state" in s
        assert "scenario" in s
        assert "speed" in s
        assert "packets_replayed" in s
        assert "flows_processed" in s
        assert "elapsed_seconds" in s
        assert "latency" in s
        assert "error" in s

    def test_start_unknown_scenario_raises(self):
        engine = ReplayEngine()
        with pytest.raises(ValueError, match="Unknown scenario"):
            engine.start(scenario="nonexistent")

    def test_stop_when_idle(self):
        engine = ReplayEngine()
        engine.stop()  # should not raise
        assert engine.status["state"] == "idle"

    def test_scenarios_defined(self):
        assert "mixed" in SCENARIOS
        assert "benign" in SCENARIOS
        assert "port_scan" in SCENARIOS
        assert "brute_force" in SCENARIOS

    def test_demo_pcaps_exist(self):
        for scenario, files in SCENARIOS.items():
            for fname in files:
                assert (DEMO_DIR / fname).exists(), f"Missing {fname} for scenario {scenario}"

    def test_stop_cleans_up_collecting_state(self):
        """Stopping during bootstrap should not leave anomaly detector stuck."""
        from app.anomaly import AnomalyDetector
        from app.capture import CaptureEngine

        engine = ReplayEngine()
        engine._capture_engine = CaptureEngine()
        detector = AnomalyDetector()
        engine._anomaly_detector = detector

        # Simulate stuck collecting state
        detector._status = "collecting"
        engine._status = "bootstrapping_baseline"

        engine.stop()

        assert detector.status != "collecting"
        assert engine.status["state"] == "idle"


# ── API endpoint tests ───────────────────────────────────────────────


class TestReplayEndpoints:
    def test_status_returns_200_no_auth(self, client: TestClient):
        """GET /api/replay/status is public."""
        resp = client.get("/api/replay/status")
        assert resp.status_code == 200

    def test_start_requires_auth(self, client: TestClient):
        """POST /api/replay/start without key returns 422."""
        resp = client.post("/api/replay/start?scenario=mixed&speed=100")
        assert resp.status_code == 422

    def test_stop_requires_auth(self, client: TestClient):
        """POST /api/replay/stop without key returns 422."""
        resp = client.post("/api/replay/stop")
        assert resp.status_code == 422

    def test_start_with_auth_returns_active_state(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Start should return an active state immediately (no race to idle)."""
        resp = client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        state = resp.json()["state"]
        # Status is set BEFORE thread spawns, so it should never be idle
        assert state in ("bootstrapping_baseline", "replaying", "completed")
        client.post("/api/replay/stop", headers=auth_headers)

    def test_stop_with_auth_returns_200(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        resp = client.post("/api/replay/stop", headers=auth_headers)
        assert resp.status_code == 200

    def test_start_unknown_scenario_returns_400(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        resp = client.post(
            "/api/replay/start?scenario=nonexistent&speed=1",
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_completed_replay_has_nonzero_elapsed(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """After completion, elapsed_seconds should reflect actual runtime."""
        client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        # Wait for completion
        for _ in range(20):
            time.sleep(0.3)
            status = client.get("/api/replay/status").json()
            if status["state"] in ("completed", "error"):
                break
        assert status["elapsed_seconds"] > 0
        assert status["packets_replayed"] > 0

    def test_capture_blocked_during_replay(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Live capture should be rejected while replay is active."""
        resp = client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        assert resp.json()["state"] != "idle"

        resp = client.post(
            "/api/capture/start",
            json={"interface": "lo0"},
            headers=auth_headers,
        )
        # 400 because replay started in an active state immediately
        assert resp.status_code == 400

        client.post("/api/replay/stop", headers=auth_headers)

    def test_replay_does_not_pollute_detector(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """After replay completes, anomaly detector should be restored."""
        # Record baseline status before replay
        before = client.get("/api/baseline/status").json()
        before_status = before["status"]

        # Run replay to completion
        client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        for _ in range(30):
            time.sleep(0.3)
            s = client.get("/api/replay/status").json()
            if s["state"] in ("completed", "error"):
                break

        # Detector should be restored to pre-replay state
        after = client.get("/api/baseline/status").json()
        assert after["status"] == before_status

    def test_replay_does_not_pollute_detection_stats(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """After replay completes, detection_stats should be clean."""
        before = client.get("/api/detection/stats").json()

        client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        for _ in range(30):
            time.sleep(0.3)
            s = client.get("/api/replay/status").json()
            if s["state"] in ("completed", "error"):
                break

        after = client.get("/api/detection/stats").json()
        assert after["total_flows_scored"] == before["total_flows_scored"]

    def test_completed_replay_has_stage_timing(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Completed replay should report per-stage timing breakdown."""
        client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        for _ in range(30):
            time.sleep(0.3)
            s = client.get("/api/replay/status").json()
            if s["state"] in ("completed", "error"):
                break

        assert s["state"] == "completed"
        stages = s.get("stage_timing", {})
        expected_keys = {"parse_ms", "features_ms", "score_ms", "classify_ms", "publish_ms", "total_ms"}
        assert set(stages.keys()) == expected_keys
        for key in expected_keys:
            assert "mean" in stages[key]
            assert "p50" in stages[key]
            assert "p95" in stages[key]
            assert "p99" in stages[key]
        # At least features should be nonzero
        assert stages["features_ms"]["mean"] > 0

    def test_replay_baseline_summary_available_after_mixed(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """After a mixed replay, /api/replay/baseline-summary should return
        the replay-specific baseline, not the live baseline."""
        client.post(
            "/api/replay/start?scenario=mixed&speed=100",
            headers=auth_headers,
        )
        for _ in range(30):
            time.sleep(0.3)
            s = client.get("/api/replay/status").json()
            if s["state"] in ("completed", "error"):
                break

        assert s["state"] == "completed"

        # Replay baseline summary should be available
        resp = client.get("/api/replay/baseline-summary")
        assert resp.status_code == 200
        summary = resp.json()
        assert len(summary) == 28  # 28 observable features
        # Each entry should have mean and std
        for name, stats in summary.items():
            assert "mean" in stats
            assert "std" in stats
