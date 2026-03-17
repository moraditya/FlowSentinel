"""
Tests for the API-key authentication module.

Verifies that public GET endpoints remain accessible without a key,
protected POST endpoints reject missing/invalid keys, and that
``verify_api_key`` behaves correctly when called directly.
"""

from __future__ import annotations

import os

import pytest
from fastapi import HTTPException

# Set the env var *before* importing auth so defaults are overridden.
os.environ["NIDS_API_KEY"] = "test-key"

from app.auth import verify_api_key  # noqa: E402

# ── Public endpoints (no key required) ────────────────────────────────


def test_get_health_no_key_ok(client):
    """GET /api/health should return 200 without an API key."""
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_get_metrics_no_key_ok(client):
    """GET /api/metrics should be public (200 or 503 if model missing)."""
    resp = client.get("/api/metrics")
    assert resp.status_code in (200, 503)


def test_get_feature_names_no_key_ok(client):
    """GET /api/feature-names should return 200 without an API key."""
    resp = client.get("/api/feature-names")
    assert resp.status_code == 200


def test_get_capture_status_no_key_ok(client):
    """GET /api/capture/status should return 200 without an API key."""
    resp = client.get("/api/capture/status")
    assert resp.status_code == 200


def test_get_baseline_status_no_key_ok(client):
    """GET /api/baseline/status should return 200 without an API key."""
    resp = client.get("/api/baseline/status")
    assert resp.status_code == 200


def test_get_simulate_no_key_ok(client):
    """GET /api/simulate should be public (200 or 503 if test data missing)."""
    resp = client.get("/api/simulate")
    assert resp.status_code in (200, 503)


# ── Protected POST endpoints reject missing key ─────────────────────


def test_predict_without_key_returns_422(client):
    """POST /api/predict without X-Api-Key header returns 422."""
    resp = client.post("/api/predict", json={"features": {}})
    assert resp.status_code == 422


def test_predict_batch_without_key_returns_422(client):
    """POST /api/predict/batch without X-Api-Key header returns 422."""
    resp = client.post("/api/predict/batch", json={"samples": [{}]})
    assert resp.status_code == 422


def test_capture_start_without_key_returns_422(client):
    """POST /api/capture/start without X-Api-Key header returns 422."""
    resp = client.post("/api/capture/start", json={"interface": "lo0"})
    assert resp.status_code == 422


def test_capture_stop_without_key_returns_422(client):
    """POST /api/capture/stop without X-Api-Key header returns 422."""
    resp = client.post("/api/capture/stop")
    assert resp.status_code == 422


def test_baseline_collect_without_key_returns_422(client):
    """POST /api/baseline/collect without X-Api-Key header returns 422."""
    resp = client.post("/api/baseline/collect", json={"duration_seconds": 10})
    assert resp.status_code == 422


# ── Protected POST endpoints reject invalid key ─────────────────────


def test_predict_invalid_key_returns_401(client):
    resp = client.post(
        "/api/predict",
        json={"features": {}},
        headers={"X-Api-Key": "wrong"},
    )
    assert resp.status_code == 401


def test_capture_start_invalid_key_returns_401(client):
    resp = client.post(
        "/api/capture/start",
        json={"interface": "lo0"},
        headers={"X-Api-Key": "wrong"},
    )
    assert resp.status_code == 401




# ── Protected POST endpoints accept valid key ────────────────────────


def test_predict_valid_key_accepted(client, all_zero_features):
    """Valid key should not return 401/422 (200 or 503 depending on model)."""
    resp = client.post(
        "/api/predict",
        json={"features": all_zero_features},
        headers={"X-Api-Key": "test-key"},
    )
    assert resp.status_code in (200, 503)


def test_capture_start_valid_key_accepted(client):
    """Valid key should not return 401/422 (200 or 400 for permissions)."""
    resp = client.post(
        "/api/capture/start",
        json={"interface": "lo0"},
        headers={"X-Api-Key": "test-key"},
    )
    assert resp.status_code in (200, 400)


# ── Direct verify_api_key tests ───────────────────────────────────────


def test_verify_valid_key():
    """A valid key should be returned as-is."""
    result = verify_api_key("test-key")
    assert result == "test-key"


def test_verify_invalid_key():
    """An invalid key should raise HTTPException with status 401."""
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key("wrong")
    assert exc_info.value.status_code == 401


def test_verify_default_key(monkeypatch):
    """Without NIDS_API_KEY in the environment, the default dev key works."""
    from app.config import settings as _settings

    monkeypatch.setattr(_settings, "NIDS_API_KEY", "dev-key-change-me")
    result = verify_api_key("dev-key-change-me")
    assert result == "dev-key-change-me"
