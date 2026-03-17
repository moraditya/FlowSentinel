"""
Tests for the AnomalyDetector class.

Exercises the full collection -> training -> scoring -> persistence lifecycle.
All tests use tmp_path to avoid polluting the real models directory.
"""

from __future__ import annotations

import numpy as np
import pytest

from app.anomaly import AnomalyDetector
from app.config import settings


def _random_features(rng: np.random.Generator | None = None) -> dict[str, float]:
    """Generate a random feature dict using the canonical 28 feature names."""
    if rng is None:
        rng = np.random.default_rng()
    return {name: float(rng.random()) for name in settings.FEATURE_NAMES}


@pytest.fixture(autouse=True)
def _isolate_model_paths(tmp_path, monkeypatch):
    """Redirect all model saves to tmp_path so tests never write to the
    real models directory."""
    monkeypatch.setattr(AnomalyDetector, "BASELINE_MODEL_PATH", tmp_path / "iforest.joblib")
    monkeypatch.setattr(AnomalyDetector, "BASELINE_SCALER_PATH", tmp_path / "scaler.joblib")


# ── Status lifecycle ──────────────────────────────────────────────────


def test_initial_status():
    """A new detector starts in 'not_collected' status."""
    det = AnomalyDetector()
    assert det.status == "not_collected"


def test_start_collection():
    """start_collection() sets status to 'collecting'."""
    det = AnomalyDetector()
    det.start_collection()
    assert det.status == "collecting"


def test_add_baseline_sample():
    """Each call to add_baseline_sample increments samples_collected."""
    det = AnomalyDetector()
    det.start_collection()
    det.add_baseline_sample(_random_features())
    assert det.samples_collected == 1
    det.add_baseline_sample(_random_features())
    assert det.samples_collected == 2


# ── Training & scoring ────────────────────────────────────────────────


def _trained_detector(n_samples: int = 50) -> AnomalyDetector:
    """Return a detector trained on *n_samples* random feature vectors."""
    rng = np.random.default_rng(42)
    det = AnomalyDetector()
    det.start_collection()
    for _ in range(n_samples):
        det.add_baseline_sample(_random_features(rng))
    det.finish_collection()
    return det


def test_finish_collection():
    """After finish_collection() the detector status is 'ready'."""
    det = _trained_detector()
    assert det.status == "ready"


def test_score_returns_float():
    """score() returns a float after training."""
    det = _trained_detector()
    result = det.score(_random_features())
    assert isinstance(result, float)


def test_is_anomaly_returns_bool():
    """is_anomaly() returns a bool after training."""
    det = _trained_detector()
    result = det.is_anomaly(_random_features())
    assert isinstance(result, bool)


def test_normalize_returns_dict():
    """normalize() returns a dict with the same keys as the input."""
    det = _trained_detector()
    features = _random_features()
    normed = det.normalize(features)
    assert isinstance(normed, dict)
    assert set(normed.keys()) == set(settings.FEATURE_NAMES)


# ── Persistence ───────────────────────────────────────────────────────


def test_save_load_roundtrip():
    """A saved model can be loaded into a fresh detector."""
    det = _trained_detector()
    det.save()

    det2 = AnomalyDetector()
    assert det2.load() is True
    assert det2.status == "ready"


def test_load_no_files(tmp_path, monkeypatch):
    """load() returns False when model files do not exist."""
    monkeypatch.setattr(AnomalyDetector, "BASELINE_MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(AnomalyDetector, "BASELINE_SCALER_PATH", tmp_path / "also_missing.joblib")

    det = AnomalyDetector()
    assert det.load() is False
