"""Unit tests for the ModelManager class.

These tests exercise the ModelManager directly (without going through
FastAPI endpoints) to verify load, predict, and analytics methods.

Skipped when model artifacts are not present on disk.
"""

from __future__ import annotations

import numpy as np
import pytest

from app.config import settings
from app.model import ModelManager
from tests.conftest import ATTACK_CLASSES, MODEL_AVAILABLE

pytestmark = pytest.mark.skipif(not MODEL_AVAILABLE, reason="No model artifacts")


@pytest.fixture(scope="module")
def manager() -> ModelManager:
    """Load a fresh ModelManager from disk for unit testing."""
    mgr = ModelManager()
    mgr.load()
    return mgr


# ── Loading ──────────────────────────────────────────────────────────


class TestModelManagerLoad:
    """Verify ModelManager.load() restores state correctly."""

    def test_is_loaded_after_load(self, manager: ModelManager) -> None:
        assert manager.is_loaded is True

    def test_multi_model_not_none(self, manager: ModelManager) -> None:
        assert manager.multi_model is not None

    def test_label_encoder_not_none(self, manager: ModelManager) -> None:
        assert manager.label_encoder is not None

    def test_feature_names_length(self, manager: ModelManager) -> None:
        assert len(manager.feature_names) == 28

    def test_feature_names_match_settings(self, manager: ModelManager) -> None:
        assert manager.feature_names == settings.FEATURE_NAMES

    def test_label_encoder_classes(self, manager: ModelManager) -> None:
        classes = list(manager.label_encoder.classes_)
        assert set(classes) == set(ATTACK_CLASSES)

    def test_load_missing_file_raises(self, tmp_path) -> None:
        """Loading from a directory with no artefacts should raise."""
        import app.config as cfg

        original = cfg.settings.MULTI_MODEL_PATH
        cfg.settings.MULTI_MODEL_PATH = tmp_path / "nonexistent.joblib"
        try:
            mgr = ModelManager()
            with pytest.raises(FileNotFoundError):
                mgr.load()
        finally:
            cfg.settings.MULTI_MODEL_PATH = original


# ── Prediction ───────────────────────────────────────────────────────


class TestModelManagerPredict:
    """Verify ModelManager.predict() with various inputs."""

    def test_predict_all_zeros(self, manager: ModelManager) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        assert "predicted_class" in result
        assert "confidence" in result
        assert "is_attack" in result
        assert "probabilities" in result

    def test_predict_returns_known_class(self, manager: ModelManager) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        assert result["predicted_class"] in ATTACK_CLASSES

    def test_predict_confidence_range(self, manager: ModelManager) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_predict_probabilities_sum_to_one(
        self, manager: ModelManager
    ) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        total = sum(result["probabilities"].values())
        assert abs(total - 1.0) < 0.01

    def test_predict_probabilities_keys(self, manager: ModelManager) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        assert set(result["probabilities"].keys()) == set(ATTACK_CLASSES)

    def test_predict_is_attack_false_for_normal(
        self, manager: ModelManager
    ) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        if result["predicted_class"] == "normal":
            assert result["is_attack"] is False

    def test_predict_is_attack_true_for_attack(
        self, manager: ModelManager
    ) -> None:
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        result = manager.predict(features)
        if result["predicted_class"] != "normal":
            assert result["is_attack"] is True

    def test_predict_partial_features(self, manager: ModelManager) -> None:
        """Missing features should default to 0.0."""
        result = manager.predict({"duration": 42.0})
        assert result["predicted_class"] in ATTACK_CLASSES

    def test_predict_empty_features(self, manager: ModelManager) -> None:
        result = manager.predict({})
        assert result["predicted_class"] in ATTACK_CLASSES

    def test_predict_extra_features_ignored(
        self, manager: ModelManager
    ) -> None:
        """Features not in the canonical list should be silently ignored."""
        features = {name: 0.0 for name in settings.FEATURE_NAMES}
        features["totally_bogus_feature"] = 999.0
        result = manager.predict(features)
        assert result["predicted_class"] in ATTACK_CLASSES

    def test_predict_deterministic(self, manager: ModelManager) -> None:
        """Same input should produce the same output."""
        features = {name: 1.0 for name in settings.FEATURE_NAMES}
        r1 = manager.predict(features)
        r2 = manager.predict(features)
        assert r1["predicted_class"] == r2["predicted_class"]
        assert r1["confidence"] == r2["confidence"]

    def test_predict_not_loaded_raises(self) -> None:
        """Calling predict on an unloaded manager should raise RuntimeError."""
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.predict({"duration": 0.0})


# ── Analytics ────────────────────────────────────────────────────────


class TestModelManagerMetrics:
    """Verify ModelManager analytics accessors."""

    def test_get_metrics_keys(self, manager: ModelManager) -> None:
        data = manager.get_metrics()
        assert "accuracy" in data
        assert "classification_report" in data

    def test_get_metrics_accuracy_type(self, manager: ModelManager) -> None:
        data = manager.get_metrics()
        assert isinstance(data["accuracy"], float)

    def test_get_metrics_accuracy_range(self, manager: ModelManager) -> None:
        data = manager.get_metrics()
        assert 0.0 <= data["accuracy"] <= 1.0

    def test_get_metrics_not_loaded_raises(self) -> None:
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.get_metrics()


class TestModelManagerFeatureImportance:
    """Verify ModelManager.get_feature_importance()."""

    def test_returns_list(self, manager: ModelManager) -> None:
        data = manager.get_feature_importance()
        assert isinstance(data, list)

    def test_length_28(self, manager: ModelManager) -> None:
        data = manager.get_feature_importance()
        assert len(data) == 28

    def test_items_have_keys(self, manager: ModelManager) -> None:
        for item in manager.get_feature_importance():
            assert "feature" in item
            assert "importance" in item

    def test_sorted_descending(self, manager: ModelManager) -> None:
        data = manager.get_feature_importance()
        importances = [d["importance"] for d in data]
        assert importances == sorted(importances, reverse=True)

    def test_not_loaded_raises(self) -> None:
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.get_feature_importance()


class TestModelManagerConfusionMatrix:
    """Verify ModelManager.get_confusion_matrix()."""

    def test_keys(self, manager: ModelManager) -> None:
        data = manager.get_confusion_matrix()
        assert "labels" in data
        assert "matrix" in data

    def test_square_matrix(self, manager: ModelManager) -> None:
        data = manager.get_confusion_matrix()
        n = len(data["labels"])
        matrix = data["matrix"]
        assert len(matrix) == n
        for row in matrix:
            assert len(row) == n

    def test_labels_match_classes(self, manager: ModelManager) -> None:
        data = manager.get_confusion_matrix()
        assert set(data["labels"]) == set(ATTACK_CLASSES)

    def test_matrix_values_type(self, manager: ModelManager) -> None:
        data = manager.get_confusion_matrix()
        for row in data["matrix"]:
            for val in row:
                assert isinstance(val, (int, np.integer))

    def test_not_loaded_raises(self) -> None:
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.get_confusion_matrix()


class TestModelManagerDatasetStats:
    """Verify ModelManager.get_dataset_stats()."""

    def test_keys(self, manager: ModelManager) -> None:
        data = manager.get_dataset_stats()
        assert "total_samples" in data
        assert "attack_distribution" in data

    def test_total_positive(self, manager: ModelManager) -> None:
        data = manager.get_dataset_stats()
        assert data["total_samples"] > 0

    def test_distribution_keys(self, manager: ModelManager) -> None:
        data = manager.get_dataset_stats()
        assert set(data["attack_distribution"].keys()) == set(ATTACK_CLASSES)

    def test_distribution_sums_to_total(self, manager: ModelManager) -> None:
        data = manager.get_dataset_stats()
        assert sum(data["attack_distribution"].values()) == data["total_samples"]

    def test_not_loaded_raises(self) -> None:
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.get_dataset_stats()


_test_data_available = settings.TEST_DATA_PATH.exists()


@pytest.mark.skipif(not _test_data_available, reason="test_data.joblib not present")
class TestModelManagerSimulateBatch:
    """Verify ModelManager.simulate_batch() (requires test_data.joblib)."""

    def test_returns_list(self, manager: ModelManager) -> None:
        events = manager.simulate_batch(n=3)
        assert isinstance(events, list)
        assert len(events) == 3

    def test_event_keys(self, manager: ModelManager) -> None:
        events = manager.simulate_batch(n=1)
        event = events[0]
        assert "timestamp" in event
        assert "features" in event
        assert "predicted_class" in event
        assert "confidence" in event
        assert "is_attack" in event

    def test_simulate_one(self, manager: ModelManager) -> None:
        events = manager.simulate_batch(n=1)
        assert len(events) == 1

    def test_simulate_twenty(self, manager: ModelManager) -> None:
        events = manager.simulate_batch(n=20)
        assert len(events) == 20


class TestModelManagerSimulateBatchErrors:
    """Verify simulate_batch error handling."""

    def test_not_loaded_raises(self) -> None:
        mgr = ModelManager()
        with pytest.raises(RuntimeError, match="not loaded"):
            mgr.simulate_batch(n=1)

    def test_missing_test_data_raises_file_not_found(self, manager: ModelManager) -> None:
        """If test data was never generated, FileNotFoundError is raised."""
        manager._test_X = None  # force re-load attempt
        original = settings.TEST_DATA_PATH
        import app.config as cfg
        cfg.settings.TEST_DATA_PATH = original.parent / "nonexistent.joblib"
        try:
            with pytest.raises(FileNotFoundError):
                manager.simulate_batch(n=1)
        finally:
            cfg.settings.TEST_DATA_PATH = original
