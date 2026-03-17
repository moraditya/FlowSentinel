"""
Model manager — serialisation, inference, and analytics.

Manages the supplementary XGBoost multiclass classifier that labels
anomalous flows detected by the Isolation Forest.  The model is loaded
from pre-trained artifacts on disk; training is not handled here (it
will be re-introduced when live-compatible training data is available
via PCAP replay in a later phase).
"""

from __future__ import annotations

import logging
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from app.config import settings

logger = logging.getLogger(__name__)


class ModelManager:
    """Load, serve, and expose analytics for the multiclass XGBoost classifier."""

    # ── Construction ─────────────────────────────────────────────────

    def __init__(self) -> None:
        self.multi_model: XGBClassifier | None = None
        self.label_encoder: LabelEncoder | None = None
        self.feature_names: list[str] = settings.FEATURE_NAMES

        # Cached evaluation artefacts (populated from metadata)
        self._confusion_matrix: np.ndarray | None = None
        self._confusion_labels: list[str] | None = None
        self._feature_importance: list[dict[str, Any]] | None = None
        self._multi_report: dict | None = None
        self._multi_accuracy: float | None = None
        self._dataset_stats: dict[str, Any] | None = None
        self._test_X: np.ndarray | None = None
        self._test_y: np.ndarray | None = None

        self._loaded = False

    # ── Public predicates ────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    # ── Loading from disk ────────────────────────────────────────────

    def load(self) -> None:
        """Restore model and metadata from joblib artefacts.

        Raises ``ValueError`` if the saved model was trained on a
        different feature schema version than the current code expects.
        """
        required_paths = [
            settings.MULTI_MODEL_PATH,
            settings.LABEL_ENCODER_PATH,
            settings.METADATA_PATH,
        ]
        for p in required_paths:
            if not p.exists():
                raise FileNotFoundError(f"Model artefact missing: {p}")

        meta: dict[str, Any] = joblib.load(settings.METADATA_PATH)

        # Schema version gate — refuse to load stale artifacts
        saved_version = meta.get("feature_schema_version")
        if saved_version != settings.FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Model was trained on schema '{saved_version}' but code "
                f"expects '{settings.FEATURE_SCHEMA_VERSION}'. "
                "Re-run training to generate compatible artifacts."
            )

        self.multi_model = joblib.load(settings.MULTI_MODEL_PATH)
        self.label_encoder = joblib.load(settings.LABEL_ENCODER_PATH)

        self.feature_names = meta["feature_names"]
        self._confusion_matrix = meta["confusion_matrix"]
        self._confusion_labels = meta["confusion_labels"]
        self._feature_importance = meta["feature_importance"]
        self._multi_report = meta["multi_report"]
        self._multi_accuracy = meta["multi_accuracy"]
        self._dataset_stats = meta["dataset_stats"]

        self._test_X = None
        self._test_y = None

        self._loaded = True
        logger.info("Model and metadata loaded from disk (schema=%s)", saved_version)

    # ── Inference ────────────────────────────────────────────────────

    def predict(self, features: dict[str, float]) -> dict[str, Any]:
        """Run a single sample through the multiclass model.

        The multiclass model already includes "normal" as a class, so
        there is no need for a separate binary gate.
        """
        self._assert_loaded()

        vector = np.array(
            [features.get(f, 0.0) for f in self.feature_names],
            dtype=np.float32,
        ).reshape(1, -1)

        multi_proba = self.multi_model.predict_proba(vector)[0]
        multi_idx = int(np.argmax(multi_proba))
        predicted_class = self.label_encoder.inverse_transform([multi_idx])[0]
        confidence = float(multi_proba[multi_idx])
        is_attack = predicted_class != "normal"

        probabilities = {
            cls: float(prob)
            for cls, prob in zip(self.label_encoder.classes_, multi_proba)
        }

        return {
            "predicted_class": predicted_class,
            "confidence": round(confidence, 6),
            "is_attack": is_attack,
            "probabilities": {
                k: round(v, 6) for k, v in probabilities.items()
            },
        }

    # ── Analytics accessors ──────────────────────────────────────────

    def get_metrics(self) -> dict[str, Any]:
        self._assert_loaded()
        return {
            "accuracy": self._multi_accuracy,
            "classification_report": self._multi_report,
        }

    def get_feature_importance(self) -> list[dict[str, Any]]:
        self._assert_loaded()
        assert self._feature_importance is not None
        return self._feature_importance

    def get_confusion_matrix(self) -> dict[str, Any]:
        self._assert_loaded()
        assert self._confusion_matrix is not None
        return {
            "labels": self._confusion_labels,
            "matrix": self._confusion_matrix.tolist(),
        }

    def get_dataset_stats(self) -> dict[str, Any]:
        self._assert_loaded()
        assert self._dataset_stats is not None
        return self._dataset_stats

    # ── Simulation ───────────────────────────────────────────────────

    def _load_test_data(self) -> None:
        if self._test_X is not None:
            return
        if not settings.TEST_DATA_PATH.exists():
            raise FileNotFoundError(
                f"Test data not found: {settings.TEST_DATA_PATH}. "
                "No training data available."
            )
        td = joblib.load(settings.TEST_DATA_PATH)
        self._test_X = td["test_X"]
        self._test_y = td["test_y"]

    def simulate_batch(self, n: int = 10) -> list[dict[str, Any]]:
        """Pick *n* random test-set samples, predict, and return events."""
        self._assert_loaded()
        self._load_test_data()

        rng = np.random.default_rng()
        indices = rng.choice(len(self._test_X), size=min(n, len(self._test_X)), replace=False)

        events: list[dict[str, Any]] = []
        for idx in indices:
            sample = self._test_X[idx]
            features_dict = {
                name: float(sample[i])
                for i, name in enumerate(self.feature_names)
            }
            result = self.predict(features_dict)
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "features": {k: round(v, 6) for k, v in features_dict.items()},
                "predicted_class": result["predicted_class"],
                "confidence": result["confidence"],
                "is_attack": result["is_attack"],
            })

        return events

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _ensure_writable(path: Path) -> None:
        try:
            path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IWGRP)
        except OSError:
            pass

    def _assert_loaded(self) -> None:
        if not self._loaded:
            raise RuntimeError(
                "Models are not loaded. No pre-trained artifacts found."
            )
