"""
Anomaly detection using Isolation Forest trained on user baseline traffic.

Provides an ``AnomalyDetector`` class that supports a three-phase workflow:

1. **Collection** -- gather baseline (normal) traffic samples.
2. **Training** -- fit an Isolation Forest and a MinMaxScaler on the
   collected samples.
3. **Scoring** -- score new flows against the learned baseline.
"""

from __future__ import annotations

import logging
import time as _time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from app.config import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation-Forest-based anomaly detector trained on baseline traffic."""

    BASELINE_MODEL_PATH: Path = settings.MODELS_DIR / "baseline_iforest.joblib"
    BASELINE_SCALER_PATH: Path = settings.MODELS_DIR / "baseline_scaler.joblib"

    BASELINE_SUMMARY_PATH: Path = settings.MODELS_DIR / "baseline_summary.joblib"

    def __init__(self) -> None:
        self._model: IsolationForest | None = None
        self._scaler: MinMaxScaler | None = None
        self._status: str = "not_collected"  # "not_collected" | "collecting" | "ready"
        self._samples_collected: int = 0
        self._collection_buffer: list[np.ndarray] = []
        self._started_at: float | None = None
        self._duration_seconds: int = 0
        # Per-feature baseline statistics (populated during training)
        self._feature_means: np.ndarray | None = None
        self._feature_stds: np.ndarray | None = None

    # ── Properties ────────────────────────────────────────────────────

    @property
    def status(self) -> str:
        """Current detector status."""
        return self._status

    @property
    def samples_collected(self) -> int:
        """Number of feature vectors accumulated so far."""
        return self._samples_collected

    @property
    def started_at(self) -> float | None:
        """Epoch timestamp when collection started."""
        return self._started_at

    @property
    def duration_seconds(self) -> int:
        """Requested baseline duration in seconds."""
        return self._duration_seconds

    # ── Collection helpers ────────────────────────────────────────────

    def _features_to_array(self, features: dict[str, float]) -> np.ndarray:
        """Convert a feature dict to a 1-D numpy array in canonical order."""
        return np.array(
            [features[name] for name in settings.FEATURE_NAMES], dtype=np.float64
        )

    def add_baseline_sample(self, features: dict[str, float]) -> None:
        """Add a single feature vector to the collection buffer."""
        if self._status != "collecting":
            return
        vec = self._features_to_array(features)
        self._collection_buffer.append(vec)
        self._samples_collected += 1

    def start_collection(self, duration_seconds: int = 60) -> None:
        """Set status to ``'collecting'`` and clear any previous buffer."""
        self._status = "collecting"
        self._collection_buffer.clear()
        self._samples_collected = 0
        self._started_at = _time.time()
        self._duration_seconds = duration_seconds
        logger.info("Baseline collection started (duration=%ds)", duration_seconds)

    def cancel_collection(self) -> None:
        """Cancel an in-progress collection and reset to not_collected."""
        if self._status == "collecting":
            self._status = "not_collected"
            self._collection_buffer.clear()
            self._samples_collected = 0
            self._started_at = None
            self._duration_seconds = 0
            logger.info("Baseline collection cancelled")

    def finish_collection(self) -> None:
        """Train an Isolation Forest on the collected samples.

        Fits a ``MinMaxScaler`` on the raw feature matrix, then trains
        an ``IsolationForest`` on the *unscaled* data.  Both artefacts
        are persisted to disk.
        """
        if not self._collection_buffer:
            raise ValueError("No samples collected — cannot train")

        X = np.vstack(self._collection_buffer)

        # Compute per-feature baseline statistics
        self._feature_means = np.mean(X, axis=0)
        self._feature_stds = np.std(X, axis=0)

        # Fit scaler
        self._scaler = MinMaxScaler()
        self._scaler.fit(X)

        # Train Isolation Forest on raw features
        self._model = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X)

        self._status = "ready"
        # Clear timing metadata now that collection is complete
        self._started_at = None
        self._duration_seconds = 0
        self.save()
        logger.info(
            "Baseline model trained on %d samples and saved to disk",
            len(self._collection_buffer),
        )

    # ── Scoring ───────────────────────────────────────────────────────

    def score(self, features: dict[str, float]) -> float:
        """Score a single flow against the baseline model.

        Uses ``decision_function``: negative values indicate anomalies,
        positive values indicate normal traffic.
        """
        if self._model is None:
            raise RuntimeError("Model not trained or loaded")
        vec = self._features_to_array(features).reshape(1, -1)
        return float(self._model.decision_function(vec)[0])

    def is_anomaly(self, features: dict[str, float], threshold: float = 0.0) -> bool:
        """Return ``True`` if the flow's anomaly score is below *threshold*."""
        return self.score(features) < threshold

    # ── Normalisation ─────────────────────────────────────────────────

    def normalize(self, features: dict[str, float]) -> dict[str, float]:
        """Apply the fitted ``MinMaxScaler`` to a feature dict."""
        if self._scaler is None:
            raise RuntimeError("Scaler not fitted or loaded")
        vec = self._features_to_array(features).reshape(1, -1)
        scaled = self._scaler.transform(vec).flatten()
        return {name: float(scaled[i]) for i, name in enumerate(settings.FEATURE_NAMES)}

    # ── Persistence ───────────────────────────────────────────────────

    def save(self) -> None:
        """Persist the model, scaler, and feature summary to disk."""
        self.BASELINE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, self.BASELINE_MODEL_PATH)
        joblib.dump(self._scaler, self.BASELINE_SCALER_PATH)
        joblib.dump(
            {"means": self._feature_means, "stds": self._feature_stds},
            self.BASELINE_SUMMARY_PATH,
        )
        logger.info("Anomaly model saved to %s", self.BASELINE_MODEL_PATH)

    def load(self) -> bool:
        """Load a previously saved model, scaler, and summary from disk."""
        if not self.BASELINE_MODEL_PATH.exists() or not self.BASELINE_SCALER_PATH.exists():
            return False
        self._model = joblib.load(self.BASELINE_MODEL_PATH)
        self._scaler = joblib.load(self.BASELINE_SCALER_PATH)
        if self.BASELINE_SUMMARY_PATH.exists():
            summary = joblib.load(self.BASELINE_SUMMARY_PATH)
            self._feature_means = summary.get("means")
            self._feature_stds = summary.get("stds")
        self._status = "ready"
        logger.info("Anomaly model loaded from %s", self.BASELINE_MODEL_PATH)
        return True

    def get_feature_summary(self) -> dict[str, dict[str, float]]:
        """Return per-feature baseline mean and std."""
        if self._feature_means is None or self._feature_stds is None:
            return {}
        return {
            name: {
                "mean": round(float(self._feature_means[i]), 6),
                "std": round(float(self._feature_stds[i]), 6),
            }
            for i, name in enumerate(settings.FEATURE_NAMES)
        }
