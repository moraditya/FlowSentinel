"""
Anomaly detection baselines for the NIDS evaluation framework.

Every baseline implements:
  - fit(X_normal)  — train on normal-only traffic
  - score(X)       — return anomaly scores (higher = more anomalous)
  - predict(X)     — return binary labels (1 = anomaly)

All models are unsupervised: they train on normal-only data and flag
flows that deviate from the learned normal distribution.
"""

from __future__ import annotations

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


def _subsample(X: np.ndarray, max_n: int) -> np.ndarray:
    """Randomly subsample *X* if it exceeds *max_n* rows."""
    if len(X) <= max_n:
        return X
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X), size=max_n, replace=False)
    return X[idx]


class BaselineModel:
    """Abstract interface for anomaly detection baselines."""

    def fit(self, X_normal: np.ndarray) -> None:
        raise NotImplementedError

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores. Higher = more anomalous."""
        raise NotImplementedError

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        """Return binary predictions. 1 = anomaly."""
        raise NotImplementedError


class ZScoreDetector(BaselineModel):
    """Robust per-feature z-scores using median/MAD.

    Aggregate anomaly score = mean of top-k per-feature z-scores.
    """

    def __init__(self, k: int = 5) -> None:
        self.k = k
        self._median: np.ndarray | None = None
        self._mad: np.ndarray | None = None
        self._threshold: float | None = None

    def fit(self, X_normal: np.ndarray) -> None:
        self._median = np.median(X_normal, axis=0)
        # MAD = median absolute deviation
        self._mad = np.median(np.abs(X_normal - self._median), axis=0)
        # Avoid division by zero
        self._mad = np.where(self._mad == 0, 1e-10, self._mad)
        # Compute threshold from training normal scores (95th percentile)
        train_scores = self.score(X_normal)
        self._threshold = float(np.percentile(train_scores, 95))

    def score(self, X: np.ndarray) -> np.ndarray:
        assert self._median is not None
        # Per-feature absolute z-scores
        z = np.abs(X - self._median) / self._mad
        # Mean of top-k z-scores per sample
        k = min(self.k, z.shape[1])
        top_k = np.sort(z, axis=1)[:, -k:]
        return np.mean(top_k, axis=1)

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        thr = threshold if threshold is not None else self._threshold
        if thr is None:
            thr = 3.0  # fallback
        scores = self.score(X)
        return (scores > thr).astype(int)


class IsolationForestDetector(BaselineModel):
    """Isolation Forest wrapper."""

    def __init__(self, n_estimators: int = 200, contamination: str = "auto",
                 random_state: int = 42) -> None:
        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._threshold: float | None = None

    def fit(self, X_normal: np.ndarray) -> None:
        self._model.fit(X_normal)
        train_scores = self.score(X_normal)
        self._threshold = float(np.percentile(train_scores, 95))

    def score(self, X: np.ndarray) -> np.ndarray:
        # Negate so higher = more anomalous
        return -self._model.decision_function(X)

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        thr = threshold if threshold is not None else self._threshold
        if thr is None:
            raw = self._model.predict(X)
            return np.where(raw == -1, 1, 0)
        return (self.score(X) > thr).astype(int)


class LOFDetector(BaselineModel):
    """Local Outlier Factor with novelty=True for scoring new data.

    LOF is O(n * n_neighbors) at fit time and slow on large datasets,
    so training data is subsampled to ``max_train_samples``.
    """

    def __init__(self, n_neighbors: int = 20, contamination: float = 0.05,
                 max_train_samples: int = 50_000) -> None:
        self._model = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=contamination,
            novelty=True,
            n_jobs=-1,
        )
        self._max_train = max_train_samples
        self._threshold: float | None = None

    def fit(self, X_normal: np.ndarray) -> None:
        X = _subsample(X_normal, self._max_train)
        self._model.fit(X)
        train_scores = self.score(X)
        self._threshold = float(np.percentile(train_scores, 95))

    def score(self, X: np.ndarray) -> np.ndarray:
        # Negate so higher = more anomalous
        return -self._model.decision_function(X)

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        thr = threshold if threshold is not None else self._threshold
        if thr is None:
            raw = self._model.predict(X)
            return np.where(raw == -1, 1, 0)
        return (self.score(X) > thr).astype(int)


class OCSVMDetector(BaselineModel):
    """One-Class SVM with RBF kernel.

    OCSVM is O(n²) at fit time, so training data is subsampled to
    ``max_train_samples`` to keep runtime practical.
    """

    def __init__(self, kernel: str = "rbf", nu: float = 0.05,
                 gamma: str = "scale", max_train_samples: int = 30_000) -> None:
        self._model = OneClassSVM(kernel=kernel, nu=nu, gamma=gamma)
        self._scaler = StandardScaler()
        self._max_train = max_train_samples
        self._threshold: float | None = None

    def fit(self, X_normal: np.ndarray) -> None:
        X_sub = _subsample(X_normal, self._max_train)
        X_scaled = self._scaler.fit_transform(X_sub)
        self._model.fit(X_scaled)
        train_scores = self.score(X_sub)
        self._threshold = float(np.percentile(train_scores, 95))

    def score(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self._scaler.transform(X)
        return -self._model.decision_function(X_scaled)

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        thr = threshold if threshold is not None else self._threshold
        if thr is None:
            X_scaled = self._scaler.transform(X)
            raw = self._model.predict(X_scaled)
            return np.where(raw == -1, 1, 0)
        return (self.score(X) > thr).astype(int)


class PCADetector(BaselineModel):
    """PCA reconstruction error detector.

    Fits PCA on normal traffic keeping components explaining 95% variance.
    Anomaly score = L2 norm of reconstruction residual.
    """

    def __init__(self, variance_ratio: float = 0.95) -> None:
        self._pca = PCA(n_components=variance_ratio, svd_solver="full")
        self._scaler = StandardScaler()
        self._threshold: float | None = None

    def fit(self, X_normal: np.ndarray) -> None:
        X_scaled = self._scaler.fit_transform(X_normal)
        self._pca.fit(X_scaled)
        train_scores = self.score(X_normal)
        self._threshold = float(np.percentile(train_scores, 95))

    def score(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self._scaler.transform(X)
        X_proj = self._pca.transform(X_scaled)
        X_recon = self._pca.inverse_transform(X_proj)
        residual = X_scaled - X_recon
        return np.sqrt(np.sum(residual ** 2, axis=1))

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        thr = threshold if threshold is not None else self._threshold
        if thr is None:
            thr = 1.0  # fallback
        return (self.score(X) > thr).astype(int)


# Registry for easy access
BASELINE_MODELS: dict[str, type[BaselineModel]] = {
    "zscore": ZScoreDetector,
    "isolation_forest": IsolationForestDetector,
    "lof": LOFDetector,
    "ocsvm": OCSVMDetector,
    "pca": PCADetector,
}

UNSUPERVISED_MODELS: set[str] = set(BASELINE_MODELS.keys())
