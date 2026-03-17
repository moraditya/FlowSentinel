"""
Experiment runner for systematic IDS model evaluation.

Evaluation protocol:
  - **Unsupervised** models (zscore, isolation_forest, lof, ocsvm, pca)
    train on normal-only traffic.
  - **Supervised** models (xgboost, random_forest, logistic_regression)
    train on labeled mixed data (normal + attack).

This distinction is formalized via UNSUPERVISED_MODELS, not special-cased.
"""

from __future__ import annotations

import logging
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from evaluation.baselines import BASELINE_MODELS, BaselineModel
from evaluation.metrics import EvaluationMetrics

logger = logging.getLogger(__name__)

# Models that train on normal-only data
UNSUPERVISED_MODELS: set[str] = {"zscore", "isolation_forest", "lof", "ocsvm", "pca"}

# Models that train on labeled mixed data
SUPERVISED_MODELS: set[str] = {"xgboost", "random_forest", "logistic_regression"}

ALL_MODEL_TYPES: set[str] = UNSUPERVISED_MODELS | SUPERVISED_MODELS

DEFAULT_TEST_SIZE = 0.2
RANDOM_STATE = 42


# ======================================================================
# Configuration dataclass
# ======================================================================

@dataclass
class ExperimentConfig:
    """Describes a single evaluation experiment."""

    name: str
    train_dataset: str
    test_dataset: str                           # "same" = split from train
    model_type: str
    split_type: str = "stratified"
    features: list[str] | None = None           # None → settings.FEATURE_NAMES
    test_size: float = DEFAULT_TEST_SIZE
    random_state: int = RANDOM_STATE
    extra_params: dict[str, Any] = field(default_factory=dict)


# ======================================================================
# Experiment runner
# ======================================================================

class ExperimentRunner:
    """Load data, train models, and evaluate."""

    def __init__(
        self,
        data_dir: Path,
        dataset_load_kwargs: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.dataset_load_kwargs = dataset_load_kwargs or {}
        self._dataset_cache: dict[tuple[str, tuple[tuple[str, Any], ...]], pd.DataFrame] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_single(self, config: ExperimentConfig) -> dict[str, Any]:
        """Run one experiment: load, split, train, evaluate."""
        start = time.perf_counter()
        logger.info("Experiment '%s' started", config.name)

        # 1. Load data
        train_df = self._load_dataset(config.train_dataset)
        if config.test_dataset == config.train_dataset or config.test_dataset == "same":
            test_df = None
        else:
            test_df = self._load_dataset(config.test_dataset)

        # 2. Prepare features / labels
        #    Use per-dataset native features unless explicitly overridden.
        feature_cols = config.features
        if feature_cols is None:
            from datasets.loaders import derive_feature_columns
            feature_cols = derive_feature_columns(train_df)

        X_train_full, y_train_full = self._extract_xy(train_df, feature_cols)

        if test_df is not None:
            X_test, y_test = self._extract_xy(test_df, feature_cols)
            X_train, y_train = X_train_full, y_train_full
        else:
            X_train, X_test, y_train, y_test = self._split(
                X_train_full, y_train_full, config.split_type,
                config.test_size, config.random_state,
            )

        is_unsupervised = config.model_type in UNSUPERVISED_MODELS

        # 3. Train
        if is_unsupervised:
            model = self._create_unsupervised(config.model_type, config.extra_params)
            normal_mask = y_train == 0
            X_normal = X_train[normal_mask] if normal_mask.any() else X_train
            model.fit(X_normal)
            # Score training-normal data for threshold calibration
            train_normal_scores = model.score(X_normal)
        else:
            scaler: StandardScaler | None = None
            if config.model_type == "logistic_regression":
                scaler = StandardScaler()
                X_train = scaler.fit_transform(X_train)
                X_test = scaler.transform(X_test)
            model = self._create_supervised(config.model_type, config.extra_params)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                model.fit(X_train, y_train)
            train_normal_scores = None

        # 4. Predict
        if is_unsupervised:
            y_scores = model.score(X_test)
            y_pred = model.predict(X_test)
        else:
            y_pred, y_scores = self._predict_supervised(model, X_test)
            train_normal_scores = None

        # 5. Evaluate
        metrics = EvaluationMetrics.binary_metrics(y_test, y_pred, y_scores)
        recall_fpr = EvaluationMetrics.recall_at_fpr(y_test, y_scores)
        threshold_data = EvaluationMetrics.threshold_sweep(
            y_test, y_scores, train_normal_scores=train_normal_scores,
        )
        fp_stats = EvaluationMetrics.false_positives_per_10k(y_test, y_pred)
        alert_stats = EvaluationMetrics.alerts_per_volume(
            y_pred, total_flows=len(y_test),
        )

        # Calibration — labeled differently for unsupervised
        calibration = EvaluationMetrics.calibration_curve(y_test, y_scores)
        calibration["type"] = "post_hoc_score" if is_unsupervised else "probability"

        # Per-attack-family breakdown
        attack_breakdown = self._per_attack_breakdown(
            train_df if test_df is None else test_df,
            feature_cols, y_pred, y_scores, is_test_split=(test_df is None),
            y_test_indices=None,
        )

        elapsed = round(time.perf_counter() - start, 3)
        logger.info(
            "Experiment '%s' finished in %.2fs — F1=%.4f, PR-AUC=%s",
            config.name, elapsed, metrics["f1"],
            f"{metrics['pr_auc']:.4f}" if metrics["pr_auc"] else "N/A",
        )

        return {
            "name": config.name,
            "model_type": config.model_type,
            "model_class": "unsupervised" if is_unsupervised else "supervised",
            "train_dataset": config.train_dataset,
            "test_dataset": config.test_dataset,
            "split_type": config.split_type,
            "n_features": len(feature_cols),
            "n_train": int(X_train.shape[0]),
            "n_test": int(X_test.shape[0]),
            "metrics": metrics,
            "recall_at_fpr": recall_fpr,
            "threshold_sweep": threshold_data,
            "calibration": calibration,
            "alert_stats": alert_stats,
            "fp_stats": fp_stats,
            "attack_breakdown": attack_breakdown,
            "elapsed_seconds": elapsed,
        }

    def run_cross_dataset(
        self,
        train_dataset: str,
        test_dataset: str,
        model_type: str = "xgboost",
    ) -> dict[str, Any]:
        """Train on one dataset, test on another."""
        from app.config import settings as _cfg
        config = ExperimentConfig(
            name=f"cross_{train_dataset}_to_{test_dataset}_{model_type}",
            train_dataset=train_dataset,
            test_dataset=test_dataset,
            model_type=model_type,
            split_type="stratified",
            features=_cfg.FEATURE_NAMES,
        )
        return self.run_single(config)

    def prime_dataset(
        self,
        name: str,
        df: pd.DataFrame,
        **kwargs: Any,
    ) -> None:
        """Seed the in-memory cache with a dataset already loaded upstream."""
        cache_key = self._cache_key(name, kwargs)
        self._dataset_cache[cache_key] = df

    # ------------------------------------------------------------------
    # Model factories
    # ------------------------------------------------------------------

    @staticmethod
    def _create_unsupervised(
        model_type: str,
        extra_params: dict[str, Any] | None = None,
    ) -> BaselineModel:
        """Instantiate an unsupervised baseline model."""
        cls = BASELINE_MODELS.get(model_type)
        if cls is None:
            raise ValueError(f"Unknown unsupervised model: {model_type!r}")
        extra = extra_params or {}
        return cls(**extra)

    @staticmethod
    def _create_supervised(
        model_type: str,
        extra_params: dict[str, Any] | None = None,
    ) -> Any:
        """Instantiate a supervised classifier."""
        extra = extra_params or {}

        if model_type == "xgboost":
            return XGBClassifier(
                n_estimators=extra.get("n_estimators", 200),
                max_depth=extra.get("max_depth", 6),
                learning_rate=extra.get("learning_rate", 0.1),
                objective="binary:logistic",
                eval_metric="logloss",
                use_label_encoder=False,
                random_state=RANDOM_STATE,
                n_jobs=-1,
            )

        if model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=extra.get("n_estimators", 200),
                max_depth=extra.get("max_depth", None),
                random_state=RANDOM_STATE,
                n_jobs=-1,
            )

        if model_type == "logistic_regression":
            return LogisticRegression(
                max_iter=extra.get("max_iter", 1000),
                solver=extra.get("solver", "lbfgs"),
                random_state=RANDOM_STATE,
                n_jobs=-1,
            )

        raise ValueError(f"Unknown supervised model: {model_type!r}")

    # ------------------------------------------------------------------
    # Predict helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _predict_supervised(
        model: Any,
        X: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Supervised predict → (y_pred, y_scores)."""
        y_pred = model.predict(X)
        if hasattr(model, "predict_proba"):
            y_scores = model.predict_proba(X)[:, 1]
        elif hasattr(model, "decision_function"):
            y_scores = model.decision_function(X)
        else:
            y_scores = y_pred.astype(float)
        return y_pred, y_scores

    # ------------------------------------------------------------------
    # Per-attack-family breakdown
    # ------------------------------------------------------------------

    def _per_attack_breakdown(
        self,
        df: pd.DataFrame,
        feature_cols: list[str],
        y_pred: np.ndarray,
        y_scores: np.ndarray,
        is_test_split: bool,
        y_test_indices: np.ndarray | None,
    ) -> dict[str, dict[str, Any]]:
        """Compute detection rate per attack family."""
        # Try to find attack type/category column
        attack_col = None
        for candidate in ("attack_type", "attack_category", "label", "Label"):
            if candidate in df.columns:
                attack_col = candidate
                break

        if attack_col is None:
            return {}

        # Get the labels aligned with test predictions
        if is_test_split and y_test_indices is not None:
            labels = df[attack_col].iloc[y_test_indices].values
        else:
            # Best effort: take the last len(y_pred) rows
            labels = df[attack_col].values[-len(y_pred):]

        if len(labels) != len(y_pred):
            return {}

        breakdown: dict[str, dict[str, Any]] = {}
        unique_types = np.unique(labels)
        for atype in unique_types:
            mask = labels == atype
            count = int(mask.sum())
            if count == 0:
                continue
            detected = int(y_pred[mask].sum())
            breakdown[str(atype)] = {
                "total": count,
                "detected": detected,
                "detection_rate": round(detected / count, 4),
                "mean_score": round(float(y_scores[mask].mean()), 4),
            }

        return breakdown

    # ------------------------------------------------------------------
    # Data loading & splitting
    # ------------------------------------------------------------------

    def _load_dataset(self, name: str) -> pd.DataFrame:
        """Load a dataset by name or path."""
        load_kwargs = dict(self.dataset_load_kwargs.get(name, {}))
        cache_key = self._cache_key(name, load_kwargs)
        cached = self._dataset_cache.get(cache_key)
        if cached is not None:
            logger.info("Using cached dataset %s (%d rows)", name, len(cached))
            return cached

        # Try the datasets.loaders dispatcher first
        try:
            from datasets.loaders import load_dataset
            df = load_dataset(name, self.data_dir, **load_kwargs)
            self._dataset_cache[cache_key] = df
            return df
        except (ValueError, FileNotFoundError):
            pass

        # Direct path
        direct = self.data_dir / name
        if direct.is_file():
            df = self._read_csv(direct)
            self._dataset_cache[cache_key] = df
            return df

        with_ext = self.data_dir / f"{name}.csv"
        if with_ext.is_file():
            df = self._read_csv(with_ext)
            self._dataset_cache[cache_key] = df
            return df

        # Glob
        csv_matches = sorted(self.data_dir.glob(f"*{name}*"))
        csv_matches = [m for m in csv_matches if m.suffix == ".csv"]
        if csv_matches:
            frames = [self._read_csv(p) for p in csv_matches]
            df = pd.concat(frames, ignore_index=True)
            self._dataset_cache[cache_key] = df
            return df

        # Fallback: all CSVs
        all_csvs = sorted(self.data_dir.glob("*.csv"))
        if all_csvs:
            frames = [self._read_csv(p) for p in all_csvs]
            df = pd.concat(frames, ignore_index=True)
            self._dataset_cache[cache_key] = df
            return df

        raise FileNotFoundError(f"No dataset matching '{name}' in {self.data_dir}")

    @classmethod
    def _cache_key(
        cls,
        name: str,
        kwargs: dict[str, Any],
    ) -> tuple[str, tuple[tuple[str, Any], ...]]:
        frozen = tuple(sorted((key, cls._freeze_value(value)) for key, value in kwargs.items()))
        return (name, frozen)

    @classmethod
    def _freeze_value(cls, value: Any) -> Any:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            return tuple(sorted((k, cls._freeze_value(v)) for k, v in value.items()))
        if isinstance(value, (list, tuple, set)):
            return tuple(cls._freeze_value(v) for v in value)
        return value

    @staticmethod
    def _read_csv(path: Path) -> pd.DataFrame:
        try:
            df = pd.read_csv(path)
        except Exception:
            df = pd.read_csv(path, header=None)
        df.columns = [str(c).strip() for c in df.columns]
        return df

    @staticmethod
    def _extract_xy(
        df: pd.DataFrame,
        feature_cols: list[str],
    ) -> tuple[np.ndarray, np.ndarray]:
        """Extract feature matrix and binary label vector."""
        label_col: str | None = None
        for candidate in ("binary_label", "label", "Label", "class", "Class", "attack_cat"):
            if candidate in df.columns:
                label_col = candidate
                break
        if label_col is None:
            label_col = df.columns[-1]

        available = [c for c in feature_cols if c in df.columns]
        if not available:
            available = [
                c for c in df.select_dtypes(include=[np.number]).columns
                if c != label_col
            ]

        X = df[available].values.astype(np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        raw_labels = df[label_col].values
        if np.issubdtype(raw_labels.dtype, np.number):
            y = (raw_labels != 0).astype(int)
        else:
            y = np.where(
                np.isin(raw_labels, ["normal", "Normal", "BENIGN", "benign", "0"]),
                0, 1,
            ).astype(int)

        return X, y

    @staticmethod
    def _split(
        X: np.ndarray,
        y: np.ndarray,
        split_type: str,
        test_size: float,
        random_state: int,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        if split_type == "time":
            split_idx = int(len(X) * (1 - test_size))
            return X[:split_idx], X[split_idx:], y[:split_idx], y[split_idx:]

        try:
            return train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y,
            )
        except ValueError:
            return train_test_split(
                X, y, test_size=test_size, random_state=random_state,
            )

    # ------------------------------------------------------------------
    # Summary builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        results: list[dict[str, Any]],
        cross_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        valid = [r for r in results if "metrics" in r]
        if not valid:
            return {"best_model": None, "total_experiments": len(results)}

        # Separate unsupervised and supervised rankings
        unsup = [r for r in valid if r.get("model_class") == "unsupervised"]
        sup = [r for r in valid if r.get("model_class") == "supervised"]

        def _rank(items: list) -> list:
            return sorted(items, key=lambda r: r["metrics"]["f1"], reverse=True)

        ranked = _rank(valid)
        best = ranked[0]

        return {
            "best_model": {
                "name": best["name"],
                "model_type": best["model_type"],
                "model_class": best.get("model_class", "unknown"),
                "f1": best["metrics"]["f1"],
                "pr_auc": best["metrics"].get("pr_auc"),
                "roc_auc": best["metrics"].get("roc_auc"),
                "precision": best["metrics"]["precision"],
                "recall": best["metrics"]["recall"],
            },
            "best_unsupervised": _rank(unsup)[0]["name"] if unsup else None,
            "best_supervised": _rank(sup)[0]["name"] if sup else None,
            "total_experiments": len(results),
            "successful_experiments": len(valid),
            "failed_experiments": len(results) - len(valid),
            "unsupervised_ranking": [
                {"name": r["name"], "model_type": r["model_type"], "f1": r["metrics"]["f1"]}
                for r in _rank(unsup)
            ],
            "supervised_ranking": [
                {"name": r["name"], "model_type": r["model_type"], "f1": r["metrics"]["f1"]}
                for r in _rank(sup)
            ],
        }
