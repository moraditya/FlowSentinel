"""
Comprehensive ML evaluation metrics for network intrusion detection.

Provides binary classification metrics, threshold analysis, calibration
curves, per-slice breakdowns, and operational cost estimation — all
geared towards understanding IDS performance in production.
"""

from __future__ import annotations

import logging
import warnings
from typing import Any

import numpy as np
from sklearn.calibration import calibration_curve as sklearn_calibration_curve
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)


class EvaluationMetrics:
    """Compute comprehensive ML evaluation metrics.

    Every public method is a ``@staticmethod`` that accepts numpy arrays and
    returns plain dicts/lists suitable for JSON serialisation.  No internal
    state is required.
    """

    # ------------------------------------------------------------------
    # Core binary classification metrics
    # ------------------------------------------------------------------

    @staticmethod
    def binary_metrics(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """Compute accuracy, precision, recall, F1, PR-AUC, ROC-AUC.

        Parameters
        ----------
        y_true : array-like of {0, 1}
            Ground-truth binary labels.
        y_pred : array-like of {0, 1}
            Predicted binary labels.
        y_scores : array-like of float, optional
            Predicted probabilities or decision-function scores for the
            positive class.  Required for AUC metrics.

        Returns
        -------
        dict
            Keys: accuracy, precision, recall, f1, pr_auc, roc_auc,
            confusion_matrix (as nested list), support (total samples),
            positive_rate (fraction of positives in ground truth).
        """
        y_true = np.asarray(y_true, dtype=int)
        y_pred = np.asarray(y_pred, dtype=int)

        if y_true.size == 0:
            return _empty_binary_result()

        n_classes = len(np.unique(y_true))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            acc = float(accuracy_score(y_true, y_pred))
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec = float(recall_score(y_true, y_pred, zero_division=0))
            f1 = float(f1_score(y_true, y_pred, zero_division=0))

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()

        result: dict[str, Any] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "pr_auc": None,
            "roc_auc": None,
            "confusion_matrix": cm,
            "support": int(y_true.size),
            "positive_rate": float(y_true.sum() / y_true.size) if y_true.size else 0.0,
        }

        if y_scores is not None and n_classes == 2:
            y_scores = np.asarray(y_scores, dtype=float)
            try:
                result["roc_auc"] = float(roc_auc_score(y_true, y_scores))
            except ValueError:
                result["roc_auc"] = None
            try:
                result["pr_auc"] = float(average_precision_score(y_true, y_scores))
            except ValueError:
                result["pr_auc"] = None

        return result

    # ------------------------------------------------------------------
    # Recall at fixed false-positive rates
    # ------------------------------------------------------------------

    @staticmethod
    def recall_at_fpr(
        y_true: np.ndarray,
        y_scores: np.ndarray,
        target_fprs: list[float] | None = None,
    ) -> dict[str, float | None]:
        """Recall achieved at fixed false-positive rates.

        For an IDS we care deeply about *how much attack traffic we catch*
        while keeping the false-alarm rate at an operationally tolerable
        level.

        Parameters
        ----------
        y_true : array-like of {0, 1}
        y_scores : array-like of float
        target_fprs : list of float
            FPR checkpoints.  Defaults to ``[0.001, 0.005, 0.01, 0.05, 0.1]``.

        Returns
        -------
        dict
            Mapping ``"recall@fpr=<fpr>"`` to the recall value, or ``None``
            if computation failed.
        """
        if target_fprs is None:
            target_fprs = [0.001, 0.005, 0.01, 0.05, 0.1]

        y_true = np.asarray(y_true, dtype=int)
        y_scores = np.asarray(y_scores, dtype=float)

        result: dict[str, float | None] = {}

        if y_true.size == 0 or len(np.unique(y_true)) < 2:
            for fpr_target in target_fprs:
                result[f"recall@fpr={fpr_target}"] = None
            return result

        try:
            fprs, tprs, _ = roc_curve(y_true, y_scores)
        except ValueError:
            for fpr_target in target_fprs:
                result[f"recall@fpr={fpr_target}"] = None
            return result

        for fpr_target in target_fprs:
            # Find the largest TPR whose FPR is <= the target
            mask = fprs <= fpr_target
            if mask.any():
                result[f"recall@fpr={fpr_target}"] = float(tprs[mask].max())
            else:
                result[f"recall@fpr={fpr_target}"] = 0.0

        return result

    # ------------------------------------------------------------------
    # Operational alert-volume metrics
    # ------------------------------------------------------------------

    @staticmethod
    def alerts_per_volume(
        y_pred: np.ndarray,
        total_flows: int,
        window_hours: float = 1.0,
    ) -> dict[str, float]:
        """Alert-volume statistics (total alerts, not split by TP/FP)."""
        y_pred = np.asarray(y_pred, dtype=int)
        total_alerts = int(y_pred.sum())
        total_flows = max(int(total_flows), 1)
        window_hours = max(float(window_hours), 1e-9)

        return {
            "alerts_total": total_alerts,
            "alerts_per_10k_flows": round(total_alerts / total_flows * 10_000, 4),
            "alerts_per_hour": round(total_alerts / window_hours, 4),
            "alert_rate": round(total_alerts / total_flows, 6),
        }

    @staticmethod
    def false_positives_per_10k(
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> dict[str, float]:
        """False-positive volume metrics.

        Unlike ``alerts_per_volume`` which counts all alerts, this counts
        only actual false positives (predicted attack but ground-truth normal).
        """
        y_true = np.asarray(y_true, dtype=int)
        y_pred = np.asarray(y_pred, dtype=int)
        total = max(int(y_true.size), 1)
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        n_normal = max(int((y_true == 0).sum()), 1)
        return {
            "false_positives": fp,
            "fp_per_10k_flows": round(fp / total * 10_000, 4),
            "fp_rate": round(fp / n_normal, 6),
        }

    # ------------------------------------------------------------------
    # Threshold sweep
    # ------------------------------------------------------------------

    @staticmethod
    def threshold_sweep(
        y_true: np.ndarray,
        y_scores: np.ndarray,
        train_normal_scores: np.ndarray | None = None,
        n_thresholds: int = 50,
    ) -> list[dict[str, float]]:
        """Sweep thresholds and compute metrics at each.

        If *train_normal_scores* is provided, thresholds are derived from
        percentiles of the training-normal score distribution (stable,
        comparable across models).  Otherwise falls back to evenly-spaced
        percentiles of the test scores.
        """
        y_true = np.asarray(y_true, dtype=int)
        y_scores = np.asarray(y_scores, dtype=float)

        if y_true.size == 0:
            return []

        # Derive thresholds from training-normal distribution if available
        if train_normal_scores is not None:
            tns = np.asarray(train_normal_scores, dtype=float)
            percentiles = np.linspace(1, 99, n_thresholds)
            thresholds = np.unique(np.percentile(tns, percentiles))
        else:
            percentiles = np.linspace(1, 99, n_thresholds)
            thresholds = np.unique(np.percentile(y_scores, percentiles))

        total = y_true.size
        n_neg = int((y_true == 0).sum())

        rows: list[dict[str, float]] = []
        for thr in thresholds:
            preds = (y_scores >= thr).astype(int)
            tp = int(((preds == 1) & (y_true == 1)).sum())
            fp = int(((preds == 1) & (y_true == 0)).sum())
            fn = int(((preds == 0) & (y_true == 1)).sum())

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            fpr = fp / n_neg if n_neg > 0 else 0.0
            alert_count = int(preds.sum())

            rows.append({
                "threshold": round(float(thr), 6),
                "precision": round(prec, 6),
                "recall": round(rec, 6),
                "fpr": round(fpr, 6),
                "f1": round(f1, 6),
                "fp_per_10k": round(fp / total * 10_000, 4) if total else 0.0,
                "alert_rate": round(alert_count / total, 6) if total else 0.0,
            })

        return rows

    # ------------------------------------------------------------------
    # Calibration curve
    # ------------------------------------------------------------------

    @staticmethod
    def calibration_curve(
        y_true: np.ndarray,
        y_scores: np.ndarray,
        n_bins: int = 10,
    ) -> dict[str, Any]:
        """Reliability / calibration diagram data.

        Returns
        -------
        dict
            mean_predicted: list of mean predicted probabilities per bin,
            fraction_positive: list of actual positive fractions per bin,
            bin_counts: list of sample counts per bin,
            ece: expected calibration error.
        """
        y_true = np.asarray(y_true, dtype=int)
        y_scores = np.asarray(y_scores, dtype=float)

        if y_true.size == 0 or len(np.unique(y_true)) < 2:
            return {
                "mean_predicted": [],
                "fraction_positive": [],
                "bin_counts": [],
                "ece": None,
            }

        try:
            fraction_pos, mean_pred = sklearn_calibration_curve(
                y_true, y_scores, n_bins=n_bins, strategy="uniform"
            )
        except ValueError:
            return {
                "mean_predicted": [],
                "fraction_positive": [],
                "bin_counts": [],
                "ece": None,
            }

        # Bin counts via histogram
        bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
        bin_counts, _ = np.histogram(y_scores, bins=bin_edges)

        # Expected Calibration Error
        # Weight each bin by its proportion of samples
        total = y_true.size
        # sklearn calibration_curve may drop empty bins, so recompute
        # bin counts aligned with the returned bins
        aligned_counts: list[int] = []
        for mp in mean_pred:
            # Find the bin this mean_pred falls into
            idx = int(np.clip(np.digitize(mp, bin_edges) - 1, 0, n_bins - 1))
            aligned_counts.append(int(bin_counts[idx]))

        aligned_arr = np.array(aligned_counts, dtype=float)
        weights = aligned_arr / total if total > 0 else aligned_arr
        ece = float(np.sum(weights * np.abs(fraction_pos - mean_pred)))

        return {
            "mean_predicted": [round(float(v), 6) for v in mean_pred],
            "fraction_positive": [round(float(v), 6) for v in fraction_pos],
            "bin_counts": [int(c) for c in aligned_counts],
            "ece": round(ece, 6),
        }

    # ------------------------------------------------------------------
    # Per-slice analysis
    # ------------------------------------------------------------------

    @staticmethod
    def slice_analysis(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_scores: np.ndarray,
        groups: dict[str, np.ndarray],
    ) -> dict[str, dict[str, Any]]:
        """Per-slice metrics.

        Parameters
        ----------
        groups : dict
            Maps a human-readable slice name to a boolean mask of the same
            length as y_true.

        Returns
        -------
        dict
            ``{slice_name: {precision, recall, f1, support, alert_rate,
            roc_auc}}``
        """
        y_true = np.asarray(y_true, dtype=int)
        y_pred = np.asarray(y_pred, dtype=int)
        y_scores = np.asarray(y_scores, dtype=float)

        result: dict[str, dict[str, Any]] = {}
        for name, mask in groups.items():
            mask = np.asarray(mask, dtype=bool)
            if mask.sum() == 0:
                result[name] = {
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "support": 0,
                    "alert_rate": 0.0,
                    "roc_auc": None,
                }
                continue

            yt = y_true[mask]
            yp = y_pred[mask]
            ys = y_scores[mask]
            support = int(yt.size)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                prec = float(precision_score(yt, yp, zero_division=0))
                rec = float(recall_score(yt, yp, zero_division=0))
                f1 = float(f1_score(yt, yp, zero_division=0))

            alert_rate = float(yp.sum() / support) if support > 0 else 0.0

            auc_val: float | None = None
            if len(np.unique(yt)) == 2:
                try:
                    auc_val = float(roc_auc_score(yt, ys))
                except ValueError:
                    pass

            result[name] = {
                "precision": round(prec, 6),
                "recall": round(rec, 6),
                "f1": round(f1, 6),
                "support": support,
                "alert_rate": round(alert_rate, 6),
                "roc_auc": round(auc_val, 6) if auc_val is not None else None,
            }

        return result

    # ------------------------------------------------------------------
    # Cost / capacity analysis
    # ------------------------------------------------------------------

    @staticmethod
    def cost_analysis(
        y_true: np.ndarray,
        y_scores: np.ndarray,
        thresholds: list[float],
        analyst_capacity_per_day: int = 100,
    ) -> list[dict[str, Any]]:
        """Operational cost estimate at each threshold.

        For each threshold compute how many alerts fire, how many analyst-
        hours are needed to review them, how many real attacks are caught,
        and how many are missed.

        Parameters
        ----------
        analyst_capacity_per_day : int
            Number of alerts one analyst can review in an 8-hour shift.

        Returns
        -------
        list of dict
            Each entry: threshold, alerts_per_day, analyst_hours_needed,
            analysts_required, recall, missed_attacks, total_attacks,
            false_alerts, precision.
        """
        y_true = np.asarray(y_true, dtype=int)
        y_scores = np.asarray(y_scores, dtype=float)
        total_attacks = int(y_true.sum())
        total_samples = int(y_true.size)
        capacity = max(int(analyst_capacity_per_day), 1)

        if total_samples == 0:
            return []

        rows: list[dict[str, Any]] = []
        for thr in sorted(thresholds):
            preds = (y_scores >= thr).astype(int)
            tp = int(((preds == 1) & (y_true == 1)).sum())
            fp = int(((preds == 1) & (y_true == 0)).sum())
            fn = int(((preds == 0) & (y_true == 1)).sum())
            total_alerts = int(preds.sum())

            # Scale to daily estimate (assume dataset represents one day)
            alerts_per_day = total_alerts
            analyst_hours = round(alerts_per_day / (capacity / 8.0), 2)
            analysts_needed = max(1, int(np.ceil(alerts_per_day / capacity)))

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0

            rows.append({
                "threshold": round(float(thr), 6),
                "alerts_per_day": alerts_per_day,
                "analyst_hours_needed": analyst_hours,
                "analysts_required": analysts_needed,
                "recall": round(rec, 6),
                "missed_attacks": fn,
                "total_attacks": total_attacks,
                "false_alerts": fp,
                "precision": round(prec, 6),
            })

        return rows


# ======================================================================
# Private helpers
# ======================================================================

def _empty_binary_result() -> dict[str, Any]:
    """Return a zeroed-out metrics dict for degenerate inputs."""
    return {
        "accuracy": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "pr_auc": None,
        "roc_auc": None,
        "confusion_matrix": [[0, 0], [0, 0]],
        "support": 0,
        "positive_rate": 0.0,
    }
