"""
Markdown report generator for evaluation results.

Produces a human-readable report with separate sections for unsupervised
anomaly detection and supervised classification, per-attack breakdown,
false-positive analysis, and threshold sweeps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate comprehensive evaluation reports in Markdown."""

    def __init__(self, results: dict[str, Any]) -> None:
        self.results = results

    def generate_markdown(self) -> str:
        sections = [
            self._header(),
            self._executive_summary(),
            self._results_table("unsupervised"),
            self._results_table("supervised"),
            self._fp_analysis(),
            self._attack_breakdown(),
            self._cross_dataset_section(),
            self._threshold_analysis(),
            self._limitations(),
            self._footer(),
        ]
        return "\n\n".join(s for s in sections if s)

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.generate_markdown()
        path.write_text(content, encoding="utf-8")
        logger.info("Report saved to %s (%d bytes)", path, len(content))

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self) -> str:
        ts = self.results.get("timestamp", datetime.now(timezone.utc).isoformat())
        elapsed = self.results.get("elapsed_seconds", "N/A")
        return (
            "# NIDS Evaluation Report\n\n"
            f"**Generated:** {ts}  \n"
            f"**Total runtime:** {elapsed}s  \n"
            f"**Feature set:** 28 observable features (Phase 2 contract)"
        )

    def _executive_summary(self) -> str:
        summary = self.results.get("summary", {})
        if not summary:
            return "## Executive Summary\n\nNo experiments completed."

        best = summary.get("best_model")
        total = summary.get("total_experiments", 0)
        success = summary.get("successful_experiments", 0)

        lines = [
            "## Executive Summary\n",
            f"- **Total experiments:** {total} ({success} succeeded)",
        ]

        if best:
            lines.extend([
                f"- **Best overall:** {best['name']} ({best.get('model_class', '?')})",
                f"  - F1={best['f1']:.4f}, PR-AUC={_fmt(best.get('pr_auc'))}",
            ])

        best_unsup = summary.get("best_unsupervised")
        best_sup = summary.get("best_supervised")
        if best_unsup:
            lines.append(f"- **Best unsupervised:** {best_unsup}")
        if best_sup:
            lines.append(f"- **Best supervised (ceiling):** {best_sup}")

        return "\n".join(lines)

    def _results_table(self, model_class: str) -> str:
        """Build a results table filtered by model_class."""
        experiments = self.results.get("experiments", [])
        filtered = [
            e for e in experiments
            if "metrics" in e and e.get("model_class") == model_class
        ]
        if not filtered:
            return ""

        title = "Unsupervised Anomaly Detection" if model_class == "unsupervised" else "Supervised Classification (Ceiling)"
        note = ""
        if model_class == "unsupervised":
            note = "\n*Trained on normal-only traffic. Scores are post-hoc anomaly scores, not probabilities.*\n"
        else:
            note = "\n*Trained on labeled mixed data. These are upper-bound results, not deployable as-is.*\n"

        header = (
            f"## {title}\n{note}\n"
            "| Model | Dataset | F1 | PR-AUC | ROC-AUC | Recall@1%FPR | FP/10k | Time |\n"
            "|---|---|---|---|---|---|---|---|"
        )
        rows: list[str] = []
        for exp in sorted(filtered, key=lambda e: e["metrics"]["f1"], reverse=True):
            m = exp["metrics"]
            rfpr = exp.get("recall_at_fpr", {})
            recall_1 = rfpr.get("recall@fpr=0.01", "N/A")
            fp = exp.get("fp_stats", {})
            fp10k = fp.get("fp_per_10k_flows", "N/A")
            rows.append(
                f"| {exp['model_type']} "
                f"| {exp.get('train_dataset', '-')} "
                f"| {m['f1']:.4f} "
                f"| {_fmt(m.get('pr_auc'))} "
                f"| {_fmt(m.get('roc_auc'))} "
                f"| {_fmt(recall_1)} "
                f"| {_fmt(fp10k)} "
                f"| {exp.get('elapsed_seconds', '-')}s |"
            )

        return header + "\n" + "\n".join(rows)

    def _fp_analysis(self) -> str:
        experiments = self.results.get("experiments", [])
        valid = [e for e in experiments if "fp_stats" in e]
        if not valid:
            return ""

        header = (
            "## False Positive Analysis\n\n"
            "| Model | Class | FP Count | FP/10k Flows | FP Rate |\n"
            "|---|---|---|---|---|"
        )
        rows = []
        for exp in sorted(valid, key=lambda e: e.get("fp_stats", {}).get("fp_per_10k_flows", 999)):
            fp = exp["fp_stats"]
            rows.append(
                f"| {exp['model_type']} "
                f"| {exp.get('model_class', '?')} "
                f"| {fp['false_positives']} "
                f"| {fp['fp_per_10k_flows']} "
                f"| {fp['fp_rate']:.4f} |"
            )

        return header + "\n" + "\n".join(rows)

    def _attack_breakdown(self) -> str:
        """Show per-attack detection rates from the best unsupervised model."""
        experiments = self.results.get("experiments", [])
        unsup = [
            e for e in experiments
            if e.get("model_class") == "unsupervised" and "metrics" in e
        ]
        if not unsup:
            return ""

        best = max(unsup, key=lambda e: e["metrics"]["f1"])
        breakdown = best.get("attack_breakdown", {})
        if not breakdown:
            return ""

        header = (
            f"## Per-Attack Detection (Best Unsupervised: {best['model_type']})\n\n"
            "| Attack Type | Total | Detected | Detection Rate | Mean Score |\n"
            "|---|---|---|---|---|"
        )
        rows = []
        for atype, stats in sorted(breakdown.items(), key=lambda x: x[1]["detection_rate"], reverse=True):
            rows.append(
                f"| {atype} "
                f"| {stats['total']} "
                f"| {stats['detected']} "
                f"| {stats['detection_rate']:.2%} "
                f"| {stats['mean_score']:.4f} |"
            )

        return header + "\n" + "\n".join(rows)

    def _cross_dataset_section(self) -> str:
        cross = self.results.get("cross_dataset", [])
        if not cross:
            return ""

        header = (
            "## Cross-Dataset Generalization\n\n"
            "| Experiment | Model | F1 | PR-AUC | ROC-AUC |\n"
            "|---|---|---|---|---|"
        )
        rows = []
        for exp in cross:
            if "error" in exp:
                rows.append(f"| {exp.get('name', '?')} | - | ERROR | - | - |")
                continue
            m = exp.get("metrics", {})
            rows.append(
                f"| {exp['name']} "
                f"| {exp.get('model_type', '-')} "
                f"| {m.get('f1', 0):.4f} "
                f"| {_fmt(m.get('pr_auc'))} "
                f"| {_fmt(m.get('roc_auc'))} |"
            )

        return header + "\n" + "\n".join(rows)

    def _threshold_analysis(self) -> str:
        experiments = self.results.get("experiments", [])
        unsup = [
            e for e in experiments
            if e.get("model_class") == "unsupervised" and "metrics" in e
        ]
        if not unsup:
            return ""

        best = max(unsup, key=lambda e: e["metrics"]["f1"])
        sweep = best.get("threshold_sweep", [])
        if not sweep:
            return ""

        indices = _sample_indices(len(sweep), 8)
        sampled = [sweep[i] for i in indices]

        header = (
            f"## Threshold Sweep (Best Unsupervised: {best['model_type']})\n\n"
            "*Thresholds derived from training-normal score percentiles.*\n\n"
            "| Threshold | Precision | Recall | FPR | F1 | FP/10k |\n"
            "|---|---|---|---|---|---|"
        )
        rows = []
        for s in sampled:
            rows.append(
                f"| {s['threshold']:.4f} "
                f"| {s['precision']:.4f} "
                f"| {s['recall']:.4f} "
                f"| {s['fpr']:.4f} "
                f"| {s['f1']:.4f} "
                f"| {s.get('fp_per_10k', 0):.1f} |"
            )

        return header + "\n" + "\n".join(rows)

    def _limitations(self) -> str:
        return (
            "## Limitations\n\n"
            "- **Label quality:** Results assume ground-truth labels are correct.\n"
            "- **Temporal validity:** Evaluated on a static snapshot; may degrade over time.\n"
            "- **Feature coverage:** 28 packet-observable features only. No payload/DPI.\n"
            "- **Class imbalance:** Minority attack types have low support and unreliable per-class metrics.\n"
            "- **Unsupervised score calibration:** Anomaly scores are not probabilities. "
            "Calibration curves for unsupervised models are post-hoc and approximate.\n"
            "- **Supervised ceiling:** The supervised oracle has access to labels and is not "
            "deployable in the live system. It represents the theoretical upper bound."
        )

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*Report generated by the NIDS Evaluation Module.*"
        )


# ======================================================================
# Private helpers
# ======================================================================

def _fmt(value: float | None) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, str):
        return value
    return f"{value:.4f}"


def _sample_indices(n: int, k: int) -> list[int]:
    if n <= k:
        return list(range(n))
    step = (n - 1) / (k - 1)
    return [int(round(i * step)) for i in range(k)]
