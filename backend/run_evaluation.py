#!/usr/bin/env python3
"""
Run the full evaluation pipeline on modern datasets.

Usage:
    python run_evaluation.py
    python run_evaluation.py --datasets cicids2018 unsw_nb15
    python run_evaluation.py --datasets unsw_nb15 --models zscore isolation_forest lof

Outputs:
    reports/evaluation.md   — Full evaluation report
    models/evaluation.json  — Raw results as JSON

Each dataset uses its own native feature space.  Cross-dataset
experiments are not run because feature spaces differ.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from datasets.loaders import load_dataset, derive_feature_columns
from evaluation.experiments import (
    ExperimentConfig,
    ExperimentRunner,
    UNSUPERVISED_MODELS,
    SUPERVISED_MODELS,
)
from evaluation.report import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
MODELS_DIR = Path(__file__).parent / "models"

ALL_MODELS = sorted(UNSUPERVISED_MODELS | SUPERVISED_MODELS)

# Subsample large datasets for unsupervised models to keep runtime sane
MAX_ROWS_UNSUPERVISED = 500_000


@contextlib.contextmanager
def _evaluation_lock(lock_path: Path):
    """Prevent overlapping evaluation runs from clobbering outputs."""
    lock_path.parent.mkdir(exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"Another evaluation run is already active. Lock file: {lock_path}"
            ) from exc

        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description="NIDS Evaluation Pipeline")
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=["cicids2018", "unsw_nb15"],
        choices=["cicids2018", "unsw_nb15"],
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=ALL_MODELS,
        choices=ALL_MODELS,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(__file__).parent / "data",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=MAX_ROWS_UNSUPERVISED,
        help="Max rows for large datasets (subsampled stratified)",
    )
    args = parser.parse_args()

    dataset_load_kwargs: dict[str, dict] = {}
    if "cicids2018" in args.datasets:
        dataset_load_kwargs["cicids2018"] = {"max_rows": args.max_rows}

    lock_path = MODELS_DIR / "evaluation.lock"
    try:
        with _evaluation_lock(lock_path):
            runner = ExperimentRunner(
                data_dir=args.data_dir,
                dataset_load_kwargs=dataset_load_kwargs,
            )
            pipeline_start = time.perf_counter()

            # ── Verify datasets ─────────────────────────────────────────────
            available_datasets: list[str] = []
            dataset_info: dict[str, dict] = {}
            for ds in args.datasets:
                try:
                    kwargs = dataset_load_kwargs.get(ds, {})
                    df = load_dataset(ds, args.data_dir, **kwargs)
                    runner.prime_dataset(ds, df, **kwargs)
                    features = derive_feature_columns(df)
                    dataset_info[ds] = {
                        "rows": len(df),
                        "n_features": len(features),
                        "feature_names": features,
                    }
                    logger.info("Loaded %s: %d rows, %d features", ds, len(df), len(features))
                    available_datasets.append(ds)
                except (FileNotFoundError, ValueError) as e:
                    logger.warning("Skipping %s: %s", ds, e)

            if not available_datasets:
                logger.error("No datasets available.")
                sys.exit(1)

            # ── E1: Single-dataset evaluation ───────────────────────────────
            logger.info("=== E1: Single-dataset evaluation ===")
            all_results: list[dict] = []

            for ds in available_datasets:
                native_features = dataset_info[ds]["feature_names"]

                for model in args.models:
                    config = ExperimentConfig(
                        name=f"{model}_on_{ds}",
                        train_dataset=ds,
                        test_dataset="same",
                        model_type=model,
                        split_type="stratified",
                        features=native_features,
                    )
                    logger.info("Running: %s (%d features)", config.name, len(native_features))
                    try:
                        result = runner.run_single(config)
                        all_results.append(result)
                        m = result["metrics"]
                        logger.info(
                            "  F1=%.4f  PR-AUC=%s  FP/10k=%s",
                            m["f1"],
                            f"{m['pr_auc']:.4f}" if m["pr_auc"] else "N/A",
                            result.get("fp_stats", {}).get("fp_per_10k_flows", "N/A"),
                        )
                    except Exception as e:
                        logger.error("  Failed: %s", e)
                        all_results.append({"name": config.name, "error": str(e)})

            # ── Build summary ───────────────────────────────────────────────
            valid = [r for r in all_results if "metrics" in r]
            unsup = [r for r in valid if r.get("model_class") == "unsupervised"]
            sup = [r for r in valid if r.get("model_class") == "supervised"]

            def _best(items):
                if not items:
                    return None
                return max(items, key=lambda r: r["metrics"]["f1"])

            best_overall = _best(valid)
            best_unsup = _best(unsup)
            best_sup = _best(sup)

            summary = {
                "best_model": {
                    "name": best_overall["name"],
                    "model_type": best_overall["model_type"],
                    "model_class": best_overall.get("model_class"),
                    "f1": best_overall["metrics"]["f1"],
                    "pr_auc": best_overall["metrics"].get("pr_auc"),
                    "roc_auc": best_overall["metrics"].get("roc_auc"),
                    "precision": best_overall["metrics"]["precision"],
                    "recall": best_overall["metrics"]["recall"],
                } if best_overall else None,
                "best_unsupervised": best_unsup["name"] if best_unsup else None,
                "best_supervised": best_sup["name"] if best_sup else None,
                "total_experiments": len(all_results),
                "successful_experiments": len(valid),
                "failed_experiments": len(all_results) - len(valid),
                "unsupervised_ranking": [
                    {"name": r["name"], "model_type": r["model_type"],
                     "dataset": r.get("train_dataset"), "f1": r["metrics"]["f1"]}
                    for r in sorted(unsup, key=lambda r: r["metrics"]["f1"], reverse=True)
                ],
                "supervised_ranking": [
                    {"name": r["name"], "model_type": r["model_type"],
                     "dataset": r.get("train_dataset"), "f1": r["metrics"]["f1"]}
                    for r in sorted(sup, key=lambda r: r["metrics"]["f1"], reverse=True)
                ],
            }

            elapsed = round(time.perf_counter() - pipeline_start, 3)

            full_results = {
                "experiments": all_results,
                "cross_dataset": [],  # not applicable under Option A (different feature spaces)
                "summary": summary,
                "datasets_used": available_datasets,
                "dataset_info": {k: {"rows": v["rows"], "n_features": v["n_features"]}
                                 for k, v in dataset_info.items()},
                "models_evaluated": args.models,
                "elapsed_seconds": elapsed,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # ── Save JSON ───────────────────────────────────────────────────
            MODELS_DIR.mkdir(exist_ok=True)
            json_path = MODELS_DIR / "evaluation.json"
            with open(json_path, "w") as f:
                json.dump(full_results, f, indent=2, default=str)
            logger.info("Raw results saved to %s", json_path)

            # ── Generate report ─────────────────────────────────────────────
            REPORTS_DIR.mkdir(exist_ok=True)
            report = ReportGenerator(full_results)
            report_path = REPORTS_DIR / "evaluation.md"
            report.save(report_path)
            logger.info("Report saved to %s", report_path)

            # ── Summary ─────────────────────────────────────────────────────
            print("\n" + "=" * 60)
            print("EVALUATION COMPLETE")
            print("=" * 60)
            for ds, info in dataset_info.items():
                print(f"  {ds}: {info['rows']} rows, {info['n_features']} native features")

            if best_unsup:
                m = best_unsup["metrics"]
                print(f"\nBest unsupervised: {best_unsup['name']}")
                print(f"  F1={m['f1']:.4f}  PR-AUC={m.get('pr_auc', 'N/A')}")

            if best_sup:
                m = best_sup["metrics"]
                print(f"\nSupervised ceiling: {best_sup['name']}")
                print(f"  F1={m['f1']:.4f}  PR-AUC={m.get('pr_auc', 'N/A')}")

            print(f"\nRuntime: {elapsed}s")
            print(f"Results: {json_path}")
            print(f"Report:  {report_path}")
    except RuntimeError as exc:
        logger.error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(130)
