"""
Dataset loading for evaluation.

Each loader reads raw CSVs, attaches ``binary_label`` and
``attack_category`` columns, cleans NaN/Inf values, and returns a
tidy DataFrame.  Feature columns are the dataset's native numeric
columns — no cross-dataset mapping is applied.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from .schema import LABEL_COLUMNS, BinaryLabel

logger = logging.getLogger(__name__)

CICIDS_LABEL_CANDIDATES = ("Label", "label")
CICIDS_SKIP_NUMERIC_COERCE = {
    "Label",
    "label",
    "Timestamp",
    "timestamp",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
}
CICIDS_CHUNK_SIZE = 250_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows with NaN/Inf in feature columns (not metadata)."""
    feature_cols = derive_feature_columns(df)
    if not feature_cols:
        return df.reset_index(drop=True)
    df = df.copy()
    df.loc[:, feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna(subset=feature_cols)
    dropped = before - len(df)
    if dropped:
        logger.info("Dropped %d rows containing NaN/Inf values", dropped)
    return df.reset_index(drop=True)


def derive_feature_columns(df: pd.DataFrame) -> list[str]:
    """Return the usable numeric feature columns for a DataFrame.

    Excludes label, ID, and metadata columns.
    """
    return [
        c for c in df.select_dtypes(include=[np.number]).columns
        if c not in LABEL_COLUMNS
    ]


def _find_cicids_label_col(columns: list[str]) -> str:
    for candidate in CICIDS_LABEL_CANDIDATES:
        if candidate in columns:
            return candidate
    raise KeyError(f"No 'Label' column found. Available: {columns[:10]}")


def _prepare_cicids_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    chunk.columns = [c.strip() for c in chunk.columns]
    label_col = _find_cicids_label_col(list(chunk.columns))

    for col in chunk.columns:
        if col in CICIDS_SKIP_NUMERIC_COERCE:
            continue
        chunk[col] = pd.to_numeric(chunk[col], errors="coerce")

    chunk["attack_category"] = chunk[label_col].astype(str).str.strip()
    chunk = chunk[chunk["attack_category"].str.lower() != "label"].copy()
    chunk["binary_label"] = chunk["attack_category"].apply(
        lambda v: BinaryLabel.NORMAL if v.lower() == "benign" else BinaryLabel.ATTACK
    )
    return _clean(chunk)


def _cicids_target_counts(
    csv_files: list[Path],
    max_rows: int,
) -> dict[int, int]:
    counts = {
        BinaryLabel.NORMAL: 0,
        BinaryLabel.ATTACK: 0,
    }

    for csv_path in csv_files:
        header = pd.read_csv(csv_path, nrows=0, encoding="utf-8", skipinitialspace=True)
        header.columns = [c.strip() for c in header.columns]
        label_col = _find_cicids_label_col(list(header.columns))

        for chunk in pd.read_csv(
            csv_path,
            usecols=[label_col],
            encoding="utf-8",
            skipinitialspace=True,
            chunksize=CICIDS_CHUNK_SIZE,
            low_memory=False,
        ):
            labels = chunk[label_col].astype(str).str.strip()
            labels = labels[labels.str.lower() != "label"]
            normal_count = int((labels.str.lower() == "benign").sum())
            attack_count = int(len(labels) - normal_count)
            counts[BinaryLabel.NORMAL] += normal_count
            counts[BinaryLabel.ATTACK] += attack_count

    total_rows = counts[BinaryLabel.NORMAL] + counts[BinaryLabel.ATTACK]
    if total_rows == 0:
        raise ValueError("CIC-IDS-2018 label scan found zero usable rows")

    normal_target = min(
        counts[BinaryLabel.NORMAL],
        int(round(max_rows * counts[BinaryLabel.NORMAL] / total_rows)),
    )
    attack_target = min(
        counts[BinaryLabel.ATTACK],
        max_rows - normal_target,
    )

    # Fill any rounding gap from the remaining class capacity.
    remaining = max_rows - (normal_target + attack_target)
    if remaining > 0:
        normal_capacity = counts[BinaryLabel.NORMAL] - normal_target
        attack_capacity = counts[BinaryLabel.ATTACK] - attack_target
        take_normal = min(remaining, max(0, normal_capacity))
        normal_target += take_normal
        remaining -= take_normal
        if remaining > 0:
            attack_target += min(remaining, max(0, attack_capacity))

    return {
        BinaryLabel.NORMAL: normal_target,
        BinaryLabel.ATTACK: attack_target,
    }


def _sample_cicids2018(
    csv_files: list[Path],
    max_rows: int,
) -> pd.DataFrame:
    targets = _cicids_target_counts(csv_files, max_rows)
    reservoirs: dict[int, pd.DataFrame | None] = {
        BinaryLabel.NORMAL: None,
        BinaryLabel.ATTACK: None,
    }
    rng = np.random.default_rng(42)

    for csv_path in csv_files:
        try:
            chunks = pd.read_csv(
                csv_path,
                encoding="utf-8",
                skipinitialspace=True,
                chunksize=CICIDS_CHUNK_SIZE,
                low_memory=False,
            )
        except UnicodeDecodeError:
            chunks = pd.read_csv(
                csv_path,
                encoding="latin-1",
                skipinitialspace=True,
                chunksize=CICIDS_CHUNK_SIZE,
                low_memory=False,
            )

        for raw_chunk in chunks:
            chunk = _prepare_cicids_chunk(raw_chunk)
            if chunk.empty:
                continue

            for label_value, target_rows in targets.items():
                if target_rows <= 0:
                    continue
                label_chunk = chunk[chunk["binary_label"] == label_value]
                if label_chunk.empty:
                    continue

                scored = label_chunk.copy()
                scored["__priority__"] = rng.random(len(scored))
                current = reservoirs[label_value]
                if current is None:
                    merged = scored
                else:
                    merged = pd.concat([current, scored], ignore_index=True)
                if len(merged) > target_rows:
                    merged = merged.nsmallest(target_rows, "__priority__")
                reservoirs[label_value] = merged

    frames = []
    for label_value in (BinaryLabel.NORMAL, BinaryLabel.ATTACK):
        frame = reservoirs[label_value]
        if frame is None or frame.empty:
            continue
        frames.append(frame.drop(columns="__priority__"))

    if not frames:
        raise ValueError("CIC-IDS-2018 sampling produced zero rows")

    df = pd.concat(frames, ignore_index=True)
    return df.sample(frac=1.0, random_state=42).reset_index(drop=True)


# ---------------------------------------------------------------------------
# CIC-IDS-2018
# ---------------------------------------------------------------------------

def load_cicids2018(data_dir: Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load CIC-IDS-2018 CICFlowMeter CSVs.

    Expects ``data_dir / "cicids2018_csv"`` to contain the day-by-day
    CSV files generated by CICFlowMeter.

    Parameters
    ----------
    data_dir : Path
        Root data directory (e.g. ``backend/data``).
    max_rows : int, optional
        If set, subsample to this many rows (stratified on label).
    """
    csv_dir = Path(data_dir) / "cicids2018_csv"
    if not csv_dir.is_dir():
        raise FileNotFoundError(
            f"Expected CIC-IDS-2018 folder at {csv_dir}. "
            "Download from https://www.unb.ca/cic/datasets/ids-2018.html"
        )

    csv_files = sorted(csv_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {csv_dir}")

    if max_rows:
        logger.info("Loading CIC-IDS-2018 with capped sample of %d rows", max_rows)
        df = _sample_cicids2018(csv_files, max_rows)
    else:
        frames: list[pd.DataFrame] = []
        for csv_path in csv_files:
            try:
                chunk = pd.read_csv(
                    csv_path, encoding="utf-8", skipinitialspace=True,
                    low_memory=False,
                )
            except UnicodeDecodeError:
                chunk = pd.read_csv(
                    csv_path, encoding="latin-1", skipinitialspace=True,
                    low_memory=False,
                )
            except Exception as exc:
                logger.error("Failed to read %s: %s", csv_path, exc)
                continue

            frames.append(_prepare_cicids_chunk(chunk))
            logger.debug("Loaded %d rows from %s", len(chunk), csv_path.name)

        df = pd.concat(frames, ignore_index=True)

    logger.info(
        "CIC-IDS-2018 loaded: %d rows, %d attack / %d normal, %d features",
        len(df),
        (df["binary_label"] == BinaryLabel.ATTACK).sum(),
        (df["binary_label"] == BinaryLabel.NORMAL).sum(),
        len(derive_feature_columns(df)),
    )
    return df


# ---------------------------------------------------------------------------
# UNSW-NB15
# ---------------------------------------------------------------------------

def load_unsw_nb15(data_dir: Path) -> pd.DataFrame:
    """Load UNSW-NB15 training and testing CSVs.

    Expects ``data_dir / "unsw_nb15"`` to contain
    ``UNSW_NB15_training-set.csv`` and/or ``UNSW_NB15_testing-set.csv``.
    """
    unsw_dir = Path(data_dir) / "unsw_nb15"
    expected = [
        "UNSW_NB15_training-set.csv",
        "UNSW_NB15_testing-set.csv",
    ]

    frames: list[pd.DataFrame] = []
    for fname in expected:
        fpath = unsw_dir / fname
        if not fpath.exists():
            logger.warning("UNSW-NB15 file not found, skipping: %s", fpath)
            continue
        try:
            chunk = pd.read_csv(fpath, skipinitialspace=True)
        except Exception as exc:
            logger.error("Failed to read %s: %s", fpath, exc)
            continue
        chunk.columns = [c.strip() for c in chunk.columns]
        frames.append(chunk)

    if not frames:
        raise FileNotFoundError(
            f"No UNSW-NB15 CSV files found in {unsw_dir}"
        )

    df = pd.concat(frames, ignore_index=True)

    # Drop the id column if present
    if "id" in df.columns:
        df = df.drop(columns=["id"])

    # Label
    if "label" in df.columns:
        df["binary_label"] = df["label"].astype(int)
    else:
        df["binary_label"] = BinaryLabel.NORMAL

    # Attack category
    if "attack_cat" in df.columns:
        df["attack_category"] = df["attack_cat"].astype(str).str.strip()
    else:
        df["attack_category"] = df["binary_label"].apply(
            lambda v: "Normal" if v == 0 else "unknown"
        )

    df = _clean(df)

    logger.info(
        "UNSW-NB15 loaded: %d rows, %d attack / %d normal, %d features",
        len(df),
        (df["binary_label"] == BinaryLabel.ATTACK).sum(),
        (df["binary_label"] == BinaryLabel.NORMAL).sum(),
        len(derive_feature_columns(df)),
    )
    return df


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_LOADERS = {
    "cicids2018": load_cicids2018,
    "cic-ids-2018": load_cicids2018,
    "unsw_nb15": load_unsw_nb15,
    "unsw-nb15": load_unsw_nb15,
}


def load_dataset(name: str, data_dir: Path, **kwargs) -> pd.DataFrame:
    """Load a dataset by name."""
    key = name.lower().strip()
    loader = _LOADERS.get(key)
    if loader is None:
        raise ValueError(
            f"Unknown dataset '{name}'. Available: {sorted(_LOADERS.keys())}"
        )
    return loader(Path(data_dir), **kwargs)
