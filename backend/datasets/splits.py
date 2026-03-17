"""
Train / validation / test splitting strategies.

Provides three splitting approaches suited to intrusion detection evaluation:

- **time_based_split**: preserves temporal ordering (prevents future-leak).
- **scenario_split**: holds out entire attack classes to test generalisation
  to unseen threat types.
- **stratified_split**: classic stratified random split with a separate
  validation set.

Every function returns a consistent 6-tuple
``(X_train, y_train, X_val, y_val, X_test, y_test)`` of NumPy arrays.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .schema import UNIFIED_FEATURES

logger = logging.getLogger(__name__)

SplitResult = Tuple[
    np.ndarray, np.ndarray,  # X_train, y_train
    np.ndarray, np.ndarray,  # X_val,   y_val
    np.ndarray, np.ndarray,  # X_test,  y_test
]


@dataclass
class SplitMetadata:
    """Descriptive record of how a dataset was partitioned."""

    split_type: str
    train_size: int
    val_size: int
    test_size: int
    train_class_distribution: Dict[int, int] = field(default_factory=dict)
    val_class_distribution: Dict[int, int] = field(default_factory=dict)
    test_class_distribution: Dict[int, int] = field(default_factory=dict)
    random_state: int | None = None
    held_out_classes: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.train_size + self.val_size + self.test_size


def _class_dist(y: np.ndarray) -> Dict[int, int]:
    """Return {label: count} for a 1-D label array."""
    unique, counts = np.unique(y, return_counts=True)
    return {int(u): int(c) for u, c in zip(unique, counts)}


def _extract_xy(
    df: pd.DataFrame, label_col: str
) -> Tuple[np.ndarray, np.ndarray]:
    """Pull feature matrix and label vector from a DataFrame.

    Uses only columns present in UNIFIED_FEATURES (and that exist in *df*)
    for the feature matrix.
    """
    feature_cols = [c for c in UNIFIED_FEATURES if c in df.columns]
    # Coerce everything to float; non-numeric columns become NaN -> 0.
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0).values.astype(np.float32)
    y = df[label_col].values.astype(np.int64)
    return X, y


# ---------------------------------------------------------------------------
# 1.  Time-based split
# ---------------------------------------------------------------------------

def time_based_split(
    df: pd.DataFrame,
    time_col: str,
    label_col: str = "binary_label",
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> Tuple[SplitResult, SplitMetadata]:
    """Split by temporal ordering of *time_col*.

    The first *train_ratio* rows (by time) go to training, the next
    *val_ratio* to validation, and the remainder to test.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain *time_col* and *label_col*.
    time_col : str
        Column used for sorting (timestamp, flow ID, etc.).
    label_col : str
        Column with integer labels.
    train_ratio, val_ratio : float
        Proportions for train and validation; test gets the rest.

    Returns
    -------
    (SplitResult, SplitMetadata)
    """
    if time_col not in df.columns:
        raise KeyError(f"Time column '{time_col}' not found in DataFrame")

    df_sorted = df.sort_values(time_col).reset_index(drop=True)
    n = len(df_sorted)
    train_end = int(n * train_ratio)
    val_end = train_end + int(n * val_ratio)

    train_df = df_sorted.iloc[:train_end]
    val_df = df_sorted.iloc[train_end:val_end]
    test_df = df_sorted.iloc[val_end:]

    X_train, y_train = _extract_xy(train_df, label_col)
    X_val, y_val = _extract_xy(val_df, label_col)
    X_test, y_test = _extract_xy(test_df, label_col)

    meta = SplitMetadata(
        split_type="time_based",
        train_size=len(y_train),
        val_size=len(y_val),
        test_size=len(y_test),
        train_class_distribution=_class_dist(y_train),
        val_class_distribution=_class_dist(y_val),
        test_class_distribution=_class_dist(y_test),
    )

    logger.info(
        "Time-based split: train=%d  val=%d  test=%d",
        meta.train_size, meta.val_size, meta.test_size,
    )
    return (X_train, y_train, X_val, y_val, X_test, y_test), meta


# ---------------------------------------------------------------------------
# 2.  Scenario split (hold-out attack classes)
# ---------------------------------------------------------------------------

def scenario_split(
    df: pd.DataFrame,
    label_col: str = "binary_label",
    held_out_classes: Sequence[str] = (),
    category_col: str = "attack_category",
    val_ratio: float = 0.15,
    random_state: int = 42,
) -> Tuple[SplitResult, SplitMetadata]:
    """Hold out specific attack types entirely for testing.

    Rows whose *category_col* value is in *held_out_classes* go to the test
    set.  The remaining data is split into train/val using stratified
    sampling.

    Parameters
    ----------
    df : pd.DataFrame
    label_col : str
        Integer label column.
    held_out_classes : sequence of str
        Attack categories to reserve for the test set.
    category_col : str
        Column containing the attack-category strings.
    val_ratio : float
        Fraction of the *non-held-out* data to use for validation.
    random_state : int
        Seed for the train/val split.

    Returns
    -------
    (SplitResult, SplitMetadata)
    """
    if category_col not in df.columns:
        raise KeyError(f"Category column '{category_col}' not found in DataFrame")

    held_out = set(held_out_classes)
    mask_test = df[category_col].isin(held_out)
    test_df = df[mask_test]
    remaining = df[~mask_test]

    if remaining.empty:
        raise ValueError("All data matched held_out_classes; nothing left for training")

    # Stratified train/val from the remaining data.
    train_df, val_df = train_test_split(
        remaining,
        test_size=val_ratio,
        stratify=remaining[label_col],
        random_state=random_state,
    )

    X_train, y_train = _extract_xy(train_df, label_col)
    X_val, y_val = _extract_xy(val_df, label_col)
    X_test, y_test = _extract_xy(test_df, label_col)

    meta = SplitMetadata(
        split_type="scenario",
        train_size=len(y_train),
        val_size=len(y_val),
        test_size=len(y_test),
        train_class_distribution=_class_dist(y_train),
        val_class_distribution=_class_dist(y_val),
        test_class_distribution=_class_dist(y_test),
        random_state=random_state,
        held_out_classes=list(held_out_classes),
    )

    logger.info(
        "Scenario split (held-out %s): train=%d  val=%d  test=%d",
        held_out_classes, meta.train_size, meta.val_size, meta.test_size,
    )
    return (X_train, y_train, X_val, y_val, X_test, y_test), meta


# ---------------------------------------------------------------------------
# 3.  Stratified random split
# ---------------------------------------------------------------------------

def stratified_split(
    df: pd.DataFrame,
    label_col: str = "binary_label",
    test_size: float = 0.2,
    val_size: float = 0.15,
    random_state: int = 42,
) -> Tuple[SplitResult, SplitMetadata]:
    """Stratified random split into train / val / test.

    Two successive stratified splits are performed: first train+val vs test,
    then train vs val.

    Parameters
    ----------
    df : pd.DataFrame
    label_col : str
        Integer label column for stratification.
    test_size, val_size : float
        Fractions of the full dataset.
    random_state : int
        Seed for reproducibility.

    Returns
    -------
    (SplitResult, SplitMetadata)
    """
    trainval_df, test_df = train_test_split(
        df,
        test_size=test_size,
        stratify=df[label_col],
        random_state=random_state,
    )

    # val_size is relative to the original dataset, so scale it relative to
    # the trainval subset.
    relative_val = val_size / (1.0 - test_size)
    train_df, val_df = train_test_split(
        trainval_df,
        test_size=relative_val,
        stratify=trainval_df[label_col],
        random_state=random_state,
    )

    X_train, y_train = _extract_xy(train_df, label_col)
    X_val, y_val = _extract_xy(val_df, label_col)
    X_test, y_test = _extract_xy(test_df, label_col)

    meta = SplitMetadata(
        split_type="stratified",
        train_size=len(y_train),
        val_size=len(y_val),
        test_size=len(y_test),
        train_class_distribution=_class_dist(y_train),
        val_class_distribution=_class_dist(y_val),
        test_class_distribution=_class_dist(y_test),
        random_state=random_state,
    )

    logger.info(
        "Stratified split: train=%d  val=%d  test=%d",
        meta.train_size, meta.val_size, meta.test_size,
    )
    return (X_train, y_train, X_val, y_val, X_test, y_test), meta
