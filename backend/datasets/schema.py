"""
Dataset schema utilities.

Each dataset has its own native feature space.  The evaluation pipeline
discovers usable numeric features at load time rather than mapping to
a shared schema.
"""

from __future__ import annotations

from enum import IntEnum


class BinaryLabel(IntEnum):
    """Binary classification target."""
    NORMAL = 0
    ATTACK = 1


# Columns to drop before deriving the numeric feature list.
# These are labels, IDs, metadata, or text columns that are not features.
LABEL_COLUMNS: set[str] = {
    "label", "Label", "class", "Class", "attack_cat", "attack_category",
    "attack_type", "binary_label", "id", "Timestamp", "timestamp",
    "Flow ID", "Src IP", "Dst IP", "Src Port",
}
