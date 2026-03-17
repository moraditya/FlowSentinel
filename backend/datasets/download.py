"""
Dataset download helpers.

Supports two download methods:
1. Kaggle CLI (recommended) — reliable, handles auth automatically
2. Direct HTTP — fallback, but upstream mirrors are often unreliable

Setup for Kaggle CLI:
    pip install kaggle
    # Go to kaggle.com/settings -> API -> Create New Token
    # Save kaggle.json to ~/.kaggle/kaggle.json
    chmod 600 ~/.kaggle/kaggle.json

Usage::

    python -m datasets.download --dataset cicids2017 --dest ./data/cicids2017
    python -m datasets.download --dataset unsw_nb15  --dest ./data/unsw_nb15
    python -m datasets.download --dataset all         --dest ./data
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Kaggle dataset identifiers
KAGGLE_DATASETS = {
    "cicids2017": "cicdataset/cicids2017",
    "unsw_nb15": "mrwellsdavid/unsw-nb15",
}


def _has_kaggle() -> bool:
    """Check if kaggle CLI is available and configured."""
    return shutil.which("kaggle") is not None


def _kaggle_download(dataset_slug: str, dest_dir: Path) -> bool:
    """Download a dataset using the Kaggle CLI."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [
                "kaggle", "datasets", "download",
                "-d", dataset_slug,
                "-p", str(dest_dir),
                "--unzip",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            logger.info("Downloaded %s to %s", dataset_slug, dest_dir)
            return True
        else:
            logger.error("Kaggle download failed: %s", result.stderr.strip())
            return False
    except FileNotFoundError:
        logger.error("kaggle CLI not found. Install: pip install kaggle")
        return False
    except subprocess.TimeoutExpired:
        logger.error("Download timed out after 10 minutes")
        return False


def download_cicids2017(dest_dir: str | Path) -> None:
    """Download CICIDS-2017 dataset.

    Tries Kaggle CLI first (cicdataset/cicids2017), falls back to
    manual download instructions.
    """
    dest = Path(dest_dir)

    if _has_kaggle():
        logger.info("Downloading CICIDS-2017 via Kaggle CLI...")
        if _kaggle_download(KAGGLE_DATASETS["cicids2017"], dest):
            return

    # Manual instructions
    print("\n" + "=" * 60)
    print("MANUAL DOWNLOAD REQUIRED: CICIDS-2017")
    print("=" * 60)
    print()
    print("Option 1 (Kaggle):")
    print("  pip install kaggle")
    print("  # Get API token from kaggle.com/settings -> API -> Create New Token")
    print(f"  kaggle datasets download -d cicdataset/cicids2017 -p {dest} --unzip")
    print()
    print("Option 2 (Direct):")
    print("  Visit: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("  Download MachineLearningCSV.zip")
    print(f"  Extract the MachineLearningCVE/ folder into {dest}/")
    print()


def download_unsw_nb15(dest_dir: str | Path) -> None:
    """Download UNSW-NB15 dataset.

    Tries Kaggle CLI first (mrwellsdavid/unsw-nb15), falls back to
    manual download instructions.
    """
    dest = Path(dest_dir)

    if _has_kaggle():
        logger.info("Downloading UNSW-NB15 via Kaggle CLI...")
        if _kaggle_download(KAGGLE_DATASETS["unsw_nb15"], dest):
            return

    # Manual instructions
    print("\n" + "=" * 60)
    print("MANUAL DOWNLOAD REQUIRED: UNSW-NB15")
    print("=" * 60)
    print()
    print("Option 1 (Kaggle):")
    print("  pip install kaggle")
    print("  # Get API token from kaggle.com/settings -> API -> Create New Token")
    print(f"  kaggle datasets download -d mrwellsdavid/unsw-nb15 -p {dest} --unzip")
    print()
    print("Option 2 (Direct):")
    print("  Visit: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
    print(f"  Download UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv into {dest}/")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download network intrusion detection datasets."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        choices=["cicids2017", "unsw_nb15", "all"],
        help="Dataset to download.",
    )
    parser.add_argument(
        "--dest",
        required=True,
        type=Path,
        help="Destination directory.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )

    if args.dataset in ("cicids2017", "all"):
        dest = args.dest / "cicids2017" if args.dataset == "all" else args.dest
        download_cicids2017(dest)

    if args.dataset in ("unsw_nb15", "all"):
        dest = args.dest / "unsw_nb15" if args.dataset == "all" else args.dest
        download_unsw_nb15(dest)


if __name__ == "__main__":
    main()
