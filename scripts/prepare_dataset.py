"""
scripts/prepare_dataset.py — downloads CIC-IDS-2017 and produces
data/cic_ids2017_subset.csv, the placeholder dataset Module 6/7/8 train against
until Abinraj's real captured_flows data is ready.

ONE-TIME SETUP (do this before running, see the setup guide for full steps):
1. Create a free Kaggle account: https://www.kaggle.com
2. Go to kaggle.com -> your profile picture -> Settings -> API -> "Create New Token"
   This downloads a file called kaggle.json
3. Move that file to: C:\\Users\\<your-username>\\.kaggle\\kaggle.json
   (create the .kaggle folder if it doesn't exist)
4. pip install kaggle pandas numpy

Owner: Andikumar (training track, Modules 6-8)
"""

import glob
import os

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
KAGGLE_DATASET = "chethuhn/network-intrusion-dataset"  # standard CIC-IDS-2017 mirror, matches our lit review citation
RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
SUBSET_SIZE = 10000  # total rows in the final subset — plenty for validating the training pipeline
LABEL_COL_CANDIDATES = ["Label", " Label"]  # this dataset's CSVs are known to have a leading space in some headers


def download_dataset():
    """Downloads and unzips the dataset via the Kaggle CLI (requires kaggle.json set up — see module docstring)."""
    os.makedirs(RAW_DIR, exist_ok=True)
    already_downloaded = glob.glob(os.path.join(RAW_DIR, "*.csv"))
    if already_downloaded:
        print(f"Found {len(already_downloaded)} CSV(s) already in {RAW_DIR}, skipping download.")
        return

    print(f"Downloading {KAGGLE_DATASET} from Kaggle (this is a few hundred MB, may take a while)...")
    exit_code = os.system(f'kaggle datasets download -d {KAGGLE_DATASET} -p "{RAW_DIR}" --unzip')
    if exit_code != 0:
        raise RuntimeError(
            "Kaggle download failed. Most common cause: kaggle.json isn't set up correctly. "
            "See the setup instructions at the top of this file."
        )


def load_and_merge() -> pd.DataFrame:
    """
    This dataset ships as one CSV per capture day (Monday, Tuesday-WorkingHours,
    Wednesday-WorkingHours, etc.) — merge them all into one DataFrame.
    """
    csv_files = glob.glob(os.path.join(RAW_DIR, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR} — did the download step run?")

    print(f"Merging {len(csv_files)} CSV file(s)...")
    frames = []
    for path in csv_files:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()  # this dataset has inconsistent leading/trailing spaces in headers
        frames.append(df)

    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Standard cleanup: infinities -> NaN -> dropped, duplicate rows removed."""
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    df = df.drop_duplicates()
    print(f"Cleaned: {before} -> {len(df)} rows (dropped NaN/inf rows and duplicates)")
    return df


def stratified_sample(df: pd.DataFrame, label_col: str, total_size: int) -> pd.DataFrame:
    """
    Samples rows so the subset keeps the same proportion of each label
    (BENIGN, DoS Hulk, PortScan, etc.) as the full dataset — important so
    the GAN doesn't just learn to generate the majority class.
    """
    fraction = total_size / len(df)
    sampled = df.groupby(label_col, group_keys=False).apply(
        lambda g: g.sample(frac=fraction, random_state=42)
    )
    print(f"Sampled {len(sampled)} rows across {sampled[label_col].nunique()} label classes:")
    print(sampled[label_col].value_counts())
    return sampled.reset_index(drop=True)


def find_label_col(df: pd.DataFrame) -> str:
    for candidate in LABEL_COL_CANDIDATES:
        if candidate in df.columns:
            return candidate
    # Fallback: any column literally named "label" case-insensitively
    for col in df.columns:
        if col.lower() == "label":
            return col
    raise KeyError(f"Couldn't find a label column. Available columns: {list(df.columns)}")


def main():
    download_dataset()
    df = load_and_merge()
    df = clean(df)

    label_col = find_label_col(df)
    subset = stratified_sample(df, label_col, SUBSET_SIZE)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    subset.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved {len(subset)} rows, {subset.shape[1]} columns to {OUTPUT_PATH}")
    print("You're unblocked — generative/train_gan.py can now run.")


if __name__ == "__main__":
    main()