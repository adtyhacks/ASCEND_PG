"""
Module 6 — sanity check for the trained GAN.

Training completing without crashing doesn't mean the generator learned
anything useful — this script actually looks at what it produces and
compares it against real data, so we're not just trusting a loss number.

Checks for:
1. Mode collapse (generator producing near-identical samples every time)
2. Wildly implausible values (way outside the real data's range)
3. Rough per-column mean/std comparison, real vs synthetic

Note: train_gan.py doesn't currently save the min/max scaling stats to
disk, so this script recomputes them from the same CSV — deterministic,
matches training exactly, but means this script must be run from a machine
that still has data/cic_ids2017_subset.csv available.

Owner: Andikumar (training track, Modules 6-8)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
import torch

from gan import Generator

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
GENERATOR_WEIGHTS = os.path.join(os.path.dirname(__file__), "..", "models", "gan_generator.pt")
NOISE_DIM = 32
N_SAMPLES = 500  # how many synthetic rows to generate for comparison

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_real_data_and_scaler():
    """Reproduces train_gan.py's exact preprocessing so the scaler stats match."""
    df = pd.read_csv(DATA_PATH)
    label_like_cols = [c for c in df.columns if c.lower() in ("label", "attack_type", "flow_id")]
    df = df.drop(columns=label_like_cols, errors="ignore")
    df = df.select_dtypes(include=["number"]).fillna(0.0)

    col_min = df.min()
    col_max = df.max()
    denom = (col_max - col_min).replace(0, 1.0)

    return df, col_min, col_max, denom


def generate_synthetic(feature_dim: int, n: int) -> np.ndarray:
    generator = Generator(NOISE_DIM, feature_dim).to(DEVICE)
    generator.load_state_dict(torch.load(GENERATOR_WEIGHTS, map_location=DEVICE))
    generator.eval()

    with torch.no_grad():
        noise = torch.randn(n, NOISE_DIM, device=DEVICE)
        scaled_output = generator(noise).cpu().numpy()  # in [-1, 1]

    return scaled_output


def main():
    real_df, col_min, col_max, denom = load_real_data_and_scaler()
    feature_dim = real_df.shape[1]

    print(f"Real data: {real_df.shape[0]} rows, {feature_dim} features")
    print(f"Generating {N_SAMPLES} synthetic samples on {DEVICE}...\n")

    scaled_synthetic = generate_synthetic(feature_dim, N_SAMPLES)

    # Inverse the [-1, 1] -> real-value scaling used in training
    unscaled_synthetic = (scaled_synthetic + 1) / 2 * denom.values + col_min.values
    synthetic_df = pd.DataFrame(unscaled_synthetic, columns=real_df.columns)

    # --- Check 1: mode collapse ---
    # If every generated row is nearly identical, std across samples will be ~0
    # even though the real data has real spread.
    synthetic_std_per_col = synthetic_df.std()
    real_std_per_col = real_df.std()
    # Avoid divide-by-zero on constant real columns
    collapse_ratio = synthetic_std_per_col / real_std_per_col.replace(0, np.nan)
    n_collapsed = (collapse_ratio < 0.05).sum()  # synthetic varies <5% as much as real
    print(f"--- Mode collapse check ---")
    print(f"Columns where synthetic variation is <5% of real variation: {n_collapsed} / {feature_dim}")
    if n_collapsed > feature_dim * 0.3:
        print("WARNING: looks like partial mode collapse — generator may be producing near-duplicate rows.")
    else:
        print("Looks OK — generator is producing varied output, not collapsing to a single mode.\n")

    # --- Check 2: implausible values ---
    # Synthetic values shouldn't wildly exceed the real data's observed range
    # (a well-behaved Tanh output shouldn't do this, but worth checking).
    over_max = (synthetic_df > col_max * 1.1).sum().sum()
    under_min = (synthetic_df < col_min * 1.1).sum().sum()
    print(f"--- Range check ---")
    print(f"Synthetic values >10% beyond real max: {over_max} cells")
    print(f"Synthetic values >10% beyond real min: {under_min} cells")
    if over_max + under_min > 0:
        print("Some out-of-range values found — expected occasionally with Tanh output, not necessarily a problem unless the count is large.\n")
    else:
        print("All synthetic values fall within the real data's observed range.\n")

    # --- Check 3: side-by-side comparison on a handful of columns ---
    print("--- Real vs synthetic: mean (std) for first 8 columns ---")
    for col in real_df.columns[:8]:
        real_mean, real_std = real_df[col].mean(), real_df[col].std()
        syn_mean, syn_std = synthetic_df[col].mean(), synthetic_df[col].std()
        print(f"{col:35s} real: {real_mean:12.2f} ({real_std:10.2f})   synthetic: {syn_mean:12.2f} ({syn_std:10.2f})")


if __name__ == "__main__":
    main()
