"""
Module 8c — Fusion layer.

Combines the LSTM detector's confidence (supervised — good at recognizing
attack patterns it's seen before) with the Autoencoder's anomaly score
(unsupervised — good at flagging traffic that just looks "off," even if
it's never seen that exact attack type). A weighted average of the two
should catch more than either alone.

Usage: load_detectors() once, then call fuse_score(window_df) per window
of WINDOW_SIZE consecutive raw flow rows (same columns as training data,
minus the label column) to get a single combined confidence in [0, 1].

This is also the function strategic/rl_env.py's real_mode will eventually
call instead of the mock detection probabilities — see that file's docstring.

Owner: Andikumar (training track, Modules 6-8)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
import torch

from lstm_detector import LSTMDetector, WINDOW_SIZE
from autoencoder_detector import AutoencoderDetector

LSTM_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "lstm_detector.pt")
AE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_detector.pt")
AE_THRESHOLD_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_threshold.json")

# Fusion weights — simple weighted average per the Session 10 plan.
# Equal weighting as a starting point; tune later once real-world false
# positive/negative rates are known (e.g. from Abinraj's real captured data).
LSTM_WEIGHT = 0.5
AE_WEIGHT = 0.5

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _scale(df: pd.DataFrame, scaling: dict) -> np.ndarray:
    """Applies a saved [0,1] min-max scaling to new raw data, matching training-time scaling exactly."""
    feature_cols = scaling["feature_cols"]
    col_min = np.array(scaling["col_min"])
    col_max = np.array(scaling["col_max"])
    denom = np.where((col_max - col_min) == 0, 1.0, col_max - col_min)

    values = df[feature_cols].select_dtypes(include=["number"]).fillna(0.0).values
    return (values - col_min) / denom


def load_detectors():
    """Loads both trained models + the autoencoder's anomaly threshold. Call this once, reuse the result."""
    if not (os.path.exists(LSTM_PATH) and os.path.exists(AE_PATH) and os.path.exists(AE_THRESHOLD_PATH)):
        raise FileNotFoundError(
            "Missing one or more trained detector files. Run lstm_detector.py and "
            "autoencoder_detector.py first (in that order doesn't matter, both are independent)."
        )

    lstm_checkpoint = torch.load(LSTM_PATH, map_location=DEVICE)
    lstm_model = LSTMDetector(lstm_checkpoint["feature_dim"]).to(DEVICE)
    lstm_model.load_state_dict(lstm_checkpoint["state_dict"])
    lstm_model.eval()

    ae_checkpoint = torch.load(AE_PATH, map_location=DEVICE)
    ae_model = AutoencoderDetector(ae_checkpoint["input_dim"]).to(DEVICE)
    ae_model.load_state_dict(ae_checkpoint["state_dict"])
    ae_model.eval()

    with open(AE_THRESHOLD_PATH) as f:
        ae_threshold = json.load(f)["threshold"]

    return {
        "lstm_model": lstm_model,
        "lstm_scaling": lstm_checkpoint["scaling"],
        "ae_model": ae_model,
        "ae_scaling": ae_checkpoint["scaling"],
        "ae_threshold": ae_threshold,
    }


def fuse_score(window_df: pd.DataFrame, detectors: dict) -> dict:
    """
    window_df: a DataFrame of exactly WINDOW_SIZE raw flow rows (no label column).
    Returns a dict with the individual scores and the fused confidence.
    """
    if len(window_df) != WINDOW_SIZE:
        raise ValueError(f"Expected exactly {WINDOW_SIZE} rows, got {len(window_df)}")

    # --- LSTM score (one score for the whole window) ---
    lstm_scaled = _scale(window_df, detectors["lstm_scaling"])
    lstm_input = torch.tensor(lstm_scaled, dtype=torch.float32).unsqueeze(0).to(DEVICE)  # (1, WINDOW_SIZE, features)
    with torch.no_grad():
        lstm_confidence = detectors["lstm_model"](lstm_input).item()

    # --- Autoencoder score (per-row reconstruction error, take the max across the window —
    #     one badly-reconstructed row should be enough to raise suspicion) ---
    ae_scaled = _scale(window_df, detectors["ae_scaling"])
    ae_input = torch.tensor(ae_scaled, dtype=torch.float32).to(DEVICE)
    with torch.no_grad():
        reconstructed = detectors["ae_model"](ae_input)
        per_row_error = ((reconstructed - ae_input) ** 2).mean(dim=1).cpu().numpy()
    max_error = float(per_row_error.max())
    # Normalize against the threshold so it's roughly comparable in scale to lstm_confidence
    ae_anomaly_score = min(max_error / detectors["ae_threshold"], 2.0) / 2.0  # cap at 1.0

    fused = LSTM_WEIGHT * lstm_confidence + AE_WEIGHT * ae_anomaly_score

    return {
        "lstm_confidence": lstm_confidence,
        "ae_anomaly_score": ae_anomaly_score,
        "ae_max_reconstruction_error": max_error,
        "fused_confidence": fused,
    }


if __name__ == "__main__":
    # Quick manual test: run fusion on the first window of the training data itself.
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
    df = pd.read_csv(data_path)
    label_col = next(c for c in df.columns if c.strip().lower() == "label")
    feature_df = df.drop(columns=[label_col])

    detectors = load_detectors()
    result = fuse_score(feature_df.iloc[:WINDOW_SIZE], detectors)
    print("Fusion result on first window of training data:")
    for k, v in result.items():
        print(f"  {k}: {v:.4f}")
