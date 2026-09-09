"""
defense/ml_detector.py

Wraps the trained LSTM + Autoencoder detectors for live inference
on Mininet traffic features.
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "detection"))

from lstm_detector import LSTMDetector, WINDOW_SIZE
from autoencoder_detector import AutoencoderDetector

LSTM_PATH = REPO_ROOT / "models" / "lstm_detector.pt"
AE_PATH = REPO_ROOT / "models" / "autoencoder_detector.pt"
AE_THRESHOLD_PATH = REPO_ROOT / "models" / "autoencoder_threshold.json"

LSTM_WEIGHT = 0.5
AE_WEIGHT = 0.5
ML_CONFIDENCE_THRESHOLD = 0.50

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _scale(df: pd.DataFrame, scaling: dict) -> np.ndarray:
    feature_cols = scaling["feature_cols"]
    col_min = np.array(scaling["col_min"])
    col_max = np.array(scaling["col_max"])
    denom = np.where((col_max - col_min) == 0, 1.0, col_max - col_min)
    # Ensure all feature columns exist and are numeric
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0.0
    values = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
    if values.shape[1] != len(col_min):
        raise ValueError(
            f"Feature count mismatch: expected {len(col_min)}, got {values.shape[1]}. "
            f"Missing columns: {[c for c in feature_cols if c not in df.columns]}"
        )
    return (values - col_min) / denom


class MLDetector:
    """Load trained LSTM + AE and run fusion scoring on live flow windows."""

    def __init__(self):
        self._loaded = False
        self._detectors = None

    def load(self):
        if not (LSTM_PATH.exists() and AE_PATH.exists() and AE_THRESHOLD_PATH.exists()):
            raise FileNotFoundError(
                f"Missing model files. Need: {LSTM_PATH}, {AE_PATH}, {AE_THRESHOLD_PATH}"
            )

        lstm_ckpt = torch.load(LSTM_PATH, map_location=DEVICE)
        lstm_model = LSTMDetector(lstm_ckpt["feature_dim"]).to(DEVICE)
        lstm_model.load_state_dict(lstm_ckpt["state_dict"])
        lstm_model.eval()

        ae_ckpt = torch.load(AE_PATH, map_location=DEVICE)
        ae_model = AutoencoderDetector(ae_ckpt["input_dim"]).to(DEVICE)
        ae_model.load_state_dict(ae_ckpt["state_dict"])
        ae_model.eval()

        with open(AE_THRESHOLD_PATH) as f:
            ae_threshold = json.load(f)["threshold"]

        self._detectors = {
            "lstm_model": lstm_model,
            "lstm_scaling": lstm_ckpt["scaling"],
            "ae_model": ae_model,
            "ae_scaling": ae_ckpt["scaling"],
            "ae_threshold": ae_threshold,
        }
        self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded

    def predict(self, window_df: pd.DataFrame) -> dict:
        if not self._loaded:
            return {
                "lstm_confidence": 0.0,
                "ae_anomaly_score": 0.0,
                "ae_max_reconstruction_error": 0.0,
                "fused_confidence": 0.0,
                "detected": False,
                "available": False,
                "error": "ML models not loaded",
            }

        if len(window_df) != WINDOW_SIZE:
            return {
                "lstm_confidence": 0.0,
                "ae_anomaly_score": 0.0,
                "ae_max_reconstruction_error": 0.0,
                "fused_confidence": 0.0,
                "detected": False,
                "available": False,
                "error": f"Window size mismatch: expected {WINDOW_SIZE}, got {len(window_df)}",
            }

        try:
            det = self._detectors

            lstm_scaled = _scale(window_df, det["lstm_scaling"])
            lstm_input = torch.tensor(lstm_scaled, dtype=torch.float32).unsqueeze(0).to(DEVICE)
            with torch.no_grad():
                lstm_conf = det["lstm_model"](lstm_input).item()

            ae_scaled = _scale(window_df, det["ae_scaling"])
            ae_input = torch.tensor(ae_scaled, dtype=torch.float32).to(DEVICE)
            with torch.no_grad():
                reconstructed = det["ae_model"](ae_input)
            per_row_error = ((reconstructed - ae_input) ** 2).mean(dim=1).cpu().numpy()
            max_error = float(per_row_error.max())
            ae_score = min(max_error / det["ae_threshold"], 2.0) / 2.0

            fused = LSTM_WEIGHT * lstm_conf + AE_WEIGHT * ae_score
            detected = fused > ML_CONFIDENCE_THRESHOLD

            return {
                "lstm_confidence": lstm_conf,
                "ae_anomaly_score": ae_score,
                "ae_max_reconstruction_error": max_error,
                "fused_confidence": fused,
                "detected": detected,
                "available": True,
            }

        except Exception as e:
            return {
                "lstm_confidence": 0.0,
                "ae_anomaly_score": 0.0,
                "ae_max_reconstruction_error": 0.0,
                "fused_confidence": 0.0,
                "detected": False,
                "available": False,
                "error": str(e),
            }
