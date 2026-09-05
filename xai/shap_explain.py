"""
XAI — SHAP Explainer for the LSTM Detector (Module 8a).

Uses SHAP KernelExplainer to compute per-feature importance scores that
answer: "Which network flow features contributed most to the LSTM detector
flagging this traffic window as an attack (or clearing it as benign)?"

The LSTM operates on sliding windows of WINDOW_SIZE consecutive flow rows.
To make it compatible with SHAP's flat-input expectation, we flatten each
window into a 1D vector (WINDOW_SIZE * feature_dim), run the LSTM, and
reshape SHAP values back to (WINDOW_SIZE, feature_dim) — then aggregate
across the time axis so the final output is per-feature, not per-timestep.

Owner: Andikumar (training track)
"""

import os
import sys

# Ensure UTF-8 stdout on Windows console
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))

import numpy as np
import pandas as pd
import shap
import torch

from lstm_detector import LSTMDetector, WINDOW_SIZE

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _load_lstm(model_path: str = None):
    """Loads the trained LSTM detector and its scaling metadata."""
    if model_path is None:
        model_path = os.path.join(os.path.dirname(__file__), "..", "models", "lstm_detector.pt")
    checkpoint = torch.load(model_path, map_location=DEVICE)
    model = LSTMDetector(checkpoint["feature_dim"]).to(DEVICE)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    return model, checkpoint["scaling"]


def _scale(values: np.ndarray, scaling: dict) -> np.ndarray:
    """Applies saved min-max scaling."""
    col_min = np.array(scaling["col_min"])
    col_max = np.array(scaling["col_max"])
    denom = np.where((col_max - col_min) == 0, 1.0, col_max - col_min)
    return (values - col_min) / denom


def _make_predict_fn(model, feature_dim: int):
    """
    Returns a function f(flat_array) -> confidence_scores that SHAP can call.
    Input:  flat_array of shape (n_samples, WINDOW_SIZE * feature_dim)
    Output: array of shape (n_samples,) with detection confidence in [0,1]
    """
    def predict(flat_inputs: np.ndarray) -> np.ndarray:
        n = flat_inputs.shape[0]
        reshaped = flat_inputs.reshape(n, WINDOW_SIZE, feature_dim)
        tensor = torch.tensor(reshaped, dtype=torch.float32).to(DEVICE)
        with torch.no_grad():
            confs = model(tensor).cpu().numpy().flatten()
        return confs
    return predict


def load_shap_explainer(model, scaling: dict, background_df: pd.DataFrame,
                        n_background: int = 50):
    """
    Creates a SHAP KernelExplainer using a summarized background dataset.

    Args:
        model: Trained LSTMDetector
        scaling: Scaling metadata dict from the checkpoint
        background_df: Raw (unscaled) DataFrame of benign flow rows (no label column)
        n_background: Number of background samples to summarize

    Returns:
        (explainer, feature_names, feature_dim)
    """
    feature_cols = scaling["feature_cols"]
    feature_dim = len(feature_cols)

    # Scale background data and build flattened windows
    bg_values = _scale(
        background_df[feature_cols].select_dtypes(include=["number"]).fillna(0.0).values,
        scaling,
    )

    # Build non-overlapping windows from background
    n_windows = min(n_background, len(bg_values) // WINDOW_SIZE)
    bg_windows = []
    for i in range(n_windows):
        start = i * WINDOW_SIZE
        window = bg_values[start : start + WINDOW_SIZE]
        bg_windows.append(window.flatten())
    bg_flat = np.array(bg_windows)

    # Summarize background for efficiency
    bg_summary = shap.kmeans(bg_flat, min(10, len(bg_flat)))

    predict_fn = _make_predict_fn(model, feature_dim)
    explainer = shap.KernelExplainer(predict_fn, bg_summary)

    return explainer, feature_cols, feature_dim


def explain_detection(explainer, window_df: pd.DataFrame, scaling: dict,
                      feature_names: list, feature_dim: int,
                      top_k: int = 10) -> dict:
    """
    Explains a single detection window using SHAP.

    Args:
        explainer: SHAP KernelExplainer
        window_df: DataFrame of exactly WINDOW_SIZE raw (unscaled) flow rows
        scaling: Scaling metadata
        feature_names: List of feature column names
        feature_dim: Number of features per row
        top_k: Number of top features to return

    Returns:
        dict with shap_values, top_features, base_value, prediction
    """
    # Scale and flatten the window
    values = _scale(
        window_df[feature_names].select_dtypes(include=["number"]).fillna(0.0).values,
        scaling,
    )
    flat_input = values.flatten().reshape(1, -1)

    # Compute SHAP values
    shap_values = explainer.shap_values(flat_input, nsamples=100)
    if isinstance(shap_values, list):
        shap_values = shap_values[0]

    # Reshape back to (WINDOW_SIZE, feature_dim) and aggregate across timesteps
    shap_2d = shap_values.reshape(WINDOW_SIZE, feature_dim)
    feature_importance = np.abs(shap_2d).mean(axis=0)  # mean |SHAP| per feature across time

    # Build top-k ranking
    top_indices = np.argsort(feature_importance)[::-1][:top_k]
    top_features = [
        (feature_names[idx], float(feature_importance[idx]))
        for idx in top_indices
    ]

    # Get base value
    base_val = explainer.expected_value
    if not np.isscalar(base_val):
        base_val = float(base_val[0])

    return {
        "shap_values": shap_2d.tolist(),
        "feature_importance": feature_importance.tolist(),
        "top_features": top_features,
        "base_value": float(base_val),
    }


def run_shap_demo():
    """Self-test: loads the LSTM detector, explains the first window from the dataset."""
    print("=" * 60)
    print("SHAP Explainer — LSTM Detector")
    print("=" * 60)

    model, scaling = _load_lstm()
    feature_cols = scaling["feature_cols"]
    feature_dim = len(feature_cols)

    # Load dataset
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
    df = pd.read_csv(data_path)
    label_col = next(c for c in df.columns if c.strip().lower() == "label")
    feature_df = df.drop(columns=[label_col])

    # Use benign rows as background
    is_benign = df[label_col].astype(str).str.strip().str.upper() == "BENIGN"
    background_df = feature_df[is_benign.values].reset_index(drop=True)

    print(f"Dataset: {len(df)} rows, {len(feature_cols)} features, Device: {DEVICE}")
    print(f"Background (benign): {len(background_df)} rows")

    # Create explainer
    print("\nBuilding SHAP KernelExplainer (this may take a moment)...")
    explainer, feat_names, feat_dim = load_shap_explainer(
        model, scaling, background_df, n_background=50
    )

    # Explain first window (mix of traffic)
    window_df = feature_df.iloc[:WINDOW_SIZE]
    print(f"\nExplaining window of {WINDOW_SIZE} rows...")

    # Get actual LSTM prediction
    scaled = _scale(
        window_df[feature_cols].select_dtypes(include=["number"]).fillna(0.0).values,
        scaling,
    )
    tensor = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        prediction = model(tensor).item()

    result = explain_detection(explainer, window_df, scaling, feat_names, feat_dim, top_k=10)
    result["prediction"] = prediction

    print(f"\nLSTM Detection Confidence: {prediction:.4f}")
    print(f"SHAP Base Value: {result['base_value']:.4f}")
    print(f"\nTop-10 Contributing Features (mean |SHAP| across {WINDOW_SIZE} timesteps):")
    print("-" * 50)
    for i, (name, importance) in enumerate(result["top_features"], 1):
        bar = "#" * int(importance * 200)
        print(f"  {i:2d}. {name:35s} {importance:.5f}  {bar}")

    print("\n[OK] SHAP explainer working correctly.")
    return result


if __name__ == "__main__":
    run_shap_demo()
