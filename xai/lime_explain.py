"""
XAI — LIME Explainer for the Autoencoder Detector (Module 8b).

Uses LIME (Local Interpretable Model-agnostic Explanations) to explain why
the autoencoder's reconstruction error is high or low for a given flow row.

The autoencoder was trained on BENIGN traffic only — high reconstruction
error means "this row doesn't look like normal traffic." LIME perturbs
individual features of a flow row and observes how the anomaly score changes,
revealing which features are most responsible for the anomaly.

Owner: Andikumar (training track)
"""

import json
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
import torch
from lime.lime_tabular import LimeTabularExplainer

from autoencoder_detector import AutoencoderDetector

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _load_autoencoder(model_path: str = None, threshold_path: str = None):
    """Loads the trained Autoencoder detector, scaling metadata, and anomaly threshold."""
    if model_path is None:
        model_path = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_detector.pt")
    if threshold_path is None:
        threshold_path = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_threshold.json")

    checkpoint = torch.load(model_path, map_location=DEVICE)
    model = AutoencoderDetector(checkpoint["input_dim"]).to(DEVICE)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    with open(threshold_path) as f:
        threshold_data = json.load(f)

    return model, checkpoint["scaling"], threshold_data["threshold"]


def _scale_row(values: np.ndarray, scaling: dict) -> np.ndarray:
    """Applies saved min-max scaling to raw feature values."""
    col_min = np.array(scaling["col_min"])
    col_max = np.array(scaling["col_max"])
    denom = np.where((col_max - col_min) == 0, 1.0, col_max - col_min)
    return (values - col_min) / denom


def _make_anomaly_predict_fn(model, scaling: dict, threshold: float):
    """
    Returns a function f(raw_values) -> anomaly_probabilities for LIME.

    Input:  raw_values of shape (n_samples, n_features) — UNSCALED
    Output: array of shape (n_samples, 2) with [P(normal), P(anomaly)]

    The anomaly probability is derived from reconstruction error normalized
    against the 95th-percentile threshold. Errors above threshold map to
    probabilities > 0.5, errors at 2x threshold saturate at ~1.0.
    """
    def predict(raw_values: np.ndarray) -> np.ndarray:
        scaled = _scale_row(raw_values, scaling)
        tensor = torch.tensor(scaled, dtype=torch.float32).to(DEVICE)
        with torch.no_grad():
            reconstructed = model(tensor)
            per_row_error = ((reconstructed - tensor) ** 2).mean(dim=1).cpu().numpy()

        # Convert MSE to anomaly probability via linear scaling against threshold
        anomaly_scores = np.clip(per_row_error / (2.0 * threshold), 0.0, 1.0)
        normal_scores = 1.0 - anomaly_scores
        return np.column_stack([normal_scores, anomaly_scores])

    return predict


def load_lime_explainer(scaling: dict, training_data: np.ndarray,
                        feature_names: list) -> LimeTabularExplainer:
    """
    Creates a LIME TabularExplainer fitted on training data statistics.

    Args:
        scaling: Scaling metadata from the autoencoder checkpoint
        training_data: Raw (unscaled) feature values used for training statistics
        feature_names: List of feature column names

    Returns:
        LimeTabularExplainer instance
    """
    explainer = LimeTabularExplainer(
        training_data=training_data,
        feature_names=feature_names,
        class_names=["Normal", "Anomaly"],
        mode="classification",
        discretize_continuous=True,
        random_state=42,
    )
    return explainer


def explain_anomaly(explainer: LimeTabularExplainer, row_values: np.ndarray,
                    predict_fn, model, scaling: dict, threshold: float,
                    num_features: int = 10) -> dict:
    """
    Explains why a single flow row was flagged (or not) as anomalous.

    Args:
        explainer: LIME TabularExplainer
        row_values: 1D array of raw (unscaled) feature values for one flow
        predict_fn: The anomaly prediction function for LIME
        model: Trained AutoencoderDetector
        scaling: Scaling metadata
        threshold: Anomaly threshold
        num_features: Number of top features to explain

    Returns:
        dict with explanation_list, anomaly_probability, reconstruction_error, threshold
    """
    # Get LIME explanation
    exp = explainer.explain_instance(
        row_values,
        predict_fn,
        num_features=num_features,
        num_samples=500,
        labels=(1,),  # explain the Anomaly class
    )

    # Compute actual reconstruction error for this row
    scaled = _scale_row(row_values.reshape(1, -1), scaling)
    tensor = torch.tensor(scaled, dtype=torch.float32).to(DEVICE)
    with torch.no_grad():
        reconstructed = model(tensor)
        reconstruction_error = float(((reconstructed - tensor) ** 2).mean().item())

    anomaly_probability = min(reconstruction_error / (2.0 * threshold), 1.0)

    explanation_list = exp.as_list(label=1)

    return {
        "explanation_list": explanation_list,
        "anomaly_probability": anomaly_probability,
        "reconstruction_error": reconstruction_error,
        "threshold": threshold,
        "is_anomaly": reconstruction_error > threshold,
    }


def run_lime_demo():
    """Self-test: loads the autoencoder, explains sample flow rows."""
    print("=" * 60)
    print("LIME Explainer — Autoencoder Anomaly Detector")
    print("=" * 60)

    model, scaling, threshold = _load_autoencoder()
    feature_cols = scaling["feature_cols"]

    # Load dataset
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
    df = pd.read_csv(data_path)
    label_col = next(c for c in df.columns if c.strip().lower() == "label")
    labels = df[label_col].astype(str).str.strip().str.upper()
    feature_df = df[feature_cols].select_dtypes(include=["number"]).fillna(0.0)

    print(f"Dataset: {len(df)} rows, {len(feature_cols)} features, Device: {DEVICE}")
    print(f"Anomaly threshold: {threshold:.5f}")

    # Create LIME explainer with all training data statistics
    training_data = feature_df.values
    explainer = load_lime_explainer(scaling, training_data, feature_cols)

    predict_fn = _make_anomaly_predict_fn(model, scaling, threshold)

    # Explain one benign row and one attack row
    benign_idx = labels[labels == "BENIGN"].index[0]
    attack_idx = labels[labels != "BENIGN"].index[0]

    for label_str, idx in [("BENIGN", benign_idx), ("ATTACK", attack_idx)]:
        row = feature_df.iloc[idx].values
        result = explain_anomaly(explainer, row, predict_fn, model, scaling, threshold)

        print(f"\n--- {label_str} Row (index {idx}) ---")
        print(f"  Reconstruction Error: {result['reconstruction_error']:.6f}")
        print(f"  Anomaly Threshold:    {threshold:.6f}")
        print(f"  Anomaly Probability:  {result['anomaly_probability']:.4f}")
        print(f"  Flagged as Anomaly:   {result['is_anomaly']}")
        print(f"\n  Top-{len(result['explanation_list'])} LIME Feature Contributions (Anomaly class):")
        print("  " + "-" * 55)
        for i, (feature_desc, weight) in enumerate(result["explanation_list"], 1):
            direction = "(+) anomaly" if weight > 0 else "(-) normal"
            print(f"  {i:2d}. {feature_desc:40s} {weight:+.5f}  {direction}")

    print("\n[OK] LIME explainer working correctly.")


if __name__ == "__main__":
    run_lime_demo()
