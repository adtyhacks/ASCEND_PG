"""
Module 8b — Autoencoder detector.

Different philosophy from the LSTM detector: trains ONLY on BENIGN rows,
learns to reconstruct normal traffic well. At inference time, anything that
reconstructs poorly (high error) is flagged as anomalous — this catches
attack patterns the model has never seen before, which a supervised
classifier (like the LSTM) can't do since it only knows the attack types
it was trained on.

Owner: Andikumar (training track, Modules 6-8)
"""

import json
import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_detector.pt")
THRESHOLD_SAVE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "autoencoder_threshold.json")

BATCH_SIZE = 32
EPOCHS = 30
LR = 1e-3
THRESHOLD_PERCENTILE = 95  # flag the worst 5% of benign reconstruction errors as the anomaly cutoff

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class AutoencoderDetector(nn.Module):
    """Small bottleneck autoencoder: input_dim -> 32 -> 8 -> 32 -> input_dim."""

    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def find_label_col(df: pd.DataFrame) -> str:
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    raise KeyError(f"No label column found. Columns: {list(df.columns)}")


def load_benign_features(df: pd.DataFrame, label_col: str):
    feature_cols = [c for c in df.columns if c != label_col]
    features = df[feature_cols].select_dtypes(include=["number"]).fillna(0.0)

    col_min, col_max = features.min(), features.max()
    denom = (col_max - col_min).replace(0, 1.0)
    scaled = (features - col_min) / denom

    is_benign = df[label_col].astype(str).str.strip().str.upper() == "BENIGN"
    benign_only = scaled[is_benign.values]
    scaling = {"col_min": col_min.values.tolist(), "col_max": col_max.values.tolist(), "feature_cols": list(features.columns)}
    return torch.tensor(benign_only.values, dtype=torch.float32), features.shape[1], scaling


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Expected data at {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    label_col = find_label_col(df)
    X_benign, input_dim, scaling = load_benign_features(df, label_col)
    print(f"Training on {len(X_benign)} BENIGN rows, {input_dim} features. Device: {DEVICE}")

    if len(X_benign) < BATCH_SIZE:
        raise ValueError(
            f"Only {len(X_benign)} BENIGN rows available — too few to train on. "
            f"Check the dataset's label distribution or lower BATCH_SIZE."
        )

    dataset = TensorDataset(X_benign)
    loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    model = AutoencoderDetector(input_dim).to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.MSELoss()

    for epoch in range(1, EPOCHS + 1):
        total_loss = 0.0
        for (xb,) in loader:
            xb = xb.to(DEVICE)
            optimizer.zero_grad()
            reconstructed = model(xb)
            loss = criterion(reconstructed, xb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(xb)

        if epoch % 5 == 0 or epoch == 1:
            print(f"Epoch {epoch:3d}/{EPOCHS} | reconstruction MSE: {total_loss/len(X_benign):.5f}")

    # Compute the anomaly threshold from benign reconstruction errors (95th percentile)
    model.eval()
    with torch.no_grad():
        reconstructed = model(X_benign.to(DEVICE))
        per_row_error = ((reconstructed - X_benign.to(DEVICE)) ** 2).mean(dim=1).cpu().numpy()
    threshold = float(np.percentile(per_row_error, THRESHOLD_PERCENTILE))
    print(f"Anomaly threshold ({THRESHOLD_PERCENTILE}th percentile of benign errors): {threshold:.5f}")

    os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "input_dim": input_dim, "scaling": scaling}, MODEL_SAVE_PATH)
    with open(THRESHOLD_SAVE_PATH, "w") as f:
        json.dump({"threshold": threshold, "percentile": THRESHOLD_PERCENTILE}, f)
    print(f"Saved autoencoder to {MODEL_SAVE_PATH} and threshold to {THRESHOLD_SAVE_PATH}")


if __name__ == "__main__":
    train()
