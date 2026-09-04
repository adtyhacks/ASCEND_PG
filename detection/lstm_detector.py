"""
Module 8a — LSTM detector.

Detects attacks by looking at a SEQUENCE of consecutive flow rows (a "window"),
not just one row in isolation — the idea is that attacks like DoS or PortScan
show up as a pattern across several flows, not a single flow's features alone.

DATA NOTE: the placeholder CIC-IDS-2017 subset isn't naturally time-ordered
per-connection (it's a stratified sample, not a raw capture), so "sequence"
here just means consecutive rows in the CSV — a reasonable stand-in for now.
Once Abinraj's real captured_flows.csv exists (genuinely time-ordered, single
network), repoint DATA_PATH below and this will produce much more meaningful
sequences with no other code changes needed.

Owner: kumar (training track, Modules 6-8)
"""

import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv")
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "lstm_detector.pt")

WINDOW_SIZE = 10   # rows per sequence
HIDDEN_SIZE = 64   # small, per the Session 10 plan (64-128 range)
BATCH_SIZE = 32
EPOCHS = 15
LR = 1e-3

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class LSTMDetector(nn.Module):
    """
    Input: a window of WINDOW_SIZE consecutive flow rows.
    Output: a single confidence score in [0, 1] — probability the window
    contains attack traffic.
    """

    def __init__(self, feature_dim: int, hidden_size: int = HIDDEN_SIZE, num_layers: int = 1):
        super().__init__()
        self.lstm = nn.LSTM(input_size=feature_dim, hidden_size=hidden_size, num_layers=num_layers, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, WINDOW_SIZE, feature_dim)
        _, (h_n, _) = self.lstm(x)
        last_hidden = h_n[-1]  # (batch, hidden_size) — final layer's hidden state
        return self.classifier(last_hidden)


def find_label_col(df: pd.DataFrame) -> str:
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    raise KeyError(f"No label column found. Columns: {list(df.columns)}")


def compute_scaling(df: pd.DataFrame, label_col: str) -> dict:
    """Fits min-max scaling on the given data only — call this on the TRAIN split only, never on test."""
    feature_cols = [c for c in df.columns if c != label_col]
    features = df[feature_cols].select_dtypes(include=["number"]).fillna(0.0)
    col_min, col_max = features.min(), features.max()
    return {"col_min": col_min.values.tolist(), "col_max": col_max.values.tolist(), "feature_cols": list(features.columns)}


def build_windows(df: pd.DataFrame, label_col: str, scaling: dict):
    """
    Slices the (row-ordered) dataframe into overlapping windows of WINDOW_SIZE
    rows. A window's label is 1 (attack) if ANY row inside it is non-BENIGN,
    0 (benign) otherwise — reasonable choice since a single attack flow inside
    an otherwise-quiet window should still trigger detection.

    Applies the given (pre-fit) scaling rather than fitting its own — this
    lets the same scaler be reused for both train and test splits, which is
    the correct way to avoid test-set information leaking into preprocessing.
    """
    feature_cols = scaling["feature_cols"]
    features = df[feature_cols].select_dtypes(include=["number"]).fillna(0.0)

    col_min = np.array(scaling["col_min"])
    col_max = np.array(scaling["col_max"])
    denom = np.where((col_max - col_min) == 0, 1.0, col_max - col_min)
    scaled_values = (features.values - col_min) / denom

    is_attack = (df[label_col].astype(str).str.strip().str.upper() != "BENIGN").astype(int).values

    windows, window_labels = [], []
    for start in range(0, len(scaled_values) - WINDOW_SIZE + 1):
        window = scaled_values[start : start + WINDOW_SIZE]
        label = int(is_attack[start : start + WINDOW_SIZE].any())
        windows.append(window)
        window_labels.append(label)

    X = torch.tensor(np.array(windows), dtype=torch.float32)
    y = torch.tensor(np.array(window_labels), dtype=torch.float32).unsqueeze(1)
    return X, y


def evaluate(model, X, y) -> dict:
    """
    Honest evaluation on held-out data — reports precision/recall/F1 alongside
    accuracy, since attack windows are the minority class (~17% in this
    dataset) and accuracy alone can look artificially high on imbalanced data
    (a model that always predicts "benign" would already score ~83%).
    """
    model.eval()
    with torch.no_grad():
        preds = (model(X.to(DEVICE)) > 0.5).float().cpu()

    y = y.cpu()
    tp = ((preds == 1) & (y == 1)).sum().item()
    fp = ((preds == 1) & (y == 0)).sum().item()
    fn = ((preds == 0) & (y == 1)).sum().item()
    tn = ((preds == 0) & (y == 0)).sum().item()

    accuracy = (tp + tn) / len(y)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    model.train()
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Expected data at {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    label_col = find_label_col(df)

    # Temporal split, NOT a random shuffle: windows overlap by WINDOW_SIZE-1 rows
    # (sliding by 1), so a random split would put near-duplicate windows on both
    # sides of the train/test boundary and quietly leak information — accuracy
    # would look great but wouldn't mean anything. Splitting by row position
    # instead means test windows never share a row with a training window.
    split_idx = int(len(df) * 0.8)
    train_df = df.iloc[:split_idx].reset_index(drop=True)
    test_df = df.iloc[split_idx:].reset_index(drop=True)

    # Fit scaling on TRAIN ONLY, then apply the same scaling to test — fitting
    # on the full dataset (including test) would leak test-set statistics into
    # preprocessing, which is its own (subtler) form of the same problem.
    scaling = compute_scaling(train_df, label_col)

    X_train, y_train = build_windows(train_df, label_col, scaling)
    X_test, y_test = build_windows(test_df, label_col, scaling)
    feature_dim = X_train.shape[2]

    print(f"Train: {len(X_train)} windows ({int(y_train.sum())} attack). "
          f"Test: {len(X_test)} windows ({int(y_test.sum())} attack). Device: {DEVICE}")

    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    model = LSTMDetector(feature_dim).to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.BCELoss()

    for epoch in range(1, EPOCHS + 1):
        total_loss, correct, total = 0.0, 0, 0
        for xb, yb in loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            preds = model(xb)
            loss = criterion(preds, yb)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(xb)
            correct += ((preds > 0.5).float() == yb).sum().item()
            total += len(xb)

        if epoch % 3 == 0 or epoch == 1:
            print(f"Epoch {epoch:3d}/{EPOCHS} | train loss: {total_loss/total:.4f} | train accuracy: {correct/total:.3f}")

    print("\n--- Held-out test set evaluation (never seen during training) ---")
    test_metrics = evaluate(model, X_test, y_test)
    print(f"Accuracy:  {test_metrics['accuracy']:.3f}")
    print(f"Precision: {test_metrics['precision']:.3f}  (of windows flagged as attack, how many really were)")
    print(f"Recall:    {test_metrics['recall']:.3f}  (of real attack windows, how many were caught)")
    print(f"F1:        {test_metrics['f1']:.3f}")
    print(f"Confusion: TP={test_metrics['tp']:.0f} FP={test_metrics['fp']:.0f} FN={test_metrics['fn']:.0f} TN={test_metrics['tn']:.0f}")
    baseline_accuracy = 1 - (y_test.sum().item() / len(y_test))
    print(f"(For reference, a model that always predicts 'benign' would score {baseline_accuracy:.3f} accuracy on this test set — "
          f"the real accuracy above needs to clearly beat this to mean anything.)")

    os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "feature_dim": feature_dim, "scaling": scaling}, MODEL_SAVE_PATH)
    print(f"\nSaved LSTM detector to {MODEL_SAVE_PATH}")


if __name__ == "__main__":
    train()