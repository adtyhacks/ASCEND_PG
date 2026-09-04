"""
Module 6 — GAN training loop.

DATA SOURCE (important, read before running):
Currently points at data/cic_ids2017_subset.csv as a PLACEHOLDER — this
lets the training loop be built and validated before Abinraj's testbed
track produces the real thing. Once data/captured_flows/labeled_flows.csv
exists, change DATA_PATH below. No other code should need to change,
since both files are expected to share the same flow-feature schema.

Sized for a 4GB VRAM GPU (RTX 3050):
- small batch size (64), mixed precision (torch.cuda.amp)
- if you hit CUDA OOM, first thing to try: drop BATCH_SIZE to 32

Owner: Andikumar (training track, Modules 6-8)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from gan import build_models

# ---------------------------------------------------------------------------
# Config — the only section you should need to touch when repointing to
# real data or tuning for a different GPU.
# ---------------------------------------------------------------------------
DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv"
)  # TODO(Andikumar): repoint to data/captured_flows/labeled_flows.csv when ready

NOISE_DIM = 32
HIDDEN_DIM = 256
BATCH_SIZE = 64
EPOCHS = 200
LR = 2e-4
MODEL_SAVE_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def load_features(csv_path: str) -> torch.Tensor:
    """
    Loads flow-feature rows and scales them to [-1, 1] to match the
    Generator's final Tanh activation.

    Drops any obvious label/identifier columns (adjust the drop list once
    the real captured-flow schema from Abinraj's pipeline is confirmed —
    label columns should never be fed into the GAN as features).
    """
    df = pd.read_csv(csv_path)

    label_like_cols = [c for c in df.columns if c.lower() in ("label", "attack_type", "flow_id")]
    df = df.drop(columns=label_like_cols, errors="ignore")

    df = df.select_dtypes(include=["number"]).fillna(0.0)

    # Min-max scale each column to [-1, 1]
    col_min = df.min()
    col_max = df.max()
    denom = (col_max - col_min).replace(0, 1.0)  # avoid divide-by-zero on constant columns
    scaled = 2 * (df - col_min) / denom - 1

    return torch.tensor(scaled.values, dtype=torch.float32)


def train():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Expected data at {DATA_PATH}. If this is a fresh checkout, run "
            f"scripts/prepare_dataset.py first, or repoint DATA_PATH to your "
            f"real captured_flows CSV."
        )

    features = load_features(DATA_PATH)
    feature_dim = features.shape[1]
    print(f"Loaded {features.shape[0]} rows, {feature_dim} features. Device: {DEVICE}")

    dataset = TensorDataset(features)
    loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)

    generator, discriminator = build_models(NOISE_DIM, feature_dim, DEVICE)
    opt_g = torch.optim.Adam(generator.parameters(), lr=LR, betas=(0.5, 0.999))
    opt_d = torch.optim.Adam(discriminator.parameters(), lr=LR, betas=(0.5, 0.999))
    criterion = nn.BCEWithLogitsLoss()

    scaler = torch.amp.GradScaler("cuda", enabled=(DEVICE.type == "cuda"))

    for epoch in range(1, EPOCHS + 1):
        d_losses, g_losses = [], []

        for (real_batch,) in loader:
            real_batch = real_batch.to(DEVICE)
            batch_size = real_batch.size(0)
            real_labels = torch.ones(batch_size, 1, device=DEVICE)
            fake_labels = torch.zeros(batch_size, 1, device=DEVICE)

            # --- Train Discriminator ---
            opt_d.zero_grad()
            with torch.amp.autocast("cuda", enabled=(DEVICE.type == "cuda")):
                noise = torch.randn(batch_size, NOISE_DIM, device=DEVICE)
                fake_batch = generator(noise).detach()

                real_pred = discriminator(real_batch)
                fake_pred = discriminator(fake_batch)
                d_loss = criterion(real_pred, real_labels) + criterion(fake_pred, fake_labels)

            scaler.scale(d_loss).backward()
            scaler.step(opt_d)
            scaler.update()

            # --- Train Generator ---
            opt_g.zero_grad()
            with torch.amp.autocast("cuda", enabled=(DEVICE.type == "cuda")):
                noise = torch.randn(batch_size, NOISE_DIM, device=DEVICE)
                fake_batch = generator(noise)
                fake_pred = discriminator(fake_batch)
                # Generator wants discriminator to think fakes are real
                g_loss = criterion(fake_pred, real_labels)

            scaler.scale(g_loss).backward()
            scaler.step(opt_g)
            scaler.update()

            d_losses.append(d_loss.item())
            g_losses.append(g_loss.item())

        if epoch % 10 == 0 or epoch == 1:
            avg_d = sum(d_losses) / len(d_losses)
            avg_g = sum(g_losses) / len(g_losses)
            print(f"Epoch {epoch:4d}/{EPOCHS} | D loss: {avg_d:.4f} | G loss: {avg_g:.4f}")

    os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
    torch.save(generator.state_dict(), os.path.join(MODEL_SAVE_DIR, "gan_generator.pt"))
    torch.save(discriminator.state_dict(), os.path.join(MODEL_SAVE_DIR, "gan_discriminator.pt"))
    print(f"Saved trained weights to {MODEL_SAVE_DIR}/")


if __name__ == "__main__":
    train()
