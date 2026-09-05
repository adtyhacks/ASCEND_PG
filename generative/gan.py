"""
Module 6 — Tabular GAN Architecture (Generator & Discriminator).

Generates synthetic network flow features (tabular data) to mutate attack
parameters, sized for a 4GB VRAM GPU (RTX 3050).

Owner: Andikumar (training track, Modules 6-8)
"""

import torch
import torch.nn as nn


class Generator(nn.Module):
    """
    MLP Generator for tabular flow features.
    Input: noise vector of shape (batch, noise_dim)
    Output: synthetic feature vector of shape (batch, feature_dim) scaled in [-1, 1] (via Tanh).
    """

    def __init__(self, noise_dim: int, feature_dim: int, hidden_dim: int = 256):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(noise_dim, hidden_dim),
            nn.LeakyReLU(0.2, inplace=True),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.LeakyReLU(0.2, inplace=True),
            nn.BatchNorm1d(hidden_dim * 2),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LeakyReLU(0.2, inplace=True),
            nn.BatchNorm1d(hidden_dim),
            nn.Linear(hidden_dim, feature_dim),
            nn.Tanh(),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.net(z)


class Discriminator(nn.Module):
    """
    MLP Discriminator for tabular flow features.
    Input: feature vector of shape (batch, feature_dim)
    Output: unnormalized logit score indicating whether the sample is real.
    """

    def __init__(self, feature_dim: int, hidden_dim: int = 256):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(feature_dim, hidden_dim * 2),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.net(x))


def build_models(noise_dim: int, feature_dim: int, device: torch.device):
    """Instantiates Generator and Discriminator and places them on the specified device."""
    generator = Generator(noise_dim, feature_dim).to(device)
    discriminator = Discriminator(feature_dim).to(device)
    return generator, discriminator
