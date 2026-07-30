import numpy as np
import pandas as pd


class RuleBasedDetector:
    """
    Baseline anomaly detector. Learns 'normal' as mean/std of the clean
    baseline traffic, then scores new traffic by how many standard
    deviations away each row falls. No training data required.
    """

    NUMERIC_FEATURES = ["packet_size_bytes", "voltage_pu"]

    def __init__(self, z_threshold=3.0):
        self.z_threshold = z_threshold
        self.mean_ = None
        self.std_ = None

    def fit(self, baseline_df):
        self.mean_ = baseline_df[self.NUMERIC_FEATURES].mean()
        self.std_ = baseline_df[self.NUMERIC_FEATURES].std().replace(0, 1e-6)
        return self

    def score(self, df):
        """Returns a per-row confidence score in [0, 1] and a verdict column."""
        z = ((df[self.NUMERIC_FEATURES] - self.mean_) / self.std_).abs()
        max_z = z.max(axis=1)
        confidence = (max_z / self.z_threshold).clip(0, 1)

        verdict = pd.cut(
            confidence,
            bins=[-0.01, 0.3, 0.7, 1.01],
            labels=["Missed", "Partially Detected", "Fully Detected"],
        )
        out = df.copy()
        out["detection_confidence"] = confidence.round(3)
        out["detection_verdict"] = verdict
        return out