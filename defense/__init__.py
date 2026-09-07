"""
defense/ — Hybrid Suricata + LSTM/AE defense module.

Components:
  - flow_extractor: Captures live Mininet traffic, extracts CIC-IDS-2017 features
  - ml_detector: Loads trained LSTM + Autoencoder for real-time inference
  - hybrid_detector: Combines Suricata alerts with ML anomaly scores
"""

from .ml_detector import MLDetector
from .hybrid_detector import HybridDetector

__all__ = ["MLDetector", "HybridDetector"]
