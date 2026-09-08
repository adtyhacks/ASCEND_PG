"""
defense/ — Hybrid Suricata + LSTM/AE defense module.

Components:
  - flow_extractor: Captures live Mininet traffic, extracts CIC-IDS-2017 features
  - ml_detector: Loads trained LSTM + Autoencoder for real-time inference
  - hybrid_detector: Combines Suricata alerts with ML anomaly scores
  - modbus_logger: Parses Modbus TCP packets for detailed ICS logging
  - flow_logger: Tracks network flow metrics (NetFlow/IPFIX style)

Note: ml_detector and hybrid_detector require torch. They are imported lazily
so that modbus_logger/flow_logger can be used without torch installed.
"""

from .modbus_logger import ModbusLogger
from .flow_logger import FlowLogger

__all__ = ["ModbusLogger", "FlowLogger"]


def __getattr__(name):
    if name == "MLDetector":
        from .ml_detector import MLDetector
        return MLDetector
    if name == "HybridDetector":
        from .hybrid_detector import HybridDetector
        return HybridDetector
    if name == "FlowExtractor":
        from .flow_extractor import FlowExtractor
        return FlowExtractor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
