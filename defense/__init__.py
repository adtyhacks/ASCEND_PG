"""
defense/ — Hybrid Suricata + LSTM/AE defense module.

Components:
  - flow_extractor: Captures live Mininet traffic, extracts CIC-IDS-2017 features
  - ml_detector: Loads trained LSTM + Autoencoder for real-time inference
  - hybrid_detector: Combines Suricata alerts with ML anomaly scores
  - modbus_logger: Parses Modbus TCP packets for detailed ICS logging
  - flow_logger: Tracks network flow metrics (NetFlow/IPFIX style)
"""

from .ml_detector import MLDetector
from .hybrid_detector import HybridDetector
from .modbus_logger import ModbusLogger
from .flow_logger import FlowLogger

__all__ = ["MLDetector", "HybridDetector", "ModbusLogger", "FlowLogger"]
