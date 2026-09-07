"""
defense/hybrid_detector.py

Combines Suricata signature-based detection with LSTM/AE ML-based anomaly
detection into a unified hybrid verdict.

Detection modes:
  - suricata_only: Legacy Suricata SID matching
  - ml_only:       LSTM + AE fusion scoring
  - hybrid:        Both signals combined (recommended)
"""

from datetime import datetime, timezone
from pathlib import Path

from .flow_extractor import FlowExtractor, FEATURE_COLS
from .ml_detector import MLDetector

try:
    import pandas as pd
except ImportError:
    pd = None


SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")
DETECTION_BUFFER_SEC = 3


def _find_suricata_alerts(sids, start, end):
    if not SURICATA_EVE_LOG.exists() or not sids:
        return []

    window_end = end.timestamp() + DETECTION_BUFFER_SEC
    matches = []

    try:
        with open(SURICATA_EVE_LOG) as f:
            for line in f:
                line = line.strip()
                if not line or '"event_type"' not in line:
                    continue
                try:
                    import json
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("event_type") != "alert":
                    continue
                alert = entry.get("alert", {})
                if alert.get("signature_id") not in sids:
                    continue

                flow = entry.get("flow", {})
                flow_start_str = flow.get("start")
                if flow_start_str:
                    ts = datetime.fromisoformat(flow_start_str.replace("Z", "+00:00"))
                else:
                    ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))

                if start.timestamp() <= ts.timestamp() <= window_end:
                    matches.append(entry)
    except Exception:
        pass

    return matches


class HybridDetector:
    """Orchestrates Suricata + ML detection layers."""

    def __init__(self, interface="s1-mon", use_ml=True, use_suricata=True):
        self.interface = interface
        self.use_ml = use_ml
        self.use_suricata = use_suricata

        self.ml_detector = MLDetector()
        self.extractor = FlowExtractor(interface=interface) if use_ml else None

        if use_ml:
            try:
                self.ml_detector.load()
                print("[hybrid] ML models loaded successfully")
            except Exception as e:
                print(f"[hybrid] Warning: could not load ML models: {e}")
                self.use_ml = False

    def is_ml_available(self) -> bool:
        return self.ml_detector.is_loaded()

    def start_capture(self):
        if self.extractor and self.use_ml:
            self.extractor.start()

    def get_verdict(self, step_start, step_end, detect_sids=None):
        detect_sids = detect_sids or []

        suricata_detected = False
        suricata_alerts = []
        if self.use_suricata:
            suricata_alerts = _find_suricata_alerts(detect_sids, step_start, step_end)
            suricata_detected = len(suricata_alerts) > 0

        ml_detected = False
        ml_confidence = 0.0
        ml_result = None
        if self.use_ml and self.extractor:
            try:
                window_df = self.extractor.get_window()
                ml_result = self.ml_detector.predict(window_df)
                ml_detected = ml_result["detected"]
                ml_confidence = ml_result["fused_confidence"]
            except Exception as e:
                print(f"[hybrid] ML inference error: {e}")

        if suricata_detected and ml_detected:
            combined = True
            method = "both"
        elif suricata_detected:
            combined = True
            method = "suricata"
        elif ml_detected:
            combined = True
            method = "ml"
        else:
            combined = False
            method = "none"

        return {
            "suricata_detected": suricata_detected,
            "suricata_alert_count": len(suricata_alerts),
            "suricata_signatures": [
                a.get("alert", {}).get("signature", "") for a in suricata_alerts
            ],
            "ml_detected": ml_detected,
            "ml_confidence": ml_confidence,
            "ml_lstm_confidence": ml_result["lstm_confidence"] if ml_result else 0.0,
            "ml_ae_score": ml_result["ae_anomaly_score"] if ml_result else 0.0,
            "ml_available": self.is_ml_available(),
            "combined_detected": combined,
            "detection_method": method,
        }
