#!/usr/bin/env python3
"""Diagnostic script to check Suricata detection pipeline."""
import json, sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from datetime import datetime, timezone

print("=== Step 1: Can we import hybrid detector? ===")
try:
    from defense.hybrid_detector import HybridDetector, _find_suricata_alerts
    print("  [OK] HybridDetector imported")
except Exception as e:
    print(f"  [FAIL] {e}")

print("\n=== Step 2: torch available? ===")
try:
    import torch
    print(f"  [OK] torch {torch.__version__}")
except ImportError as e:
    print(f"  [FAIL] {e}")

print("\n=== Step 3: Can we find Suricata alerts in eve.json? ===")
eve = Path("/var/log/suricata/eve.json")
print(f"  eve.json exists: {eve.exists()}")
if eve.exists():
    sids_to_check = [9000001, 9000004, 9000005, 9000006, 9000007, 9000010, 9000020]
    alerts = _find_suricata_alerts(sids_to_check, datetime(2026,1,1, tzinfo=timezone.utc), datetime.now(timezone.utc))
    print(f"  Total alerts found (all SIDs, all time): {len(alerts)}")
    for a in alerts[:5]:
        sig = a.get("alert", {}).get("signature", "?")
        ts = a.get("timestamp", "?")
        print(f"    - {ts}: {sig}")

print("\n=== Step 4: detect_sids per technique ===")
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME, STEP_DEFS
for t, s in TECHNIQUE_TO_STEP_NAME.items():
    if s in STEP_DEFS:
        sids = STEP_DEFS[s].get("detect_sids", [])
        print(f"  {t} -> {s} -> detect_sids={sids}")

print("\n=== Step 5: Test HybridDetector creation ===")
try:
    det = HybridDetector(interface="s1-eth7", use_ml=True, use_suricata=True)
    print(f"  use_ml: {det.use_ml}")
    print(f"  use_suricata: {det.use_suricata}")
    print(f"  is_ml_available: {det.is_ml_available()}")
except Exception as e:
    print(f"  [FAIL] {e}")

print("\n=== Step 6: Simulate detector verdict with current alerts ===")
try:
    det = HybridDetector(interface="s1-eth7", use_ml=True, use_suricata=True)
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    window_start = now - timedelta(minutes=30)
    verdict = det.get_verdict(window_start, now, [9000001, 9000004, 9000005, 9000006, 9000007, 9000010, 9000020, 9000025])
    print(f"  suricata_detected: {verdict['suricata_detected']}")
    print(f"  suricata_alert_count: {verdict['suricata_alert_count']}")
    print(f"  suricata_signatures: {verdict['suricata_signatures']}")
    print(f"  ml_detected: {verdict['ml_detected']}")
    print(f"  ml_available: {verdict['ml_available']}")
    print(f"  combined_detected: {verdict['combined_detected']}")
    print(f"  detection_method: {verdict['detection_method']}")
except Exception as e:
    print(f"  [FAIL] {e}")
    import traceback; traceback.print_exc()
