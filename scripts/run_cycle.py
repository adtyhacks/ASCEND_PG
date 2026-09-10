"""
ASCEND-PG scripts/run_cycle.py

Attack-agnostic cycle runner. Drives a sequence of steps (recon, then
one or more attacks) against the live testbed, logs each step's
start/end, then correlates against Suricata's real eve.json alerts to
produce a "detected: yes/no" verdict per step.

Design: STEPS is a plain list of dicts. Adding a new attack means
adding one dict entry here; nothing else in this file needs to change.
That's what "attack-agnostic" means in practice.

Full attack arsenal (18 steps, 18 unique scripts, 14 MITRE ATT&CK for ICS techniques):

  RECON:             recon_step.py (T0846/T0888), fc_scan.py (T0840)
  RESPONSE INJECTION: fdi_attack.py, naive_response_injection.py,
                      complex_response_injection.py (all T0836)
  COMMAND INJECTION:  cmd_inject_coil.py, cmd_inject_register.py,
                      malicious_fc.py (all T0855)
  DoS:               dos_attack.py (dos_quiet, dos_loud), dos_conn_exhaust.py (T0814)
  REPLAY:            replay_attack.py (T0832)
  MITM:              mitm_proxy.py (T0830)
  DEVICE RESTART:    device_restart.py (T0816)
  BRUTE FORCE I/O:   brute_force_io.py (T0806)
  DENIAL OF VIEW:    denial_of_view.py (T0815)
  I/O MANIPULATION:  manipulate_io_image.py (T0835)
  PROCESS MONITOR:   monitor_process_state.py (T0801)

Paths are resolved relative to this file, so the runner works from any
cwd:
    <repo>/attacks/*.py                -- step scripts
    <repo>/data/log_store.json         -- shared event log
    <repo>/data/cycle_report.json      -- merged verdict report
The Live Battle page (app/pages/3_Live_Battle.py) reads those two data/
files to render the topology + event log live.

Run this ON THE ATTACKER HOST inside the Mininet topology, e.g.:
    mininet> attacker python3 scripts/run_cycle.py

Requires: the testbed up, the OVS mirror configured (scripts/setup_mirror.sh),
Suricata running on the monitor interface (docs/suricata_setup.md), and
plc1 up on 10.0.0.1.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from testbed.topology import load_topology, get_topology

# --- path anchors (repo-relative, cwd-independent) --------------------
REPO_ROOT = Path(__file__).resolve().parent.parent   # scripts/ -> ascend-pg-webapp/
ATTACKS_DIR = REPO_ROOT / "attacks"
DATA_DIR = REPO_ROOT / "data"
LOG_STORE_PATH = DATA_DIR / "log_store.json"
REPORT_PATH = DATA_DIR / "cycle_report.json"

# Import shared utilities from testbed_executor
sys.path.insert(0, str(REPO_ROOT))
from scripts.testbed_executor import (
    run_step as _run_step,
    find_alerts_for_window as _find_alerts,
    get_hybrid_detector,
    DETECTION_SEARCH_BUFFER_SEC,
)

# --- Early diagnostics (write immediately so we see import errors) ---
_diag_path = DATA_DIR / "ml_diagnostics.txt"
try:
    with open(str(_diag_path), "w") as _d:
        _d.write(f"Python: {sys.executable}\n")
        _d.write(f"Python version: {sys.version}\n")
        _d.write(f"REPO_ROOT: {REPO_ROOT}\n")
        _d.write(f"sys.path[0:5]: {sys.path[:5]}\n")
        _d.write(f"Imports OK\n")
except Exception as _e:
    print(f"[run_cycle] WARNING: could not write early diagnostics: {_e}")

# Step ordering follows a realistic kill chain:
# 1. Reconnaissance — discover the network and fingerprint PLCs
# 2. Response/Measurement Injection — manipulate sensor data
# 3. Command Injection — inject unauthorized control commands
# 4. DoS — disrupt communications
# 5. Replay — replay captured legitimate traffic
# 6. MITM — transparent proxy intercepting Modbus responses
# 7. Device Restart — unauthorized coil write to trigger restart
# 8. Brute Force I/O — rapid register reads to discover I/O
# 9. Denial of View — flood SCADA with forged responses

STEPS = [
    # === RECONNAISSANCE ===
    {
        "name": "recon_nmap_devid",
        "techniques": ["T0846", "T0888"],
        "script": str(ATTACKS_DIR / "recon_step.py"),
        "args": ["--subnet", "10.0.0.0/24", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000004],
        "timeout": 180,     # nmap over Mininet vnet can be slow even with T4
    },
    {
        "name": "recon_fc_scan",
        "techniques": ["T0840"],
        "script": str(ATTACKS_DIR / "fc_scan.py"),
        "args": ["--target", "10.0.0.1", "--safe", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000005, 9000006],
        "timeout": 45,      # 24 FCs × 0.5s timeout + overhead
    },

    # === RESPONSE / MEASUREMENT INJECTION (T0836) ===
    {
        "name": "fdi_attack",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "fdi_attack.py"),
        "args": ["--target", "10.0.0.1", "-a", "40000", "-v", "9999"],
        "detect_sids": [9000001],
    },
    {
        "name": "naive_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "naive_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "40000", "--value", "65535",
                  "--duration", "5", "--interval", "1.0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000001],
    },
    {
        "name": "complex_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "complex_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "40000", "--mode", "ramp",
                  "--magnitude", "5", "--duration", "5", "--interval", "1.0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000001],
    },

    # === COMMAND INJECTION (T0855) ===
    {
        "name": "cmd_inject_coil",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "cmd_inject_coil.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--value", "True",
                  "--count", "5", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000007],
    },
    {
        "name": "cmd_inject_register",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "cmd_inject_register.py"),
        "args": ["--target", "10.0.0.1", "--address", "40050", "--value", "0",
                  "--count", "5", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000001],  # Caught by holding register write rule
    },
    {
        "name": "malicious_fc",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "malicious_fc.py"),
        "args": ["--target", "10.0.0.1", "--action", "all",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000006, 9000008, 9000009],
    },

    # === DENIAL OF SERVICE (T0814) ===
    {
        "name": "dos_quiet",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_attack.py"),
        "args": ["--target", "10.0.0.1", "--count", "100", "--delay", "0.05",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000023],
    },
    {
        "name": "dos_loud",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_attack.py"),
        "args": ["--target", "10.0.0.1", "--count", "600", "--delay", "0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000002],
    },
    {
        "name": "dos_conn_exhaust",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_conn_exhaust.py"),
        "args": ["--target", "10.0.0.1", "--connections", "30",
                  "--hold-time", "10", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000002, 9000010],
        "timeout": 60,      # 10s hold + socket overhead for 30 connections
    },

    # === REPLAY (T0832) ===
    {
        "name": "replay_attack",
        "techniques": ["T0832"],
        "script": str(ATTACKS_DIR / "replay_attack.py"),
        "args": ["--target", "10.0.0.1", "--iface", "s1-eth7",
                  "--capture-time", "3", "--replay-count", "1",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [],  # Replay is signature-invisible — trained detectors only
        "timeout": 120,     # 3s capture + replay + scapy init overhead
    },

    # === MITM (T0830) ===
    {
        "name": "mitm_proxy",
        "techniques": ["T0830"],
        "script": str(ATTACKS_DIR / "mitm_proxy.py"),
        "args": ["--target", "10.0.0.1", "--listen-port", "503",
                  "--mode", "offset", "--magnitude", "100",
                  "--duration", "10", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000022],  # Non-standard port 503 detection
        "timeout": 30,
    },

    # === DEVICE RESTART (T0816) ===
    {
        "name": "device_restart",
        "techniques": ["T0816"],
        "script": str(ATTACKS_DIR / "device_restart.py"),
        "args": ["--target", "10.0.0.1", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000007],  # Coil write detected
        "timeout": 30,
    },

    # === BRUTE FORCE I/O (T0806) ===
    {
        "name": "brute_force_io",
        "techniques": ["T0806"],
        "script": str(ATTACKS_DIR / "brute_force_io.py"),
        "args": ["--target", "10.0.0.1", "--count", "200", "--delay", "0.01",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000023],  # Rapid register enumeration
        "timeout": 60,
    },

    # === DENIAL OF VIEW (T0815) ===
    {
        "name": "denial_of_view",
        "techniques": ["T0815"],
        "script": str(ATTACKS_DIR / "denial_of_view.py"),
        "args": ["--scada-ip", "10.0.0.10", "--plc-ip", "10.0.0.1",
                  "--count", "100", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000001, 9000024],  # Holding write + raw byte fallback
        "timeout": 30,
    },

    # === MANIPULATE I/O IMAGE (T0835) ===
    {
        "name": "manipulate_io_image",
        "techniques": ["T0835"],
        "script": str(ATTACKS_DIR / "manipulate_io_image.py"),
        "args": ["--target", "10.0.0.1", "--coil-start", "0", "--coil-count", "20",
                  "--delay", "0.05", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000007],  # Coil writes detected
        "timeout": 30,
    },

    # === MONITOR PROCESS STATE (T0801) ===
    {
        "name": "monitor_process_state",
        "techniques": ["T0801"],
        "script": str(ATTACKS_DIR / "monitor_process_state.py"),
        "args": ["--target", "10.0.0.1", "--start-reg", "30000", "--end-reg", "30099",
                  "--count", "5", "--delay", "0.5", "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000023],  # Register enumeration
        "timeout": 30,
    },

    # === REMOTE SERVICES (T0886) ===
    {
        "name": "remote_services",
        "techniques": ["T0886"],
        "script": str(ATTACKS_DIR / "remote_services.py"),
        "args": ["--target", "10.0.0.1", "--scada-ip", "10.0.0.10",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000026],  # SSH to OT host
        "timeout": 60,
    },

    # === AUTOMATED COLLECTION (T0802) ===
    {
        "name": "automated_collection",
        "techniques": ["T0802"],
        "script": str(ATTACKS_DIR / "automated_collection.py"),
        "args": ["--target", "10.0.0.1", "--subnet", "10.0.0.0/24",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000027],  # Broad register scan
        "timeout": 120,
    },

    # === STANDARD APP LAYER PROTOCOL C2 (T0869) ===
    {
        "name": "standard_protocol_c2",
        "techniques": ["T0869"],
        "script": str(ATTACKS_DIR / "standard_protocol_c2.py"),
        "args": ["--target", "10.0.0.1", "--command", "DEAD",
                  "--count", "5", "--interval", "1.0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000028],  # Suspicious register writes
        "timeout": 60,
    },

    # === ALARM SUPPRESSION (T0878) ===
    {
        "name": "alarm_suppression",
        "techniques": ["T0878"],
        "script": str(ATTACKS_DIR / "alarm_suppression.py"),
        "args": ["--target", "10.0.0.1", "--duration", "5", "--interval", "1.0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000029],  # Alarm register clear
        "timeout": 30,
    },

    # === SERVICE STOP (T0881) ===
    {
        "name": "service_stop",
        "techniques": ["T0881"],
        "script": str(ATTACKS_DIR / "service_stop.py"),
        "args": ["--target", "10.0.0.1", "--mode", "combined", "--count", "100",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000030],  # Invalid function code flood
        "timeout": 60,
    },
]

# Suricata's modbus.flooded fires on flow timeout, not immediately.
# Re-scan for undetected steps after this many seconds to catch those.
FLOW_TIMEOUT_SEC = 660  # 11 minutes — covers Suricata's default TCP flow timeout

ATTACKER_LOG_STORE = LOG_STORE_PATH

# Use shared utilities from testbed_executor
run_step = _run_step
find_alerts_for_window = _find_alerts


def build_merged_log(step_results):
    merged = []

    attacker_events = []
    if ATTACKER_LOG_STORE.exists():
        try:
            attacker_events = json.loads(ATTACKER_LOG_STORE.read_text())
        except json.JSONDecodeError:
            pass
    for ev in attacker_events:
        merged.append({
            "timestamp": ev.get("timestamp"),
            "source": "attacker",
            "stage": ev.get("stage"),
            "technique": ev.get("technique"),
            "detail": ev.get("action"),
        })

    for step in step_results:
        for alert_entry in step["alerts"]:
            alert = alert_entry.get("alert", {})
            merged.append({
                "timestamp": alert_entry.get("timestamp"),
                "source": "suricata",
                "stage": step["name"],
                "technique": "+".join(step["techniques"]),
                "detail": alert.get("signature"),
            })

    merged.sort(key=lambda e: e["timestamp"] or "")
    return merged


def print_report(step_results):
    print("\n" + "=" * 70)
    print("ASCEND-PG TESTBED CYCLE REPORT")
    print("=" * 70)
    for step in step_results:
        detected = step.get("detected", len(step["alerts"]) > 0)
        status = "DETECTED" if detected else "NOT DETECTED"
        method = step.get("detection_method", "suricata")
        ml_info = ""
        if step.get("ml_detected"):
            ml_info = f" [ML: {step.get('ml_confidence', 0):.2f}]"
        print(f"\n[{step['name']}] techniques={'+'.join(step['techniques'])}")
        print(f"  window: {step['start'].isoformat()} -> {step['end'].isoformat()}")
        print(f"  result: {status} via {method}{ml_info}")
        for a in step["alerts"]:
            sig = a.get("alert", {}).get("signature")
            print(f"    - {a.get('timestamp', 'N/A')}: {sig}")
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG testbed cycle runner")
    parser.add_argument("--report", default=str(REPORT_PATH),
                         help="path to write the merged log + verdicts JSON "
                              "(defaults to <repo>/data/cycle_report.json)")
    parser.add_argument("--topology", default=None,
                         help="path to topology directory or JSON file")
    args = parser.parse_args()

    # Load topology for dynamic IPs
    topology = load_topology(args.topology)
    print(f"[run_cycle] Loaded topology: {topology.num_buses} buses")
    
    # Get default target IP from topology (first bus)
    default_target = topology.get_ip(0) if topology.num_buses > 0 else "10.0.0.1"
    print(f"[run_cycle] Default target IP: {default_target}")

    step_results = []
    detector = get_hybrid_detector(use_ml=True, use_suricata=True)
    
    # Write detector diagnostics (append to early diagnostics)
    diag_path = DATA_DIR / "ml_diagnostics.txt"
    with open(str(diag_path), "a") as diag:
        diag.write(f"Python: {sys.executable}\n")
        diag.write(f"Python version: {sys.version}\n")
        diag.write(f"REPO_ROOT: {REPO_ROOT}\n")
        diag.write(f"sys.path[0:5]: {sys.path[:5]}\n")
        if detector:
            diag.write(f"detector created: True\n")
            diag.write(f"detector.is_ml_available(): {detector.is_ml_available()}\n")
            diag.write(f"detector.use_ml: {detector.use_ml}\n")
            diag.write(f"detector.use_suricata: {detector.use_suricata}\n")
            if hasattr(detector, 'ml_detector'):
                diag.write(f"ml_detector._loaded: {detector.ml_detector._loaded}\n")
        else:
            diag.write(f"detector created: False\n")
        try:
            import torch
            diag.write(f"torch available: True, version: {torch.__version__}\n")
        except ImportError as e:
            diag.write(f"torch available: False, error: {e}\n")
        try:
            import scapy
            diag.write(f"scapy available: True\n")
        except ImportError as e:
            diag.write(f"scapy available: False, error: {e}\n")

    # Update STEPS with dynamic target IP
    import copy
    dynamic_steps = []
    for step in STEPS:
        step_copy = copy.deepcopy(step)
        # Replace hardcoded 10.0.0.1 with dynamic target
        step_copy["args"] = [default_target if a == "10.0.0.1" else a for a in step_copy["args"]]
        dynamic_steps.append(step_copy)

    for step in dynamic_steps:
        if detector and detector.is_ml_available():
            detector.clear_flows()
            detector.start_capture()
        try:
            timing = run_step(step)
            time.sleep(DETECTION_SEARCH_BUFFER_SEC)

            if detector and detector.is_ml_available():
                verdict = detector.get_verdict(
                    timing["start"], timing["end"], timing["detect_sids"]
                )
                timing["alerts"] = [
                    {"alert": {"signature": s}} for s in verdict["suricata_signatures"]
                ]
                timing["detected"] = verdict["combined_detected"]
                timing["ml_detected"] = verdict["ml_detected"]
                timing["ml_confidence"] = verdict["ml_confidence"]
                timing["detection_method"] = verdict["detection_method"]
            else:
                alerts = _find_alerts(timing["detect_sids"], timing["start"], timing["end"])
                timing["alerts"] = alerts
                timing["detected"] = len(alerts) > 0
                timing["ml_detected"] = False
                timing["ml_confidence"] = 0.0
                timing["detection_method"] = "suricata"
        finally:
            if detector and detector.is_ml_available():
                detector.stop_capture()
        step_results.append(timing)

    # --- Post-cycle re-scan for flow-timeout alerts ---
    undetected = [s for s in step_results if not s["alerts"]]
    if undetected:
        names = ", ".join(s["name"] for s in undetected)
        print(f"\n[run_cycle] {names} not yet detected — waiting {FLOW_TIMEOUT_SEC}s "
              "for Suricata flow-timeout alerts (modbus.flooded) ...")
        time.sleep(FLOW_TIMEOUT_SEC)
        for timing in undetected:
            alerts = find_alerts_for_window(
                timing["detect_sids"], timing["start"], timing["end"])
            timing["alerts"] = alerts
            if alerts:
                print(f"  [re-scan] {timing['name']}: DETECTED "
                      f"({len(alerts)} flow-timeout alert(s))")

    print_report(step_results)

    merged_log = build_merged_log(step_results)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({
        "steps": [
            {
                "name": s["name"], "techniques": s["techniques"],
                "start": s["start"].isoformat(), "end": s["end"].isoformat(),
                "detected": s.get("detected", len(s["alerts"]) > 0),
                "alert_count": len(s["alerts"]),
                "ml_detected": s.get("ml_detected", False),
                "ml_confidence": s.get("ml_confidence", 0.0),
                "detection_method": s.get("detection_method", "suricata"),
            }
            for s in step_results
        ],
        "merged_log": merged_log,
    }, indent=2, default=str))
    print(f"\n[run_cycle] merged report written to {report_path}")


if __name__ == "__main__":
    main()
