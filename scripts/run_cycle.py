"""
ASCEND-PG scripts/run_cycle.py

Attack-agnostic cycle runner. Drives a sequence of steps (recon, then
one or more attacks) against the live testbed, logs each step's
start/end, then correlates against Suricata's real eve.json alerts to
produce a "detected: yes/no" verdict per step.

Design: STEPS is a plain list of dicts. Adding a new attack means
adding one dict entry here; nothing else in this file needs to change.
That's what "attack-agnostic" means in practice.

Full attack arsenal (Session 17 expansion — 14 steps, 13 unique scripts,
9 MITRE ATT&CK for ICS techniques, all 4 Morris & Gao categories):

  RECON:             recon_step.py (T0846/T0888), fc_scan.py (T0840)
  RESPONSE INJECTION: fdi_attack.py, naive_response_injection.py,
                      complex_response_injection.py (all T0836)
  COMMAND INJECTION:  cmd_inject_coil.py, cmd_inject_register.py,
                      malicious_fc.py (all T0855)
  DoS:               dos_attack.py, dos_conn_exhaust.py (T0814)
  REPLAY:            replay_attack.py (T0832)
  MITM:              mitm_proxy.py (T0830)

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
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --- path anchors (repo-relative, cwd-independent) --------------------
REPO_ROOT = Path(__file__).resolve().parent.parent   # scripts/ -> ascend-pg-webapp/
ATTACKS_DIR = REPO_ROOT / "attacks"
DATA_DIR = REPO_ROOT / "data"
LOG_STORE_PATH = DATA_DIR / "log_store.json"
REPORT_PATH = DATA_DIR / "cycle_report.json"

# Step ordering follows a realistic kill chain:
# 1. Reconnaissance — discover the network and fingerprint PLCs
# 2. Response/Measurement Injection — manipulate sensor data
# 3. Command Injection — inject unauthorized control commands
# 4. DoS — disrupt communications
# 5. Replay — replay captured legitimate traffic
# Note: MITM (mitm_proxy.py) is excluded from the automated cycle because
# it requires the SCADA client to be redirected to the proxy port (:503).
# Run it separately per docs/testbed_runbook.md.

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
        "args": ["--target", "10.0.0.1", "-a", "0", "-v", "9999"],
        "detect_sids": [9000001],
    },
    {
        "name": "naive_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "naive_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--value", "65535",
                  "--duration", "5", "--interval", "1.0",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [9000001],
    },
    {
        "name": "complex_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "complex_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--mode", "ramp",
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
        "args": ["--target", "10.0.0.1", "--address", "50", "--value", "0",
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
        "detect_sids": [9000002],
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
        "args": ["--target", "10.0.0.1", "--iface", "s1-mon",
                  "--capture-time", "3", "--replay-count", "1",
                  "--log", str(LOG_STORE_PATH)],
        "detect_sids": [],  # Replay is signature-invisible — trained detectors only
        "timeout": 120,     # 3s capture + replay + scapy init overhead
    },
]

DETECTION_SEARCH_BUFFER_SEC = 3

# Suricata's modbus.flooded fires on flow timeout, not immediately.
# Re-scan for undetected steps after this many seconds to catch those.
FLOW_TIMEOUT_SEC = 660  # 11 minutes — covers Suricata's default TCP flow timeout

ATTACKER_LOG_STORE = LOG_STORE_PATH
SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if ATTACKER_LOG_STORE.exists():
        try:
            events = json.loads(ATTACKER_LOG_STORE.read_text())
        except json.JSONDecodeError:
            events = []
    events.append(event)
    ATTACKER_LOG_STORE.parent.mkdir(parents=True, exist_ok=True)
    ATTACKER_LOG_STORE.write_text(json.dumps(events, indent=2))


def run_step(step: dict) -> dict:
    print(f"\n=== Running step: {step['name']} ({', '.join(step['techniques'])}) ===")
    start = datetime.now(timezone.utc)
    log_event({
        "stage": step["name"], "technique": "+".join(step["techniques"]),
        "action": "step_start",
    })

    # Per-step timeout: steps can declare their own "timeout" key (seconds).
    # Nmap recon needs ~60s; fc_scan needs ~30s; dos_conn_exhaust holds
    # connections for 10s + overhead. Default is 90s which covers most attacks.
    step_timeout = step.get("timeout", 90)

    # sys.executable (not bare "python3") so the step scripts run under the
    # same interpreter/venv as the runner — the one that has pymodbus installed.
    try:
        result = subprocess.run(
            [sys.executable, step["script"], *step["args"]],
            capture_output=True, text=True, timeout=step_timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[run_cycle] WARNING: {step['name']} timed out after {step_timeout}s — skipping")
        log_event({
            "stage": step["name"], "technique": "+".join(step["techniques"]),
            "action": "step_timeout", "timeout_sec": step_timeout,
        })
        end = datetime.now(timezone.utc)
        return {"name": step["name"], "start": start, "end": end,
                "detect_sids": step["detect_sids"], "techniques": step["techniques"]}

    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0:
        print(f"[run_cycle] WARNING: {step['script']} exited {result.returncode}")
        if result.stderr:
            print(result.stderr.strip())

    end = datetime.now(timezone.utc)
    log_event({
        "stage": step["name"], "technique": "+".join(step["techniques"]),
        "action": "step_end", "returncode": result.returncode,
    })
    return {"name": step["name"], "start": start, "end": end,
            "detect_sids": step["detect_sids"], "techniques": step["techniques"]}


def find_alerts_for_window(sids, start, end):
    if not SURICATA_EVE_LOG.exists():
        return []

    window_end = end.timestamp() + DETECTION_SEARCH_BUFFER_SEC
    matches = []
    with open(SURICATA_EVE_LOG) as f:
        for line in f:
            line = line.strip()
            # Cheap pre-filter to skip non-event lines, then parse and check
            # the field on the decoded object — robust to JSON whitespace
            # rather than assuming Suricata's compact one-event-per-line default.
            if not line or '"event_type"' not in line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event_type") != "alert":
                continue
            alert = entry.get("alert", {})
            if alert.get("signature_id") not in sids:
                continue
            # Match on flow start time, not alert timestamp.
            # Suricata's modbus.flooded fires on flow timeout — the alert
            # timestamp can be minutes after the flood. The flow.start
            # field always falls within the step that generated the traffic.
            flow = entry.get("flow", {})
            flow_start_str = flow.get("start")
            if flow_start_str:
                ts = datetime.fromisoformat(flow_start_str.replace("Z", "+00:00"))
            else:
                # Fallback for alerts without flow data (e.g. packet-level rules)
                ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
            if start.timestamp() <= ts.timestamp() <= window_end:
                matches.append(entry)
    return matches


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
        detected = len(step["alerts"]) > 0
        status = "DETECTED" if detected else "NOT DETECTED"
        print(f"\n[{step['name']}] techniques={'+'.join(step['techniques'])}")
        print(f"  window: {step['start'].isoformat()} -> {step['end'].isoformat()}")
        print(f"  result: {status} ({len(step['alerts'])} matching alert(s))")
        for a in step["alerts"]:
            sig = a.get("alert", {}).get("signature")
            print(f"    - {a.get('timestamp')}: {sig}")
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG testbed cycle runner")
    parser.add_argument("--report", default=str(REPORT_PATH),
                         help="path to write the merged log + verdicts JSON "
                              "(defaults to <repo>/data/cycle_report.json)")
    args = parser.parse_args()

    step_results = []
    for step in STEPS:
        timing = run_step(step)
        time.sleep(DETECTION_SEARCH_BUFFER_SEC)
        alerts = find_alerts_for_window(timing["detect_sids"], timing["start"], timing["end"])
        timing["alerts"] = alerts
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
                "detected": len(s["alerts"]) > 0,
                "alert_count": len(s["alerts"]),
            }
            for s in step_results
        ],
        "merged_log": merged_log,
    }, indent=2, default=str))
    print(f"\n[run_cycle] merged report written to {report_path}")


if __name__ == "__main__":
    main()
