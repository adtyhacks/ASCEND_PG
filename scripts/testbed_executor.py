"""
scripts/testbed_executor.py

Shared module for executing individual attack steps against the Mininet
testbed and checking Suricata + ML detection results.

Used by:
  - ppo_step_watcher.py  (PPO-driven single-step execution)
  - run_cycle.py         (full 12-step automated cycle)

Provides:
  - TECHNIQUE_TO_STEP: mapping from PPO MITRE technique IDs to step dicts
  - build_step(technique_id): resolve a PPO action to a testbed step
  - run_step(step): execute one attack script via subprocess
  - find_alerts_for_window(sids, start, end): scan Suricata eve.json
  - log_event(event): append to shared data/log_store.json
  - get_hybrid_detector(): get or create the global hybrid detector
  - execute_single_attack(technique_id, detection_mode): run attack + hybrid detection

Run attack scripts ON THE ATTACKER HOST inside the Mininet topology.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACKS_DIR = REPO_ROOT / "attacks"
DATA_DIR = REPO_ROOT / "data"
LOG_STORE_PATH = DATA_DIR / "log_store.json"
WSL_LOG_PATH = str(LOG_STORE_PATH).replace("\\", "/")

DETECTION_SEARCH_BUFFER_SEC = 5
SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")

_hybrid_detector = None

# ---------------------------------------------------------------------------
# PPO technique ID -> testbed step name mapping
# Only techniques with real attack scripts are mapped.
# None means fallback to mock mode.
# ---------------------------------------------------------------------------
TECHNIQUE_TO_STEP_NAME = {
    # Stage 0: Reconnaissance
    "T0846": "recon_nmap_devid",
    "T0888": "recon_nmap_devid",
    "T0842": "recon_fc_scan",
    # Stage 1: Lateral Movement / Collection
    "T0830": "mitm_proxy",
    "T0801": "monitor_process_state",
    # Stage 2: Impair Process Control
    "T0814": "dos_loud",
    "T0816": "device_restart",
    "T0836": "fdi_attack",
    "T0806": "brute_force_io",
    "T0835": "manipulate_io_image",
    # Stage 3: Impact
    "T0832": "replay_attack",
    "T0815": "denial_of_view",
}

# All step definitions (subset of run_cycle.py STEPS, used for single-step exec)
STEP_DEFS = {
    "recon_nmap_devid": {
        "name": "recon_nmap_devid",
        "techniques": ["T0846", "T0888"],
        "script": str(ATTACKS_DIR / "recon_step.py"),
        "args": ["--subnet", "10.0.0.0/24", "--log", WSL_LOG_PATH],
        "detect_sids": [9000004],
        "timeout": 240,
    },
    "recon_fc_scan": {
        "name": "recon_fc_scan",
        "techniques": ["T0840"],
        "script": str(ATTACKS_DIR / "fc_scan.py"),
        "args": ["--target", "10.0.0.1", "--safe", "--log", WSL_LOG_PATH],
        "detect_sids": [9000005, 9000006],
        "timeout": 120,
    },
    "fdi_attack": {
        "name": "fdi_attack",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "fdi_attack.py"),
        "args": ["--target", "10.0.0.1", "-a", "0", "-v", "9999"],
        "detect_sids": [9000001],
        "timeout": 120,
    },
    "naive_response_injection": {
        "name": "naive_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "naive_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--value", "65535",
                  "--duration", "5", "--interval", "1.0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 120,
    },
    "complex_response_injection": {
        "name": "complex_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "complex_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--mode", "ramp",
                  "--magnitude", "5", "--duration", "5", "--interval", "1.0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 120,
    },
    "cmd_inject_coil": {
        "name": "cmd_inject_coil",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "cmd_inject_coil.py"),
        "args": ["--target", "10.0.0.1", "--address", "0", "--value", "True",
                  "--count", "5", "--log", WSL_LOG_PATH],
        "detect_sids": [9000007],
        "timeout": 120,
    },
    "cmd_inject_register": {
        "name": "cmd_inject_register",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "cmd_inject_register.py"),
        "args": ["--target", "10.0.0.1", "--address", "50", "--value", "0",
                  "--count", "5", "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 120,
    },
    "malicious_fc": {
        "name": "malicious_fc",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "malicious_fc.py"),
        "args": ["--target", "10.0.0.1", "--action", "all",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000006, 9000008, 9000009],
        "timeout": 120,
    },
    "dos_quiet": {
        "name": "dos_quiet",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_attack.py"),
        "args": ["--target", "10.0.0.1", "--count", "100", "--delay", "0.05",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000002],
        "timeout": 120,
    },
    "dos_loud": {
        "name": "dos_loud",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_attack.py"),
        "args": ["--target", "10.0.0.1", "--count", "600", "--delay", "0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000002],
        "timeout": 120,
    },
    "dos_conn_exhaust": {
        "name": "dos_conn_exhaust",
        "techniques": ["T0814"],
        "script": str(ATTACKS_DIR / "dos_conn_exhaust.py"),
        "args": ["--target", "10.0.0.1", "--connections", "30",
                  "--hold-time", "10", "--log", WSL_LOG_PATH],
        "detect_sids": [9000002, 9000010],
        "timeout": 120,
    },
    "replay_attack": {
        "name": "replay_attack",
        "techniques": ["T0832"],
        "script": str(ATTACKS_DIR / "replay_attack.py"),
        "args": ["--target", "10.0.0.1", "--iface", "s1-eth7",
                  "--capture-time", "3", "--replay-count", "1",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [],
        "timeout": 180,
    },
    "mitm_proxy": {
        "name": "mitm_proxy",
        "techniques": ["T0830"],
        "script": str(ATTACKS_DIR / "mitm_proxy.py"),
        "args": ["--target", "10.0.0.1", "--listen-port", "503",
                  "--mode", "offset", "--magnitude", "100",
                  "--duration", "10", "--log", WSL_LOG_PATH],
        "detect_sids": [],
        "timeout": 120,
    },
    "device_restart": {
        "name": "device_restart",
        "techniques": ["T0816"],
        "script": str(ATTACKS_DIR / "device_restart.py"),
        "args": ["--target", "10.0.0.1", "--log", WSL_LOG_PATH],
        "detect_sids": [9000007],
        "timeout": 90,
    },
    "brute_force_io": {
        "name": "brute_force_io",
        "techniques": ["T0806"],
        "script": str(ATTACKS_DIR / "brute_force_io.py"),
        "args": ["--target", "10.0.0.1", "--count", "200", "--delay", "0.01",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000002],
        "timeout": 120,
    },
    "denial_of_view": {
        "name": "denial_of_view",
        "techniques": ["T0815"],
        "script": str(ATTACKS_DIR / "denial_of_view.py"),
        "args": ["--scada-ip", "10.0.0.10", "--plc-ip", "10.0.0.1",
                  "--count", "100", "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 90,
    },
    "manipulate_io_image": {
        "name": "manipulate_io_image",
        "techniques": ["T0835"],
        "script": str(ATTACKS_DIR / "manipulate_io_image.py"),
        "args": ["--target", "10.0.0.1", "--start-coil", "0", "--end-coil", "19",
                  "--delay", "0.05", "--log", WSL_LOG_PATH],
        "detect_sids": [9000007],
        "timeout": 90,
    },
    "monitor_process_state": {
        "name": "monitor_process_state",
        "techniques": ["T0801"],
        "script": str(ATTACKS_DIR / "monitor_process_state.py"),
        "args": ["--target", "10.0.0.1", "--start-reg", "0", "--end-reg", "99",
                  "--count", "5", "--delay", "0.5", "--log", WSL_LOG_PATH],
        "detect_sids": [9000002],
        "timeout": 90,
    },
}


def build_step(technique_id: str) -> dict | None:
    """Resolve a PPO technique ID to a testbed step definition.

    Returns the step dict if a real testbed script exists, None otherwise
    (caller should fall back to mock mode).
    """
    step_name = TECHNIQUE_TO_STEP_NAME.get(technique_id)
    if step_name and step_name in STEP_DEFS:
        return STEP_DEFS[step_name]
    return None


def log_event(event: dict):
    """Append one event to the shared JSON log store."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    log_path = Path(WSL_LOG_PATH)
    if log_path.exists():
        try:
            events = json.loads(log_path.read_text())
        except (json.JSONDecodeError, OSError):
            events = []
    events.append(event)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(events, indent=2))


def run_step(step: dict) -> dict:
    """Execute one attack script via subprocess and return timing info.

    Returns dict with: name, start, end, detect_sids, techniques.
    """
    print(f"\n=== [executor] Running: {step['name']} ({'+'.join(step['techniques'])}) ===")
    start = datetime.now(timezone.utc)

    log_event({
        "stage": step["name"],
        "technique": "+".join(step["techniques"]),
        "action": "step_start",
    })

    step_timeout = step.get("timeout", 90)

    try:
        result = subprocess.run(
            ["sudo", sys.executable, step["script"], *step["args"]],
            capture_output=True, text=True, timeout=step_timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[executor] WARNING: {step['name']} timed out after {step_timeout}s")
        log_event({
            "stage": step["name"],
            "technique": "+".join(step["techniques"]),
            "action": "step_timeout",
            "timeout_sec": step_timeout,
        })
        end = datetime.now(timezone.utc)
        return {
            "name": step["name"], "start": start, "end": end,
            "detect_sids": step["detect_sids"], "techniques": step["techniques"],
        }

    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0:
        print(f"[executor] WARNING: {step['script']} exited {result.returncode}")
        if result.stderr:
            print(result.stderr.strip())

    end = datetime.now(timezone.utc)
    log_event({
        "stage": step["name"],
        "technique": "+".join(step["techniques"]),
        "action": "step_end",
        "returncode": result.returncode,
    })
    return {
        "name": step["name"], "start": start, "end": end,
        "detect_sids": step["detect_sids"], "techniques": step["techniques"],
    }


def find_alerts_for_window(sids: list, start: datetime, end: datetime) -> list:
    """Scan Suricata's eve.json for alerts matching the given SIDs
    within the time window [start, end + buffer].

    Returns list of matching alert entry dicts.
    """
    if not SURICATA_EVE_LOG.exists():
        return []

    window_end = end.timestamp() + DETECTION_SEARCH_BUFFER_SEC
    matches = []

    with open(SURICATA_EVE_LOG) as f:
        for line in f:
            line = line.strip()
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

            flow = entry.get("flow", {})
            flow_start_str = flow.get("start")
            if flow_start_str:
                ts = datetime.fromisoformat(flow_start_str.replace("Z", "+00:00"))
            else:
                ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))

            if start.timestamp() <= ts.timestamp() <= window_end:
                matches.append(entry)

    return matches


def get_hybrid_detector(interface="s1-eth7", use_ml=True):
    global _hybrid_detector
    if _hybrid_detector is None:
        try:
            sys.path.insert(0, str(REPO_ROOT))
            from defense.hybrid_detector import HybridDetector
            _hybrid_detector = HybridDetector(
                interface=interface, use_ml=use_ml, use_suricata=True
            )
            print(f"[executor] Hybrid detector initialized (ml={'on' if use_ml else 'off'})")
        except Exception as e:
            print(f"[executor] Warning: Hybrid detector init failed: {e}")
            print("[executor] Falling back to Suricata-only detection")
            _hybrid_detector = None
    return _hybrid_detector


def execute_single_attack(technique_id: str, detection_mode="hybrid") -> dict:
    step = build_step(technique_id)
    if step is None:
        raise ValueError(f"No testbed step for technique {technique_id}")

    detector = get_hybrid_detector(use_ml=(detection_mode != "suricata_only"))

    if detector and detection_mode == "hybrid":
        detector.start_capture()

    timing = run_step(step)
    time.sleep(DETECTION_SEARCH_BUFFER_SEC)

    if detector and detection_mode == "hybrid":
        verdict = detector.get_verdict(
            timing["start"], timing["end"], timing["detect_sids"]
        )
        return {
            "detected": verdict["combined_detected"],
            "alert_count": verdict["suricata_alert_count"],
            "alert_signatures": verdict["suricata_signatures"],
            "ml_detected": verdict["ml_detected"],
            "ml_confidence": verdict["ml_confidence"],
            "ml_lstm_confidence": verdict["ml_lstm_confidence"],
            "ml_ae_score": verdict["ml_ae_score"],
            "ml_available": verdict["ml_available"],
            "detection_method": verdict["detection_method"],
            "step_name": timing["name"],
            "techniques": timing["techniques"],
            "mode": "hybrid",
        }

    alerts = find_alerts_for_window(
        timing["detect_sids"], timing["start"], timing["end"]
    )
    return {
        "detected": len(alerts) > 0,
        "alert_count": len(alerts),
        "alert_signatures": [
            a.get("alert", {}).get("signature", "unknown") for a in alerts
        ],
        "ml_detected": False,
        "ml_confidence": 0.0,
        "ml_lstm_confidence": 0.0,
        "ml_ae_score": 0.0,
        "ml_available": False,
        "detection_method": "suricata",
        "step_name": timing["name"],
        "techniques": timing["techniques"],
        "mode": "suricata_only",
    }
