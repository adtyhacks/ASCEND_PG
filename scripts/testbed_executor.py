"""
scripts/testbed_executor.py

Shared module for executing individual attack steps against the CORE 9.2.1
testbed and checking Suricata + ML detection results.

Key Capabilities:
  - Explicit Attack Execution State Machine (SUCCESS, DETECTED, UNDETECTED, FAILED, TIMEOUT, etc.)
  - Authoritative MITRE ATT&CK for ICS mappings via data.mitre_registry (including T0855 & T0840/T0842)
  - Non-colliding network addressing (SCADA 10.0.0.100, Attacker 10.0.0.66, IDS 10.0.0.99)
  - Dynamic CORE network interface discovery (eth0 in node namespaces, bridge taps in root)
  - Research-grade evaluation: Failed/timed out attacks are NEVER classified as evasions
"""

import copy
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from testbed.ip_config import SCADA_IP, ATTACKER_IP, MONITOR_IP, get_plc_ip
from data.mitre_registry import (
    TECHNIQUES,
    get_technique_by_id,
    get_step_for_technique,
)

ATTACKS_DIR = REPO_ROOT / "attacks"
DATA_DIR = REPO_ROOT / "data"
LOG_STORE_PATH = DATA_DIR / "log_store.json"
WSL_LOG_PATH = str(LOG_STORE_PATH).replace("\\", "/")

DETECTION_SEARCH_BUFFER_SEC = 5
_hybrid_detector = None
_INTERFACE_CACHE = None


class AttackStatus(str, Enum):
    """Explicit attack execution and detection states."""
    SUCCESS = "SUCCESS"                   # Attack subprocess finished successfully (returncode == 0)
    DETECTED = "DETECTED"                 # Executed and detected by Suricata or ML models
    UNDETECTED = "UNDETECTED"             # Verified evasion: attack ran, target reached, 0 alerts
    FAILED = "FAILED"                     # Subprocess exited non-zero or crashed
    TIMEOUT = "TIMEOUT"                   # Attack timed out
    INVALID = "INVALID"                   # Invalid target or parameters
    UNSUPPORTED = "UNSUPPORTED"           # No attack implementation found
    EXECUTION_ERROR = "EXECUTION_ERROR"   # Unhandled exception during execution


def _detect_interface() -> str:
    """
    Dynamically discover the network capture interface.
    Inside CORE node namespaces, host interfaces are named 'eth0'.
    In the root namespace, Suricata monitors the bridge tap (e.g. b.1.1, s1) or eth0.
    """
    global _INTERFACE_CACHE
    if _INTERFACE_CACHE is not None:
        return _INTERFACE_CACHE

    env_iface = os.environ.get("ASCEND_CAPTURE_IFACE")
    if env_iface:
        _INTERFACE_CACHE = env_iface
        return env_iface

    # Priority list of interface candidates
    # In Linux network namespaces (vcmd/vnoded), eth0 is the standard link.
    candidates = ["eth0", "s1", "b.1.1", "core.br.1", "attacker-eth0", "s1-eth7", "lo"]
    import subprocess as _sp
    for iface in candidates:
        try:
            res = _sp.run(["ip", "link", "show", iface],
                          capture_output=True, timeout=3, check=True)
            if res.returncode == 0:
                _INTERFACE_CACHE = iface
                print(f"[executor] Auto-detected interface: {iface}")
                return iface
        except Exception:
            continue

    _INTERFACE_CACHE = "eth0"
    return _INTERFACE_CACHE


def _parse_suricata_ts(ts_str: str) -> datetime:
    """Parse Suricata timestamps like '2026-09-09T14:48:03.781984+0530'."""
    import re
    ts_str = ts_str.replace("Z", "+00:00")
    if re.search(r'[+-]\d{4}$', ts_str):
        ts_str = ts_str[:-2] + ':' + ts_str[-2:]
    return datetime.fromisoformat(ts_str)


# ---------------------------------------------------------------------------
# Technique ID -> Testbed Step Name mapping (Authoritative)
# ---------------------------------------------------------------------------
TECHNIQUE_TO_STEP_NAME: Dict[str, str] = {
    # Stage 0: Initial Access & Discovery
    "T0886": "remote_services",
    "T0846": "recon_nmap_devid",
    "T0888": "recon_nmap_devid",
    "T0840": "recon_fc_scan",
    "T0842": "recon_fc_scan",  # Historical alias for T0840 in RL agent
    # Stage 1: Lateral Movement & Collection & C2
    "T0830": "mitm_proxy",
    "T0801": "monitor_process_state",
    "T0802": "automated_collection",
    "T0869": "standard_protocol_c2",
    # Stage 2: Inhibit Response & Impair Process Control
    "T0814": "dos_loud",
    "T0878": "alarm_suppression",
    "T0816": "device_restart",
    "T0881": "service_stop",
    "T0836": "fdi_attack",
    "T0835": "manipulate_io_image",
    "T0806": "brute_force_io",
    "T0855": "cmd_inject_coil",  # Primary command injection
    # Stage 3: Impact
    "T0832": "replay_attack",
    "T0815": "denial_of_view",
}

# Step Definitions with arguments
STEP_DEFS: Dict[str, Dict[str, Any]] = {
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
        "techniques": ["T0840", "T0842"],
        "script": str(ATTACKS_DIR / "fc_scan.py"),
        "args": ["--target", "10.0.0.1", "--safe", "--log", WSL_LOG_PATH],
        "detect_sids": [9000005, 9000006],
        "timeout": 120,
    },
    "fdi_attack": {
        "name": "fdi_attack",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "fdi_attack.py"),
        "args": ["--target", "10.0.0.1", "-a", "40000", "-v", "9999"],
        "detect_sids": [9000001],
        "timeout": 120,
        "register_arg": "-a",
        "value_arg": "-v",
    },
    "naive_response_injection": {
        "name": "naive_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "naive_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "40000", "--value", "65535",
                  "--duration", "5", "--interval", "1.0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 120,
    },
    "complex_response_injection": {
        "name": "complex_response_injection",
        "techniques": ["T0836"],
        "script": str(ATTACKS_DIR / "complex_response_injection.py"),
        "args": ["--target", "10.0.0.1", "--address", "40000", "--mode", "ramp",
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
        "register_arg": "--address",
        "value_arg": "--value",
    },
    "cmd_inject_register": {
        "name": "cmd_inject_register",
        "techniques": ["T0855"],
        "script": str(ATTACKS_DIR / "cmd_inject_register.py"),
        "args": ["--target", "10.0.0.1", "--address", "40050", "--value", "0",
                  "--count", "5", "--log", WSL_LOG_PATH],
        "detect_sids": [9000001],
        "timeout": 120,
        "register_arg": "--address",
        "value_arg": "--value",
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
        "detect_sids": [9000023],
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
        "args": ["--target", "10.0.0.1", "--iface", "eth0",
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
        "detect_sids": [9000022],
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
        "detect_sids": [9000023],
        "timeout": 120,
    },
    "denial_of_view": {
        "name": "denial_of_view",
        "techniques": ["T0815"],
        "script": str(ATTACKS_DIR / "denial_of_view.py"),
        "args": ["--scada-ip", SCADA_IP, "--plc-ip", "10.0.0.1",
                  "--count", "100", "--log", WSL_LOG_PATH],
        "detect_sids": [9000001, 9000024],
        "timeout": 90,
    },
    "manipulate_io_image": {
        "name": "manipulate_io_image",
        "techniques": ["T0835"],
        "script": str(ATTACKS_DIR / "manipulate_io_image.py"),
        "args": ["--target", "10.0.0.1", "--coil-start", "0", "--coil-count", "20",
                  "--delay", "0.05", "--log", WSL_LOG_PATH],
        "detect_sids": [9000007],
        "timeout": 90,
    },
    "monitor_process_state": {
        "name": "monitor_process_state",
        "techniques": ["T0801"],
        "script": str(ATTACKS_DIR / "monitor_process_state.py"),
        "args": ["--target", "10.0.0.1", "--start-reg", "30000", "--end-reg", "30099",
                  "--count", "5", "--delay", "0.5", "--log", WSL_LOG_PATH],
        "detect_sids": [9000023],
        "timeout": 90,
    },
    "remote_services": {
        "name": "remote_services",
        "techniques": ["T0886"],
        "script": str(ATTACKS_DIR / "remote_services.py"),
        "args": ["--target", "10.0.0.1", "--scada-ip", SCADA_IP,
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000026],
        "timeout": 120,
        "register_arg": "-a",
        "value_arg": "-v",
    },
    "automated_collection": {
        "name": "automated_collection",
        "techniques": ["T0802"],
        "script": str(ATTACKS_DIR / "automated_collection.py"),
        "args": ["--target", "10.0.0.1", "--subnet", "10.0.0.0/24",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000027],
        "timeout": 180,
        "register_arg": "-a",
        "value_arg": "-v",
    },
    "standard_protocol_c2": {
        "name": "standard_protocol_c2",
        "techniques": ["T0869"],
        "script": str(ATTACKS_DIR / "standard_protocol_c2.py"),
        "args": ["--target", "10.0.0.1", "--command", "DEAD",
                  "--count", "5", "--interval", "1.0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000028],
        "timeout": 120,
        "register_arg": "-a",
        "value_arg": "-v",
    },
    "alarm_suppression": {
        "name": "alarm_suppression",
        "techniques": ["T0878"],
        "script": str(ATTACKS_DIR / "alarm_suppression.py"),
        "args": ["--target", "10.0.0.1", "--duration", "5", "--interval", "1.0",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000029],
        "timeout": 120,
        "register_arg": "-a",
        "value_arg": "-v",
    },
    "service_stop": {
        "name": "service_stop",
        "techniques": ["T0881"],
        "script": str(ATTACKS_DIR / "service_stop.py"),
        "args": ["--target", "10.0.0.1", "--mode", "combined", "--count", "100",
                  "--log", WSL_LOG_PATH],
        "detect_sids": [9000030],
        "timeout": 120,
        "value_arg": "-v",
    },
}


def build_step(technique_id: str, target_ip: str = "10.0.0.1",
               register_address: int = 40000,
               value_magnitude: float = 1.0) -> Optional[Dict[str, Any]]:
    """Resolve a technique ID to an executable testbed step definition."""
    step_name = TECHNIQUE_TO_STEP_NAME.get(technique_id)
    if step_name and step_name in STEP_DEFS:
        step = copy.deepcopy(STEP_DEFS[step_name])
        new_args = [target_ip if a == "10.0.0.1" else a for a in step["args"]]
        reg_flag = step.get("register_arg")
        val_flag = step.get("value_arg")
        if technique_id == "T0855" and step_name == "cmd_inject_coil" and reg_flag in new_args and val_flag in new_args:
            # T0855's configured value is a boolean actuator command. Apply the
            # selected coil address in place, but do not feed the generic PPO
            # floating-point magnitude into cmd_inject_coil's boolean option.
            register_index = new_args.index(reg_flag) + 1
            new_args[register_index] = str(register_address)
        elif technique_id == "T0836" and reg_flag in new_args and val_flag in new_args:
            register_index = new_args.index(reg_flag) + 1
            value_index = new_args.index(val_flag) + 1
            new_args[register_index] = str(register_address)
            new_args[value_index] = str(round(int(new_args[value_index]) * value_magnitude))
        elif reg_flag and val_flag:
            new_args.extend([reg_flag, str(register_address),
                             val_flag, str(value_magnitude)])
        step["args"] = new_args
        return step
    return None


def log_event(event: Dict[str, Any]):
    """Append one event to the shared JSON log store."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path = Path(WSL_LOG_PATH)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def run_step(step: Dict[str, Any]) -> Dict[str, Any]:
    """Execute attack script subprocess with full returncode and error capture."""
    detected_iface = _detect_interface()
    # Replace any legacy interface placeholder with dynamically detected interface
    step_args = [detected_iface if a in ("eth0", "s1-eth7", "attacker-eth0") else a for a in step["args"]]

    print(f"\n=== [executor] Running: {step['name']} ({'+'.join(step['techniques'])}) ===")
    print(f"[executor] Using interface: {detected_iface}")
    start = datetime.now(timezone.utc)

    log_event({
        "stage": step["name"],
        "technique": "+".join(step["techniques"]),
        "action": "step_start",
    })

    step_timeout = step.get("timeout", 90)
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    cmd_prefix = [sys.executable] if is_root else ["sudo", sys.executable]

    status = AttackStatus.SUCCESS
    returncode = 0
    stdout = ""
    stderr = ""
    error_msg = None

    try:
        result = subprocess.run(
            cmd_prefix + [step["script"], *step_args],
            capture_output=True, text=True, timeout=step_timeout,
        )
        returncode = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if returncode != 0:
            status = AttackStatus.FAILED
            error_msg = f"Process exited with code {returncode}: {stderr.strip()[:200]}"
            print(f"[executor] WARNING: {step['script']} exited {returncode}")
            if stderr:
                print(stderr.strip())
        else:
            status = AttackStatus.SUCCESS
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        status = AttackStatus.TIMEOUT
        returncode = -1
        error_msg = f"Timed out after {step_timeout}s"
        print(f"[executor] WARNING: {step['name']} timed out after {step_timeout}s")
        log_event({
            "stage": step["name"],
            "technique": "+".join(step["techniques"]),
            "action": "step_timeout",
            "timeout_sec": step_timeout,
        })
    except Exception as exc:
        status = AttackStatus.EXECUTION_ERROR
        returncode = -2
        error_msg = str(exc)
        print(f"[executor] ERROR running {step['name']}: {exc}")

    end = datetime.now(timezone.utc)
    log_event({
        "stage": step["name"],
        "technique": "+".join(step["techniques"]),
        "action": "step_end",
        "status": status.value,
        "returncode": returncode,
        "error": error_msg,
    })

    return {
        "name": step["name"],
        "start": start,
        "end": end,
        "detect_sids": step["detect_sids"],
        "techniques": step["techniques"],
        "status": status,
        "success": status == AttackStatus.SUCCESS,
        "return_code": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "error": error_msg,
    }


# Re-export from hybrid_detector to avoid duplicate implementation
try:
    from defense.hybrid_detector import _find_suricata_alerts as find_alerts_for_window
except ImportError:
    def find_alerts_for_window(sids, start, end):
        return []


def get_hybrid_detector(interface=None, use_ml=True, use_suricata=True):
    global _hybrid_detector
    if _hybrid_detector is not None:
        return _hybrid_detector
    if interface is None:
        interface = _detect_interface()
    try:
        from defense.hybrid_detector import HybridDetector
        _hybrid_detector = HybridDetector(
            interface=interface, use_ml=use_ml, use_suricata=use_suricata
        )
        print(f"[executor] Hybrid detector initialized (ml={'on' if use_ml else 'off'}, suricata={'on' if use_suricata else 'off'})")
    except Exception as e:
        print(f"[executor] Warning: Hybrid detector init failed: {e}")
        print("[executor] Falling back to Suricata-only detection")
        _hybrid_detector = None
    return _hybrid_detector


def execute_single_attack(technique_id: str, detection_mode="hybrid",
                          target_ip: str = "10.0.0.1",
                          register_address: int = 40000,
                          value_magnitude: float = 1.0) -> Dict[str, Any]:
    """
    Execute attack and correlate with Suricata & ML detection.
    Enforces the scientific contract: Failed/timed out attacks are NEVER marked as evasions.
    """
    step = build_step(technique_id, target_ip=target_ip,
                      register_address=register_address,
                      value_magnitude=value_magnitude)
    if step is None:
        return {
            "status": AttackStatus.UNSUPPORTED.value,
            "success": False,
            "detected": False,
            "evaded": False,
            "technique_id": technique_id,
            "step_name": "unknown",
            "target_ip": target_ip,
            "return_code": -1,
            "alert_count": 0,
            "alert_signatures": [],
            "ml_detected": False,
            "ml_confidence": 0.0,
            "detection_method": "none",
            "error": f"No testbed step mapping for technique {technique_id}",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "mode": detection_mode,
            "network_flows": [],
        }

    use_ml = detection_mode in ("hybrid", "ml_only")
    use_suricata = detection_mode in ("hybrid", "suricata_only")
    detector = get_hybrid_detector(use_ml=use_ml, use_suricata=use_suricata)
    captured_flows = []

    if detector and use_ml:
        detector.clear_flows()
        detector.start_capture()

    timing = run_step(step)
    time.sleep(DETECTION_SEARCH_BUFFER_SEC)

    suricata_alerts = []
    ml_detected = False
    ml_confidence = 0.0
    ml_lstm = 0.0
    ml_ae = 0.0
    ml_avail = False
    ml_err = None
    detection_method = "suricata"

    try:
        if detector and use_ml:
            verdict = detector.get_verdict(
                timing["start"], timing["end"], timing["detect_sids"]
            )
            detected = verdict["combined_detected"]
            alert_count = verdict["suricata_alert_count"]
            alert_signatures = verdict["suricata_signatures"]
            ml_detected = verdict["ml_detected"]
            ml_confidence = verdict["ml_confidence"]
            ml_lstm = verdict["ml_lstm_confidence"]
            ml_ae = verdict["ml_ae_score"]
            ml_avail = verdict["ml_available"]
            ml_err = verdict.get("ml_error")
            detection_method = verdict["detection_method"]
        else:
            if use_suricata:
                suricata_alerts = find_alerts_for_window(
                    timing["detect_sids"], timing["start"], timing["end"]
                )
            detected = len(suricata_alerts) > 0
            alert_count = len(suricata_alerts)
            alert_signatures = [
                a.get("alert", {}).get("signature", "unknown") for a in suricata_alerts
            ]
            detection_method = "suricata" if detected else "none"
    finally:
        if detector and use_ml:
            try:
                if detector.extractor:
                    captured_flows = detector.extractor.raw_flow_snapshot()
            except Exception as exc:
                print(f"[executor] Warning: captured-flow snapshot failed: {exc}")
            finally:
                detector.stop_capture()

    # Determine final state & verified evasion
    execution_success = timing["success"]
    if timing["status"] == AttackStatus.TIMEOUT:
        final_status = AttackStatus.TIMEOUT
        evaded = False
        detected = False
    elif not execution_success:
        final_status = AttackStatus.FAILED
        evaded = False
        detected = False
    elif detected:
        final_status = AttackStatus.DETECTED
        evaded = False
    else:
        # TRUE EVASION: executed successfully AND 0 alerts detected
        final_status = AttackStatus.UNDETECTED
        evaded = True

    from metrics.finding_evidence import retain_evidence, passive_scada, attack_log_records
    finding_evidence = retain_evidence(timing["name"], timing.get("stdout"), timing.get("stderr"),
        timing["end"].isoformat(), passive_scada(Path(__file__).resolve().parents[1] / "data/core-runtime/scada.jsonl"),
        attack_log_records(Path(__file__).resolve().parents[1] / "data/log_store.json", timing["name"]))
    return {
        "status": final_status.value,
        "finding_evidence": finding_evidence,
        "success": execution_success,
        "detected": detected,
        "evaded": evaded,
        "technique_id": technique_id,
        "step_name": timing["name"],
        "target_ip": target_ip,
        "return_code": timing["return_code"],
        "alert_count": alert_count,
        "alert_signatures": alert_signatures,
        "ml_detected": ml_detected,
        "ml_confidence": ml_confidence,
        "ml_lstm_confidence": ml_lstm,
        "ml_ae_score": ml_ae,
        "ml_available": ml_avail,
        "ml_error": ml_err or timing.get("error"),
        "detection_method": detection_method,
        "techniques": timing["techniques"],
        "mode": detection_mode,
        "start_time": timing["start"].isoformat(),
        "end_time": timing["end"].isoformat(),
        "network_flows": captured_flows,
        "error": timing.get("error"),
    }
