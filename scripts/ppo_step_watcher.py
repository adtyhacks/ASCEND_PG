#!/usr/bin/env python3
"""
scripts/ppo_step_watcher.py

File-based step executor and heartbeat provider for PPO-driven testbed attacks.
Runs on the CORE ATTACKER HOST (or WSL testbed runner).

Key Capabilities:
  - Active Heartbeat: periodically writes data/watcher_heartbeat.json with status
    (STARTING, IDLE, BUSY, ERROR, OFFLINE) and epoch timestamps.
  - Consumes pending steps from data/pending_step.json.
  - Executes attacks via testbed_executor.execute_single_attack().
  - Enforces explicit execution status (SUCCESS, DETECTED, UNDETECTED, FAILED, TIMEOUT).
  - Writes structured results to data/step_result.json.
"""

import atexit
import fcntl
import json
import os
import signal
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.testbed_executor import (
    STEP_DEFS,
    AttackStatus,
    execute_single_attack,
    get_hybrid_detector,
    log_event,
)
from testbed.run_store import append_event

DATA_DIR = REPO_ROOT / "data"
PENDING_STEP = DATA_DIR / "pending_step.json"
STEP_RESULT = DATA_DIR / "step_result.json"
HEARTBEAT_FILE = DATA_DIR / "watcher_heartbeat.json"

POLL_INTERVAL = 0.5          # seconds
HEARTBEAT_INTERVAL = 1.0     # seconds
_watcher_lock = None
_heartbeat_lock = threading.RLock()
_heartbeat_stop = threading.Event()
_heartbeat_latest = ("STARTING", None)

def generation_matches(payload: Dict[str, Any], generation_id: str) -> bool:
    """Reject stale handoff records even when CORE reuses a numeric ID."""
    return bool(generation_id) and payload.get("generation_id") == generation_id


def atomic_json(path, value):
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def write_heartbeat(status: str, extra: Optional[Dict[str, Any]] = None):
    """Write active heartbeat for the Streamlit UI to monitor."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "timestamp": time.time(),
        "utc_time": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(),
        "session_id": os.environ.get("ASCEND_SESSION_ID"),
        "generation_id": os.environ.get("ASCEND_SESSION_GENERATION"),
    }
    if extra:
        payload.update(extra)
    global _heartbeat_latest
    with _heartbeat_lock:
        _heartbeat_latest = (status, extra)
        try:
            atomic_json(HEARTBEAT_FILE, payload)
        except OSError as exc:
            print(f"[watcher] Heartbeat write failed: {exc}", file=sys.stderr)


def heartbeat_loop():
    while not _heartbeat_stop.wait(HEARTBEAT_INTERVAL):
        with _heartbeat_lock:
            if not _heartbeat_stop.is_set():
                write_heartbeat(*_heartbeat_latest)


def cleanup():
    """Mark watcher as OFFLINE on process exit."""
    if _watcher_lock is None:
        return
    _heartbeat_stop.set()
    try:
        write_heartbeat("OFFLINE")
        if HEARTBEAT_FILE.exists():
            HEARTBEAT_FILE.unlink(missing_ok=True)
    except Exception:
        pass


atexit.register(cleanup)


def read_pending_step() -> Optional[Dict[str, Any]]:
    """Read and consume the pending step file atomically."""
    if not PENDING_STEP.exists():
        return None
    try:
        data = json.loads(PENDING_STEP.read_text(encoding="utf-8"))
        PENDING_STEP.unlink(missing_ok=True)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def write_step_result(result: Dict[str, Any]):
    """Write the step result for Streamlit to consume."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    atomic_json(STEP_RESULT, result)


def clear_old_result():
    """Remove any stale result or pending files on startup."""
    STEP_RESULT.unlink(missing_ok=True)
    PENDING_STEP.unlink(missing_ok=True)


def record_attack_started(pending: Dict[str, Any], generation_id: str) -> dict:
    """Persist the start boundary immediately before the real executor runs."""
    scenario_id = pending["scenario_id"]
    run_id = pending["run_id"]
    return append_event(
        scenario_id, run_id, category="security", event_type="attack_started",
        source_node="attacker", target_node=pending["target_node"],
        result="started", mitre_technique=pending["technique_id"],
        attack_stage=pending.get("attack_stage", 0), campaign_id=pending["campaign_id"],
        generation_id=generation_id, correlation_id=pending["correlation_id"],
        evidence={"step_name": pending["step_name"], "target_ip": pending["target_ip"],
                  "register_address": pending.get("register_address"),
                  "value_magnitude": pending.get("value_magnitude")},
    )


def record_network_events(pending: Dict[str, Any], result: Dict[str, Any]) -> list[dict]:
    """Persist observed captured flows using the validated pending-step identity."""
    if result.get("success") is not True:
        return []

    identity_fields = ("scenario_id", "run_id", "generation_id", "correlation_id")
    if any(not pending.get(field) for field in identity_fields):
        return []

    recorded = []
    for flow in result.get("network_flows") or []:
        if not isinstance(flow, dict):
            continue
        timestamp = flow.get("timestamp")
        source_ip = flow.get("source_ip")
        destination_ip = flow.get("destination_ip")
        protocol = flow.get("protocol")
        if timestamp is None or not source_ip or not destination_ip or not protocol:
            continue

        source_node = None
        target_node = None
        target_ip = pending.get("target_ip")
        requested_target = pending.get("target_node")
        if requested_target and target_ip == destination_ip:
            target_node = requested_target
        elif requested_target and target_ip == source_ip:
            source_node = requested_target

        event_timestamp = datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat()
        identity = {
            "campaign_id": pending.get("campaign_id"),
            "generation_id": pending["generation_id"],
            "correlation_id": pending["correlation_id"],
            "ppo_step": pending.get("current_step"),
            "technique_id": pending.get("technique_id"),
            "step_name": pending.get("step_name"),
        }
        # The watcher process is launched for one owned session generation;
        # preserve its session identity when the normal launcher supplied it.
        session_id = os.environ.get("ASCEND_SESSION_ID")
        if session_id:
            identity["core_session_id"] = session_id

        event = append_event(
            pending["scenario_id"], pending["run_id"],
            category="network", event_type="flow_observed",
            timestamp=event_timestamp, source_node=source_node, target_node=target_node,
            severity="INFO", protocol=protocol,
            source_ip=source_ip, destination_ip=destination_ip,
            source_port=flow.get("source_port"),
            destination_port=flow.get("destination_port"),
            evidence={
                "flow_end_timestamp": flow.get("end_timestamp"),
                "flow_duration_seconds": flow.get("flow_duration_seconds"),
                "packet_count": flow.get("packet_count"),
                "forward_packet_count": flow.get("forward_packet_count"),
                "backward_packet_count": flow.get("backward_packet_count"),
                "captured_tcp_payload_bytes": flow.get("captured_tcp_payload_bytes"),
            },
            **identity,
        )
        recorded.append(event)
    return recorded


def main():
    global _watcher_lock
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock = (DATA_DIR / "watcher.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        raise RuntimeError("A PPO watcher is already running for this checkout")
    _watcher_lock = lock
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print("=" * 60)
    print(" ASCEND-PG PPO Step Watcher & Heartbeat Service")
    print("=" * 60)
    print(f" Polling:   {PENDING_STEP}")
    print(f" Results:   {STEP_RESULT}")
    print(f" Heartbeat: {HEARTBEAT_FILE}")
    print(f" Interval:  {POLL_INTERVAL}s")
    print("=" * 60)

    write_heartbeat("STARTING")
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    detector = get_hybrid_detector()
    if detector and detector.is_ml_available():
        print(" [defense] ML models loaded (LSTM + Autoencoder)")
        print(" [defense] Suricata: active | ML: active | Mode: hybrid")
    else:
        print(" [defense] ML models NOT available — using Suricata only")

    clear_old_result()
    steps_executed = 0
    last_heartbeat = 0.0

    print(" Waiting for steps from Live Battle page...")
    print(" Press Ctrl+C to stop.")

    try:
        while True:
            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                write_heartbeat("IDLE", {"steps_executed": steps_executed})
                last_heartbeat = now

            pending = read_pending_step()
            if pending is not None:
                technique_id = pending.get("technique_id", "")
                step_name = pending.get("step_name", "unknown")
                register_address = pending.get("register_address", 40000)
                value_magnitude = pending.get("value_magnitude", 1.0)
                target_bus = pending.get("target_bus", 0)
                target_ip = pending.get("target_ip", "10.0.0.1")
                generation = os.environ.get("ASCEND_SESSION_GENERATION")
                if not generation_matches(pending, generation):
                    print("[watcher] Ignored pending step from a different session generation")
                    continue

                print(f"\n[watcher] Received step: {step_name} ({technique_id})")
                print(f"  Target: {target_ip} (Bus {target_bus})")
                print(f"  Register: {register_address} | Value magnitude: {value_magnitude:.3f}")

                write_heartbeat("BUSY", {
                    "current_step": step_name,
                    "technique_id": technique_id,
                    "target_ip": target_ip,
                    "steps_executed": steps_executed,
                })

                log_event({
                    "stage": step_name,
                    "technique": technique_id,
                    "action": "watcher_received",
                    "target": target_ip,
                    "register": register_address,
                    "value_magnitude": value_magnitude,
                })

                try:
                    started_event = record_attack_started(pending, generation)
                    result = execute_single_attack(
                        technique_id,
                        detection_mode="hybrid",
                        target_ip=target_ip,
                        register_address=register_address,
                        value_magnitude=value_magnitude,
                    )
                    result["target_bus"] = target_bus
                    result["register_address"] = register_address
                    result["value_magnitude"] = value_magnitude
                    result["generation_id"] = generation
                    result["campaign_id"] = pending.get("campaign_id")
                    result["correlation_id"] = pending.get("correlation_id")
                    result["run_id"] = pending.get("run_id")
                    result["scenario_id"] = pending.get("scenario_id")
                    result["attack_started_at"] = started_event["timestamp"]
                    from metrics.finding_evidence import bind_evidence
                    result["finding_evidence"] = bind_evidence(result.get("finding_evidence"),
                        pending, started_event["timestamp"], result.get("end_time"))

                    steps_executed += 1
                    status = result.get("status", AttackStatus.SUCCESS.value)
                    method = result.get("detection_method", "none")
                    ml_conf = result.get("ml_confidence", 0.0)

                    print(f"[watcher] Result: status={status}, detected={result.get('detected')}, "
                          f"evaded={result.get('evaded')}, method={method}, alerts={result.get('alert_count', 0)}, "
                          f"ml_conf={ml_conf:.3f}")

                except Exception as exc:
                    result = {
                        "status": AttackStatus.EXECUTION_ERROR.value,
                        "success": False,
                        "detected": False,
                        "evaded": False,
                        "error": str(exc),
                        "technique_id": technique_id,
                        "step_name": step_name,
                        "target_ip": target_ip,
                        "target_bus": target_bus,
                        "return_code": -2,
                        "alert_count": 0,
                        "alert_signatures": [],
                        "ml_detected": False,
                        "ml_confidence": 0.0,
                        "detection_method": "failed",
                        "start_time": datetime.now(timezone.utc).isoformat(),
                        "end_time": datetime.now(timezone.utc).isoformat(),
                        "generation_id": generation,
                        "campaign_id": pending.get("campaign_id"),
                        "correlation_id": pending.get("correlation_id"),
                        "run_id": pending.get("run_id"),
                        "scenario_id": pending.get("scenario_id"),
                    }
                    print(f"[watcher] EXECUTION ERROR: {exc}")
                    write_heartbeat("ERROR", {"error": str(exc)})

                try:
                    record_network_events(pending, result)
                except Exception as exc:
                    # Evidence persistence must not rewrite the authoritative step result.
                    print(f"[watcher] Network event persistence failed: {exc}", file=sys.stderr)

                write_step_result(result)
                print(f"[watcher] Result written. Total steps executed: {steps_executed}")
                write_heartbeat("IDLE", {"steps_executed": steps_executed})
                last_heartbeat = time.time()

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[watcher] Stopped by user. Total steps executed: {steps_executed}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
