#!/usr/bin/env python3
"""
scripts/ppo_step_watcher.py

File-based step executor for PPO-driven testbed attacks.

Runs on the Mininet ATTACKER HOST. Polls data/pending_step.json for
step commands written by the Streamlit Live Battle page (running on
Windows). Executes the attack, scans Suricata for alerts, writes
the result to data/step_result.json.

Protocol:
  1. Streamlit writes:  data/pending_step.json
  2. Watcher reads it, deletes the file, executes the attack
  3. Watcher writes:    data/step_result.json
  4. Streamlit reads the result, deletes the file, feeds to PPO

Usage (on the attacker host inside Mininet):
    python3 scripts/ppo_step_watcher.py

Or via start_testbed.py menu option [6].
"""

import json
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.testbed_executor import (
    STEP_DEFS,
    execute_single_attack,
    log_event,
)

DATA_DIR = REPO_ROOT / "data"
PENDING_STEP = DATA_DIR / "pending_step.json"
STEP_RESULT = DATA_DIR / "step_result.json"

POLL_INTERVAL = 0.5  # seconds


def read_pending_step() -> dict | None:
    """Read and consume the pending step file."""
    if not PENDING_STEP.exists():
        return None
    try:
        data = json.loads(PENDING_STEP.read_text(encoding="utf-8"))
        PENDING_STEP.unlink(missing_ok=True)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def write_step_result(result: dict):
    """Write the step result for Streamlit to consume."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STEP_RESULT.write_text(json.dumps(result, indent=2), encoding="utf-8")


def clear_old_result():
    """Remove any stale result file on startup."""
    STEP_RESULT.unlink(missing_ok=True)


def main():
    print("=" * 60)
    print(" ASCEND-PG PPO Step Watcher")
    print("=" * 60)
    print(f" Polling: {PENDING_STEP}")
    print(f" Results: {STEP_RESULT}")
    print(f" Interval: {POLL_INTERVAL}s")
    print(" Waiting for steps from Live Battle page...")
    print(" Press Ctrl+C to stop.")
    print("=" * 60)

    clear_old_result()
    steps_executed = 0

    try:
        while True:
            pending = read_pending_step()
            if pending is not None:
                technique_id = pending.get("technique_id", "")
                step_name = pending.get("step_name", "unknown")
                print(f"\n[watcher] Received step: {step_name} ({technique_id})")

                log_event({
                    "stage": step_name,
                    "technique": technique_id,
                    "action": "watcher_received",
                })

                try:
                    step_def = STEP_DEFS.get(step_name)
                    if step_def is None:
                        result = {
                            "success": False,
                            "error": f"Unknown step: {step_name}",
                            "technique_id": technique_id,
                            "step_name": step_name,
                            "mode": "real",
                        }
                    else:
                        result = execute_single_attack(technique_id)
                        result["success"] = True
                        result["technique_id"] = technique_id

                    steps_executed += 1
                    print(f"[watcher] Result: detected={result.get('detected', '?')}, "
                          f"alerts={result.get('alert_count', 0)}")

                except Exception as exc:
                    result = {
                        "success": False,
                        "error": str(exc),
                        "technique_id": technique_id,
                        "step_name": step_name,
                        "mode": "real",
                        "detected": False,
                        "alert_count": 0,
                        "alert_signatures": [],
                    }
                    print(f"[watcher] ERROR: {exc}")

                write_step_result(result)
                print(f"[watcher] Result written. Total steps executed: {steps_executed}")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[watcher] Stopped. Total steps executed: {steps_executed}")


if __name__ == "__main__":
    main()
