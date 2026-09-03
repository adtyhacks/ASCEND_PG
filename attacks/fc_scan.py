#!/usr/bin/env python3
"""
ASCEND-PG attacks/fc_scan.py

Function Code Scanner (MITRE ATT&CK for ICS: T0840 — Network Sniffing / Reconnaissance).

Probes a target PLC by sending Modbus requests for all function codes (1–127).
Fingerprints supported vs unsupported function codes by inspecting PLC responses
and Modbus exception codes (e.g., Exception Code 0x01: Illegal Function indicates
unsupported; valid responses or Exception Codes 0x02/0x03 indicate the function code
is implemented by the server).

Reconnaissance capabilities:
  - Identifies standard read/write function codes (FC 01, 02, 03, 04, 05, 06, etc.)
  - Detects vendor-specific or diagnostic function codes (FC 08, 17, 43, etc.)
  - Safe mode enabled by default to prevent unintended writes during discovery
  - Logs all probe results to the shared ASCEND-PG log store

Usage examples:
    # Basic safe scan against PLC at 10.0.0.1:
    python3 attacks/fc_scan.py --target 10.0.0.1

    # Scan with custom port and write operations enabled:
    python3 attacks/fc_scan.py --target 10.0.0.1 --port 502 --no-safe

    # Scan a specific FC range (e.g., standard FCs 1–24):
    python3 attacks/fc_scan.py --target 10.0.0.1 --start-fc 1 --end-fc 24

    # Run inside Mininet attacker host:
    mininet> attacker python3 attacks/fc_scan.py --target 10.0.0.1
"""

import argparse
import json
import logging
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pymodbus.client import ModbusTcpClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
log = logging.getLogger("fc_scan")

MODBUS_PORT = 502
TECHNIQUE_ID = "T0840"

# Shared event log store — repo data/ dir, anchored to this file (attacks/ -> repo root)
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"

# Known Modbus Function Code definitions
FUNCTION_CODE_NAMES: Dict[int, str] = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Read Device Identification / Encapsulated Interface",
}

# Modbus write function codes that may alter PLC state
WRITE_FUNCTION_CODES = {5, 6, 15, 16, 21, 22, 23}

# Modbus Exception Code definitions
EXCEPTION_NAMES: Dict[int, str] = {
    1: "ILLEGAL FUNCTION",
    2: "ILLEGAL DATA ADDRESS",
    3: "ILLEGAL DATA VALUE",
    4: "SLAVE DEVICE FAILURE",
    5: "ACKNOWLEDGE",
    6: "SLAVE DEVICE BUSY",
    8: "MEMORY PARITY ERROR",
    10: "GATEWAY PATH UNAVAILABLE",
    11: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
}


def _json_safe(obj):
    """Fallback encoder for json.dumps: decodes bytes to strings."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    return str(obj)


def log_event(log_path: Path, event: dict) -> None:
    """Append one event to the shared JSON log store (list of dicts)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if log_path.exists():
        try:
            events = json.loads(log_path.read_text())
        except json.JSONDecodeError:
            events = []
    events.append(event)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(events, indent=2, default=_json_safe))
    except Exception as exc:
        log.warning("Failed to write to log store %s: %s", log_path, exc)


def probe_with_pymodbus(
    client: ModbusTcpClient, fc: int, device_id: int
) -> Optional[Tuple[bool, str, Optional[int]]]:
    """
    Attempt to probe known function codes using pymodbus 3.14.x client methods.
    Returns (supported: bool, status_message: str, exception_code: Optional[int])
    or None if the FC is not mapped to a high-level pymodbus method.
    """
    try:
        resp = None
        if fc == 1:
            resp = client.read_coils(address=0, count=1, device_id=device_id)
        elif fc == 2:
            resp = client.read_discrete_inputs(address=0, count=1, device_id=device_id)
        elif fc == 3:
            resp = client.read_holding_registers(address=0, count=1, device_id=device_id)
        elif fc == 4:
            resp = client.read_input_registers(address=0, count=1, device_id=device_id)
        elif fc == 5:
            resp = client.write_coil(address=0, value=False, device_id=device_id)
        elif fc == 6:
            resp = client.write_register(address=0, value=0, device_id=device_id)
        elif fc == 7:
            if hasattr(client, "read_exception_status"):
                resp = client.read_exception_status(device_id=device_id)
            else:
                return None
        elif fc == 8:
            if hasattr(client, "diagnostic"):
                resp = client.diagnostic(sub_function=0, data=[0], device_id=device_id)
            elif hasattr(client, "diag_query_data"):
                resp = client.diag_query_data(data=0, device_id=device_id)
            else:
                return None
        elif fc == 15:
            resp = client.write_coils(address=0, values=[False], device_id=device_id)
        elif fc == 16:
            resp = client.write_registers(address=0, values=[0], device_id=device_id)
        elif fc == 17:
            if hasattr(client, "report_slave_id"):
                resp = client.report_slave_id(device_id=device_id)
            else:
                return None
        elif fc == 43:
            if hasattr(client, "read_device_information"):
                resp = client.read_device_information(device_id=device_id)
            else:
                return None
        else:
            return None

        if resp is None:
            return None

        if resp.isError():
            # Check exception code if available
            exc_code = getattr(resp, "exception_code", None)
            if exc_code == 1:
                return False, f"UNSUPPORTED (Exception 0x01: {EXCEPTION_NAMES.get(1)})", 1
            elif exc_code is not None:
                exc_name = EXCEPTION_NAMES.get(exc_code, f"Code {exc_code}")
                return True, f"SUPPORTED (Exception 0x{exc_code:02X}: {exc_name})", exc_code
            return False, f"ERROR ({resp})", None
        else:
            return True, "SUPPORTED (Success 0x00)", 0

    except Exception as exc:
        log.debug("pymodbus probe exception for FC %d: %s", fc, exc)
        return None


def probe_with_raw_socket(
    target_ip: str, port: int, fc: int, device_id: int, timeout: float = 2.0
) -> Tuple[bool, str, Optional[int]]:
    """
    Send raw Modbus TCP (MBAP + PDU) frame for any arbitrary function code (1-127).
    Inspects response header and exception codes.
    Returns (supported: bool, status_message: str, exception_code: Optional[int]).
    """
    # Build Modbus TCP frame
    # MBAP: Transaction ID (2B) | Protocol ID (2B, 0) | Length (2B) | Unit ID (1B)
    # PDU : Function Code (1B) | Dummy Payload (2B address + 2B count/data)
    tx_id = fc & 0xFFFF
    pdu_payload = struct.pack(">BHH", fc, 0, 1)
    mbap_length = 1 + len(pdu_payload)
    mbap_hdr = struct.pack(">HHHB", tx_id, 0, mbap_length, device_id)
    request_frame = mbap_hdr + pdu_payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target_ip, port))
        sock.sendall(request_frame)

        # Read 7-byte MBAP header
        resp_mbap = sock.recv(7)
        if len(resp_mbap) < 7:
            return False, "NO RESPONSE / CLOSED", None

        resp_tx, resp_proto, resp_len, resp_unit = struct.unpack(">HHHB", resp_mbap)
        pdu_len = resp_len - 1
        if pdu_len <= 0:
            return False, "MALFORMED RESPONSE (Empty PDU)", None

        resp_pdu = sock.recv(pdu_len)
        if len(resp_pdu) < 1:
            return False, "TRUNCATED RESPONSE", None

        resp_fc = resp_pdu[0]

        # Valid success response: response FC == requested FC
        if resp_fc == fc:
            return True, "SUPPORTED (Success 0x00)", 0

        # Modbus Exception response: response FC == requested FC | 0x80
        if resp_fc == (fc | 0x80):
            if len(resp_pdu) >= 2:
                exc_code = resp_pdu[1]
                exc_name = EXCEPTION_NAMES.get(exc_code, f"Code {exc_code}")
                if exc_code == 1:
                    # Illegal Function -> PLC explicitly does not support this FC
                    return False, f"UNSUPPORTED (Exception 0x01: {exc_name})", exc_code
                else:
                    # Other exceptions (Illegal Address, Illegal Value, etc.) mean the FC IS supported!
                    return True, f"SUPPORTED (Exception 0x{exc_code:02X}: {exc_name})", exc_code
            return False, "ERROR (Exception frame missing code)", None

        return False, f"UNEXPECTED RESPONSE (FC 0x{resp_fc:02X})", None

    except socket.timeout:
        return False, "TIMEOUT", None
    except ConnectionRefusedError:
        return False, "CONNECTION REFUSED", None
    except Exception as exc:
        return False, f"COMMUNICATION ERROR ({exc})", None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_function_code(
    target_ip: str,
    port: int,
    fc: int,
    device_id: int = 1,
    safe_mode: bool = True,
    client: Optional[ModbusTcpClient] = None,
    timeout: float = 2.0,
) -> Tuple[bool, str, Optional[int], bool]:
    """
    Probe a single function code against the target PLC.
    Returns (supported: bool, status_message: str, exception_code: Optional[int], skipped: bool).
    """
    if safe_mode and fc in WRITE_FUNCTION_CODES:
        return False, "SKIPPED (Safe Mode: Write FC)", None, True

    # Try pymodbus high-level client first if available for standard FCs
    if client and client.connected:
        pymodbus_result = probe_with_pymodbus(client, fc, device_id)
        if pymodbus_result is not None:
            supported, status, exc_code = pymodbus_result
            return supported, status, exc_code, False

    # Fall back to raw Modbus TCP socket probe
    supported, status, exc_code = probe_with_raw_socket(
        target_ip, port, fc, device_id, timeout=timeout
    )
    return supported, status, exc_code, False


def scan_function_codes(
    target_ip: str,
    port: int = MODBUS_PORT,
    device_id: int = 1,
    safe_mode: bool = True,
    start_fc: int = 1,
    end_fc: int = 127,
    timeout: float = 2.0,
    log_path: Optional[Path] = None,
) -> List[Dict]:
    """
    Scan a range of function codes (start_fc to end_fc) against target PLC.
    Returns list of result dictionaries per function code.
    """
    log.info(
        "Starting Function Code Scan on %s:%d (Unit: %d, FCs: %d-%d, Safe: %s)",
        target_ip,
        port,
        device_id,
        start_fc,
        end_fc,
        safe_mode,
    )

    if log_path:
        log_event(
            log_path,
            {
                "stage": "recon",
                "technique": TECHNIQUE_ID,
                "action": "fc_scan_start",
                "target": target_ip,
                "port": port,
                "device_id": device_id,
                "safe_mode": safe_mode,
                "start_fc": start_fc,
                "end_fc": end_fc,
            },
        )

    results = []
    client = ModbusTcpClient(target_ip, port=port, timeout=timeout)
    client.connect()

    try:
        for fc in range(start_fc, end_fc + 1):
            fc_name = FUNCTION_CODE_NAMES.get(fc, "User-Defined / Reserved")
            supported, status, exc_code, skipped = probe_function_code(
                target_ip=target_ip,
                port=port,
                fc=fc,
                device_id=device_id,
                safe_mode=safe_mode,
                client=client,
                timeout=timeout,
            )

            result_entry = {
                "fc": fc,
                "fc_hex": f"0x{fc:02X}",
                "name": fc_name,
                "supported": supported,
                "status": status,
                "exception_code": exc_code,
                "skipped": skipped,
                "is_write": fc in WRITE_FUNCTION_CODES,
            }
            results.append(result_entry)

            if supported:
                log.info("[+] FC %02d (0x%02X) - %-30s : %s", fc, fc, fc_name, status)
            elif skipped:
                log.debug("[*] FC %02d (0x%02X) - %-30s : %s", fc, fc, fc_name, status)
            else:
                log.debug("[-] FC %02d (0x%02X) - %-30s : %s", fc, fc, fc_name, status)

            time.sleep(0.02)  # Gentle pacing between probes

    finally:
        client.close()

    supported_fcs = [r["fc"] for r in results if r["supported"]]
    skipped_fcs = [r["fc"] for r in results if r["skipped"]]
    unsupported_fcs = [r["fc"] for r in results if not r["supported"] and not r["skipped"]]

    log.info(
        "Scan completed: %d supported, %d unsupported, %d skipped out of %d probed",
        len(supported_fcs),
        len(unsupported_fcs),
        len(skipped_fcs),
        len(results),
    )

    if log_path:
        log_event(
            log_path,
            {
                "stage": "recon",
                "technique": TECHNIQUE_ID,
                "action": "fc_scan_complete",
                "target": target_ip,
                "port": port,
                "device_id": device_id,
                "total_probed": len(results),
                "supported_count": len(supported_fcs),
                "unsupported_count": len(unsupported_fcs),
                "skipped_count": len(skipped_fcs),
                "supported_fcs": supported_fcs,
                "results": results,
            },
        )

    return results


def print_summary_table(target_ip: str, port: int, results: List[Dict], safe_mode: bool) -> None:
    """Print an ASCII formatted table of function code probe results."""
    print("\n" + "=" * 80)
    print(f" ASCEND-PG Modbus Function Code Reconnaissance Report")
    print(f" Target: {target_ip}:{port} | Safe Mode: {safe_mode} | Technique: {TECHNIQUE_ID}")
    print("=" * 80)
    print(f"{'FC (Dec)':<10}{'FC (Hex)':<10}{'Function Name':<32}{'Result':<12}{'Details'}")
    print("-" * 80)

    for r in results:
        # Highlight supported or non-standard FCs
        if r["supported"]:
            tag = "[SUPPORTED]"
        elif r["skipped"]:
            tag = "[SKIPPED]"
        else:
            tag = "[NO]"

        # Truncate or clean details string
        details = r["status"]
        print(f"{r['fc']:<10}{r['fc_hex']:<10}{r['name']:<32}{tag:<12}{details}")

    print("=" * 80)
    supported = [r for r in results if r["supported"]]
    skipped = [r for r in results if r["skipped"]]
    unsupported = [r for r in results if not r["supported"] and not r["skipped"]]

    print(f"Summary: {len(supported)} Supported | {len(unsupported)} Unsupported | {len(skipped)} Skipped")
    if supported:
        supported_list = ", ".join(f"FC{r['fc']} ({r['name']})" for r in supported)
        print(f"Supported Functionality: {supported_list}")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="ASCEND-PG Modbus Function Code Scanner (MITRE ATT&CK: T0840)"
    )
    parser.add_argument(
        "--target", required=True, help="Target PLC IP address (e.g., 10.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=MODBUS_PORT, help="Modbus TCP port (default: 502)"
    )
    parser.add_argument(
        "-u", "--unit", type=int, default=1, help="Modbus Unit ID / Device ID (default: 1)"
    )
    parser.add_argument(
        "--start-fc", type=int, default=1, help="Starting function code to scan (default: 1)"
    )
    parser.add_argument(
        "--end-fc", type=int, default=127, help="Ending function code to scan (default: 127)"
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0, help="Per-probe socket timeout in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--safe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip write function codes (05, 06, 15, 16, 21, 22, 23) to avoid state changes (default: True)",
    )
    parser.add_argument(
        "--log",
        default=str(DEFAULT_LOG),
        help=f"Path to shared event log store (default: {DEFAULT_LOG})",
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    results = scan_function_codes(
        target_ip=args.target,
        port=args.port,
        device_id=args.unit,
        safe_mode=args.safe,
        start_fc=args.start_fc,
        end_fc=args.end_fc,
        timeout=args.timeout,
        log_path=log_path,
    )

    print_summary_table(args.target, args.port, results, args.safe)


if __name__ == "__main__":
    main()
