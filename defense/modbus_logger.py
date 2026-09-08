"""
defense/modbus_logger.py

Parses Modbus TCP packets from live Mininet traffic and logs detailed
packet-level information (function codes, registers, values).

Produces realistic ICS/SCADA network logs suitable for thesis documentation.

Usage:
    logger = ModbusLogger(interface="s1-eth7")
    logger.start()
    # ... attack runs ...
    logs = logger.stop()  # returns list of detailed Modbus log dicts
"""

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import AsyncSniffer, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_STORE = REPO_ROOT / "data" / "modbus_log.json"

MODBUS_FUNC_CODES = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    7: "read_exception_status",
    8: "diagnostics",
    11: "get_comm_event_counter",
    12: "get_comm_event_log",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    17: "report_server_id",
    22: "mask_write_register",
    23: "read_write_multiple_registers",
    24: "read_fifo_queue",
    43: "encapsulated_interface_transport",
}

MODBUS_EXCEPTION_CODES = {
    1: "illegal_function",
    2: "illegal_data_address",
    3: "illegal_data_value",
    4: "server_device_failure",
    5: "acknowledge",
    6: "server_device_busy",
    8: "memory_parity_error",
    10: "gateway_path_unavailable",
    11: "gateway_target_failed_to_respond",
}


class ModbusLogger:
    """Captures Modbus TCP packets and extracts detailed protocol information."""

    def __init__(self, interface="s1-eth7"):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required: pip install scapy")
        self.interface = interface
        self._packets = []
        self._sniffer = None
        self._lock = threading.Lock()

    def _parse_modbus_tcp(self, pkt):
        """Parse a Modbus TCP packet and extract protocol details."""
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        raw = bytes(pkt[Raw].load)

        if len(raw) < 7:
            return

        ts = float(pkt.time)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)

        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport

        mbap_trans_id = int.from_bytes(raw[0:2], "big")
        mbap_proto_id = int.from_bytes(raw[2:4], "big")
        mbap_length = int.from_bytes(raw[4:6], "big")
        mbap_unit_id = raw[6]

        func_code = raw[7] if len(raw) > 7 else 0

        is_response = func_code >= 0x80
        actual_func = func_code & 0x7F if is_response else func_code
        func_name = MODBUS_FUNC_CODES.get(actual_func, f"unknown_{actual_func}")

        exception_code = None
        if is_response and len(raw) > 8:
            exception_code = MODBUS_EXCEPTION_CODES.get(raw[8], f"exception_{raw[8]}")

        registers = []
        values = []
        start_addr = None
        quantity = None

        if actual_func in (3, 4, 6, 23) and not is_response:
            if len(raw) > 10:
                start_addr = int.from_bytes(raw[8:10], "big")
            if actual_func in (3, 4) and len(raw) > 12:
                quantity = int.from_bytes(raw[10:12], "big")
            elif actual_func == 6 and len(raw) > 12:
                value = int.from_bytes(raw[10:12], "big")
                values.append(value)

        if actual_func in (3, 4) and is_response and len(raw) > 9:
            byte_count = raw[8]
            for i in range(0, byte_count, 2):
                if 9 + i + 2 <= len(raw):
                    val = int.from_bytes(raw[9 + i:11 + i], "big")
                    values.append(val)

        if actual_func == 16 and not is_response and len(raw) > 12:
            start_addr = int.from_bytes(raw[8:10], "big")
            quantity = int.from_bytes(raw[10:12], "big")
            byte_count = raw[12] if len(raw) > 12 else 0
            for i in range(0, byte_count, 2):
                if 13 + i + 2 <= len(raw):
                    val = int.from_bytes(raw[13 + i:15 + i], "big")
                    values.append(val)

        direction = "request" if dst_port == 502 else "response"

        log_entry = {
            "timestamp": dt.isoformat(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "Modbus/TCP",
            "direction": direction,
            "mbap_trans_id": mbap_trans_id,
            "mbap_unit_id": mbap_unit_id,
            "function_code": actual_func,
            "function_name": func_name,
            "is_exception": is_response,
            "exception_code": exception_code,
            "start_address": start_addr,
            "quantity": quantity,
            "values": values,
            "raw_hex": raw.hex(),
            "packet_length": len(raw),
        }

        with self._lock:
            self._packets.append(log_entry)

        self._write_live_event(log_entry)

    def _write_live_event(self, entry):
        """Append to modbus_log.json atomically."""
        try:
            events = []
            if LOG_STORE.exists():
                try:
                    events = json.loads(LOG_STORE.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    events = []
            events.append(entry)
            LOG_STORE.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=str(LOG_STORE.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(events, f, indent=2)
                os.replace(tmp_path, str(LOG_STORE))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception:
            pass

    def start(self):
        """Start packet capture in background thread (non-blocking)."""
        if not SCAPY_AVAILABLE:
            return
        if self._sniffer is not None:
            return  # already running
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter="tcp port 502",
            prn=self._parse_modbus_tcp,
            store=False,
        )
        self._sniffer.start()

    def stop(self):
        """Stop capture and return collected packets."""
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        with self._lock:
            packets = list(self._packets)
            self._packets.clear()

        return packets

    def get_recent(self, n=50):
        """Get the last N packets without stopping capture."""
        with self._lock:
            return list(self._packets[-n:])
