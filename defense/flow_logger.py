"""
defense/flow_logger.py

Tracks network flow metrics (bytes, packets, duration, flags) from live
Mininet traffic. Produces NetFlow/IPFIX-style logs.

Usage:
    logger = FlowLogger(interface="s1-eth7")
    logger.start()
    # ... attack runs ...
    flows = logger.stop()  # returns list of flow dicts
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import AsyncSniffer, TCP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

REPO_ROOT = Path(__file__).resolve().parent.parent
FLOW_LOG_STORE = REPO_ROOT / "data" / "flow_log.json"


class _FlowKey:
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "proto")

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip
                and self.src_port == other.src_port and self.dst_port == other.dst_port
                and self.proto == other.proto)

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def to_dict(self):
        return {
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.proto,
        }


class _FlowStats:
    __slots__ = (
        "start_time", "end_time", "fwd_packets", "bwd_packets",
        "fwd_bytes", "bwd_bytes", "fwd_flags", "bwd_flags",
        "min_pkt_len", "max_pkt_len",
    )

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_flags = []
        self.bwd_flags = []
        self.min_pkt_len = float("inf")
        self.max_pkt_len = 0

    def add_packet(self, ts, length, is_fwd, flags):
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts

        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_flags.append(flags)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_flags.append(flags)

        self.min_pkt_len = min(self.min_pkt_len, length)
        self.max_pkt_len = max(self.max_pkt_len, length)

    def to_dict(self, key):
        duration = (self.end_time - self.start_time) if self.start_time and self.end_time else 0.0
        duration = max(duration, 0.001)

        all_flags = self.fwd_flags + self.bwd_flags
        syn_count = sum(1 for f in all_flags if f & 0x02)
        ack_count = sum(1 for f in all_flags if f & 0x10)
        psh_count = sum(1 for f in all_flags if f & 0x08)
        rst_count = sum(1 for f in all_flags if f & 0x04)
        fin_count = sum(1 for f in all_flags if f & 0x01)

        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        return {
            "timestamp": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "flow_end": datetime.fromtimestamp(self.end_time, tz=timezone.utc).isoformat(),
            **key.to_dict(),
            "duration_sec": round(duration, 6),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "bytes_per_sec": round(total_bytes / duration, 2),
            "packets_per_sec": round(total_packets / duration, 2),
            "min_packet_length": self.min_pkt_len if self.min_pkt_len != float("inf") else 0,
            "max_packet_length": self.max_pkt_len,
            "avg_packet_length": round(total_bytes / total_packets, 2) if total_packets > 0 else 0,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "psh_count": psh_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
        }


class FlowLogger:
    """Captures packets and computes flow-level metrics."""

    def __init__(self, interface="s1-eth7", flow_timeout=30.0):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required: pip install scapy")
        self.interface = interface
        self.flow_timeout = flow_timeout
        self._flows = {}
        self._completed = []
        self._sniffer = None
        self._lock = threading.Lock()

    def _process_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        ts = float(pkt.time)
        pkt_len = len(tcp.payload)
        flags = int(tcp.flags)

        src_ip, dst_ip = ip.src, ip.dst
        src_port, dst_port = tcp.sport, tcp.dport

        if dst_port == 502:
            fwd_key = _FlowKey(src_ip, dst_ip, src_port, dst_port, "TCP")
            is_fwd = True
        elif src_port == 502:
            fwd_key = _FlowKey(dst_ip, src_ip, dst_port, src_port, "TCP")
            is_fwd = False
        else:
            if src_port <= dst_port:
                fwd_key = _FlowKey(src_ip, dst_ip, src_port, dst_port, "TCP")
                is_fwd = True
            else:
                fwd_key = _FlowKey(dst_ip, src_ip, dst_port, src_port, "TCP")
                is_fwd = False

        with self._lock:
            if fwd_key not in self._flows:
                self._flows[fwd_key] = _FlowStats()
            self._flows[fwd_key].add_packet(ts, pkt_len, is_fwd, flags)

            expired = []
            for key, stats in self._flows.items():
                if stats.end_time and (ts - stats.end_time) > self.flow_timeout:
                    expired.append(key)
            for key in expired:
                self._completed.append(self._flows.pop(key).to_dict(key))

    def start(self):
        """Start packet capture in background thread (non-blocking)."""
        if not SCAPY_AVAILABLE:
            return
        if self._sniffer is not None:
            return  # already running
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter="tcp",
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self):
        """Stop capture and return completed flows."""
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        with self._lock:
            for key, stats in self._flows.items():
                self._completed.append(stats.to_dict(key))
            self._flows.clear()
            flows = list(self._completed)
            self._completed.clear()

        if flows:
            try:
                FLOW_LOG_STORE.parent.mkdir(parents=True, exist_ok=True)
                with open(FLOW_LOG_STORE, "a", encoding="utf-8") as f:
                    for flow in flows:
                        f.write(json.dumps(flow) + "\n")
            except Exception:
                pass

        return flows
