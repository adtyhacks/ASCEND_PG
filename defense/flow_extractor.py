"""
defense/flow_extractor.py

Captures live Mininet traffic via scapy and extracts CIC-IDS-2017 compatible
flow features (78 dimensions) for input to the LSTM/AE detectors.

Usage:
    extractor = FlowExtractor(interface="s1-eth7")
    extractor.start()
    # ... attack runs ...
    flows_df = extractor.stop()  # returns DataFrame with 78 feature columns
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from scapy.all import sniff, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

WINDOW_SIZE = 10

FEATURE_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
    "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std",
    "Idle Max", "Idle Min",
]


class _FlowState:
    """Tracks per-flow packet statistics for feature extraction."""

    __slots__ = (
        "packets", "fwd_packets", "bwd_packets", "start_time",
        "last_time", "fwd_times", "bwd_times", "fwd_lengths",
        "bwd_lengths", "all_lengths", "fwd_flags", "bwd_flags",
        "fwd_init_win", "bwd_init_win",
    )

    def __init__(self):
        self.packets = 0
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.start_time = None
        self.last_time = None
        self.fwd_times = []
        self.bwd_times = []
        self.fwd_lengths = []
        self.bwd_lengths = []
        self.all_lengths = []
        self.fwd_flags = []
        self.bwd_flags = []
        self.fwd_init_win = 0
        self.bwd_init_win = 0


def _flag_count(flags_list, flag_name):
    flag_map = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
                "ACK": 0x10, "URG": 0x20, "CWE": 0x40, "ECE": 0x80}
    mask = flag_map.get(flag_name, 0)
    return sum(1 for f in flags_list if f & mask)


def _safe_div(a, b):
    return a / b if b != 0 else 0.0


def _std(values, mean_val):
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean_val) ** 2 for x in values) / (len(values) - 1)
    return variance ** 0.5


def _compute_flow_features(flow_id, state):
    """Compute 78 CIC-IDS-2017 features from a single flow's packet list."""
    src_ip, dst_ip, src_port, dst_port, proto = flow_id

    fwd_lens = state.fwd_lengths if state.fwd_lengths else [0]
    bwd_lens = state.bwd_lengths if state.bwd_lengths else [0]
    all_lens = state.all_lengths if state.all_lengths else [0]
    fwd_times = state.fwd_times
    bwd_times = state.bwd_times

    duration = (state.last_time - state.start_time) if state.start_time and state.last_time else 0.0
    duration = max(duration, 1e-6)

    total_fwd_bytes = sum(fwd_lens)
    total_bwd_bytes = sum(bwd_lens)

    fwd_mean = np.mean(fwd_lens)
    bwd_mean = np.mean(bwd_lens)
    all_mean = np.mean(all_lens)

    fwd_iat = [fwd_times[i+1] - fwd_times[i] for i in range(len(fwd_times)-1)] if len(fwd_times) > 1 else []
    bwd_iat = [bwd_times[i+1] - bwd_times[i] for i in range(len(bwd_times)-1)] if len(bwd_times) > 1 else []
    all_times = sorted(fwd_times + bwd_times)
    flow_iat = [all_times[i+1] - all_times[i] for i in range(len(all_times)-1)] if len(all_times) > 1 else []

    fwd_iat_mean = np.mean(fwd_iat) if fwd_iat else 0.0
    bwd_iat_mean = np.mean(bwd_iat) if bwd_iat else 0.0
    flow_iat_mean = np.mean(flow_iat) if flow_iat else 0.0

    act_data = sum(1 for l in state.fwd_lengths if l > 0)
    init_win_fwd = state.fwd_init_win
    init_win_bwd = state.bwd_init_win

    fwd_seg_sizes = [l for l in state.fwd_lengths if l > 0] or [0]
    bwd_seg_sizes = [l for l in state.bwd_lengths if l > 0] or [0]

    down_up = _safe_div(total_bwd_bytes, total_fwd_bytes) if total_fwd_bytes > 0 else 0.0

    return {
        "Destination Port": dst_port,
        "Flow Duration": duration,
        "Total Fwd Packets": state.fwd_packets,
        "Total Backward Packets": state.bwd_packets,
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": max(fwd_lens),
        "Fwd Packet Length Min": min(fwd_lens),
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": _std(fwd_lens, fwd_mean),
        "Bwd Packet Length Max": max(bwd_lens),
        "Bwd Packet Length Min": min(bwd_lens),
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": _std(bwd_lens, bwd_mean),
        "Flow Bytes/s": _safe_div(total_fwd_bytes + total_bwd_bytes, duration),
        "Flow Packets/s": _safe_div(state.packets, duration),
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": _std(flow_iat, flow_iat_mean),
        "Flow IAT Max": max(flow_iat) if flow_iat else 0.0,
        "Flow IAT Min": min(flow_iat) if flow_iat else 0.0,
        "Fwd IAT Total": sum(fwd_iat),
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": _std(fwd_iat, fwd_iat_mean),
        "Fwd IAT Max": max(fwd_iat) if fwd_iat else 0.0,
        "Fwd IAT Min": min(fwd_iat) if fwd_iat else 0.0,
        "Bwd IAT Total": sum(bwd_iat),
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": _std(bwd_iat, bwd_iat_mean),
        "Bwd IAT Max": max(bwd_iat) if bwd_iat else 0.0,
        "Bwd IAT Min": min(bwd_iat) if bwd_iat else 0.0,
        "Fwd PSH Flags": _flag_count(state.fwd_flags, "PSH"),
        "Bwd PSH Flags": _flag_count(state.bwd_flags, "PSH"),
        "Fwd URG Flags": _flag_count(state.fwd_flags, "URG"),
        "Bwd URG Flags": _flag_count(state.bwd_flags, "URG"),
        "Fwd Header Length": sum(state.fwd_lengths),
        "Bwd Header Length": sum(state.bwd_lengths),
        "Fwd Packets/s": _safe_div(state.fwd_packets, duration),
        "Bwd Packets/s": _safe_div(state.bwd_packets, duration),
        "Min Packet Length": min(all_lens),
        "Max Packet Length": max(all_lens),
        "Packet Length Mean": all_mean,
        "Packet Length Std": _std(all_lens, all_mean),
        "Packet Length Variance": float(np.var(all_lens)) if len(all_lens) > 1 else 0.0,
        "FIN Flag Count": _flag_count(state.fwd_flags, "FIN") + _flag_count(state.bwd_flags, "FIN"),
        "SYN Flag Count": _flag_count(state.fwd_flags, "SYN") + _flag_count(state.bwd_flags, "SYN"),
        "RST Flag Count": _flag_count(state.fwd_flags, "RST") + _flag_count(state.bwd_flags, "RST"),
        "PSH Flag Count": _flag_count(state.fwd_flags, "PSH") + _flag_count(state.bwd_flags, "PSH"),
        "ACK Flag Count": _flag_count(state.fwd_flags, "ACK") + _flag_count(state.bwd_flags, "ACK"),
        "URG Flag Count": _flag_count(state.fwd_flags, "URG") + _flag_count(state.bwd_flags, "URG"),
        "CWE Flag Count": _flag_count(state.fwd_flags, "CWE") + _flag_count(state.bwd_flags, "CWE"),
        "ECE Flag Count": _flag_count(state.fwd_flags, "ECE") + _flag_count(state.bwd_flags, "ECE"),
        "Down/Up Ratio": down_up,
        "Average Packet Size": _safe_div(total_fwd_bytes + total_bwd_bytes, state.packets),
        "Avg Fwd Segment Size": np.mean(fwd_seg_sizes),
        "Avg Bwd Segment Size": np.mean(bwd_seg_sizes),
        "Fwd Header Length.1": sum(state.fwd_lengths),
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": state.fwd_packets,
        "Subflow Fwd Bytes": total_fwd_bytes,
        "Subflow Bwd Packets": state.bwd_packets,
        "Subflow Bwd Bytes": total_bwd_bytes,
        "Init_Win_bytes_forward": init_win_fwd,
        "Init_Win_bytes_backward": init_win_bwd,
        "act_data_pkt_fwd": act_data,
        "min_seg_size_forward": min(fwd_seg_sizes) if fwd_seg_sizes else 0,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
    }


class FlowExtractor:
    """Captures packets on a Mininet interface and extracts flow features."""

    def __init__(self, interface="s1-eth7"):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required: pip install scapy")
        self.interface = interface
        self._flows = defaultdict(_FlowState)
        self._sniffer = None
        self._running = False
        self._lock = threading.Lock()

    def _process_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        ts = float(pkt.time)

        src_ip, dst_ip = ip.src, ip.dst
        src_port, dst_port = tcp.sport, tcp.dport

        if src_port <= dst_port:
            flow_id = (src_ip, dst_ip, src_port, dst_port, "TCP")
            is_fwd = True
        else:
            flow_id = (dst_ip, src_ip, dst_port, src_port, "TCP")
            is_fwd = False

        pkt_len = len(tcp.payload)
        flags = int(tcp.flags)

        with self._lock:
            state = self._flows[flow_id]

            if state.start_time is None:
                state.start_time = ts
            state.last_time = ts
            state.packets += 1
            state.all_lengths.append(pkt_len)

            if is_fwd:
                state.fwd_packets += 1
                state.fwd_times.append(ts)
                state.fwd_lengths.append(pkt_len)
                state.fwd_flags.append(flags)
                if state.fwd_init_win == 0:
                    state.fwd_init_win = tcp.window
            else:
                state.bwd_packets += 1
                state.bwd_times.append(ts)
                state.bwd_lengths.append(pkt_len)
                state.bwd_flags.append(flags)
                if state.bwd_init_win == 0:
                    state.bwd_init_win = tcp.window

    def start(self):
        """Start packet capture in background thread."""
        self._running = True
        self._sniffer = sniff(
            iface=self.interface,
            filter="tcp",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        """Stop capture and return flow features as DataFrame."""
        self._running = False
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

        with self._lock:
            flows = {}
            for flow_id, state in self._flows.items():
                if state.packets >= 2:
                    flows[flow_id] = _compute_flow_features(flow_id, state)
            self._flows.clear()

        if not flows:
            return pd.DataFrame(columns=FEATURE_COLS)

        df = pd.DataFrame(list(flows.values()))
        for col in FEATURE_COLS:
            if col not in df.columns:
                df[col] = 0.0
        return df[FEATURE_COLS].fillna(0.0)

    def get_window(self):
        """Get last WINDOW_SIZE flows for LSTM input. Pads with zeros if needed."""
        df = self.stop()
        if len(df) >= WINDOW_SIZE:
            return df.iloc[-WINDOW_SIZE:]
        padding = pd.DataFrame(
            0.0, index=range(WINDOW_SIZE - len(df)), columns=FEATURE_COLS
        )
        return pd.concat([padding, df], ignore_index=True)
