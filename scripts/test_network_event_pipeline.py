"""Deterministic flow-to-canonical-network-event regression; no runtime required."""
from __future__ import annotations

import tempfile
import os
import sys
import json
from datetime import datetime, timezone
import threading
import types
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch

# The intended regression environment is Linux/WSL. Keep this focused unit
# test runnable on Windows-only analysis hosts without pretending to test
# inter-process locking there.
if os.name == "nt":
    fcntl_stub = types.ModuleType("fcntl")
    fcntl_stub.LOCK_EX = 1
    fcntl_stub.LOCK_SH = 2
    fcntl_stub.LOCK_UN = 8
    fcntl_stub.flock = lambda *_args: None
    sys.modules.setdefault("fcntl", fcntl_stub)

# Raw snapshotting does not use ML or its tensor runtime.
sys.modules.setdefault("detection.lstm_detector", types.SimpleNamespace(WINDOW_SIZE=10))

from defense import flow_extractor as flow_module
from scripts.ppo_step_watcher import record_network_events
from scripts import testbed_executor as executor
from testbed import run_store


class _IPLayer:
    src = "10.0.0.100"
    dst = "10.0.0.8"
    ihl = 5


class _TCPLayer:
    sport = 51000
    dport = 502
    payload = b"modbus-request"
    flags = 0x18
    dataofs = 5
    window = 4096


class _Packet:
    def __init__(self, timestamp: float, ip: _IPLayer, tcp: _TCPLayer):
        self.time = timestamp
        self._layers = {_IPLayer: ip, _TCPLayer: tcp}

    def haslayer(self, layer) -> bool:
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]


def main() -> None:
    original_runs = run_store.RUNS
    with tempfile.TemporaryDirectory() as temporary:
        run_store.RUNS = Path(temporary)
        try:
            extractor = flow_module.FlowExtractor.__new__(flow_module.FlowExtractor)
            extractor._flows = defaultdict(flow_module._FlowState)
            extractor._sniffer = None
            extractor._lock = threading.Lock()

            first_tcp = _TCPLayer()
            reverse_ip = _IPLayer()
            reverse_ip.src, reverse_ip.dst = "10.0.0.8", "10.0.0.100"
            reverse_tcp = _TCPLayer()
            reverse_tcp.sport, reverse_tcp.dport = 502, 51000
            with patch.object(flow_module, "IP", _IPLayer, create=True), \
                    patch.object(flow_module, "TCP", _TCPLayer, create=True):
                extractor._process_packet(_Packet(1_800_000_000.25, _IPLayer(), first_tcp))
                extractor._process_packet(_Packet(1_800_000_001.5, reverse_ip, reverse_tcp))

            raw_flows = extractor.raw_flow_snapshot()
            assert len(raw_flows) == 1
            captured = raw_flows[0]
            assert captured["timestamp"] == 1_800_000_000.25
            assert captured["source_ip"] == "10.0.0.100"
            assert captured["destination_ip"] == "10.0.0.8"
            assert captured["protocol"] == "TCP"
            assert captured["source_port"] == 51000 and captured["destination_port"] == 502
            assert captured["packet_count"] == 2
            assert extractor.raw_flow_snapshot() == raw_flows

            class _FakeDetector:
                def __init__(self):
                    self.extractor = extractor

                def clear_flows(self):
                    pass

                def start_capture(self):
                    pass

                def get_verdict(self, *_args):
                    return {
                        "combined_detected": True, "suricata_alert_count": 0,
                        "suricata_signatures": [], "ml_detected": True,
                        "ml_confidence": 0.9, "ml_lstm_confidence": 0.8,
                        "ml_ae_score": 0.7, "ml_available": True,
                        "ml_error": None, "detection_method": "ml",
                    }

                def stop_capture(self):
                    pass

            start = datetime.fromtimestamp(1_800_000_000.25, timezone.utc)
            end = datetime.fromtimestamp(1_800_000_001.5, timezone.utc)
            timing = {
                "status": executor.AttackStatus.SUCCESS, "success": True,
                "name": "remote_services", "return_code": 0, "detect_sids": [],
                "start": start, "end": end, "techniques": [], "error": None,
            }
            with patch.object(executor, "build_step", return_value={"name": "remote_services"}), \
                    patch.object(executor, "get_hybrid_detector", return_value=_FakeDetector()), \
                    patch.object(executor, "run_step", return_value=timing), \
                    patch.object(executor.time, "sleep", return_value=None):
                step_result = executor.execute_single_attack("T0886", target_ip="10.0.0.8")
            assert step_result["success"] is True and step_result["detected"] is True
            assert step_result["network_flows"] == raw_flows

            run = run_store.create_run({"topology_version": "test", "nodes": [], "links": []},
                                       scenario_id="scenario-network-test")
            pending = {
                "scenario_id": run["scenario_id"],
                "run_id": run["run_id"],
                "generation_id": "generation-approved-test",
                "campaign_id": run["run_id"],
                "current_step": 0,
                "correlation_id": "step-1-network-test",
                "technique_id": "T0886",
                "step_name": "remote_services",
                "target_ip": "10.0.0.8",
                "target_node": "plc8",
            }
            security_before = run_store.append_event(
                run["scenario_id"], run["run_id"], category="security",
                event_type="attack_started", correlation_id=pending["correlation_id"],
                generation_id=pending["generation_id"],
            )
            with patch.dict(os.environ, {"ASCEND_SESSION_ID": "7"}):
                events = record_network_events(pending, step_result)

            assert len(events) == 1
            event = events[0]
            assert event["category"] == "network" and event["event_type"] == "flow_observed"
            assert event["timestamp"] == "2027-01-15T08:00:00.250000+00:00"
            assert event["source_ip"] == "10.0.0.100" and event["destination_ip"] == "10.0.0.8"
            assert event["protocol"] == "TCP" and event["source_port"] == 51000
            assert event["destination_port"] == 502 and event["target_node"] == "plc8"
            assert event["source_node"] is None
            for field in ("scenario_id", "run_id", "generation_id", "campaign_id",
                          "ppo_step", "correlation_id", "technique_id", "step_name"):
                assert event[field] == (pending["current_step"] if field == "ppo_step" else pending[field])
            assert event["core_session_id"] == "7"
            assert "modbus" not in event and "ids" not in event and "suricata" not in event
            security_after = run_store.read_events(run["scenario_id"], run["run_id"], "security")
            assert security_after == [security_before]
            assert run_store.read_events(run["scenario_id"], run["run_id"], "network") == events

            assert record_network_events(pending, {"success": True, "network_flows": []}) == []
            assert record_network_events(pending, {"success": False, "network_flows": raw_flows}) == []
            extractor.clear_flows()
            assert extractor.raw_flow_snapshot() == []
        finally:
            run_store.RUNS = original_runs
    print("Network event pipeline regression: PASS")
    print("Example canonical network event:")
    print(json.dumps(event, sort_keys=True))


if __name__ == "__main__":
    main()
