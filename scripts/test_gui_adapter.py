"""Deterministic Phase 3A GUI adapter checks; no CORE or campaign is started."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from gui import adapter
from testbed import run_store


class FakeTopology:
    def __init__(self, case_name: str = "case14", node_count: int = 2):
        self.case_name = case_name
        self.node_count = node_count

    def to_dict(self) -> dict:
        return {"case_name": self.case_name,
                "nodes": [{"bus_id": index, "type": "pq"} for index in range(self.node_count - 1)], "edges": []}

    def canonical_snapshot(self) -> dict:
        nodes = [{"id": "hub", "hostname": "s1", "node_type": "hub"}]
        nodes += [{"id": f"plc{index + 1}", "hostname": f"plc{index + 1}", "node_type": "plc"} for index in range(self.node_count - 1)]
        links = [{"from": "hub", "to": node["id"], "type": "comm", "protocol": "TCP/IP"} for node in nodes[1:]]
        return {"topology_version": f"{self.case_name}:{self.node_count}", "case_name": self.case_name, "nodes": nodes, "links": links}


def main() -> None:
    original_data, original_runs = adapter.DATA, run_store.RUNS
    original_request, original_topology, original_load_case = adapter.core_request, adapter.canonical_topology, adapter.load_case
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); adapter.DATA = root / "data"; run_store.RUNS = adapter.DATA / "runs"; selected_model = {"topology": FakeTopology()}; adapter.canonical_topology = lambda: selected_model["topology"]; adapter._active_cache.clear()
            references = adapter.DATA / "sample_topologies"; references.mkdir(parents=True)
            for case, name in (("case14", "IEEE 14"), ("case30", "IEEE 30")):
                (references / f"{case}.json").write_text(json.dumps({"name": name, "pandapower_case": case}), encoding="utf-8")
            def offline(_: str) -> dict: raise RuntimeError("CORE daemon unavailable")
            adapter.core_request = offline
            status = adapter.get_system_status()
            assert status["core"]["state"] == "OFFLINE" and status["watcher"]["state"] == "STOPPED"
            assert adapter.get_active_run() is None
            (adapter.DATA / "core-runtime").mkdir(parents=True)
            (adapter.DATA / "core-runtime" / "session.json").write_text("{broken", encoding="utf-8")
            assert adapter.get_system_status()["runtime_marker"] is False
            generation = "c6f2c4a9cb8f4c41aba19789dcadf6c3"
            (adapter.DATA / "core-runtime" / "session.json").write_text(json.dumps({"id": 3, "generation_id": generation}), encoding="utf-8")
            adapter.core_request = lambda _: {"state": "RUNTIME", "session_id": 3, "watcher": "IDLE"}
            topology = FakeTopology().canonical_snapshot(); run = run_store.create_run(topology, scenario_id="scenario-guiadapter")
            run_store.update_run(run["scenario_id"], run["run_id"], core_session_id=3, generation_id=generation, lifecycle_status="RUNNING")
            active = adapter.get_active_run()
            assert active and active["state"] == "ACTIVE" and active["integrity_validated"] is False
            assert adapter.get_displayable_active_run()["integrity_validated"] is True
            (Path(run["path"]) / "events.jsonl").write_text("{broken\n", encoding="utf-8")
            adapter._active_cache.clear()
            assert adapter.get_displayable_active_run()["state"] == "REJECTED"
            (Path(run["path"]) / "events.jsonl").unlink()
            adapter._active_cache.clear()
            assert adapter.get_recent_network_events(run["scenario_id"], run["run_id"], 100) == []
            assert adapter.get_recent_security_events(run["scenario_id"], run["run_id"], 100) == []
            configuration = adapter.get_network_configuration(); assert configuration["node_count"] == 2 and configuration["edge_count"] == 1
            assert {item["case_name"] for item in configuration["available_topologies"]} == {"case14", "case30"}
            adapter.load_case = lambda case: selected_model.update(topology=FakeTopology(case, 3 if case == "case30" else 2)) or selected_model["topology"]
            runtime_marker = adapter.DATA / "core-runtime" / "session.json"
            saved_marker = runtime_marker.read_text(encoding="utf-8"); runtime_marker.unlink()
            adapter.core_request = lambda action: (_ for _ in ()).throw(AssertionError("topology selection must not query or operate CORE"))
            selected = adapter.select_topology("case30")
            assert selected["topology"]["case_name"] == "case30" and len(selected["visual"]["nodes"]) == 3
            assert "plc2" in selected["pyvis_html"] and selected["configuration"]["selected_case"] == "case30"
            runtime_marker.write_text(saved_marker, encoding="utf-8")
            try: adapter.select_topology("case14")
            except ValueError as exc: assert "session marker exists" in str(exc)
            else: raise AssertionError("topology must not change during an owned CORE runtime")
            adapter.core_request = lambda _: {"state": "RUNTIME", "session_id": 3, "watcher": "IDLE"}
            assert {node["state"] for node in adapter.get_topology()["visual"]["nodes"]} == {"normal"}
            assert "plc2" in adapter.get_topology()["pyvis_html"]
            for number in range(140): run_store.append_event(run["scenario_id"], run["run_id"], category="network", event_type="packet", source_node="attacker", target_node="plc1", sequence=number)
            for number in range(120): run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="attack_started", target_node="plc1", correlation_id=f"corr-{number}", sequence=number)
            run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="attack_finished", target_node="plc1", correlation_id="corr-report", mitre_technique="T0836", result="detected", evidence={"step_name": "write register", "ml_confidence": 0.91, "detection_method": "hybrid"})
            run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="detection", target_node="plc1", correlation_id="corr-report", result="detected", severity="HIGH", detection_method="hybrid")
            network = adapter.get_recent_network_events(run["scenario_id"], run["run_id"], 100); security = adapter.get_recent_security_events(run["scenario_id"], run["run_id"], 100)
            assert len(network) == 100 and len(security) == 100
            assert {event["category"] for event in network} == {"network"} and {event["category"] for event in security} == {"security"}
            assert network[-1]["sequence"] == 139 and any(event.get("sequence") == 119 for event in security)
            assert "source_port" not in network[0] and "mitre_technique" not in security[0]
            try: adapter.get_recent_network_events(run["scenario_id"], run["run_id"], 501)
            except ValueError: pass
            else: raise AssertionError("event limit must be bounded")
            runtime = adapter.DATA / "core-runtime"; (runtime / "suricata").mkdir(parents=True)
            scada_rows = [
                {"timestamp": "2026-10-05T10:00:00Z", "stage": "normal_traffic", "action": "poll_10.0.0.8", "target": "10.0.0.8"},
                {"timestamp": "2026-10-05T10:00:01Z", "stage": "other", "action": "unrelated", "target": "10.0.0.9"},
                "{malformed",
            ]
            (runtime / "scada.jsonl").write_text("\n".join(json.dumps(row) if not isinstance(row, str) else row for row in scada_rows) + "\n", encoding="utf-8")
            eve_rows = [
                {"timestamp": "2026-10-05T10:00:02Z", "event_type": "flow", "src_ip": "10.0.0.100", "src_port": 40000,
                 "dest_ip": "10.0.0.8", "dest_port": 502, "proto": "TCP", "app_proto": "modbus",
                 "flow": {"pkts_toserver": 2, "bytes_toserver": 42, "alerted": False}},
                {"event_type": "alert", "src_ip": "10.0.0.100", "dest_ip": "10.0.0.8"},
                {"event_type": "flow", "src_ip": "missing-destination"},
            ]
            (runtime / "suricata" / "eve.json").write_text("\n".join(json.dumps(row) for row in eve_rows) + "\n", encoding="utf-8")
            background = adapter.get_background_network_events(10)
            assert len(background) == 2
            flow = next(row for row in background if row["source_type"] == "Suricata EVE flow")
            poll = next(row for row in background if row["source_type"] == "SCADA poll log")
            assert (flow["source_ip"], flow["destination_ip"], flow["protocol"], flow["destination_port"]) == ("10.0.0.100", "10.0.0.8", "TCP", 502)
            assert flow["application_protocol"] == "modbus" and flow["flow"]["alerted"] is False
            assert poll["destination_ip"] == "10.0.0.8" and poll["source_ip"] is None and poll["protocol"] is None
            assert not any(key in poll for key in ("correlation_id", "ppo_step", "run_id"))
            tail_path = runtime / "bounded.jsonl"
            tail_path.write_text("".join(json.dumps({"index": number}) + "\n" for number in range(150)), encoding="utf-8")
            tail = adapter._recent_tolerant_jsonl(tail_path, 4)
            assert [row["index"] for row in tail] == [146, 147, 148, 149]
            assert adapter._recent_tolerant_jsonl(runtime / "missing.jsonl", 4) == []
            snapshot = adapter.get_live_battle_snapshot(100)
            assert len(snapshot["network_events"]) == 100 and len(snapshot["security_events"]) == 100
            assert snapshot["network_events"][-1]["sequence"] == 139
            assert len(snapshot["background_network"]) == 2
            assert snapshot["pyvis_html"] and snapshot["visual_signature"]
            unchanged_visual = adapter.get_live_battle_snapshot(100, snapshot["visual_signature"])
            assert unchanged_visual["pyvis_html"] is None, "unchanged PyVis state should not be resent on each live refresh"
            assert all(row.get("category") != "network" for row in snapshot["background_network"])
            assert {node["state"] for node in snapshot["visual"]["nodes"]} >= {"detected"}
            summary = adapter.get_report_summary()
            assert summary["available"] is False and summary["normalized_records"] == 1
            (Path(run["path"]) / "report.html").write_text("existing report", encoding="utf-8")
            assert adapter.get_report_summary()["available"] is True
            network_path = Path(run["path"]) / "network_events.jsonl"
            network_path.write_bytes(network_path.read_bytes() + b"{partial")
            try: adapter.get_recent_network_events(run["scenario_id"], run["run_id"], 100)
            except ValueError: pass
            else: raise AssertionError("partial canonical event data must be rejected")
    finally:
        adapter.DATA, run_store.RUNS = original_data, original_runs
        adapter.core_request, adapter.canonical_topology, adapter.load_case = original_request, original_topology, original_load_case; adapter._active_cache.clear()
    print("GUI Phase 3A adapter regression: PASS")


if __name__ == "__main__": main()
