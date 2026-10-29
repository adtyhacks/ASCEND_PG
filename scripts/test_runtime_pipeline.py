"""Fast structural test for the local canonical topology and event pipeline."""
import shutil
from pathlib import Path

from testbed.topology import Topology
from testbed.run_store import RUNS, append_event, create_run, metrics, read_events, visual_data
from testbed.visualize_topology import render_topology

def main():
    topology = Topology.from_pandapower("case14").canonical_snapshot()
    assert len(topology["nodes"]) == 18
    run = create_run(topology, scenario_id="scenario-runtime-test")
    append_event(run["scenario_id"], run["run_id"], category="security", event_type="attack_started", source_node="attacker", target_node="plc1", timestamp="2026-01-01T00:00:00+00:00")
    append_event(run["scenario_id"], run["run_id"], category="security", event_type="attack_finished", source_node="attacker", target_node="plc1", result="compromised", timestamp="2026-01-01T00:00:02+00:00")
    append_event(run["scenario_id"], run["run_id"], category="security", event_type="detection", source_node="ids_monitor", target_node="plc1", timestamp="2026-01-01T00:00:03+00:00")
    append_event(run["scenario_id"], run["run_id"], category="security", event_type="defense_action", source_node="ids_monitor", target_node="plc1", defense_action="isolate", timestamp="2026-01-01T00:00:04+00:00")
    data = metrics(run["scenario_id"], run["run_id"])
    assert data["time_to_detection_seconds"] == 3.0 and data["compromised_assets"] == 1
    nodes, edges, compromised, detected, paths = visual_data(topology, read_events(run["scenario_id"], run["run_id"], "security"))
    assert nodes and edges and "plc1" in compromised and "plc1" in detected and paths
    assert "vis-network" in render_topology(nodes, edges, compromised, detected, [])
    shutil.rmtree(RUNS / run["scenario_id"])
    print("runtime pipeline: OK")

if __name__ == "__main__": main()
