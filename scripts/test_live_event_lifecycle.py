"""Regression coverage for real executor start boundaries and PyVis run states."""
from unittest.mock import patch

from scripts.ppo_step_watcher import record_attack_started
from testbed.run_store import report_events, visual_data


TOPOLOGY = {"nodes": [
    {"id": "attacker", "hostname": "attacker", "node_type": "attacker"},
    {"id": "plc1", "hostname": "plc1", "node_type": "plc"},
], "links": []}


def node_state(events):
    nodes, *_ = visual_data(TOPOLOGY, events)
    return next(node["state"] for node in nodes if node["id"] == "plc1")


def main():
    pending = {
        "scenario_id": "scenario-lifecycle", "run_id": "run-lifecycle",
        "campaign_id": "run-lifecycle", "generation_id": "generation-live",
        "correlation_id": "step-1", "technique_id": "T0836", "step_name": "fdi_attack",
        "target_node": "plc1", "target_ip": "10.0.0.1", "attack_stage": 2,
        "register_address": 40000, "value_magnitude": 9999,
    }
    with patch("scripts.ppo_step_watcher.append_event", return_value={"timestamp": "2026-01-01T00:00:00+00:00"}) as append:
        record_attack_started(pending, "generation-live")
    kwargs = append.call_args.kwargs
    assert kwargs["event_type"] == "attack_started"
    assert kwargs["campaign_id"] == pending["campaign_id"]
    assert kwargs["generation_id"] == "generation-live"
    assert kwargs["correlation_id"] == pending["correlation_id"]

    started = {"event_type": "attack_started", "target_node": "plc1", "correlation_id": "step-1"}
    finished = {"event_type": "attack_finished", "timestamp": "2026-01-01T00:00:01+00:00", "target_node": "plc1", "correlation_id": "step-1", "mitre_technique": "T0836", "evidence": {}}
    detection = {"event_type": "detection", "target_node": "plc1", "correlation_id": "step-1"}
    isolate = {"event_type": "defense_action", "target_node": "plc1", "defense_action": "isolate", "correlation_id": "step-1"}
    restore = {"event_type": "defense_action", "target_node": "plc1", "defense_action": "restore", "correlation_id": "step-1"}
    assert node_state([]) == "normal"
    assert node_state([started]) == "attacking"
    assert node_state([started, detection]) == "detected"
    assert node_state([started, finished, detection]) == "detected"
    assert node_state([started, finished, detection, isolate]) == "isolated"
    assert node_state([started, finished, detection, isolate, restore]) == "restored"
    assert len(report_events([started, finished, detection])) == 1
    print("live event lifecycle regression: PASS")


if __name__ == "__main__":
    main()
