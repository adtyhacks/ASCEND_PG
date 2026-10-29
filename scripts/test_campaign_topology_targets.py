"""Focused campaign topology/target regressions; starts no runtime components."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gui import campaign
from testbed.topology import Topology, get_topology, load_case, set_topology


class FixedModel:
    def __init__(self, target: int):
        self.target = target

    def predict(self, _observation, deterministic=False):
        from strategic.rl_env import MITRE_TECHNIQUES

        technique = next(index for index, item in enumerate(MITRE_TECHNIQUES)
                         if item["id"] == "T0816")
        return [technique, 0, 0, self.target], None


def custom_four_bus_topology() -> Topology:
    nodes = [
        {"bus_id": index, "name": f"Bus{index + 1}",
         "type": "slack" if index == 0 else "pq", "voltage": 1.0,
         "ip": f"10.0.0.{index + 1}", "plc_type": "generic_modbus"}
        for index in range(4)
    ]
    return Topology(nodes=nodes, edges=[(0, 1), (1, 2), (2, 3)],
                    case_name="custom_campaign_test")


class CampaignTopologyTargetTests(unittest.TestCase):
    def setUp(self):
        self.original_topology = get_topology()
        self.controller = campaign.CampaignController(topology=lambda: self.original_topology)

    def tearDown(self):
        set_topology(self.original_topology)

    def select(self, topology: Topology, raw_target: int) -> dict:
        environment = self.controller._create_environment(topology)
        return self.controller._select_step({
            "env": environment,
            "model": FixedModel(raw_target),
            "observation": [0],
        })

    def test_custom_topology_binds_environment_and_constrains_t0816_target(self):
        topology = custom_four_bus_topology()
        environment = self.controller._create_environment(topology)
        self.assertIs(environment._topo, topology)
        self.assertEqual(environment._num_buses, 4)

        for raw_target in (0, 3, 4, 8, 49):
            step = self.select(topology, raw_target)
            self.assertLess(step["target_bus"], topology.num_buses)
            target_ip, target_node = self.controller._resolve_target(
                topology, step["target_bus"]
            )
            self.assertIn(target_ip, topology.ip_map.values())
            self.assertIn(target_node, {f"plc{bus + 1}" for bus in topology.bus_id_set})

        t0816 = self.select(topology, 8)
        target_ip, target_node = self.controller._resolve_target(
            topology, t0816["target_bus"]
        )
        self.assertEqual(t0816["technique_id"], "T0816")
        self.assertEqual((target_ip, target_node), ("10.0.0.1", "plc1"))
        self.assertNotEqual(target_ip, "10.0.0.9")

    def test_ieee14_and_ieee30_targets_remain_valid(self):
        for case, expected_buses in ((14, 14), (30, 30)):
            with self.subTest(case=case):
                topology = load_case(case)
                environment = self.controller._create_environment(topology)
                self.assertIs(environment._topo, topology)
                self.assertEqual(environment._num_buses, expected_buses)
                step = self.select(topology, expected_buses - 1)
                self.assertEqual(step["target_bus"], expected_buses - 1)
                target_ip, target_node = self.controller._resolve_target(
                    topology, step["target_bus"]
                )
                self.assertEqual(target_ip, topology.get_ip(expected_buses - 1))
                self.assertEqual(target_node, f"plc{expected_buses}")

    def test_invalid_target_is_rejected_before_pending_step_is_published(self):
        topology = custom_four_bus_topology()
        controller = campaign.CampaignController(topology=lambda: topology)
        run = {"run_id": "run-test", "scenario_id": "scenario-test"}
        controller._campaign = lambda: (
            {"generation_id": "generation-test"},
            run,
            {"state": "READY"},
        )
        controller._core_and_watcher = lambda *_args, **_kwargs: None
        controller._sessions[run["run_id"]] = {"current_step": 0}
        controller._select_step = lambda _session: {
            "technique_id": "T0816", "step_name": "device_restart",
            "target_bus": 8, "register_address": 99,
            "value_magnitude": 1.0, "attack_stage": 2,
            "_action": [10, 0, 0, 8],
        }

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(campaign, "PENDING_STEP", Path(directory) / "pending.json"), \
                patch.object(campaign, "_atomic_json") as publish, \
                patch.object(campaign.run_store, "update_run") as update_run:
            with self.assertRaises(campaign.CampaignError) as raised:
                controller.next_step()

        self.assertEqual(raised.exception.code, "invalid_campaign_target")
        publish.assert_not_called()
        update_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
