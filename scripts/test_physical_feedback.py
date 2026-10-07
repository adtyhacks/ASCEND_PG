"""Real Pandapower + supported Modbus datastore integration; no attacks or CORE."""
from copy import deepcopy
import json
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np

from testbed.topology import Topology
from testbed.physical_feedback import PhysicalFeedback, mappings, load_state
from strategic.rl_env import AttackStrategyEnv, NUM_TECHNIQUES, NUM_STAGES


class PhysicalFeedbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Topology.from_pandapower("case14").to_dict()

    def setUp(self):
        from testbed import topology, run_store, core_runtime
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for p in (patch.object(topology, "SELECTION_PATH", self.root / "selection.json"), patch.object(topology, "_current_topology", None), patch.object(topology, "_selection_fingerprint", None), patch.object(run_store, "RUNS", self.root / "runs"), patch.object(core_runtime, "ROOT", self.root)):
            p.start(); self.addCleanup(p.stop)
        data = deepcopy(self.base)
        data["nodes"][1]["plc"] = {"id": "plc2", "bus_id": 1, "registers": [
            {"type": "holding_register", "address": 0, "name": "Generator voltage", "semantic": "generator_voltage_setpoint", "unit": "p.u.",
             "data_type": "uint16", "scale": 10000, "attackable": True, "initial_value": 10450,
             "physical_mapping": {"model": "pandapower", "element": "gen", "parameter": "vm_pu", "index": 0}}]}
        self.topology = Topology.from_dict(data)
        topology.activate_topology(self.topology)
        from testbed.plc_server import build_context
        from pymodbus.simulator.simcore import SimCore
        # The actual PLC context, accessed with real FC3/FC6 datastore operations.
        self.datastore = SimCore(build_context(1, node_data=self.topology.nodes[1]).simdevices)
        self.reader = lambda r: asyncio.run(self.datastore.async_getValues(r["unit_id"], 3, r["address"], 1))[0]
        run = run_store.create_run(self.topology.canonical_snapshot())
        self.run = run_store.update_run(run["scenario_id"], run["run_id"], generation_id="g", core_session_id=1)
        self.identity = {k: self.run[k] for k in ("scenario_id", "run_id", "generation_id")}
        self.state_path = Path(run["path"]) / "physical_state.json"
        marker = self.root / "data/core-runtime/session.json"; marker.parent.mkdir(parents=True)
        marker.write_text(json.dumps({"id": 1, "token": "g", "generation_id": "g"}))

    def feedback(self): return PhysicalFeedback(self.topology, self.identity, self.state_path, self.reader)

    def write(self, value):
        self.assertIsNone(asyncio.run(self.datastore.async_setValues(1, 6, 0, [value])))

    def test_deterministic_datastore_power_flow_canonical_and_next_observation(self):
        from testbed.topology import get_topology
        with patch("testbed.topology.load_case", side_effect=AssertionError("Preset replacement forbidden")):
            env = AttackStrategyEnv(topology=get_topology())
        self.assertIs(env._topo, get_topology())
        revision = self.topology.revision
        original = self.topology.to_dict()
        observation_before = env._get_obs()
        feedback = self.feedback(); before = feedback.before(1)
        self.write(10250)
        after = feedback.after(before)
        self.assertTrue(after["power_flow_success"])
        self.assertEqual(feedback.net.gen.at[0, "vm_pu"], 1.025)
        self.assertGreater(max(abs(v) for v in after["voltage_delta"].values()), 1e-5)
        self.assertTrue(after["affected_buses"])
        np.testing.assert_allclose(self.topology.voltages, [after["voltage_after"][str(i)] for i in range(14)])
        offset = 3 + NUM_TECHNIQUES + NUM_STAGES + 3
        observation_after = env._get_obs()
        np.testing.assert_allclose(observation_after[offset:offset + 14], np.array(self.topology.voltages) / 1.1, rtol=1e-6)
        self.assertFalse(np.array_equal(observation_before[offset:offset + 14], observation_after[offset:offset + 14]))
        self.assertEqual(observation_after.shape, observation_before.shape)
        self.assertEqual(self.topology.revision, revision, "Runtime voltage must not invalidate CORE generation topology identity")
        self.assertEqual(self.topology.to_dict(), original)
        change = after["physical_state_change"][0]
        self.assertEqual((change["address"], change["raw_before"], change["raw_after"]), (0, 10450, 10250))
        self.assertIn("line_loading", after["physical_after"])
        self.assertIn("generator_output", after["physical_after"])
        restored = Topology.from_dict(original)
        load_state(restored, self.run)
        self.assertEqual(restored.voltages, self.topology.voltages)
        resumed = self.feedback()
        self.assertIsNone(resumed.error)
        self.assertEqual(resumed.net.gen.at[0, "vm_pu"], 1.025, "Next watcher step must restore the changed Pandapower parameter")
        self.assertEqual(env.resolve_register_address("T0836", 0, 1), 0)
        self.assertEqual(env.resolve_register_address("T0835", 0, 1), 0)
        print("Deterministic physical feedback:", json.dumps({"minimum_before": after["min_voltage_before"], "minimum_after": after["min_voltage_after"], "max_abs_voltage_delta": max(abs(v) for v in after["voltage_delta"].values()), "affected_buses": after["affected_buses"], "observation_dimension": len(observation_after)}))

    def test_power_flow_failure_blocks_observation_and_retains_evidence(self):
        env = AttackStrategyEnv(topology=self.topology)
        feedback = self.feedback(); before = feedback.before(1)
        self.write(10250)
        with patch("testbed.topology.run_power_flow", side_effect=RuntimeError("nonconvergence")):
            after = feedback.after(before)
        self.assertFalse(after["power_flow_success"])
        self.assertEqual(after["voltage_after"], {})
        self.assertIsNone(after["min_voltage_after"])
        self.assertTrue(after["physical_state_change"])
        with self.assertRaisesRegex(ValueError, "unavailable"): env._get_obs()
        self.assertFalse(json.loads(self.state_path.read_text())["power_flow_success"])
        retry = self.feedback()
        self.assertIn("Previous physical update failed", retry.error)

    def test_no_fabricated_mapping_or_change(self):
        feedback = self.feedback(); before = feedback.before(1); after = feedback.after(before)
        self.assertTrue(after["power_flow_success"])
        self.assertEqual(after["physical_state_change"], [])
        self.assertTrue(all(v == 0 for v in after["voltage_delta"].values()))
        self.topology.nodes[1]["plc"]["registers"][0]["semantic"] = "arbitrary_sensor"
        with self.assertRaisesRegex(ValueError, "mismatched"): mappings(self.topology)

    def test_network_only_explicitly_unavailable(self):
        from testbed.external_topology import parse_gns3
        topology = Topology.from_exchange(parse_gns3({"topology": {"nodes": [{"node_id": "n", "name": "Client", "node_type": "vpcs"}], "links": []}}))
        feedback = PhysicalFeedback(topology, self.identity)
        evidence = feedback.after(feedback.before(0))
        self.assertFalse(evidence["physical_model_available"])
        self.assertEqual(evidence["voltage_after"], {})
        with self.assertRaisesRegex(ValueError, "physical_model_available=false"): AttackStrategyEnv(topology=topology)

    def test_generation_mismatch_and_read_failure(self):
        feedback = self.feedback(); before = feedback.before(1); feedback.after(before)
        with self.assertRaisesRegex(ValueError, "match"): load_state(self.topology, {**self.run, "generation_id": "other"})
        broken = PhysicalFeedback(self.topology, self.identity, reader=lambda r: (_ for _ in ()).throw(RuntimeError("PLC read failed")))
        result = broken.after(broken.before(1))
        self.assertFalse(result["power_flow_success"])
        self.assertEqual(result["voltage_after"], {})

    def test_source_failure_never_creates_unit_voltage_fallback(self):
        with patch("testbed.topology.run_power_flow", side_effect=RuntimeError("nonconvergence")):
            with self.assertRaisesRegex(ValueError, "power flow failed"):
                Topology.from_pandapower("case14")

    def test_new_run_clears_previous_physical_context(self):
        from testbed import run_store
        feedback = self.feedback(); before = feedback.before(1); self.write(10250)
        feedback.after(before)
        new = run_store.create_run(self.topology.canonical_snapshot())
        new["generation_id"] = "next"
        self.assertIsNone(load_state(self.topology, new))
        self.assertIsNone(self.topology.physical_state)

    def test_physical_event_persistence(self):
        from testbed.physical_feedback import finish_step
        from testbed import run_store
        feedback = self.feedback(); before = feedback.before(1); self.write(10250)
        pending = {**self.identity, "target_node": "plc2", "target_bus": 1, "target_ip": self.topology.get_ip(1), "correlation_id": "controlled-step"}
        result = finish_step(feedback, before, pending)
        event = run_store.read_events(self.run["scenario_id"], self.run["run_id"])[0]
        self.assertEqual(event["event_type"], "physical_state_updated")
        self.assertEqual(event["evidence"]["voltage_after"], result["voltage_after"])
        self.assertEqual(event["generation_id"], "g")

    def test_campaign_handoff_passes_solved_voltage_to_next_ppo_prediction(self):
        from gui.campaign import CampaignController
        env = AttackStrategyEnv(topology=self.topology)
        class Predictor:
            observed = None
            def predict(self, observation, **kwargs):
                self.observed = np.array(observation)
                return [12, 0, 5, 1], None
        model = Predictor()
        controller = CampaignController(topology=lambda: self.topology)
        action = np.array([12, 0, 5, 1])
        session = {"env": env, "model": model, "observation": env._get_obs(), "current_step": 0,
                   "pending_action": {"correlation_id": "controlled-step", "action": action}}
        controller._sessions[self.run["run_id"]] = session
        request = {**self.identity, "campaign_id": self.run["run_id"], "correlation_id": "controlled-step",
                   "technique_id": "T0836", "step_name": "fdi_attack", "target_node": "plc2", "target_bus": 1,
                   "attack_stage": 2, "value_magnitude": 1.0}
        feedback = self.feedback(); before = feedback.before(1); self.write(10250)
        evidence = feedback.after(before)
        controller._complete(self.run, request, {"status": "SUCCESS", "success": True, "physical_impact": evidence})
        controller._select_step(session)
        offset = 3 + NUM_TECHNIQUES + NUM_STAGES + 3
        np.testing.assert_allclose(model.observed[offset:offset + 14], np.array(self.topology.voltages) / 1.1, rtol=1e-6)
        self.assertEqual(session["current_step"], 1)


if __name__ == "__main__": unittest.main()
