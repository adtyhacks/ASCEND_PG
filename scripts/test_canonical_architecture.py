"""Canonical projections and capability validation; no live services or attacks."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
from testbed import topology as module
from testbed.topology import Topology, get_topology, activate_topology

ROOT = Path(__file__).resolve().parents[1]


class CanonicalArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.presets = {case: Topology.from_pandapower(case) for case in (14, 30)}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.patchers = [patch.object(module, "SELECTION_PATH", Path(self.directory.name) / "active.json"),
                         patch.object(module, "_current_topology", None), patch.object(module, "_selection_fingerprint", None)]
        for p in self.patchers: p.start(); self.addCleanup(p.stop)
        self.definition = json.loads((ROOT / "examples/custom_capabilities.json").read_text())

    def custom(self): return Topology.from_custom_dict(self.definition)

    def test_presets_become_active_and_replace_previous(self):
        for case in (14, 30):
            activate_topology(self.presets[case])
            self.assertEqual(get_topology().num_buses, case)
            self.assertEqual(get_topology().source, "ieee")
            module._current_topology = None
            self.assertEqual(get_topology().num_buses, case)
        self.assertEqual(len(get_topology().canonical_snapshot()["nodes"]), 34)

    def test_custom_active_and_reload_preserves_semantics(self):
        activate_topology(self.custom()); revision = get_topology().revision
        module._current_topology = None
        self.assertEqual(get_topology().revision, revision)
        self.assertEqual(get_topology().num_buses, 3)
        self.assertEqual(get_topology().nodes[1]["plc"]["registers"][0]["semantic"], "generator_voltage_setpoint")

    def test_imported_gns3_is_only_active_graph(self):
        from testbed.external_topology import parse_gns3
        from gui import adapter, imports
        doc = parse_gns3(json.loads((ROOT / "examples/scada_firewall_plc.gns3").read_text()))
        activate_topology(Topology.from_exchange(doc))
        self.assertEqual(get_topology().source, "gns3")
        view = adapter.get_topology()
        self.assertEqual({n["id"] for n in view["visual"]["nodes"]}, {d["id"] for d in doc["network"]["devices"]})
        self.assertNotIn("hub", {n["id"] for n in view["visual"]["nodes"]})
        self.assertEqual(imports.active()["firewall_policies"][0]["name"], "FW-1")
        self.assertFalse(get_topology().physical_available)
        with self.assertRaises(ValueError): get_topology().to_pandapower()
        activate_topology(self.presets[14])
        self.assertIsNone(imports.current())
        self.assertEqual(imports.active()["firewall_policies"], [])

    def test_ascend_import_uses_own_physical_data(self):
        from testbed.external_topology import parse_native
        doc = parse_native(json.loads((ROOT / "examples/ascend_exchange.json").read_text()))
        doc["power_grid"]["buses"][0]["type"] = "slack"
        doc["power_grid"]["buses"][1]["type"] = "pq"
        activate_topology(Topology.from_exchange(doc))
        net = get_topology().to_pandapower()
        self.assertEqual(len(net.bus), 2)
        self.assertEqual(float(net.load.p_mw.sum()), 25)
        self.assertFalse(get_topology().core_compatible, "Firewall graph must not be silently replaced by a hub")

    def test_pandapower_and_grid_view_use_active_object(self):
        from gui.grid_status import get_baseline_grid
        activate_topology(self.custom())
        net = get_topology().to_pandapower()
        self.assertEqual(len(net.bus), 3)
        self.assertAlmostEqual(float(net.gen.p_mw.sum()), 20)
        self.assertEqual(get_baseline_grid()["summary"]["electrical_buses"], 3)
        for case in (14, 30):
            activate_topology(self.presets[case])
            net = get_topology().to_pandapower()
            self.assertEqual(len(net.bus), case)
            self.assertGreater(float(net.load.p_mw.sum()), 0)

    def test_core_generation_uses_selected_custom_and_rejects_gns3(self):
        from testbed.generate_core_topo import generate_core_xml
        activate_topology(self.custom())
        with patch("testbed.generate_core_topo.load_case", side_effect=AssertionError("Preset reload forbidden")):
            path = generate_core_xml(output_path=str(Path(self.directory.name) / "custom.xml"))
        text = Path(path).read_text()
        self.assertIn('name="plc3"', text)
        self.assertNotIn('name="plc4"', text)
        from testbed.external_topology import parse_gns3
        activate_topology(Topology.from_exchange(parse_gns3(json.loads((ROOT / "examples/scada_firewall_plc.gns3").read_text()))))
        with self.assertRaises(ValueError): generate_core_xml(output_path=str(Path(self.directory.name) / "invalid.xml"))
        self.assertFalse((Path(self.directory.name) / "invalid.xml").exists())

    def test_supported_native_import_retains_semantic_and_electrical_projection(self):
        from testbed.external_topology import parse_native
        from testbed.generate_core_topo import generate_core_xml
        selected = Topology.from_exchange(parse_native(self.definition))
        activate_topology(selected)
        self.assertTrue(selected.core_compatible)
        self.assertTrue(selected.ppo_compatible)
        self.assertEqual(len(selected.to_pandapower().bus), 3)
        self.assertEqual(selected.nodes[1]["plc"]["registers"][0]["physical_mapping"]["element"], "gen")
        generated = generate_core_xml(output_path=str(Path(self.directory.name) / "import.xml"))
        self.assertIn('name="plc3"', Path(generated).read_text())

    def test_ppo_uses_selected_custom_without_replacing_global(self):
        from strategic.rl_env import AttackStrategyEnv
        from gui.campaign import CampaignController
        definition = deepcopy(self.definition); definition["nodes"][1].pop("plc")
        activate_topology(Topology.from_custom_dict(definition)); selected = get_topology()
        with patch("testbed.topology.load_case", side_effect=AssertionError("Preset reload forbidden")):
            env = CampaignController()._create_environment(selected)
        self.assertIs(env._topo, selected)
        self.assertIs(get_topology(), selected)
        self.assertEqual(env._num_buses, 3)
        with self.assertRaises(ValueError): AttackStrategyEnv(case=14)
        self.assertEqual(get_topology().num_buses, 3)
        self.assertTrue(self.custom().ppo_compatible, "Explicit addresses within 50 slots use the client-offset adapter without changing action dimensions")

    def test_register_blocks_use_declared_client_offsets(self):
        from testbed.plc_server import build_context
        node = self.custom().nodes[1]
        context = build_context(1, node_data=node)
        # Installed pymodbus exposes the converted simulator data, not legacy
        # context subscripting. No network/server is needed to verify blocks.
        self.assertEqual(context.simdevices[0].simdata[2][0].values, [10400])
        self.assertEqual(context.simdevices[0].simdata[3][0].values, [10400])

    def test_invalid_semantics_rejected(self):
        mutations = [
            lambda d: d["nodes"][1].update(attack_capabilities=["imaginary_attack"]),
            lambda d: d["nodes"][1].update(detection_capabilities=["voltage_recovery_detector"]),
            lambda d: d["nodes"][1]["plc"].update(bus_id=99),
            lambda d: d["nodes"][1]["plc"]["registers"][0]["physical_mapping"].update(index=99),
            lambda d: d["nodes"][1]["plc"]["registers"][0]["physical_mapping"].update(parameter="imaginary"),
            lambda d: d["nodes"][1]["plc"]["registers"].append(deepcopy(d["nodes"][1]["plc"]["registers"][0])),
            lambda d: d["nodes"][1]["plc"]["registers"][1].update(attackable=True),
            lambda d: d["nodes"][0].update(voltage_min_pu=1.2, voltage_max_pu=0.8),
        ]
        for mutate in mutations:
            doc = deepcopy(self.definition); mutate(doc)
            with self.assertRaises(ValueError): Topology.from_custom_dict(doc)

    def test_invalid_selection_never_falls_back(self):
        module.SELECTION_PATH.write_text('{"case_name":"custom_bad","nodes":[],"edges":[]}')
        with self.assertRaises(ValueError): get_topology()
        with self.assertRaises(ValueError): module.load_topology("missing-file.json")
        with self.assertRaises(ValueError): Topology.from_pandapower("invalid_case")

    def test_external_process_selection_invalidates_cached_projection(self):
        activate_topology(self.custom())
        old_revision = get_topology().revision
        module.SELECTION_PATH.write_text(json.dumps(self.presets[30].to_dict()))
        self.assertEqual(get_topology().num_buses, 30)
        self.assertNotEqual(get_topology().revision, old_revision)

    def test_conflicting_serialized_physical_projection_rejected(self):
        document = self.presets[14].to_dict()
        document["nodes"] = deepcopy(document["nodes"])
        document["nodes"][0]["voltage"] = 0.5
        with self.assertRaisesRegex(ValueError, "conflicts"):
            Topology.from_dict(document)

    def test_core_gui_absent_from_application_workflow(self):
        html = (ROOT / "gui/web/index.html").read_text()
        js = (ROOT / "gui/web/app.js").read_text()
        server = (ROOT / "gui/server.py").read_text()
        self.assertNotIn('id="core-gui"', html)
        self.assertNotIn("/api/runtime/gui", js + server)


if __name__ == "__main__": unittest.main()
