"""Focused MVP smoke/negative tests. No server, CORE, watcher, PPO or attacks."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from firewall.model import evaluate
from remediation.engine import recommend
from testbed.external_topology import parse_native, parse_gns3, validate, visual_data, classify_gns3

ROOT = Path(__file__).resolve().parents[1]


class ExternalMvpTests(unittest.TestCase):
    def setUp(self):
        from testbed import topology
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        for p in (patch.object(topology, "SELECTION_PATH", Path(directory.name) / "active.json"), patch.object(topology, "_current_topology", None), patch.object(topology, "_selection_fingerprint", None)):
            p.start(); self.addCleanup(p.stop)
        self.base = {"case_name": "custom_test", "nodes": [{"bus_id": 0, "type": "slack"}, {"bus_id": 1, "type": "pq"}], "edges": [[0, 1]]}
        topology.set_topology(topology.Topology.from_custom_dict(self.base))
        self.native = json.loads((ROOT / "examples/ascend_exchange.json").read_text())
        self.gns3 = json.loads((ROOT / "examples/scada_firewall_plc.gns3").read_text())

    def test_native_sample_and_electrical_mapping(self):
        doc = parse_native(self.native)
        self.assertEqual(doc["mapping"][0], {"bus": "bus8", "device": "plc8"})
        nodes, edges = visual_data(doc)
        self.assertEqual(len(nodes), 6)
        self.assertTrue(any(e["from"] == "fw1" and e["to"] == "plc8" for e in edges))
        self.assertTrue(any(e["type"] == "power_line" for e in edges))

    def test_gns3_nodes_ports_links_unknown_and_ip(self):
        doc = parse_gns3(self.gns3)
        nodes = {d["id"]: d for d in doc["network"]["devices"]}
        self.assertEqual(nodes["unknown"]["type"], "generic")
        self.assertEqual(nodes["fw1"]["name"], "FW-1")
        self.assertEqual(nodes["fw1"]["normalized_type"], "firewall")
        self.assertEqual(nodes["fw1"]["original_type"], "qemu")
        self.assertEqual(nodes["scada"]["interfaces"][0]["name"], "Ethernet0")
        self.assertTrue(nodes["plc8"]["interfaces"][0]["inferred_from_link"])
        self.assertEqual(nodes["plc8"]["ip"], "10.0.0.8")
        self.assertEqual(len(doc["links"]), 2)
        self.assertEqual(doc["power_grid"]["buses"], [])
        self.assertFalse(doc["firewalls"][0]["configuration_available"])
        self.assertEqual(doc["firewalls"][0]["rules"], [])

    def test_firewall_classification_priority_and_boundaries(self):
        for name in ("FW", "FW-1", "FW1", "FIREWALL", "Firewall", "ASA", "OPNsense", "pfSense", "FortiGate", "Fortinet"):
            self.assertEqual(classify_gns3({"name": name, "node_type": "qemu"})[0], "firewall")
        for name in ("Client1", "SW-1", "Internet", "software", "forwarder", "Casablanca", "firewalling"):
            self.assertNotEqual(classify_gns3({"name": name, "node_type": "qemu"})[0], "firewall")
        self.assertEqual(classify_gns3({"name": "FW-1", "device_type": "router"})[0], "router")
        self.assertEqual(classify_gns3({"name": "Client1", "appliance": {"name": "FortiGate"}})[0], "firewall")
        self.assertEqual(classify_gns3({"name": "Client1", "template_name": "pfSense"})[0], "firewall")

    def test_described_gns3_layout_and_multiple_firewalls(self):
        names = ["Client1", "Client2", "Client3", "SW-1", "FW-1", "Internet", "FW-2"]
        project = {"topology": {"nodes": [{"node_id": name, "name": name, "node_type": "qemu"} for name in names], "links": []}}
        doc = parse_gns3(project)
        self.assertEqual([d["name"] for d in doc["network"]["devices"] if d["type"] == "firewall"], ["FW-1", "FW-2"])
        fw = next(d for d in doc["network"]["devices"] if d["name"] == "FW-1")
        self.assertEqual(fw["original_type"], "qemu")
        self.assertEqual(fw["metadata"]["original_node"]["name"], "FW-1")
        self.assertTrue(all(not p["configuration_available"] and not p["rules"] for p in doc["firewalls"]))

    def test_existing_custom_electrical_json_compatibility(self):
        doc = parse_native({"case_name": "custom_import", "nodes": [
            {"bus_id": 0, "name": "Generator", "type": "slack", "voltage": 1.06},
            {"bus_id": 1, "name": "Load", "type": "pq", "voltage": 1.0}],
            "edges": [{"from": 0, "to": 1}]})
        self.assertEqual(len(doc["power_grid"]["buses"]), 2)
        self.assertTrue(any(d["id"] == "plc1" for d in doc["network"]["devices"]))

    def test_render_both_imports_and_untrusted_labels(self):
        from gui.imports import preview
        for document in (parse_native(self.native), parse_gns3(self.gns3)):
            document["network"]["devices"][0]["name"] = '<img src=x onerror="alert(1)">'
            result = preview(document)
            self.assertTrue(result["valid"])
            self.assertIn("vis.Network", result["pyvis_html"])
            self.assertNotIn('<img src=x onerror=', result["pyvis_html"])

    def test_duplicate_ids(self):
        self.native["network"]["devices"].append(deepcopy(self.native["network"]["devices"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate/invalid"):
            validate(self.native)

    def test_malformed_shapes_are_validation_errors(self):
        for mutation in (
            lambda d: d["network"]["devices"][0].update(type=[]),
            lambda d: d["links"][0]["endpoints"][0].update(device=[]),
            lambda d: d["links"][0]["endpoints"][0].update(interface={}),
            lambda d: d["power_grid"]["lines"][0].update(to_bus=[]),
            lambda d: d.update(metadata=[]),
            lambda d: d["firewalls"][0].update(default_action=[]),
            lambda d: d["firewalls"][0]["rules"][0].update(action=[]),
        ):
            doc = deepcopy(self.native); mutation(doc)
            with self.assertRaises(ValueError): parse_native(doc)

    def test_invalid_references_types_and_endpoints(self):
        mutations = [
            lambda d: d["links"][0]["endpoints"][0].update(device="missing"),
            lambda d: d["links"][0]["endpoints"][0].update(interface="missing"),
            lambda d: d["links"][0].update(endpoints=[]),
            lambda d: d["network"]["devices"][0].update(type="alien"),
            lambda d: d["firewalls"][0].update(id="scada"),
            lambda d: d["firewalls"][0]["rules"][0].update(source="unknown"),
            lambda d: d["mapping"][0].update(bus="missing"),
            lambda d: d["mapping"][0].update(device="scada"),
            lambda d: d["power_grid"]["lines"][0].update(to_bus="missing"),
            lambda d: d["network"]["devices"][0].update(ip="not-an-ip"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = deepcopy(self.native); mutate(document)
                with self.assertRaises(ValueError): validate(document)

    def test_gns3_invalid_links_and_duplicate_nodes(self):
        for mutation in (
            lambda d: d["topology"]["links"][0]["nodes"][0].update(node_id="missing"),
            lambda d: d["topology"]["links"][0].update(nodes=[]),
            lambda d: d["topology"]["nodes"].append(deepcopy(d["topology"]["nodes"][0])),
        ):
            doc = deepcopy(self.gns3); mutation(doc)
            with self.assertRaises(ValueError): parse_gns3(doc)

    def test_allow_deny_default_and_order(self):
        policy = self.native["firewalls"][0]
        scada = {"source": "scada", "destination": "plc8", "protocol": "tcp", "destination_port": 502}
        attacker = {**scada, "source": "attacker"}
        self.assertTrue(evaluate(policy, scada)["allowed"])
        self.assertFalse(evaluate(policy, attacker)["allowed"])
        self.assertFalse(evaluate(policy, {**scada, "destination_port": 503})["allowed"])
        policy["rules"].insert(0, {**policy["rules"][0], "rule_id": "broad", "source": "any", "priority": 1})
        self.assertTrue(evaluate(policy, attacker)["allowed"])
        self.assertFalse(evaluate(policy, attacker)["enforced"])

    def test_cidr_zone_source_port_and_tie_order(self):
        rule = {"rule_id": "cidr", "priority": 0, "source": "10.0.0.0/24", "destination": "any", "protocol": "tcp", "source_port": 1234, "destination_port": 502, "action": "allow"}
        traffic = {"source": "10.0.0.100", "destination": "plc8", "protocol": "TCP", "source_port": 1234, "destination_port": 502}
        policy = {"rules": [rule, {**rule, "rule_id": "deny", "action": "deny"}]}
        self.assertTrue(evaluate(policy, traffic)["allowed"])
        self.assertFalse(evaluate(policy, {**traffic, "source_port": 5})["allowed"])
        rule["source"] = "zone:operations"
        self.assertTrue(evaluate(policy, {**traffic, "source_zone": "operations"})["allowed"])

    def test_invalid_rules_and_traffic(self):
        for key, value in (("action", "drop"), ("destination_port", 65536), ("priority", True), ("protocol", "banana")):
            policy = deepcopy(self.native["firewalls"][0]); policy["rules"][0][key] = value
            with self.assertRaises(ValueError): evaluate(policy, {})
        with self.assertRaises(ValueError): evaluate(self.native["firewalls"][0], {"source": "scada"})

    def test_recommendation_existing_deny_and_broad_allow(self):
        finding = {"id": "finding-1", "technique_id": "T0836", "target": "plc8", "severity": "High", "attack_path": ["attacker", "fw1", "plc8"]}
        result = recommend(finding, self.native)
        self.assertFalse(result["applied"])
        self.assertIn("deny modeled", result["observed_weakness"])
        self.assertEqual(result["attack_path"], finding["attack_path"])
        self.assertEqual(result["proposed_rules"][-1]["action"], "deny")
        self.native["firewalls"][0]["rules"][0].update(source="any")
        self.assertIn("permits attacker", recommend(finding, self.native)["observed_weakness"])

    def test_old_or_unmapped_finding_does_not_invent_config(self):
        result = recommend({"id": "old", "target": "unmapped", "technique_id": "T0836"}, self.native)
        self.assertEqual(result["current_configuration"]["asset_mapping"], "unavailable")
        self.assertEqual(result["current_configuration"]["firewalls"], [])
        self.assertEqual(result["proposed_rules"], [])

    def test_report_contains_structured_advice_preserves_detection(self):
        from reports.pentest_report import generate_report, render_html
        events = [{"MITRE ID": "T0836", "Technique Name": "FDI", "Target Host": "plc8", "Detected": True,
                   "Detector Confidence": 0.75, "Detection Method": "suricata", "Mode": "CORE", "Stage": 3, "Status": "DETECTED"}]
        report = generate_report(events, {"imported_design": self.native})
        finding = report["findings"][0]
        self.assertTrue(finding["detected"])
        self.assertEqual(finding["detection_method"], "suricata")
        self.assertEqual(finding["remediation_recommendation"]["current_configuration"]["asset_mapping"], "matched")
        html = render_html(report)
        for text in ("Structured remediation recommendation", "Expected security benefit", "Retest procedure", "Proposed", "Current configuration"):
            self.assertIn(text, html)
        old = generate_report(events)["findings"][0]["remediation_recommendation"]
        self.assertEqual(old["current_configuration"]["firewalls"], [])
        snapshot = generate_report(events, {"run_metadata": {"imported_design": self.native}})
        self.assertEqual(snapshot["findings"][0]["remediation_recommendation"]["current_configuration"]["asset_mapping"], "matched")

    def test_new_run_snapshots_import_without_changing_core_layout(self):
        from gui.campaign import CampaignController
        from unittest.mock import Mock
        topology = Mock(); topology.canonical_snapshot.return_value = {"schema": "ascend.topology/v1", "nodes": []}
        request = Mock(side_effect=[{"state": "STOPPED"}, {"session_id": 7}])
        controller = CampaignController(request=request, topology=lambda: topology)
        controller._runtime = lambda: {"id": 7, "generation_id": "generation-test"}
        with patch("gui.imports.current", return_value=self.native), patch("gui.campaign.generate_core_xml", return_value="unused.xml"), \
             patch("gui.campaign.run_store.create_run", return_value={"scenario_id": "scenario-test", "run_id": "run-test"}) as create, \
             patch("gui.campaign.run_store.update_run", return_value={"scenario_id": "scenario-test", "run_id": "run-test", "generation_id": "generation-test"}) as update:
            controller.start_core()
            self.assertEqual(create.call_args.args[0], topology.canonical_snapshot.return_value)
            self.assertEqual(update.call_args_list[0].kwargs["imported_design"], self.native)

    def test_saved_workspace_and_failed_import_preservation(self):
        from gui import imports
        with tempfile.TemporaryDirectory() as directory, patch.object(imports, "PATH", Path(directory) / "import.json"), patch("gui.adapter._require_topology_editable"):
            imports.import_document({"format": "ascend", "document": self.native})
            before = imports.PATH.read_bytes()
            with self.assertRaises(ValueError): imports.import_document({"format": "gns3", "document": {}})
            self.assertEqual(before, imports.PATH.read_bytes())
            self.assertIsNone(imports.current())
            imports.use_imported({"revision": imports.revision(imports.candidate())})
            imports.import_document({"format": "gns3", "document": self.gns3, "save": False})
            self.assertEqual(before, imports.PATH.read_bytes())
            self.assertTrue(imports.decision({"firewall_id": "fw1", "traffic": {"source": "scada", "destination": "plc8", "protocol": "tcp", "destination_port": 502}})["allowed"])

    def test_gns3_filename_selects_gns3_parser(self):
        from gui import imports
        result = imports.import_document({"format": "ascend", "filename": "fortigate-lab.GNS3", "document": self.gns3, "save": False})
        self.assertEqual(result["document"]["metadata"]["source"], "gns3")

    def test_api_routes_without_server_or_runtime(self):
        from gui.server import GuiHandler
        from gui import imports
        with tempfile.TemporaryDirectory() as directory, patch.object(imports, "PATH", Path(directory) / "import.json"), patch("gui.adapter._require_topology_editable"):
            handler = object.__new__(GuiHandler)
            replies = []
            handler._write_json = lambda status, value: replies.append((status, value))
            for path, body in (("/api/topology/import", {"format": "ascend", "document": self.native}),
                               ("/api/topology/use-imported", {"revision": imports.revision(self.native)}),
                               ("/api/firewall/evaluate", {"firewall_id": "fw1", "traffic": {"source": "attacker", "destination": "plc8", "protocol": "tcp", "destination_port": 502}})):
                handler.path = path; handler._json_body = lambda: body
                with patch("gui.campaign.core_request", side_effect=AssertionError("Runtime must not be invoked")):
                    handler.do_POST()
                self.assertEqual(replies[-1][0], 200)
                self.assertTrue(replies[-1][1]["ok"])
            self.assertFalse(replies[-1][1]["allowed"])

    def test_active_source_isolation_and_empty_gns3_policy(self):
        from gui import imports
        with tempfile.TemporaryDirectory() as directory, patch.object(imports, "PATH", Path(directory) / "import.json"), patch("gui.adapter._require_topology_editable"):
            imports.import_document({"format": "ascend", "document": self.native})
            imports.use_imported({"revision": imports.revision(imports.candidate())})
            first = imports.active()
            imports.import_document({"format": "gns3", "document": self.gns3})
            self.assertEqual(imports.active()["revision"], first["revision"], "Validation must not activate the candidate")
            imports.use_imported({"revision": imports.revision(imports.candidate())})
            second = imports.active()
            self.assertEqual(second["firewall_policies"][0]["rules"], [])
            self.assertEqual(second["firewall_policies"][0]["configuration_origin"], "configuration_unavailable")
            with self.assertRaisesRegex(ValueError, "unavailable"):
                imports.decision({"firewall_id": "fw1", "traffic": {"source": "scada", "destination": "plc8", "protocol": "tcp", "destination_port": 502}})
            with self.assertRaisesRegex(ValueError, "changed"):
                imports.decision({"revision": first["revision"], "firewall_id": "fw1"})
            from testbed.topology import activate_topology, Topology
            activate_topology(Topology.from_custom_dict(self.base))
            self.assertIsNone(imports.current())
            self.assertEqual(imports.active()["firewall_policies"], [])
            with self.assertRaisesRegex(ValueError, "Unknown firewall"):
                imports.decision({"firewall_id": "fw1"})


if __name__ == "__main__":
    unittest.main()
