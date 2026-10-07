"""Offline configuration imports; no runtime services or packets."""
from copy import deepcopy
import unittest

from scripts import test_external_mvp
from testbed.external_topology import parse_gns3, classify_gns3
from firewall.model import evaluate


class Gns3FirewallTests(unittest.TestCase):
    # Reuse temporary canonical-store setup, not the inherited test suite.
    setUp = test_external_mvp.ExternalMvpTests.setUp
    def config(self):
        return {"hostname": "edge-asa", "interfaces": [{"id": "inside", "name": "inside", "ip": "10.0.0.1/24", "zone": "operations"}],
                "zones": [{"id": "operations"}], "address_objects": [{"id": "clients", "network": "10.0.0.0/24"}],
                "services": [{"id": "modbus", "protocol": "tcp", "destination_port": 502}], "default_policy": "DENY",
                "rules": [{"rule_id": "deny-first", "priority": 7, "source": "scada", "destination": "plc8", "protocol": "TCP", "source_port": 1234, "destination_port": 502, "action": "DENY"},
                          {"rule_id": "allow-second", "priority": 7, "source": "any", "destination": "any", "protocol": "TCP", "source_port": "any", "destination_port": 502, "action": "ALLOW"}]}

    def supplied(self, config=None):
        project = deepcopy(self.gns3)
        project["topology"]["nodes"][1]["properties"] = {"firewall_configuration": self.config() if config is None else config}
        return project

    def test_identification_evidence_priority(self):
        for vendor in ("ASA", "pfSense", "OPNsense", "FortiGate", "Fortinet"):
            self.assertEqual(classify_gns3({"name": "node1", "appliance": {"product": vendor}})[0], "firewall")
        self.assertEqual(classify_gns3({"name": "node1", "template_name": "pfSense", "node_type": "router"})[0], "firewall")
        self.assertEqual(classify_gns3({"name": "FW-1", "device_type": "router", "template_name": "ASA"})[0], "router")
        self.assertEqual(classify_gns3({"name": "Router1", "node_type": "router"})[0], "router")
        self.assertNotEqual(classify_gns3({"name": "bonfire", "node_type": "qemu"})[0], "firewall")
        self.assertEqual(classify_gns3({"name": "node1", "metadata": {"type": "firewall"}})[0], "firewall")

    def test_structured_import_full_fidelity(self):
        project = self.supplied(); policy = parse_gns3(project)["firewalls"][0]
        self.assertTrue(policy["configuration_available"])
        self.assertEqual(policy["hostname"], "edge-asa")
        for key in ("interfaces", "zones", "address_objects", "services"):
            self.assertEqual(policy[key], self.config()[key])
        self.assertEqual(policy["default_action"], "deny")
        self.assertEqual([r["rule_id"] for r in policy["rules"]], ["deny-first", "allow-second"])
        self.assertEqual([r["order"] for r in policy["rules"]], [0, 1])
        self.assertEqual([r["action"] for r in policy["rules"]], ["deny", "allow"])
        rule = policy["rules"][0]
        self.assertEqual((rule["source"], rule["destination"], rule["protocol"], rule["source_port"], rule["destination_port"]), ("scada", "plc8", "tcp", 1234, 502))
        self.assertEqual(policy["original_source_metadata"]["payload"], self.config())
        self.assertEqual(project, self.supplied(), "Parser must not mutate original evidence")
        self.assertFalse(evaluate(policy, {"source": "scada", "destination": "plc8", "protocol": "tcp", "source_port": 1234, "destination_port": 502})["allowed"])

    def test_each_explicit_source(self):
        for field in ("firewall_configuration", "appliance", "template"):
            project = deepcopy(self.gns3)
            project["topology"]["nodes"][1][field] = self.config() if field == "firewall_configuration" else {"firewall_configuration": self.config()}
            self.assertTrue(parse_gns3(project)["firewalls"][0]["configuration_available"])
        for field in ("appliance", "template"):
            project = deepcopy(self.gns3)
            project["topology"]["nodes"][1]["properties"] = {field: {"firewall_configuration": self.config()}}
            self.assertTrue(parse_gns3(project)["firewalls"][0]["configuration_available"])

    def test_source_precedence_does_not_merge(self):
        project = self.supplied()
        project["topology"]["nodes"][1]["firewall_configuration"] = {"rules": [], "default_action": "allow"}
        policy = parse_gns3(project)["firewalls"][0]
        self.assertEqual(policy["rules"], [])
        self.assertEqual(policy["default_action"], "allow")

    def test_missing_and_path_only_do_not_fabricate(self):
        for properties in ({}, {"startup_config": "configs/firewall.cfg", "hda_disk_image": "FortiGate.qcow2"}):
            project = deepcopy(self.gns3); project["topology"]["nodes"][1]["properties"] = properties
            policy = parse_gns3(project)["firewalls"][0]
            self.assertFalse(policy["configuration_available"])
            self.assertEqual(policy["rules"], [])
            self.assertIsNone(policy["default_policy"])
            with self.assertRaisesRegex(ValueError, "unavailable"): evaluate(policy, {})

    def test_present_empty_rules_is_available(self):
        policy = parse_gns3(self.supplied({"rules": [], "default_policy": "ALLOW"}))["firewalls"][0]
        self.assertTrue(policy["configuration_available"])
        self.assertEqual(policy["rules"], [])
        self.assertEqual(policy["default_action"], "allow")

    def test_missing_default_is_unknown_not_fabricated(self):
        policy = parse_gns3(self.supplied({"rules": []}))["firewalls"][0]
        self.assertIsNone(policy["default_action"])
        self.assertFalse(policy["evaluation_supported"])

    def test_malformed_config_fails_without_wildcards(self):
        for mutation in (lambda c: c.pop("rules"), lambda c: c["rules"][0].pop("destination_port"),
                         lambda c: c["rules"][0].pop("source"), lambda c: c["interfaces"][0].update(ip="bad")):
            config = self.config(); mutation(config)
            with self.assertRaises(ValueError): parse_gns3(self.supplied(config))

    def test_objects_retained_without_uncontrolled_expansion(self):
        config = self.config(); config["rules"][0]["source"] = "object:clients"
        policy = parse_gns3(self.supplied(config))["firewalls"][0]
        self.assertEqual(policy["rules"][0]["source"], "object:clients")
        self.assertFalse(policy["evaluation_supported"])

    def test_asa_inline_acl_interfaces_order_ports_and_bindings(self):
        text = """hostname edge
interface GigabitEthernet0/0
 nameif inside
 ip address 10.0.0.1 255.255.255.0
!
access-list INSIDE extended deny tcp host 10.0.0.2 eq 1234 host 10.0.0.8 eq 502
access-list INSIDE extended permit ip any any
access-group INSIDE in interface inside
"""
        project = deepcopy(self.gns3); project["topology"]["nodes"][1]["properties"] = {"startup_config_content": text}
        policy = parse_gns3(project)["firewalls"][0]
        self.assertTrue(policy["configuration_available"])
        self.assertEqual(policy["interfaces"][0]["ip"], "10.0.0.1/24")
        self.assertEqual(policy["zones"][0]["id"], "inside")
        self.assertEqual([r["action"] for r in policy["rules"]], ["deny", "allow"])
        self.assertEqual(policy["rules"][0]["source_port"], 1234)
        self.assertEqual(policy["rules"][0]["destination_port"], 502)
        self.assertEqual(policy["acl_bindings"][0]["interface"], "inside")
        self.assertFalse(policy["evaluation_supported"])
        self.assertIsNone(policy["default_action"])

    def test_unsupported_content_retained_and_cannot_evaluate(self):
        for text in ("config firewall policy\nend", "access-list A extended permit tcp object-group X any eq 502\naccess-group A in interface inside"):
            project = deepcopy(self.gns3); project["topology"]["nodes"][1]["properties"] = {"startup_config_content": text}
            policy = parse_gns3(project)["firewalls"][0]
            self.assertTrue(policy["configuration_available"])
            self.assertFalse(policy["import_complete"])
            self.assertEqual(policy["rules"], [])
            self.assertEqual(policy["original_source_metadata"]["payload"], text)

    def test_configuration_roundtrip_and_switch_context(self):
        from gui import imports
        from testbed.topology import Topology, activate_topology
        doc = parse_gns3(self.supplied()); activate_topology(Topology.from_exchange(doc))
        context = imports.active()
        self.assertEqual([p["id"] for p in context["firewall_policies"]], ["fw1"])
        self.assertEqual(Topology.from_dict(Topology.from_exchange(doc).to_dict()).exchange["firewalls"], doc["firewalls"])
        activate_topology(Topology.from_exchange(parse_gns3(self.gns3)))
        current = imports.active()
        self.assertFalse(current["firewall_policies"][0]["configuration_available"])
        self.assertEqual(current["firewall_policies"][0]["rules"], [])
        with self.assertRaisesRegex(ValueError, "changed"):
            imports.decision({"revision": context["revision"], "firewall_id": "fw1"})

    def test_unavailable_policy_does_not_break_retained_advice(self):
        from remediation.engine import recommend
        project = deepcopy(self.gns3)
        project["topology"]["nodes"].append({"node_id": "attacker", "name": "attacker", "node_type": "vpcs"})
        result = recommend({"id": "finding", "affected_asset": "plc8", "attack_technique": "T0836"}, parse_gns3(project))
        self.assertEqual(result["current_configuration"]["modeled_attack_access"], [])

    def test_device_addresses_resolved_only_from_active_topology(self):
        from gui import imports
        from testbed.topology import Topology, activate_topology
        config = self.config()
        config["rules"] = [{**config["rules"][0], "action": "ALLOW", "source": "any", "destination": "10.0.0.8/32"}]
        activate_topology(Topology.from_exchange(parse_gns3(self.supplied(config))))
        data = {"firewall_id": "fw1", "traffic": {"source": "scada", "destination": "plc8", "protocol": "tcp", "source_port": 1234, "destination_port": 502, "destination_addresses": ["192.0.2.1"]}}
        self.assertTrue(imports.decision(data)["allowed"])
        data["traffic"]["destination"] = "old-plc"
        with self.assertRaisesRegex(ValueError, "active topology"): imports.decision(data)

    def test_saved_candidate_upgrade_is_read_only_and_keeps_existing_policy(self):
        from testbed.external_topology import normalize_saved_gns3
        old = parse_gns3(self.supplied()); original = deepcopy(old)
        old["firewalls"] = []
        upgraded = normalize_saved_gns3(old)
        self.assertEqual(upgraded["firewalls"][0]["rules"], original["firewalls"][0]["rules"])
        self.assertEqual(old["firewalls"], [])
        self.assertEqual(normalize_saved_gns3(original)["firewalls"], original["firewalls"])


if __name__ == "__main__": unittest.main()
