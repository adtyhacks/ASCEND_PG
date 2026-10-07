"""Focused offline compiler/runtime tests. Fake gRPC commands, never CORE packets."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from firewall.compiler import compile_policy, nft_script
from firewall.runtime import install, verify
from testbed.firewall_topology import build_plan, scenario, xml_plan
from testbed.topology import Topology
from testbed.core_xml import validate_xml
from testbed.generate_core_topo import generate_core_xml

ROOT = Path(__file__).resolve().parents[1]


class FakeCore:
    def __init__(self, failure=None):
        self.installed = False; self.forwarding = "0"; self.commands = []; self.failure = failure
        self.rules = {"nftables": [{"table": {"family": "ip", "name": "ascend_fw"}},
                    {"chain": {"family": "ip", "table": "ascend_fw", "name": "forward", "hook": "forward", "policy": "drop", "prio": 0, "type": "filter"}}]}
        document = json.loads((ROOT / "examples/core_firewall_smoke.json").read_text())
        compiled = compile_policy(document["firewalls"][0], document["network"]["devices"])
        for i, rule in enumerate(compiled["rules"] + [{"action": compiled["default"]}]):
            expressions = []
            for side, field in (("source", "saddr"), ("destination", "daddr")):
                if rule.get(side): expressions.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": field}}, "right": rule[side]}})
            if rule.get("protocol", "any") != "any": expressions.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "protocol"}}, "right": rule["protocol"]}})
            expressions += [{"counter": {"packets": 0, "bytes": 0}}, {rule["action"]: None}]
            self.rules["nftables"].append({"rule": {"family": "ip", "table": "ascend_fw", "chain": "forward", "comment": f"ascend:{i}" if i < len(compiled["rules"]) else "ascend:default", "expr": expressions}})
    def node_command(self, sid, nid, command, shell):
        self.commands.append(command)
        if self.failure and self.failure in command: return 1, "injected failure"
        if command.startswith("readlink"): return 0, "net:[222]"
        if command == "nft -j list ruleset": return 0, json.dumps(self.rules if self.installed else {"nftables": [{"metainfo": {}}]})
        if "| nft -f -" in command: self.installed = True
        if "ip_forward=" in command: self.forwarding = command[-1]
        if command == "sysctl -n net.ipv4.ip_forward": return 0, self.forwarding
        return 0, ""


class FirewallCoreTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/core_firewall_smoke.json").read_text())
        self.topology = Topology.from_exchange(self.document)
        self.plan = build_plan(self.document, self.topology.revision)
        self.session = SimpleNamespace(id=5)

    def test_firewall_and_exact_interface_mapping(self):
        root = scenario(self.plan)
        firewall = root.find("devices/device[@name='FW-1']")
        self.assertIsNotNone(firewall)
        fw = next(d for d in self.plan["devices"] if d["id"] == "fw")
        self.assertEqual([(p["id"], p["core_name"], p["ip"]) for p in fw["interfaces"]], [("inside", "eth0", "10.77.1.1/24"), ("outside", "eth1", "10.77.2.1/24")])
        self.assertEqual(len(root.findall("links/link")), len(self.document["links"]))
        self.assertEqual(next(d for d in self.plan["devices"] if d["id"] == "client")["core_gateway"], "10.77.1.1")
        self.assertTrue(self.topology.core_compatible)
        self.assertFalse(self.topology.ppo_compatible)

    def test_xml_compiles_only_canonical_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(generate_core_xml(output_path=str(Path(directory) / "fw.xml"), topology=self.topology))
            root = validate_xml(path)
            self.assertEqual(xml_plan(root), self.plan)
            root.find("devices/device").set("name", "other")
            import xml.etree.ElementTree as ET
            path.write_text(ET.tostring(root, encoding="unicode"))
            with self.assertRaisesRegex(ValueError, "deviates"): validate_xml(path)

    def test_nft_allow_drop_default_and_order(self):
        text = nft_script(self.plan["compiled"])
        self.assertIn("policy drop", text)
        self.assertLess(text.index("10.77.1.3/32"), text.index("10.77.1.2/32"))
        self.assertIn('counter drop comment "ascend:0"', text)
        self.assertIn('counter accept comment "ascend:1"', text)
        self.assertIn('counter drop comment "ascend:default"', text)
        self.assertNotIn("established", text)

    def test_protocol_ports_cidrs_and_stable_priority(self):
        p = self.document["firewalls"][0]
        p["rules"] = [{"rule_id": "late", "priority": 9, "source": "10.77.1.0/24", "destination": "10.77.2.0/24", "protocol": "tcp", "source_port": 1234, "destination_port": 502, "action": "allow"},
                      {"rule_id": "first", "priority": 0, "source": "any", "destination": "any", "protocol": "udp", "source_port": "any", "destination_port": 53, "action": "deny"},
                      {"rule_id": "tie", "priority": 0, "source": "any", "destination": "any", "protocol": "icmp", "action": "allow"}]
        compiled = compile_policy(p, self.document["network"]["devices"])
        self.assertEqual([r["rule_id"] for r in compiled["rules"]], ["first", "tie", "late"])
        self.assertIn("tcp sport 1234 tcp dport 502", nft_script(compiled))
        p["default_action"] = "allow"
        self.assertIn('counter accept comment "ascend:default"', nft_script(compile_policy(p, self.document["network"]["devices"])))

    def test_unknown_unavailable_and_semantic_broadening_rejected(self):
        for edit in (lambda d: d["network"]["devices"][0]["interfaces"][0].pop("ip"),
                     lambda d: d["firewalls"][0].update(configuration_available=False),
                     lambda d: d["firewalls"][0]["rules"][0].update(source_port=1234),
                     lambda d: d["firewalls"][0].pop("default_action")):
            document = deepcopy(self.document); edit(document)
            with self.assertRaises(ValueError): build_plan(document, "r")

    def test_bypass_subnet_overlap_and_disconnected_rejected(self):
        d = deepcopy(self.document)
        d["network"]["devices"][4]["interfaces"][0]["ip"] = "10.77.1.4/24"
        with self.assertRaisesRegex(ValueError, "subnet"): build_plan(d, "r")
        d = deepcopy(self.document); d["links"].pop()
        with self.assertRaises(ValueError): build_plan(d, "r")

    def test_runtime_installation_verified_from_readback(self):
        core = FakeCore(); events = []
        with patch("firewall.runtime.os.readlink", return_value="net:[111]"):
            result = install(core, self.session, self.plan, "generation", lambda name, data: events.append((name, deepcopy(data))))
        self.assertTrue(result["enforced"])
        self.assertEqual(result["backend"], "nftables")
        self.assertEqual(result["rules_installed"], 3)
        self.assertEqual([e[0] for e in events], ["firewall_initialized", "firewall_configuration_loaded", "firewall_rules_installed", "firewall_enforcement_state"])
        self.assertLess(next(i for i, cmd in enumerate(core.commands) if "| nft -f -" in cmd), core.commands.index("sysctl -qw net.ipv4.ip_forward=1"))
        self.assertFalse(any(name in ("packet_allowed", "packet_denied") for name, _ in events))
        self.assertTrue(verify(core, self.session, self.plan, result)["enforced"])
        core.rules["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
        self.assertFalse(verify(core, self.session, self.plan, result)["enforced"])

    def test_failed_installation_and_host_namespace_fail_closed(self):
        for failure in ("| nft -c", "| nft -f", "net.ipv4.ip_forward=1"):
            core = FakeCore(failure=failure); events = []
            with patch("firewall.runtime.os.readlink", return_value="net:[111]"):
                result = install(core, self.session, self.plan, "g", lambda name, data: events.append(name))
            self.assertFalse(result["enforced"])
            self.assertEqual(core.forwarding, "0")
            self.assertIn("firewall_installation_failed", events)
        core = FakeCore()
        with patch("firewall.runtime.os.readlink", return_value="net:[222]"):
            result = install(core, self.session, self.plan, "g", lambda *args: None)
        self.assertFalse(result["enforced"])
        self.assertEqual(core.commands, ["readlink /proc/self/ns/net"])

    def test_counter_changes_do_not_invalidate_installation(self):
        core = FakeCore()
        with patch("firewall.runtime.os.readlink", return_value="net:[111]"):
            result = install(core, self.session, self.plan, "g", lambda *args: None)
        core.rules["nftables"][2]["rule"]["expr"][-2]["counter"]["packets"] = 100
        self.assertTrue(verify(core, self.session, self.plan, result)["enforced"])

    def test_installation_rejects_wrong_actual_verdict(self):
        core = FakeCore()
        core.rules["nftables"][2]["rule"]["expr"][-1] = {"accept": None}
        with patch("firewall.runtime.os.readlink", return_value="net:[111]"):
            result = install(core, self.session, self.plan, "g", lambda *args: None)
        self.assertFalse(result["enforced"])
        self.assertIn("semantics", result["error"])

    def test_smoke_requires_packet_outcome_and_drop_counter(self):
        from firewall.smoke import probe
        core = FakeCore()
        with patch("firewall.runtime.os.readlink", return_value="net:[111]"):
            status = install(core, self.session, self.plan, "g", lambda *args: None)
        # A failed ping without a matching drop counter is never packet-denied evidence.
        original = core.node_command
        def command(sid, nid, cmd, shell):
            if " ping " in cmd: return (0, "reply") if nid == self.plan["node_ids"]["client"] else (1, "timeout")
            return original(sid, nid, cmd, shell)
        core.node_command = command
        events = []
        result = probe(core, self.session, self.plan, status, lambda kind, data: events.append(kind))
        self.assertFalse(result["packet_enforcement_verified"])
        self.assertNotIn("packet_denied", events)
        def counted(sid, nid, cmd, shell):
            if " ping " in cmd:
                index = 1 if nid == self.plan["node_ids"]["client"] else 0
                core.rules["nftables"][index + 2]["rule"]["expr"][-2]["counter"]["packets"] += 1
                return (0, "reply") if index == 1 else (1, "timeout")
            return original(sid, nid, cmd, shell)
        core.node_command = counted
        self.assertTrue(probe(core, self.session, self.plan, status, lambda *args: None)["packet_enforcement_verified"])


class FirewallLifecycleTests(unittest.TestCase):
    def test_installation_uses_owned_start_and_status(self):
        try:
            from scripts import core_session as manager
        except ImportError:
            self.skipTest("Run this integration check with installed CORE Python.")
        for failure in (None, "| nft -f -"):
            with tempfile.TemporaryDirectory() as directory:
                topology = Topology.from_exchange(json.loads((ROOT / "examples/core_firewall_smoke.json").read_text()))
                path = generate_core_xml(output_path=str(Path(directory) / "fw.xml"), topology=topology)
                state = Path(directory) / "session.json"
                fake = FakeCore(failure=failure); c = MagicMock(); c.address = "localhost:50051"
                c.create_session.return_value = SimpleNamespace(id=5)
                live = SimpleNamespace(id=5, state=manager.w.SessionState.RUNTIME, nodes={1: SimpleNamespace(name="client")}, metadata={})
                def start(definition):
                    live.metadata = dict(definition.metadata)
                    return True, []
                c.start_session.side_effect = start
                c.get_session.return_value = live; c.check_session.return_value = True
                c.node_command.side_effect = fake.node_command
                with patch.object(manager, "STATE", state), patch.object(manager, "preflight"), patch.object(manager, "register"), patch.object(manager, "firewall_record"), patch("firewall.runtime.os.readlink", return_value="net:[111]"):
                    result = manager.perform(c, {"action": "start", "xml": path})
                    self.assertEqual(result["firewalls"][0]["enforced"], failure is None)
                    self.assertEqual(json.loads(state.read_text())["firewall_status"], result["firewalls"])
                    status = manager.perform(c, {"action": "status"})
                    self.assertEqual(status["firewalls"][0]["enforced"], failure is None)
                    with self.assertRaisesRegex(RuntimeError, "generation changed"):
                        manager.perform(c, {"action": "stop", "generation_id": "old"})
                c.delete_session.assert_not_called()


if __name__ == "__main__": unittest.main()
