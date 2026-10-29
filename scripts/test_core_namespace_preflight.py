"""Socket-free regression for the Phase 3F.5 namespace precheck."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts.core_namespace_preflight import validate_namespace_isolation


ROOT = Path(__file__).resolve().parents[1]


class NamespacePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = ET.parse(ROOT / "core_topology.xml").getroot()

    def setUp(self):
        self.inspection = {
            "host_namespace": "net:[4026531840]",
            "commands": {
                "namespace": "net:[4026533000]",
                "routes": json.dumps([
                    {"dst": "default", "gateway": "10.0.0.1", "dev": "eth0", "flags": []},
                    {"dst": "10.0.0.0/24", "dev": "eth0", "protocol": "kernel",
                     "scope": "link", "prefsrc": "10.0.0.66", "flags": []},
                ]),
                "routes6": json.dumps([{"dst": "fe80::/64", "dev": "eth0"}]),
                "addresses": json.dumps([
                    {"ifname": "lo", "addr_info": [
                        {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                        {"family": "inet6", "local": "::1", "prefixlen": 128}]},
                    {"ifname": "eth0", "address": "00:00:00:aa:00:03", "addr_info": [
                        {"family": "inet", "local": "10.0.0.66", "prefixlen": 24},
                        {"family": "inet6", "local": "fe80::a", "prefixlen": 64}]},
                ]),
            },
        }
        guards = ExitStack()
        self.addCleanup(guards.close)
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen",
                       "subprocess.run", "os.system", "builtins.open", "pathlib.Path.open"):
            guards.enter_context(patch(target, side_effect=AssertionError(f"Forbidden effect: {target}")))

    def validate(self, inspection=None, topology=None):
        return validate_namespace_isolation(
            self.inspection if inspection is None else inspection,
            self.topology if topology is None else topology)

    def test_canonical_default_route_is_accepted_without_mutation(self):
        before = deepcopy(self.inspection)
        topology_before = ET.tostring(self.topology)
        result = self.validate()
        self.assertEqual(result["canonical_gateway"], "10.0.0.1")
        self.assertTrue(result["default_route_present"])
        self.assertEqual(self.inspection, before)
        self.assertEqual(ET.tostring(self.topology), topology_before)

    def test_connected_only_route_is_isolated(self):
        self.inspection["commands"]["routes"] = json.dumps(
            json.loads(self.inspection["commands"]["routes"])[1:])
        self.assertFalse(self.validate()["default_route_present"])

    def test_unexpected_route_or_gateway_is_rejected(self):
        original = json.loads(self.inspection["commands"]["routes"])
        variants = [
            [{**original[0], "gateway": gateway}, original[1]]
            for gateway in ("192.168.1.1", "203.0.113.1", "10.0.0.254")]
        variants += [
            [{**original[0], "dev": "eth1"}, original[1]],
            original + [deepcopy(original[0])],
            original + [{"dst": "203.0.113.0/24", "dev": "eth0"}],
            [{**original[0], "nexthops": [{"gateway": "192.168.1.1"}]}, original[1]],
        ]
        for routes in variants:
            with self.subTest(routes=routes):
                self.inspection["commands"]["routes"] = json.dumps(routes)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_host_namespace_is_rejected(self):
        self.inspection["commands"]["namespace"] = self.inspection["host_namespace"]
        with self.assertRaisesRegex(ValueError, "namespace"):
            self.validate()

    def test_unexpected_interface_or_address_is_rejected(self):
        original = json.loads(self.inspection["commands"]["addresses"])
        variants = [original + [{"ifname": "eth1", "addr_info": []}]]
        for field, value in (("address", "00:00:00:aa:00:ff"),):
            changed = deepcopy(original); changed[1][field] = value; variants.append(changed)
        for field, value in (("local", "192.168.1.2"), ("prefixlen", 16)):
            changed = deepcopy(original); changed[1]["addr_info"][0][field] = value; variants.append(changed)
        changed = deepcopy(original)
        changed[1]["addr_info"].append({"family": "inet6", "local": "2001:db8::2", "prefixlen": 64})
        variants.append(changed)
        for addresses in variants:
            with self.subTest(addresses=addresses):
                self.inspection["commands"]["addresses"] = json.dumps(addresses)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_external_ipv6_or_missing_route_evidence_is_rejected(self):
        for route in ({"dst": "default", "gateway": "fe80::1", "dev": "eth0"},
                      {"dst": "2001:db8::/32", "dev": "eth0"}):
            with self.subTest(route=route):
                self.inspection["commands"]["routes6"] = json.dumps([route])
                with self.assertRaises(ValueError):
                    self.validate()
        del self.inspection["commands"]["routes6"]
        with self.assertRaisesRegex(ValueError, "Missing IPv6"):
            self.validate()

    def test_external_topology_or_unconfigured_default_is_rejected(self):
        for change in ("no_default", "external_node", "controlnet"):
            with self.subTest(change=change):
                topology = deepcopy(self.topology)
                attacker = topology.find("devices/device[@name='attacker']")
                if change == "no_default":
                    services = attacker.find("services")
                    services.remove(services.find("service[@name='DefaultRoute']"))
                elif change == "external_node":
                    attacker.set("type", "RJ45")
                else:
                    topology.find("session_options/configuration[@name='controlnet']").set("value", "192.168.1.0/24")
                with self.assertRaises(ValueError):
                    self.validate(topology=topology)


if __name__ == "__main__":
    unittest.main()
