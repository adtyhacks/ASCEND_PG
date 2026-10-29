"""Pure verification of supplied CORE namespace evidence; performs no I/O."""
from ipaddress import ip_address, ip_interface, ip_network
import json
import re

from testbed.ip_config import ATTACKER_IP, SUBNET_CIDR


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_namespace_isolation(inspection, topology):
    """Accept canonical CORE routing while rejecting unexpected connectivity.

    ``topology`` is the canonical XML root, not a replacement topology model.
    ``inspection`` contains read-only namespace, IPv4/IPv6 route and address
    command output. Passing checks the supplied configuration, not packet flow.
    Session ownership/generation validation remains the caller's responsibility.
    """
    networks = topology.findall("networks/network")
    devices = topology.findall("devices/device")
    links = topology.findall("links/link")
    _require(len(networks) == 1 and networks[0].get("type") in {"HUB", "SWITCH"},
             "Unexpected external topology network")
    _require(all(node.get("type") in {"PC", "host"} for node in devices),
             "Unexpected external topology endpoint")
    _require(not any(option.get("value") for option in topology.findall(
        "session_options/configuration[@name='controlnet']")), "Unexpected control network")
    hub = networks[0].get("id")
    device_ids = {node.get("id") for node in devices}
    _require(len(links) == len(devices) and
             {link.get("node1") for link in links} == device_ids and
             all(link.get("node2") == hub and len(link.findall("iface1")) == 1
                 for link in links), "Unexpected topology link")
    attackers = [node for node in devices if node.get("name") == "attacker"]
    _require(len(attackers) == 1, "Missing or ambiguous canonical attacker")
    attacker = attackers[0]
    interface = next(link.find("iface1") for link in links
                     if link.get("node1") == attacker.get("id"))
    address = ip_interface(f"{interface.get('ip4')}/{interface.get('ip4_mask')}")
    _require(str(address.ip) == ATTACKER_IP and str(address.network) == SUBNET_CIDR
             and interface.get("name") == "eth0", "Unexpected canonical attacker interface")
    # CORE DefaultRouteService uses the first interface's network[1]. It does
    # not imply that the chosen peer (canonical PLC1) forwards to the outside.
    gateway = str(address.network[1])
    default_enabled = attacker.find("services/service[@name='DefaultRoute']") is not None
    commands = inspection["commands"]
    namespace = commands["namespace"].strip()
    host_namespace = inspection["host_namespace"].strip()
    _require(re.fullmatch(r"net:\[\d+\]", namespace) and
             re.fullmatch(r"net:\[\d+\]", host_namespace) and
             namespace != host_namespace, "Host namespace leakage or invalid namespace evidence")

    addresses = json.loads(commands["addresses"])
    _require(len(addresses) == 2 and {item["ifname"] for item in addresses} == {"lo", "eth0"},
             "Unexpected or missing network interface")
    eth0 = next(item for item in addresses if item["ifname"] == "eth0")
    _require(eth0.get("address", "").lower() == interface.get("mac", "").lower(),
             "Canonical interface MAC mismatch")
    ipv4 = [item for item in eth0.get("addr_info", []) if item["family"] == "inet"]
    _require(len(ipv4) == 1 and ipv4[0]["local"] == str(address.ip) and
             ipv4[0]["prefixlen"] == address.network.prefixlen, "Unexpected IPv4 address")
    for item in addresses:
        for record in item.get("addr_info", []):
            ip = ip_address(record["local"])
            _require(record["family"] == ("inet" if ip.version == 4 else "inet6"),
                     "Address family mismatch")
            _require(ip.is_loopback if item["ifname"] == "lo" else
                     (ip == address.ip if ip.version == 4 else ip.is_link_local),
                     "Unexpected external interface address")

    routes = json.loads(commands["routes"])
    defaults, connected = 0, 0
    for route in routes:
        _require(route.get("dev") == "eth0" and route.get("type", "unicast") == "unicast"
                 and route.get("table", "main") in {"main", 254}
                 and not any(key in route for key in ("multipath", "nexthops", "via", "nhid", "encap")),
                 "Unexpected route interface, table or next hop")
        if route.get("dst") in {"default", "0.0.0.0/0"}:
            _require(default_enabled and route.get("gateway") == gateway,
                     "Unexpected default gateway or unconfigured DefaultRoute")
            defaults += 1
        else:
            _require(route.get("dst") == str(address.network) and not route.get("gateway")
                     and route.get("scope", "link") == "link"
                     and route.get("prefsrc", str(address.ip)) == str(address.ip),
                     "Unexpected external or non-canonical connected route")
            connected += 1
    _require(connected == 1 and defaults <= 1, "Missing connected route or duplicate routing")
    # IPv4 evidence alone cannot rule out an unexpected IPv6 default route.
    _require("routes6" in commands, "Missing IPv6 route evidence")
    for route in json.loads(commands["routes6"]):
        _require(route.get("dev") == "eth0" and route.get("type", "unicast") == "unicast"
                 and route.get("table", "main") in {"main", 254}
                 and not any(key in route for key in ("gateway", "multipath", "nexthops", "via", "nhid", "encap"))
                 and route.get("dst") not in {None, "default", "::/0"}
                 and ip_network(route["dst"]).version == 6 and ip_network(route["dst"]).is_link_local,
                 "Unexpected external IPv6 route")
    return {"namespace": namespace, "interface": "eth0", "subnet": str(address.network),
            "canonical_gateway": gateway, "default_route_present": bool(defaults)}
