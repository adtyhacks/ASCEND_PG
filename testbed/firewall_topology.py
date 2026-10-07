"""Canonical addressed routed-firewall projection, separate from legacy hub layout."""
from copy import deepcopy
from ipaddress import ip_interface
import json
import re
import xml.etree.ElementTree as ET
from firewall.compiler import compile_policy
from testbed.core_services import FILES, service_name

PLAN_KEY = "ascend_firewall_plan"


def build_plan(document, revision):
    from testbed.external_topology import validate
    validate(document)
    devices = deepcopy(document["network"]["devices"])
    by_id = {d["id"]: d for d in devices}
    firewalls = [d for d in devices if d["type"] == "firewall"]
    if len(firewalls) != 1: raise ValueError("Routed CORE projection currently requires exactly one firewall.")
    fw = firewalls[0]
    policy = next((p for p in document.get("firewalls", []) if p["id"] == fw["id"]), None)
    if not policy: raise ValueError("Firewall requires supplied configuration before CORE deployment.")
    configured = {p["id"]: p for p in policy.get("interfaces", [])}
    for d in devices:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", d.get("name", d["id"])):
            raise ValueError("CORE node names must be unique safe identifiers (1–63 characters).")
        if d["type"] not in ("firewall", "switch", "scada", "plc", "rtu", "generic", "attacker", "hmi"):
            raise ValueError(f"Routed CORE role {d['type']} is unsupported; no role is substituted.")
        if d.get("plc"): raise ValueError("Routed smoke projection does not launch declared PLC register services.")
        for interface in d.get("interfaces", []):
            if d is fw and interface.get("ip") and configured.get(interface["id"], {}).get("ip") and ip_interface(interface["ip"]) != ip_interface(configured[interface["id"]]["ip"]):
                raise ValueError("Canonical firewall and configuration interface addresses conflict.")
            if d is fw and not interface.get("ip") and configured.get(interface["id"], {}).get("ip"):
                interface["ip"] = configured[interface["id"]]["ip"]
    if len({d.get("name", d["id"]) for d in devices}) != len(devices): raise ValueError("CORE node names must be unique.")
    ids = {d["id"]: i + 1 for i, d in enumerate(devices)}
    graph = {d["id"]: set() for d in devices}
    used = {d["id"]: set() for d in devices}
    links = deepcopy(document["links"])
    for link in links:
        a, b = link["endpoints"]
        for e in (a, b):
            if e["interface"] in used[e["device"]]: raise ValueError("Each canonical interface may have only one CORE link.")
            used[e["device"]].add(e["interface"])
        graph[a["device"]].add(b["device"]); graph[b["device"]].add(a["device"])
    if len(used[fw["id"]]) < 2: raise ValueError("Firewall must sit between at least two segments.")
    addresses = set()
    for d in devices:
        if not used[d["id"]]: raise ValueError("Disconnected devices cannot be deployed.")
        if d["type"] == "switch": continue
        if used[d["id"]] != {p["id"] for p in d.get("interfaces", [])}: raise ValueError("All endpoint/firewall interfaces must map to links.")
        if d is not fw and len(used[d["id"]]) != 1: raise ValueError("Endpoints must have exactly one interface; routers are not inferred.")
        for index, p in enumerate(d["interfaces"]):
            if not p.get("ip"): raise ValueError(f"Missing explicit interface address on {d['id']}/{p['id']}.")
            address = ip_interface(p["ip"])
            if address.version != 4 or address.ip in addresses: raise ValueError("Unique IPv4 interface addresses are required.")
            addresses.add(address.ip)
            p.update(core_id=index, core_name=f"eth{index}")
    components, unseen = [], set(by_id) - {fw["id"]}
    while unseen:
        todo = [next(iter(unseen))]; component = set()
        while todo:
            ident = todo.pop()
            if ident == fw["id"] or ident in component: continue
            component.add(ident); todo.extend(graph[ident] - component - {fw["id"]})
        unseen -= component; components.append(component)
    segments = []
    for component in components:
        attachments = [e for link in links for e in link["endpoints"] if e["device"] == fw["id"] and any(o["device"] in component for o in link["endpoints"])]
        if len(attachments) != 1: raise ValueError("Ambiguous/bypass path: each segment must attach to exactly one firewall interface.")
        port = next(p for p in fw["interfaces"] if p["id"] == attachments[0]["interface"])
        gateway = ip_interface(port["ip"])
        if any(gateway.network.overlaps(other) for other in segments): raise ValueError("Firewall segments must have disjoint subnets.")
        segments.append(gateway.network)
        for ident in component:
            d = by_id[ident]
            if d["type"] == "switch": continue
            p = d["interfaces"][0]; address = ip_interface(p["ip"])
            if address.network != gateway.network: raise ValueError("Endpoint and firewall interface must share the exact segment subnet.")
            d["core_gateway"] = str(gateway.ip)
        # Acyclic L2 segments prevent switching loops.
        edges = sum(len(graph[n] & component) for n in component) // 2
        if edges != len(component) - 1: raise ValueError("L2 segments must be trees.")
    compiled = compile_policy(policy, devices)
    return {"revision": revision, "devices": devices, "node_ids": ids, "links": links,
            "firewall_id": fw["id"], "compiled": compiled, "canonical_document": deepcopy(document)}


def network_templates(device):
    commands = ["#!/bin/sh", "set -eu"]
    if device["type"] == "firewall": commands += ["sysctl -qw net.ipv4.ip_forward=0", "sysctl -qw net.ipv6.conf.all.forwarding=0"]
    if device.get("core_gateway"):
        commands += [f"ip route replace default via {device['core_gateway']} dev eth0"]
    # No applications/PPO/IDS are synthesized for imported guest roles.
    commands += ["true"]
    return dict(zip(FILES, ["\n".join(commands) + "\n", "#!/bin/sh\nset -eu\ntrue\n", "#!/bin/sh\ntrue\n"]))


def scenario(plan):
    root = ET.Element("scenario")
    networks = ET.SubElement(root, "networks"); devices = ET.SubElement(root, "devices")
    links = ET.SubElement(root, "links"); configs = ET.SubElement(root, "service_configurations")
    for index, d in enumerate(plan["devices"]):
        nid = plan["node_ids"][d["id"]]; switch = d["type"] == "switch"
        node = ET.SubElement(networks if switch else devices, "network" if switch else "device",
                             id=str(nid), name=d.get("name", d["id"]), type="SWITCH" if switch else "PC", canvas="1", icon="", image="")
        ET.SubElement(node, "position", x=str(150 + index * 100), y="300")
        if not switch:
            scripts = network_templates(d); name = service_name(scripts)
            ET.SubElement(ET.SubElement(node, "services"), "service", name=name)
            config = ET.SubElement(configs, "service", node=str(nid), name=name)
            templates = ET.SubElement(config, "templates")
            for filename, content in scripts.items(): ET.SubElement(templates, "template", name=filename).text = content
    by_id = {d["id"]: d for d in plan["devices"]}
    for link_index, link in enumerate(plan["links"]):
        a, b = link["endpoints"]
        element = ET.SubElement(links, "link", node1=str(plan["node_ids"][a["device"]]), node2=str(plan["node_ids"][b["device"]]))
        for side, endpoint in enumerate((a, b), 1):
            d = by_id[endpoint["device"]]
            p = next(p for p in d["interfaces"] if p["id"] == endpoint["interface"])
            if d["type"] == "switch": continue
            address = ip_interface(p["ip"])
            nid = plan["node_ids"][d["id"]]
            ET.SubElement(element, f"iface{side}", id=str(p["core_id"]), name=p["core_name"],
                          mac=f"02:00:{nid // 256:02x}:{nid % 256:02x}:{p['core_id'] // 256:02x}:{p['core_id'] % 256:02x}",
                          ip4=str(address.ip), ip4_mask=str(address.network.prefixlen))
    options = ET.SubElement(root, "session_options")
    for name, value in (("controlnet", ""), ("enablerj45", "0"), ("preservedir", "0"), ("enablesdt", "0"), ("ovs", "0")):
        ET.SubElement(options, "configuration", name=name, value=value)
    metadata = ET.SubElement(root, "session_metadata")
    ET.SubElement(metadata, "configuration", name=PLAN_KEY, value=json.dumps(plan, sort_keys=True))
    return root


def xml_plan(root):
    item = root.find(f"session_metadata/configuration[@name='{PLAN_KEY}']")
    if item is None: return None
    plan = json.loads(item.get("value"))
    from testbed.topology import Topology
    topology = Topology.from_exchange(plan["canonical_document"])
    if topology.revision != plan["revision"]: raise ValueError("Firewall plan revision mismatch.")
    expected = build_plan(topology.exchange, topology.revision)
    if expected != plan: raise ValueError("Firewall plan does not match its canonical source.")
    expected_root = scenario(expected)
    if ET.tostring(root) != ET.tostring(expected_root):
        # Pretty-print whitespace is not semantic.
        for tree in (root, expected_root):
            for node in tree.iter():
                if node.text is not None and not node.text.strip(): node.text = None
                if node.tail is not None and not node.tail.strip(): node.tail = None
        if ET.tostring(root) != ET.tostring(expected_root): raise ValueError("Routed XML deviates from canonical firewall projection.")
    return plan
