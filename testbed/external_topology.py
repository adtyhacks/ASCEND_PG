"""ASCEND exchange v1 and focused GNS3 import. Pure parsing, no testbed calls."""
from copy import deepcopy
from ipaddress import ip_interface, ip_network
import math
import re
from firewall.model import validate_policy

SCHEMA = "ascend.exchange/v1"
DEVICE_TYPES = {"switch", "router", "scada", "hmi", "plc", "rtu", "attacker", "ids", "ips", "firewall", "generic"}


def _objects(value, label):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be a list of objects.")
    return value


def _ids(items, label):
    result = set()
    for item in items:
        ident = item.get("id")
        if not isinstance(ident, str) or not ident.strip() or ident in result:
            raise ValueError(f"{label}: IDs must be nonempty unique strings (duplicate/invalid {ident!r}).")
        result.add(ident)
    return result


def _ref(value, ids):
    return isinstance(value, str) and value in ids


def validate(document):
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError(f"Expected schema {SCHEMA}.")
    if not isinstance(document.get("name", "Imported design"), str):
        raise ValueError("Topology name must be a string.")
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("warnings", []), list) or any(not isinstance(w, str) for w in metadata.get("warnings", [])):
        raise ValueError("metadata must be an object with a list of warning strings.")
    network, power = document.get("network"), document.get("power_grid")
    if not isinstance(network, dict) or not isinstance(power, dict):
        raise ValueError("network and power_grid must be objects.")
    devices = _objects(network.get("devices", []), "network.devices")
    device_ids = _ids(devices, "network.devices")
    if not devices:
        raise ValueError("At least one network device is required.")
    if len(devices) > 500:
        raise ValueError("MVP limit: 500 network devices.")
    interfaces, zones = {}, {}
    for device in devices:
        if not isinstance(device.get("type"), str) or device["type"] not in DEVICE_TYPES:
            raise ValueError(f"Device {device['id']}: invalid type {device.get('type')!r}; use generic for unknown devices.")
        if device["id"].startswith("electrical:"):
            raise ValueError("Device ID prefix electrical: is reserved for bus visualization.")
        if device.get("zone") is not None and not isinstance(device["zone"], str):
            raise ValueError("Device zone must be a string.")
        if not isinstance(device.get("name", device["id"]), str):
            raise ValueError(f"Device {device['id']}: name must be a string.")
        ports = _objects(device.get("interfaces", []), f"Device {device['id']} interfaces")
        interfaces[device["id"]] = _ids(ports, f"Device {device['id']} interfaces")
        for port in ports:
            if not isinstance(port.get("name", port["id"]), str):
                raise ValueError("Interface name must be a string.")
            if port.get("ip") is not None:
                try:
                    ip_interface(port["ip"])
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid interface IP on {device['id']}/{port['id']}.") from None
            if port.get("zone") is not None and not isinstance(port["zone"], str):
                raise ValueError("Interface zone must be a string.")
        zones[device["id"]] = {p["zone"] for p in ports if p.get("zone")}
        if device.get("ip") is not None:
            try:
                ip_interface(device["ip"])
            except (ValueError, TypeError):
                raise ValueError(f"Invalid device IP on {device['id']}.") from None
    links = _objects(document.get("links", []), "links")
    _ids(links, "links")
    if len(links) > 2000:
        raise ValueError("MVP limit: 2000 network links.")
    for link in links:
        endpoints = link.get("endpoints")
        if not isinstance(endpoints, list) or len(endpoints) != 2:
            raise ValueError(f"Link {link['id']}: exactly two endpoints required.")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not _ref(endpoint.get("device"), device_ids):
                raise ValueError(f"Link {link['id']}: missing/unknown device endpoint.")
            if not _ref(endpoint.get("interface"), interfaces[endpoint["device"]]):
                raise ValueError(f"Link {link['id']}: unknown interface on {endpoint['device']}.")
        if endpoints[0] == endpoints[1]:
            raise ValueError(f"Link {link['id']}: identical endpoints are invalid.")
    buses = _objects(power.get("buses", []), "power_grid.buses")
    if len(buses) > 500:
        raise ValueError("MVP limit: 500 electrical buses.")
    bus_ids = _ids(buses, "power_grid.buses")
    for bus in buses:
        from testbed.capabilities import validate_bus
        validate_bus(bus)
        if "type" in bus and bus["type"] not in ("slack", "pv", "pq"):
            raise ValueError("Electrical bus type must be slack, pv or pq.")
        for key in ("voltage_pu", "vn_kv"):
            value = bus.get(key)
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value <= 0):
                raise ValueError(f"Bus {bus['id']}: {key} must be finite and positive.")
    for group in ("lines", "generators", "loads"):
        items = _objects(power.get(group, []), f"power_grid.{group}")
        if len(items) > 2000:
            raise ValueError(f"MVP limit: 2000 power_grid.{group} entries.")
        _ids(items, f"power_grid.{group}")
        for item in items:
            refs = (item.get("from_bus"), item.get("to_bus")) if group == "lines" else (item.get("bus"),)
            if any(not _ref(ref, bus_ids) for ref in refs):
                raise ValueError(f"{group} {item['id']}: unknown bus reference.")
            if group == "lines" and refs[0] == refs[1]:
                raise ValueError(f"Line {item['id']}: self-link is invalid.")
            for key in ("p_mw", "q_mvar"):
                value = item.get(key)
                if value is not None and (type(value) not in (int, float) or not math.isfinite(value)):
                    raise ValueError(f"{group} {item['id']}: {key} must be finite numeric metadata.")
    mapped_buses, mapped_devices = set(), set()
    for item in _objects(document.get("mapping", []), "mapping"):
        if not _ref(item.get("bus"), bus_ids) or not _ref(item.get("device"), device_ids):
            raise ValueError("Mapping references an unknown bus/device.")
        if next(d for d in devices if d["id"] == item["device"])["type"] not in {"plc", "rtu"}:
            raise ValueError("Electrical mapping device must be a PLC or RTU.")
        if item["bus"] in mapped_buses or item["device"] in mapped_devices:
            raise ValueError("Duplicate/conflicting bus-to-PLC mapping.")
        mapped_buses.add(item["bus"]); mapped_devices.add(item["device"])
    from testbed.capabilities import validate_semantics
    counts = {"bus": len(buses), "res_bus": len(buses), "gen": sum(b.get("type") == "pv" for b in buses),
              "ext_grid": sum(b.get("type") == "slack" for b in buses), "load": len({l["bus"] for l in power.get("loads", [])}), "line": len(power.get("lines", []))}
    validate_semantics(document, bus_ids, counts)
    for device in devices:
        validate_semantics(device, bus_ids, counts, device["id"])
        if any(r.get("physical_mapping") for r in (device.get("plc") or {}).get("registers", [])) and (sum(b.get("type") == "slack" for b in buses) != 1 or any(b.get("type") not in {"slack", "pv", "pq"} for b in buses)):
            raise ValueError("Physical register mappings require a supported electrical model in the same topology.")
        if device.get("plc"):
            if device["type"] not in {"plc", "rtu"} or not any(m["device"] == device["id"] and m["bus"] == device["plc"]["bus_id"] for m in document.get("mapping", [])):
                raise ValueError("PLC semantic metadata must match the bus-to-device mapping.")
    policies = _objects(document.get("firewalls", []), "firewalls")
    _ids(policies, "firewalls")
    for policy in policies:
        if policy["id"] not in device_ids or next(d for d in devices if d["id"] == policy["id"])["type"] != "firewall":
            raise ValueError(f"Firewall {policy['id']}: must reference a firewall device.")
        validate_policy(policy)
        policy_zones = zones[policy["id"]] | {z["id"] for z in policy.get("zones", [])}
        objects = {o["id"] for o in policy.get("address_objects", [])}
        services = {s["id"] for s in policy.get("services", [])}
        for rule in policy.get("rules", []):
            if rule.get("service") and (not isinstance(rule["service"], str) or rule["service"] not in services):
                raise ValueError(f"Rule {rule['rule_id']}: unknown service reference.")
            for field in ("source", "destination"):
                selector = rule[field]
                if selector.lower() == "any" or selector in device_ids:
                    continue
                if selector.startswith("zone:") and selector[5:] in policy_zones:
                    continue
                if selector.startswith("object:") and selector[7:] in objects and policy.get("evaluation_supported") is False:
                    continue
                try:
                    ip_network(selector, strict=False)
                except ValueError:
                    raise ValueError(f"Rule {rule['rule_id']}: unknown {field} device/zone/IP reference {selector!r}.") from None
    return document


def parse_native(value):
    if not isinstance(value, dict):
        raise ValueError("ASCEND JSON must contain an object.")
    # Existing ASCEND custom electrical JSON remains importable as an exchange preview.
    if "schema" not in value and "nodes" in value and "edges" in value:
        from testbed.topology import Topology
        from firewall.model import normalize_policy
        topo = Topology.from_custom_dict(value)
        snapshot = topo.canonical_snapshot()
        devices = [{"id": n["id"], "name": n["hostname"], "type": "switch" if n["node_type"] == "hub" else n["node_type"], "ip": n.get("ip"), "interfaces": [{"id": "eth0", "name": "eth0"}]} for n in snapshot["nodes"]]
        for device in devices:
            if device["type"] == "plc":
                node = topo.nodes[int(device["id"][3:]) - 1]
                for key in ("plc_type", "attack_capabilities", "detection_capabilities"):
                    if key in node: device[key] = deepcopy(node[key])
                if node.get("plc"): device["plc"] = {**deepcopy(node["plc"]), "bus_id": str(node["bus_id"])}
        firewalls = []
        for source_policy in _objects(value.get("firewalls", []), "firewalls"):
            if source_policy.get("default_action", source_policy.get("default_policy")) is None:
                raise ValueError(f"Custom firewall {source_policy.get('id', '<unknown>')}: default_action is required.")
            policy = normalize_policy(
                source_policy,
                configuration_origin="custom",
                original_source_metadata={"source": "custom_topology", "payload": source_policy},
                require_explicit_ports=True,
            )
            # Object/service references are retained but are not expanded by the
            # flat first-match evaluator.
            if any(rule.get("service") or any(str(rule.get(field, "")).startswith("object:") for field in ("source", "destination")) for rule in policy["rules"]):
                policy["evaluation_supported"] = False
            if any(device["id"] == policy["id"] for device in devices):
                raise ValueError(f"Firewall {policy['id']}: device ID conflicts with the generated custom network.")
            devices.append({"id": policy["id"], "name": policy["name"], "type": "firewall",
                            "normalized_type": "firewall", "interfaces": deepcopy(policy["interfaces"]),
                            "metadata": {"source": "custom_topology"}})
            firewalls.append(policy)
        value = {"schema": SCHEMA, "name": topo.case_name, "network": {"devices": devices},
                 "power_grid": {"buses": [{"id": str(n["bus_id"]), "type": n["type"], "vn_kv": n["vn_kv"], "voltage_pu": n["voltage"], "voltage_min_pu": n.get("voltage_min_pu", 0.9), "voltage_max_pu": n.get("voltage_max_pu", 1.1)} for n in topo.nodes],
                                "lines": [{"id": f"line-{i}", "from_bus": str(a), "to_bus": str(b), **{k: v for k, v in topo.edge_models[i].items() if k not in {"from", "to"}}} for i, (a, b) in enumerate(topo.edges)],
                                "generators": [{"id": f"generator-{n['bus_id']}", "bus": str(n["bus_id"]), "p_mw": n["pg"], "q_mvar": n["qg"]} for n in topo.nodes if n["type"] in {"pv", "slack"}],
                                "loads": [{"id": f"load-{n['bus_id']}", "bus": str(n["bus_id"]), "p_mw": n["pl"], "q_mvar": n["ql"]} for n in topo.nodes if n["pl"] or n["ql"]]},
                 "links": [{"id": f"link-{i}", "endpoints": [{"device": e["from"], "interface": "eth0"}, {"device": e["to"], "interface": "eth0"}]} for i, e in enumerate(snapshot["links"]) if e["core_link"]],
                 "mapping": [{"bus": str(n["bus_id"]), "device": f"plc{n['bus_id'] + 1}"} for n in topo.nodes], "firewalls": firewalls,
                 "metadata": {"source": "custom", "warnings": []}}
    return validate(deepcopy(value))


def classify_gns3(node):
    """Controlled metadata priority; no substring-based firewall guessing."""
    properties = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    def names(value):
        if isinstance(value, str): return [value]
        if isinstance(value, dict): return [value.get(k) for k in ("device_type", "type", "name", "vendor", "product") if isinstance(value.get(k), str)]
        return []
    candidates = [
        ("explicit_metadata", [node.get("device_type"), node.get("type"), metadata.get("device_type"), metadata.get("type"), properties.get("device_type")]),
        ("appliance_metadata", names(node.get("appliance")) + names(properties.get("appliance")) + names(node.get("template")) + names(properties.get("template")) + [node.get("template_name"), properties.get("template_name"), node.get("appliance_name"), properties.get("appliance_name")]),
        ("node_type", [node.get("node_type")]),
        ("template_name", [node.get("template_name"), properties.get("template_name"), node.get("appliance_name"), properties.get("appliance_name")]),
        ("node_name", [node.get("name")]),
    ]
    for basis, values in candidates:
        for value in values:
            if not isinstance(value, str): continue
            text = value.strip().lower()
            if re.search(r"(?<![a-z0-9])(?:fw\d*|firewall|asa|opnsense|pfsense|fortigate|fortinet)(?![a-z0-9])", text):
                return "firewall", basis
            kind = {"ethernet_switch": "switch", "ethernet_hub": "switch"}.get(text, text)
            if kind in DEVICE_TYPES and kind != "generic": return kind, basis
            if basis == "node_name":
                for kind in ("scada", "plc", "rtu", "hmi", "attacker", "ids", "ips", "switch"):
                    if re.fullmatch(rf"{kind}(?:[-_ ]?\d+)?", text): return kind, basis
                if re.fullmatch(r"sw[-_ ]?\d+", text): return "switch", basis
    return "generic", "unrecognized"


def normalize_saved_gns3(document):
    """Upgrade classification in memory, without rewriting saved import evidence."""
    result = deepcopy(document)
    for device in result.get("network", {}).get("devices", []):
        metadata = device.get("metadata", {})
        if not isinstance(metadata, dict): continue
        if device.get("type") == "generic" and metadata.get("gns3_node_type"):
            original = metadata.get("original_node", {})
            dtype, basis = classify_gns3({**(original if isinstance(original, dict) else {}), "name": device.get("name"), "node_type": metadata["gns3_node_type"]})
            device["type"] = dtype
            device["normalized_type"] = dtype
            device["original_type"] = metadata["gns3_node_type"]
            metadata["classification"] = basis
    if result.get("metadata", {}).get("source") == "gns3":
        from firewall.gns3 import import_configuration
        existing = {p["id"] for p in result.get("firewalls", [])}
        for device in result.get("network", {}).get("devices", []):
            if device.get("type") == "firewall" and device["id"] not in existing:
                original = device.get("metadata", {}).get("original_node", {})
                result.setdefault("firewalls", []).append(import_configuration(original if isinstance(original, dict) else {}, device))
    return result


def parse_gns3(value):
    if not isinstance(value, dict) or not isinstance(value.get("topology"), dict):
        raise ValueError("GNS3 project must contain a topology object.")
    topology = value["topology"]
    devices, by_id = [], {}
    for node in _objects(topology.get("nodes", []), "GNS3 nodes"):
        ident = node.get("node_id")
        if not isinstance(ident, str) or not ident or ident in by_id:
            raise ValueError("GNS3 node_id must be nonempty and unique.")
        name, kind = node.get("name", ident), node.get("node_type", "generic")
        name = name if isinstance(name, str) else ident
        dtype, basis = classify_gns3(node)
        device = {"id": ident, "name": name, "type": dtype, "normalized_type": dtype, "original_type": kind, "interfaces": [], "metadata": {"gns3_node_type": kind, "template_id": node.get("template_id"), "classification": basis, "original_node": deepcopy(node)}}
        if node.get("ip") is not None:
            device["ip"] = node["ip"]
        for port in _objects(node.get("ports", []), "GNS3 ports"):
            adapter, number = port.get("adapter_number", 0), port.get("port_number")
            if type(adapter) is not int or adapter < 0 or type(number) is not int or number < 0:
                raise ValueError(f"GNS3 node {ident}: invalid adapter/port number.")
            interface = {"id": f"{adapter}:{number}", "name": port.get("name") or port.get("short_name") or f"adapter{adapter}/port{number}"}
            if port.get("ip") is not None:
                interface["ip"] = port["ip"]
            device["interfaces"].append(interface)
        devices.append(device); by_id[ident] = device
    links = []
    for index, link in enumerate(_objects(topology.get("links", []), "GNS3 links")):
        endpoints = []
        for endpoint in _objects(link.get("nodes", []), "GNS3 link endpoints"):
            ident, adapter, port = endpoint.get("node_id"), endpoint.get("adapter_number", 0), endpoint.get("port_number")
            if not _ref(ident, by_id) or type(adapter) is not int or adapter < 0 or type(port) is not int or port < 0:
                raise ValueError(f"GNS3 link {index}: unknown node or invalid adapter/port endpoint.")
            iid = f"{adapter}:{port}"
            if not any(p["id"] == iid for p in by_id[ident]["interfaces"]):
                by_id[ident]["interfaces"].append({"id": iid, "name": f"adapter{adapter}/port{port}", "inferred_from_link": True})
            endpoints.append({"device": ident, "interface": iid})
        links.append({"id": link.get("link_id") or f"gns3-link-{index}", "endpoints": endpoints})
    from firewall.gns3 import import_configuration
    firewalls = [import_configuration(d["metadata"]["original_node"], d) for d in devices if d["type"] == "firewall"]
    warnings = ["No electrical model, guest addresses, or firewall rules are inferred from appliance names, template IDs or images."]
    for policy in firewalls:
        warnings.extend(f"{policy['name']}: {message}" for message in policy.get("warnings", []))
    document = {"schema": SCHEMA, "name": value.get("name", "GNS3 import"), "network": {"devices": devices}, "links": links,
                "power_grid": {"buses": [], "lines": [], "generators": [], "loads": []}, "mapping": [], "firewalls": firewalls,
                "metadata": {"source": "gns3", "project_id": value.get("project_id"), "warnings": warnings}}
    return validate(document)


def visual_data(document):
    """Project validated exchange data onto the existing PyVis renderer contract."""
    validate(document)
    nodes = [{"id": d["id"], "label": d.get("name", d["id"]), "type": {"switch": "hub", "router": "generic", "rtu": "plc", "ips": "ids"}.get(d["type"], d["type"])} for d in document["network"]["devices"]]
    edges = [{"from": link["endpoints"][0]["device"], "to": link["endpoints"][1]["device"], "type": "comm", "protocol": link.get("protocol", "network")} for link in document["links"]]
    for bus in document["power_grid"].get("buses", []):
        nodes.append({"id": "electrical:" + bus["id"], "label": "Bus " + bus["id"], "type": "distribution_substation"})
    edges.extend({"from": "electrical:" + line["from_bus"], "to": "electrical:" + line["to_bus"], "type": "power_line"} for line in document["power_grid"].get("lines", []))
    edges.extend({"from": "electrical:" + m["bus"], "to": m["device"], "type": "local"} for m in document.get("mapping", []))
    return nodes, edges
