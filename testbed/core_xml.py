"""Validate canonical legacy or routed-firewall XML before allocating CORE resources."""
import ipaddress
from pathlib import Path
import xml.etree.ElementTree as ET

from testbed.core_services import SERVICE, FILES, service_name


def validate_xml(path):
    data = Path(path).read_bytes()
    if len(data) > 2_000_000 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("Oversized XML or DTD/entity declarations are not supported")
    root = ET.fromstring(data)
    if root.tag != "scenario":
        raise ValueError("Expected CORE scenario XML")
    from testbed.firewall_topology import xml_plan
    if xml_plan(root) is not None:
        return root
    nodes = root.findall("networks/network") + root.findall("devices/device")
    ids = [int(n.attrib["id"]) for n in nodes]
    names = [n.attrib["name"] for n in nodes]
    if not ids or len(ids) != len(set(ids)) or min(ids) < 1 or len(names) != len(set(names)):
        raise ValueError("Node IDs/names must be unique and IDs positive")
    networks = root.findall("networks/network")
    if len(networks) != 1 or networks[0].get("type") not in ("HUB", "SWITCH"):
        raise ValueError("ASCEND supports one HUB or SWITCH network")
    network_id = int(networks[0].get("id"))
    devices = root.findall("devices/device")
    device_ids = {int(n.get("id")) for n in devices}
    services = {}
    for n in devices:
        selected = {s.get("name") for s in n.findall("services/service")}
        if not selected or any(s != "DefaultRoute" and not s.startswith(SERVICE + "_") for s in selected):
            raise ValueError(f"Unsupported/unregistered services on {n.get('name')}: {selected}")
        services[int(n.get("id"))] = selected
    linked, addresses, macs = set(), set(), set()
    for link in root.findall("links/link"):
        a, b = int(link.attrib["node1"]), int(link.attrib["node2"])
        iface = link.find("iface1")
        if a not in device_ids or b != network_id or a in linked or iface is None:
            raise ValueError("Each device must have exactly one link to the central network")
        linked.add(a)
        address = ipaddress.IPv4Interface(f"{iface.attrib['ip4']}/{iface.attrib['ip4_mask']}")
        if address.ip in addresses or iface.get("mac") in macs:
            raise ValueError("Duplicate IP or MAC address")
        addresses.add(address.ip)
        macs.add(iface.get("mac"))
    if linked != device_ids:
        raise ValueError("Every device needs an interface/link")
    configured = set()
    for config in root.findall("service_configurations/service"):
        nid = int(config.attrib["node"])
        key = (nid, config.get("name"))
        if key in configured or config.get("name") not in services.get(nid, set()):
            raise ValueError("Invalid or duplicate service configuration")
        configured.add(key)
        templates = config.findall("templates/template")
        if {t.get("name") for t in templates} != set(FILES) or len(templates) != len(FILES):
            raise ValueError("Missing service startup/validation/shutdown templates")
        if any(not t.text for t in templates):
            raise ValueError("Empty service template")
        if config.get("name") != service_name({t.get("name"): t.text for t in templates}):
            raise ValueError("Service template fingerprint mismatch; regenerate the XML")
    expected = {(nid, s) for nid, selected in services.items() for s in selected if s != "DefaultRoute"}
    if configured != expected:
        raise ValueError("Application service configuration missing")
    return root


def to_session(root, session_id):
    from core.api.grpc import wrappers as w
    session = w.Session(id=session_id)
    for element in root.findall("networks/network") + root.findall("devices/device"):
        nid = int(element.get("id"))
        network = element.tag == "network"
        position = element.find("position")
        node = w.Node(id=nid, name=element.get("name"),
                      type=w.NodeType[element.get("type")] if network else w.NodeType.DEFAULT,
                      model=None if network else element.get("type"), canvas=1,
                      position=w.Position(x=float(position.get("x")), y=float(position.get("y"))),
                      services={s.get("name") for s in element.findall("services/service")})
        session.nodes[nid] = node
    network_ports = {}
    network_ids = {int(e.get("id")) for e in root.findall("networks/network")}
    def interface(element, side):
        nid = int(element.get(f"node{side}")); i = element.find(f"iface{side}")
        if i is None:
            if nid not in network_ids: raise ValueError("Endpoint interface is missing.")
            port = network_ports.get(nid, 0); network_ports[nid] = port + 1
            return w.Interface(id=port)
        return w.Interface(id=int(i.get("id")), name=i.get("name"), mac=i.get("mac"), ip4=i.get("ip4"), ip4_mask=int(i.get("ip4_mask")))
    for element in root.findall("links/link"):
        session.links.append(w.Link(node1_id=int(element.get("node1")), node2_id=int(element.get("node2")),
                                   iface1=interface(element, 1), iface2=interface(element, 2)))
    for element in root.findall("service_configurations/service"):
        session.nodes[int(element.get("node"))].service_configs[element.get("name")] = w.ServiceData(
            templates={t.get("name"): t.text for t in element.findall("templates/template")})
    session.metadata = {e.get("name"): e.get("value") for e in root.findall("session_metadata/configuration")}
    session.set_options({e.get("name"): e.get("value") for e in root.findall("session_options/configuration")})
    origin = root.find("session_origin")
    if origin is not None:
        session.location = w.SessionLocation(x=0, y=0, z=0, lat=float(origin.get("lat")),
                                            lon=float(origin.get("lon")), alt=float(origin.get("alt")),
                                            scale=float(origin.get("scale")))
    return session
