"""
Export ICS/OT topology to Cisco Packet Tracer XML format.

Generates a .xml file that can be imported into Packet Tracer
or used as a reference template for network simulation.
"""
import xml.etree.ElementTree as ET
from xml.dom import minidom


# Map OT device types to Packet Tracer device categories
PT_DEVICE_MAP = {
    "scada_server":       ("Server", "Server-PT"),
    "historian":          ("Server", "Server-PT"),
    "hmi":                ("End Devices", "PC-PT"),
    "firewall":           ("Security", "Firewall-PT"),
    "generation_substation": ("Switches", "2960-24TT"),
    "distribution_substation": ("Switches", "2960-24TT"),
    "pmu":                ("End Devices", "Generic"),
    "rtu":                ("End Devices", "Generic"),
}


def export_pkt_xml(nodes, edges, filepath):
    """Export topology as Packet Tracer XML template.

    Creates a simplified XML representation suitable for Packet Tracer
    import or as a reference topology definition.
    """
    root = ET.Element("network_topology", name="ASCEND-PG Topology")

    # Metadata
    meta = ET.SubElement(root, "metadata")
    ET.SubElement(meta, "name").text = "ASCEND-PG ICS/OT Network"
    ET.SubElement(meta, "description").text = "IEEE-14 bus power grid with OT communication overlay"
    ET.SubElement(meta, "node_count").text = str(len(nodes))
    ET.SubElement(meta, "edge_count").text = str(len(edges))

    # Devices
    devices_el = ET.SubElement(root, "devices")
    for n in nodes:
        dev_el = ET.SubElement(devices_el, "device",
                              id=n["id"],
                              label=n.get("label", n["id"]),
                              device_type=n.get("type", "unknown"))
        cat, model = PT_DEVICE_MAP.get(n["type"], ("End Devices", "Generic"))
        ET.SubElement(dev_el, "pt_category").text = cat
        ET.SubElement(dev_el, "pt_model").text = model
        # IP address based on device type
        if n["id"].startswith("plc"):
            bus_num = n["id"][3:]
            if bus_num.isdigit():
                ET.SubElement(dev_el, "ip_address").text = f"10.0.0.{int(bus_num)}"
        elif n["id"].startswith("rtu_") or n["id"].startswith("pmu_") or n["id"].startswith("substation_"):
            bus_num = n["id"].split("_")[-1]
            if bus_num.isdigit():
                ET.SubElement(dev_el, "ip_address").text = f"10.0.0.{int(bus_num) + 1}"
        elif n["id"] == "scada_server":
            ET.SubElement(dev_el, "ip_address").text = "10.0.0.20"
        elif n["id"] == "hmi":
            ET.SubElement(dev_el, "ip_address").text = "10.0.0.11"
        elif n["id"] == "historian":
            ET.SubElement(dev_el, "ip_address").text = "10.0.0.12"
        elif n["id"] == "firewall":
            ET.SubElement(dev_el, "ip_address").text = "10.0.0.1"

    # Connections
    connections_el = ET.SubElement(root, "connections")
    for e in edges:
        conn_el = ET.SubElement(connections_el, "connection",
                               source=e["from"],
                               target=e["to"],
                               link_type=e.get("type", "unknown"))
        if "protocol" in e:
            ET.SubElement(conn_el, "protocol").text = e["protocol"]

    rough = ET.tostring(root, encoding="unicode", xml_declaration=True)
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(pretty)
    return filepath
