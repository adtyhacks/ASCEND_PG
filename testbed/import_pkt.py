"""
Import topology from Packet Tracer XML or custom CSV format.

Supports:
- .xml files exported by export_pkt.py
- CSV pairs (nodes.csv + edges.csv) as defined in Live_Battle.py
"""
import xml.etree.ElementTree as ET
from pathlib import Path


def import_from_pkt_xml(filepath):
    """Import topology from Packet Tracer XML file.

    Returns:
        tuple: (nodes_list, edges_list) compatible with render_topology()
    """
    tree = ET.parse(filepath)
    root = tree.getroot()

    nodes = []
    devices_el = root.find("devices")
    if devices_el is not None:
        for dev in devices_el.findall("device"):
            nodes.append({
                "id": dev.get("id"),
                "label": dev.get("label", dev.get("id")),
                "type": dev.get("device_type", "unknown"),
            })

    edges = []
    connections_el = root.find("connections")
    if connections_el is not None:
        for conn in connections_el.findall("connection"):
            edge = {
                "from": conn.get("source"),
                "to": conn.get("target"),
                "type": conn.get("link_type", "comm"),
            }
            proto_el = conn.find("protocol")
            if proto_el is not None and proto_el.text:
                edge["protocol"] = proto_el.text
            edges.append(edge)

    return nodes, edges


def import_from_csv(nodes_csv_path, edges_csv_path):
    """Import topology from CSV files.

    Expected columns:
        nodes.csv: bus_id, name, type, voltage, ip, plc_type, bus_role
        edges.csv: from_bus, to_bus

    Returns:
        tuple: (nodes_list, edges_list) compatible with render_topology()
    """
    import csv

    nodes = []
    node_id_map = {}  # bus_id -> node_id

    with open(nodes_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            bus_id = row.get("bus_id", "")
            node_id = f"plc{bus_id}" if bus_id.isdigit() else row.get("name", f"node_{bus_id}")
            node_id_map[bus_id] = node_id

            # Determine node type from CSV fields
            bus_role = row.get("bus_role", "")
            if bus_role == "generator":
                ntype = "generation_substation"
            elif row.get("name", "").lower() == "scada":
                ntype = "scada_server"
            elif row.get("name", "").lower() == "hmi":
                ntype = "hmi"
            elif row.get("name", "").lower() == "historian":
                ntype = "historian"
            else:
                ntype = "distribution_substation"

            nodes.append({
                "id": node_id,
                "label": row.get("name", node_id),
                "type": ntype,
            })

    edges = []
    with open(edges_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            src = node_id_map.get(row.get("from_bus", ""), row.get("from_bus", ""))
            dst = node_id_map.get(row.get("to_bus", ""), row.get("to_bus", ""))
            edges.append({
                "from": src,
                "to": dst,
                "type": "power_line",
            })

    return nodes, edges


def import_topology(filepath):
    """Auto-detect format and import topology.

    Returns:
        tuple: (nodes_list, edges_list) compatible with render_topology()
    """
    p = Path(filepath)
    suffix = p.suffix.lower()

    if suffix == ".xml":
        return import_from_pkt_xml(filepath)
    elif suffix == ".csv":
        if "node" in p.stem.lower():
            edges_csv = str(p.parent / p.stem.replace("node", "edge")) + suffix
            return import_from_csv(filepath, edges_csv)
        elif "edge" in p.stem.lower():
            nodes_csv = str(p.parent / p.stem.replace("edge", "node")) + suffix
            return import_from_csv(nodes_csv, filepath)
        else:
            raise ValueError(
                f"CSV filename must contain 'node' or 'edge' "
                f"(got '{p.name}')"
            )
    raise ValueError(f"Unsupported topology file format: {suffix}")
