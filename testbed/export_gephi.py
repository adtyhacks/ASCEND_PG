"""
Export ICS/OT topology to Gephi-compatible formats (GraphML and GEXF).

GraphML is widely supported by Gephi, Cytoscape, and other graph tools.
GEXF is Gephi's native XML format with richer attribute support.
"""
import xml.etree.ElementTree as ET
from xml.dom import minidom


def export_graphml(nodes, edges, filepath):
    """Export topology as GraphML XML file."""
    root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")

    # Attribute declarations
    for attr_id, attr_name, attr_type in [
        ("node_type", "node_type", "string"),
        ("label", "label", "string"),
        ("edge_type", "edge_type", "string"),
        ("protocol", "protocol", "string"),
    ]:
        for_val = "node" if attr_id in ("node_type", "label") else "edge"
        key = ET.SubElement(root, "key", id=attr_id,
                           attrib={"for": for_val, "attr.name": attr_name, "attr.type": attr_type})

    graph = ET.SubElement(root, "graph", id="ascend_pg_topology",
                         edgedefault="undirected")

    for n in nodes:
        node_el = ET.SubElement(graph, "node", id=n["id"])
        data_label = ET.SubElement(node_el, "data", key="label")
        data_label.text = n.get("label", n["id"])
        data_type = ET.SubElement(node_el, "data", key="node_type")
        data_type.text = n.get("type", "unknown")

    for e in edges:
        edge_el = ET.SubElement(graph, "edge",
                               source=str(e["from"]), target=str(e["to"]))
        data_etype = ET.SubElement(edge_el, "data", key="edge_type")
        data_etype.text = e.get("type", "unknown")
        if "protocol" in e:
            data_proto = ET.SubElement(edge_el, "data", key="protocol")
            data_proto.text = e["protocol"]

    rough = ET.tostring(root, encoding="unicode", xml_declaration=True)
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(pretty)
    return filepath


def export_gexf(nodes, edges, filepath):
    """Export topology as GEXF (Gephi native XML) file."""
    root = ET.Element("gexf", xmlns="http://www.gexf.net/1.2draft",
                      version="1.2")

    graph = ET.SubElement(root, "graph", defaultedgetype="undirected",
                          mode="static")

    # Node attributes
    vattrs = ET.SubElement(graph, "attributes", {"class": "node", "mode": "static"})
    ET.SubElement(vattrs, "attribute", id="0", title="Type", type="string")

    # Edge attributes
    eattrs = ET.SubElement(graph, "attributes", {"class": "edge", "mode": "static"})
    ET.SubElement(eattrs, "attribute", id="0", title="Type", type="string")
    ET.SubElement(eattrs, "attribute", id="1", title="Protocol", type="string")

    nodes_el = ET.SubElement(graph, "nodes")
    for n in nodes:
        node_el = ET.SubElement(nodes_el, "node", id=n["id"],
                                label=n.get("label", n["id"]))
        attrs_el = ET.SubElement(node_el, "attvalues")
        av = ET.SubElement(attrs_el, "attvalue", {"for": "0", "value": n.get("type", "unknown")})

    edges_el = ET.SubElement(graph, "edges")
    for i, e in enumerate(edges):
        edge_el = ET.SubElement(edges_el, "edge",
                               id=str(i),
                               source=str(e["from"]),
                               target=str(e["to"]),
                               label=e.get("type", ""))
        attrs_el = ET.SubElement(edge_el, "attvalues")
        ET.SubElement(attrs_el, "attvalue", {"for": "0", "value": e.get("type", "unknown")})
        if "protocol" in e:
            ET.SubElement(attrs_el, "attvalue", {"for": "1", "value": e["protocol"]})

    rough = ET.tostring(root, encoding="unicode", xml_declaration=True)
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(pretty)
    return filepath
