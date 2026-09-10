"""
Generate Cytoscape.js compatible JSON from ICS/OT topology.

Produces a JSON structure consumable by the Cytoscape.js library for
browser-based graph visualization with rich styling and interactivity.
"""
import json


# Node style mapping (mirrors DEVICE_STYLE colors for consistency)
NODE_COLORS = {
    "scada_server":            "#4295f5",
    "historian":               "#3465a4",
    "hmi":                     "#f15a24",
    "firewall":                "#006699",
    "generation_substation":   "#4295f5",
    "distribution_substation": "#4295f5",
    "pmu":                     "#4295f5",
    "rtu":                     "#4295f5",
}

NODE_SHAPES = {
    "scada_server":            "rectangle",
    "historian":               "diamond",
    "hmi":                     "roundrectangle",
    "firewall":                "hexagon",
    "generation_substation":   "ellipse",
    "distribution_substation": "ellipse",
    "pmu":                     "triangle",
    "rtu":                     "tag",
}


def generate_cytoscape_json(nodes, edges, compromised_ids=None,
                            detected_ids=None, attack_paths=None):
    """Generate Cytoscape.js JSON elements array.

    Args:
        nodes: List of node dicts with keys: id, label, type
        edges: List of edge dicts with keys: from, to, type, (optional) protocol
        compromised_ids: Set of compromised node IDs
        detected_ids: Set of detected node IDs
        attack_paths: List of node ID lists for attack paths

    Returns:
        dict: {"nodes": [...], "edges": [...]} for Cytoscape.js
    """
    compromised_ids = compromised_ids or set()
    detected_ids = detected_ids or set()
    attack_paths = attack_paths or []

    cy_nodes = []
    for n in nodes:
        nid = n["id"]
        ntype = n.get("type", "unknown")
        color = NODE_COLORS.get(ntype, "#888888")
        shape = NODE_SHAPES.get(ntype, "ellipse")

        if nid in compromised_ids:
            color = "#ff3b30"
        elif nid in detected_ids:
            color = "#34c759"

        cy_nodes.append({
            "data": {
                "id": nid,
                "label": n.get("label", nid),
                "node_type": ntype,
            },
            "classes": "compromised" if nid in compromised_ids else
                       ("detected" if nid in detected_ids else ""),
            "style": {
                "background-color": color,
                "shape": shape,
                "label": n.get("label", nid),
                "text-wrap": "wrap",
                "text-max-width": "80px",
                "font-size": "10px",
                "color": "#ffffff",
                "text-valign": "bottom",
                "text-margin-y": 5,
            },
        })

    cy_edges = []
    for e in edges:
        etype = e.get("type", "unknown")
        if etype == "power_line":
            color, width, style = "#f5a623", 3, "solid"
        elif etype == "comm":
            color, width, style = "#4a90d9", 2, "dashed"
        else:
            color, width, style = "#666666", 1, "solid"

        cy_edges.append({
            "data": {
                "source": e["from"],
                "target": e["to"],
                "edge_type": etype,
                "protocol": e.get("protocol", ""),
            },
            "style": {
                "line-color": color,
                "width": width,
                "line-style": style,
            },
        })

    # Attack path edges (red, thick, dashed)
    for path in attack_paths:
        for i in range(len(path) - 1):
            cy_edges.append({
                "data": {
                    "source": path[i],
                    "target": path[i + 1],
                    "edge_type": "attack_path",
                },
                "classes": "attack-path",
                "style": {
                    "line-color": "#ff0000",
                    "width": 4,
                    "line-style": "dashed",
                },
            })

    return {"nodes": cy_nodes, "edges": cy_edges}


def generate_cytoscape_html(nodes, edges, compromised_ids=None,
                            detected_ids=None, attack_paths=None):
    """Generate a standalone HTML page with embedded Cytoscape.js visualization."""
    elements = generate_cytoscape_json(nodes, edges, compromised_ids,
                                       detected_ids, attack_paths)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ASCEND-PG Topology - Cytoscape.js</title>
  <script src="https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
  <style>
    body {{ margin: 0; background: #1e1e1e; font-family: sans-serif; }}
    #cy {{ width: 100%; height: 100vh; position: absolute; top: 0; left: 0; }}
    #legend {{ position: absolute; bottom: 20px; left: 20px; background: rgba(30,30,30,0.9);
               color: #fff; padding: 15px; border-radius: 8px; font-size: 13px;
               border: 1px solid #444; z-index: 1000; }}
    .legend-item {{ display: flex; align-items: center; margin-bottom: 6px; }}
    .legend-line {{ width: 25px; height: 3px; margin-right: 10px; }}
    .legend-dot {{ width: 14px; height: 14px; border-radius: 50%; margin-right: 10px; border: 3px solid; box-sizing: border-box; }}
  </style>
</head>
<body>
  <div id="cy"></div>
  <div id="legend">
    <b>Topology Legend</b><br>
    <div class="legend-item"><div class="legend-line" style="background:#f5a623;"></div> Power Line</div>
    <div class="legend-item"><div class="legend-line" style="border-bottom:2px dashed #4a90d9;height:0;"></div> Comm Link</div>
    <div class="legend-item"><div class="legend-dot" style="border-color:#ff3b30;"></div> Compromised</div>
    <div class="legend-item"><div class="legend-dot" style="border-color:#34c759;"></div> Detected</div>
    <div class="legend-item"><div class="legend-line" style="background:#ff0000;border-style:dashed;height:0;border-top:3px dashed;"></div> Attack Path</div>
  </div>
  <script>
    var cy = cytoscape({{
      container: document.getElementById('cy'),
      elements: {json.dumps(elements)},
      style: [
        {{ selector: 'node', style: {{ 'background-color': '#4295f5', 'label': 'data(label)',
                 'text-wrap': 'wrap', 'text-max-width': '80px', 'font-size': '10px',
                 'color': '#fff', 'text-valign': 'bottom', 'text-margin-y': 5 }} }},
        {{ selector: 'edge', style: {{ 'curve-style': 'bezier' }} }},
        {{ selector: '.attack-path', style: {{ 'line-color': '#ff0000', 'width': 4, 'line-style': 'dashed' }} }},
        {{ selector: '.compromised', style: {{ 'border-width': 3, 'border-color': '#ff3b30' }} }},
        {{ selector: '.detected', style: {{ 'border-width': 3, 'border-color': '#34c759' }} }},
      ],
      layout: {{ name: 'cose', idealEdgeLength: 100, nodeOverlap: 20, refresh: 20,
                 randomize: false, componentSpacing: 100, nodeRepulsion: 8000,
                 edgeElasticity: 100, nestingFactor: 5, gravity: 0.25 }}
    }});
  </script>
</body>
</html>"""
