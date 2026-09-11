"""
Generate standalone vis.js HTML for ICS/OT topology visualization.

Produces a self-contained HTML file using vis-network CDN for
interactive graph rendering outside of Streamlit.
"""
import json


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
    "scada_server":            "box",
    "historian":               "diamond",
    "hmi":                     "box",
    "firewall":                "hexagon",
    "generation_substation":   "ellipse",
    "distribution_substation": "ellipse",
    "pmu":                     "triangle",
    "rtu":                     "square",
}


def generate_vis_json(nodes, edges, compromised_ids=None,
                      detected_ids=None, attack_paths=None):
    """Generate vis.js Network data structure.

    Returns:
        dict: {"nodes": [...], "edges": [...]} for vis.js
    """
    compromised_ids = compromised_ids or set()
    detected_ids = detected_ids or set()
    attack_paths = attack_paths or []

    vis_nodes = []
    for n in nodes:
        nid = n["id"]
        ntype = n.get("type", "unknown")
        color = NODE_COLORS.get(ntype, "#888888")
        shape = NODE_SHAPES.get(ntype, "dot")
        border_color = "rgba(0,0,0,0)"
        border_width = 0

        if nid in compromised_ids:
            color = "#ff3b30"
            border_color = "#ff3b30"
            border_width = 3
        elif nid in detected_ids:
            color = "#34c759"
            border_color = "#34c759"
            border_width = 3

        vis_nodes.append({
            "id": nid,
            "label": n.get("label", nid),
            "shape": shape,
            "color": {"background": color, "border": border_color, "highlight": {"background": color, "border": border_color}},
            "borderWidth": border_width,
            "font": {"color": "#ffffff", "size": 10},
            "title": f"<b>{n.get('label', nid)}</b><br>Type: {ntype}",
        })

    vis_edges = []
    for e in edges:
        etype = e.get("type", "unknown")
        if etype == "power_line":
            color, width = "#f5a623", 3
        elif etype == "comm":
            color, width = "#4a90d9", 2
        else:
            color, width = "#666666", 1

        edge_obj = {
            "from": e["from"],
            "to": e["to"],
            "color": {"color": color},
            "width": width,
            "dashes": etype == "comm",
            "title": f"{etype}" + (f" ({e.get('protocol','')})" if e.get("protocol") else ""),
        }
        vis_edges.append(edge_obj)

    for path in attack_paths:
        for i in range(len(path) - 1):
            vis_edges.append({
                "from": path[i],
                "to": path[i + 1],
                "color": {"color": "#ff0000"},
                "width": 4,
                "dashes": [10, 5],
                "title": "Attack Path",
            })

    return {"nodes": vis_nodes, "edges": vis_edges}


def generate_vis_html(nodes, edges, compromised_ids=None,
                      detected_ids=None, attack_paths=None):
    """Generate a standalone HTML page with embedded vis-network visualization."""
    data = generate_vis_json(nodes, edges, compromised_ids, detected_ids, attack_paths)

    n_comp = len(compromised_ids or set())
    n_det = len(detected_ids or set())

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ASCEND-PG Topology - vis.js</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ margin: 0; background: #1e1e1e; font-family: sans-serif; }}
    #network {{ width: 100%; height: 100vh; position: absolute; top: 0; left: 0; }}
    #legend {{ position: absolute; bottom: 20px; left: 20px; background: rgba(30,30,30,0.9);
               color: #fff; padding: 15px; border-radius: 8px; font-size: 13px;
               border: 1px solid #444; z-index: 1000; }}
    .legend-item {{ display: flex; align-items: center; margin-bottom: 6px; }}
    .legend-line {{ width: 25px; height: 3px; margin-right: 10px; }}
    .legend-dot {{ width: 14px; height: 14px; border-radius: 50%; margin-right: 10px;
                   border: 3px solid; box-sizing: border-box; }}
    #stats {{ position: absolute; top: 20px; right: 20px; background: rgba(30,30,30,0.9);
              color: #fff; padding: 15px; border-radius: 8px; font-size: 13px;
              border: 1px solid #444; z-index: 1000; }}
  </style>
</head>
<body>
  <div id="network"></div>
  <div id="legend">
    <b>Topology Legend</b><br>
    <div class="legend-item"><div class="legend-line" style="background:#f5a623;"></div> Power Line</div>
    <div class="legend-item"><div class="legend-line" style="border-bottom:2px dashed #4a90d9;height:0;"></div> Comm Link</div>
    <div class="legend-item"><div class="legend-dot" style="border-color:#ff3b30;"></div> Compromised</div>
    <div class="legend-item"><div class="legend-dot" style="border-color:#34c759;"></div> Detected</div>
    <div class="legend-item"><div class="legend-line" style="background:#ff0000;border-style:dashed;height:0;border-top:3px dashed #ff0000;"></div> Attack Path</div>
  </div>
  <div id="stats">
    <b>Topology Stats</b><br>
    Nodes: {len(data['nodes'])}<br>
    Edges: {len(data['edges'])}<br>
    Compromised: <span style="color:#ff3b30;">{n_comp}</span><br>
    Detected: <span style="color:#34c759;">{n_det}</span>
  </div>
  <script>
    var data = {json.dumps(data)};
    var container = document.getElementById('network');
    var network = new vis.Network(container, data, {{
      physics: {{
        barnesHut: {{ gravitationalConstant: -3000, centralGravity: 0.3,
                      springLength: 100, springConstant: 0.04 }},
        stabilization: {{ iterations: 150 }}
      }},
      interaction: {{ hover: true, tooltipDelay: 200 }},
      edges: {{ smooth: {{ type: 'continuous' }} }}
    }});
  </script>
</body>
</html>"""
