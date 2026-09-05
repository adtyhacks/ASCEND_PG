"""
Renders the ICS/OT topology as an interactive HTML diagram using pyvis.
Device types are shown as colored, emoji-labeled boxes rather than
downloaded icon images — no external assets, no licensing concerns.
Nodes can be highlighted red (compromised) or green (detected) to show
a live attack/defense state.
"""
from pyvis.network import Network

DEVICE_STYLE = {
    "generation_substation":   {"image": "https://upload.wikimedia.org/wikipedia/commons/3/30/Router_symbol.svg"},
    "distribution_substation": {"image": "https://upload.wikimedia.org/wikipedia/commons/8/80/Switch_symbol.svg"},
    "pmu":                     {"image": "https://upload.wikimedia.org/wikipedia/commons/3/30/Router_symbol.svg"},
    "rtu":                     {"image": "https://upload.wikimedia.org/wikipedia/commons/8/80/Switch_symbol.svg"},
    "scada_server":            {"image": "https://upload.wikimedia.org/wikipedia/commons/a/a3/Server_symbol.svg"},
    "historian":               {"image": "https://upload.wikimedia.org/wikipedia/commons/1/18/Database.svg"},
    "hmi":                     {"image": "https://upload.wikimedia.org/wikipedia/commons/a/a5/Laptop_Flat_Icon_Vector.svg"},
    "firewall":                {"image": "https://upload.wikimedia.org/wikipedia/commons/8/82/Firewall_%28computing%29.svg"},
}


def render_topology(nodes, edges, compromised_ids=None, detected_ids=None):
    compromised_ids = compromised_ids or set()
    detected_ids = detected_ids or set()

    net_viz = Network(height="650px", width="100%", bgcolor="#1e1e1e",
                       font_color="white", directed=False)
    net_viz.barnes_hut()  # physics layout — nodes auto-arrange and can be dragged

    for n in nodes:
        style = DEVICE_STYLE.get(n["type"], {"image": "https://upload.wikimedia.org/wikipedia/commons/a/a3/Server_symbol.svg"})
        border = "rgba(0,0,0,0)"
        if n["id"] in compromised_ids:
            border = "#ff3b30"   # red ring = currently under attack
        elif n["id"] in detected_ids:
            border = "#34c759"   # green ring = attack detected here

        net_viz.add_node(
            n["id"],
            label=n["label"],
            shape="circularImage" if n["id"] in (compromised_ids | detected_ids) else "image",
            image=style["image"],
            color={"border": border, "background": "#2b2b2b"},
            borderWidth=5 if n["id"] in (compromised_ids | detected_ids) else 0,
            title=n["label"],
            size=30,
        )

    for e in edges:
        if e["type"] == "power_line":
            kwargs = {"color": "#f5a623", "width": 3, "title": "Power Line (electrical layer)"}
        elif e["type"] == "comm":
            proto = e.get("protocol", "TCP/IP")
            kwargs = {"color": "#4a90d9", "dashes": True, "title": f"Comm Link ({proto})"}
        else:
            kwargs = {"color": "#666666", "width": 1}
        net_viz.add_edge(e["from"], e["to"], **kwargs)

    return net_viz.generate_html()