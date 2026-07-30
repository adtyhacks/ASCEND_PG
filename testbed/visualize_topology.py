"""
Renders the ICS/OT topology as an interactive HTML diagram using pyvis.
Device types are shown as colored, emoji-labeled boxes rather than
downloaded icon images — no external assets, no licensing concerns.
Nodes can be highlighted red (compromised) or green (detected) to show
a live attack/defense state.
"""
from pyvis.network import Network

DEVICE_STYLE = {
    "generation_substation":   {"color": "#f5a623", "emoji": "🏭"},
    "distribution_substation": {"color": "#4a90d9", "emoji": "🏢"},
    "pmu":                     {"color": "#7ed321", "emoji": "📡"},
    "rtu":                     {"color": "#9013fe", "emoji": "🔌"},
    "scada_server":            {"color": "#d0021b", "emoji": "🖥️"},
    "historian":               {"color": "#50e3c2", "emoji": "💾"},
    "hmi":                     {"color": "#f8e71c", "emoji": "🖱️"},
    "firewall":                {"color": "#333333", "emoji": "🛡️"},
}


def render_topology(nodes, edges, compromised_ids=None, detected_ids=None):
    compromised_ids = compromised_ids or set()
    detected_ids = detected_ids or set()

    net_viz = Network(height="650px", width="100%", bgcolor="#1e1e1e",
                       font_color="white", directed=False)
    net_viz.barnes_hut()  # physics layout — nodes auto-arrange and can be dragged

    for n in nodes:
        style = DEVICE_STYLE.get(n["type"], {"color": "#888888", "emoji": "❓"})
        border = "#ffffff"
        if n["id"] in compromised_ids:
            border = "#ff3b30"   # red ring = currently under attack
        elif n["id"] in detected_ids:
            border = "#34c759"   # green ring = attack detected here

        net_viz.add_node(
            n["id"],
            label=f"{style['emoji']} {n['label']}",
            shape="box",
            color={"background": style["color"], "border": border},
            borderWidth=4 if n["id"] in (compromised_ids | detected_ids) else 1,
            title=n["label"],
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