#!/usr/bin/env python3
"""
ASCEND-PG — Live Battle (Streamlit page)

Small live view window: polls the testbed's shared logs
(data/log_store.json + data/cycle_report.json, written by
scripts/run_cycle.py) and renders the network topology + event log,
updating every few seconds.

Integrated from the mock testbed's mock_live_view.py. This is the
intentionally-minimal "view window" per the plan — Karthik owns the
major Live Battle UI; this gives a working real-time view to build on.

Runs as page 3 of the Streamlit app (streamlit run app/Home.py, then
pick "Live Battle" in the sidebar) or standalone:
    streamlit run app/pages/3_Live_Battle.py
"""
import json
import time
import base64
from pathlib import Path
from datetime import datetime

import streamlit as st
import streamlit.components.v1 as components

# data/ log store lives at the repo root; this file is app/pages/3_Live_Battle.py
# so the repo root is three parents up.
_REPO = Path(__file__).resolve().parent.parent.parent
LOG_STORE = _REPO / "data" / "log_store.json"
CYCLE_REPORT = _REPO / "data" / "cycle_report.json"

PLCS = [f"plc{i}" for i in range(1, 6)]
NODE_IPS = {
    "plc1": "10.0.0.1", "plc2": "10.0.0.2", "plc3": "10.0.0.3",
    "plc4": "10.0.0.4", "plc5": "10.0.0.5",
    "scada": "10.0.0.10", "attacker": "10.0.0.66",
}


# ---- Hand-drawn SVG icons (shared with the testbed's diagram) ----
def _svg_data_uri(svg: str) -> str:
    return f"data:image/svg+xml;base64,{base64.b64encode(svg.encode()).decode()}"

ICON_PLC = _svg_data_uri("""
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <rect x="10" y="6" width="44" height="52" rx="3" fill="#3b4a5a" stroke="#1f2933" stroke-width="2"/>
  <rect x="16" y="12" width="32" height="6" rx="1" fill="#8fb4d9"/>
  <rect x="16" y="22" width="32" height="4" rx="1" fill="#5c7893"/>
  <rect x="16" y="29" width="32" height="4" rx="1" fill="#5c7893"/>
  <rect x="16" y="36" width="32" height="4" rx="1" fill="#5c7893"/>
  <circle cx="20" cy="47" r="3" fill="#4caf6a"/>
  <circle cx="30" cy="47" r="3" fill="#e0a83d"/>
  <circle cx="40" cy="47" r="3" fill="#c9483b"/>
</svg>
""")

ICON_SCADA = _svg_data_uri("""
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <rect x="8" y="10" width="48" height="32" rx="2" fill="#2f3b52" stroke="#1f2933" stroke-width="2"/>
  <rect x="12" y="14" width="40" height="24" fill="#7fa8d9"/>
  <rect x="20" y="18" width="24" height="3" fill="#2f3b52"/>
  <rect x="20" y="23" width="16" height="3" fill="#2f3b52"/>
  <rect x="20" y="28" width="20" height="3" fill="#2f3b52"/>
  <rect x="27" y="42" width="10" height="8" fill="#3b4a5a"/>
  <rect x="18" y="50" width="28" height="4" rx="1" fill="#1f2933"/>
</svg>
""")

ICON_ATTACKER = _svg_data_uri("""
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <rect x="10" y="14" width="44" height="28" rx="2" fill="#5a2a2a" stroke="#3a1a1a" stroke-width="2"/>
  <rect x="14" y="18" width="36" height="20" fill="#c96b5a"/>
  <path d="M20 24 L28 24 L28 32 L20 32 Z" fill="#5a2a2a"/>
  <path d="M32 24 L44 24 L44 27 L32 27 Z" fill="#5a2a2a"/>
  <path d="M32 29 L40 29 L40 32 L32 32 Z" fill="#5a2a2a"/>
  <path d="M8 46 L56 46 L52 52 L12 52 Z" fill="#3a1a1a"/>
</svg>
""")

ICON_IDS = _svg_data_uri("""
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <path d="M32 6 L54 14 L54 30 C54 44 44 54 32 58 C20 54 10 44 10 30 L10 14 Z"
        fill="#2d5a4a" stroke="#1a332a" stroke-width="2"/>
  <path d="M32 12 L48 18 L48 30 C48 41 40 49 32 52 C24 49 16 41 16 30 L16 18 Z"
        fill="#5fae8f"/>
  <path d="M24 31 L29 36 L40 24" stroke="#1a332a" stroke-width="3.5"
        fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
""")

ICON_SWITCH = _svg_data_uri("""
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <rect x="6" y="24" width="52" height="16" rx="2" fill="#454f5b" stroke="#262c33" stroke-width="2"/>
  <rect x="11" y="29" width="4" height="6" fill="#8fb4d9"/>
  <rect x="18" y="29" width="4" height="6" fill="#8fb4d9"/>
  <rect x="25" y="29" width="4" height="6" fill="#8fb4d9"/>
  <rect x="32" y="29" width="4" height="6" fill="#8fb4d9"/>
  <rect x="39" y="29" width="4" height="6" fill="#8fb4d9"/>
  <rect x="46" y="29" width="4" height="6" fill="#8fb4d9"/>
</svg>
""")


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def determine_state():
    # First check cycle_report for completed steps with verdicts
    report = load_json(CYCLE_REPORT)
    completed_steps = {}
    if report and report.get("steps"):
        for step in report["steps"]:
            completed_steps[step["name"]] = {
                "detected": step["detected"],
                "techniques": "+".join(step["techniques"]),
            }

    # Infer current active stage from live attacker events in log_store
    events = load_json(LOG_STORE) or []
    attacker_events = [e for e in events if e.get("source") == "attacker" or (e.get("stage") and not e.get("source"))]

    # Track the most recent step_start without a matching step_end
    active_stage = None
    active_technique = None
    step_stack = []  # (stage, technique, start_time)

    for ev in attacker_events:
        stage = ev.get("stage")
        technique = ev.get("technique")
        action = ev.get("action")
        if action == "step_start":
            step_stack.append((stage, technique))
        elif action == "step_end" and step_stack:
            step_stack.pop()

    if step_stack:
        active_stage, active_technique = step_stack[-1]

    # Determine detected status: if in completed_steps, use that; otherwise unknown (None)
    detected = None
    if active_stage and active_stage in completed_steps:
        detected = completed_steps[active_stage]["detected"]
        techniques = completed_steps[active_stage]["techniques"]
    elif active_stage:
        techniques = active_technique
    else:
        # No active step - show last completed
        if report and report.get("steps"):
            last = report["steps"][-1]
            active_stage = last["name"]
            detected = last["detected"]
            techniques = "+".join(last["techniques"])
        else:
            techniques = None

    return {
        "active_stage": active_stage,
        "detected": detected,
        "techniques": techniques,
        "completed_steps": completed_steps,
    }


def build_nodes_edges(state):
    nodes = []
    edges = []

    nodes.append({"id": "attacker", "label": f"attacker\n{NODE_IPS['attacker']}",
                  "shape": "image", "image": ICON_ATTACKER, "size": 34})
    nodes.append({"id": "switch", "label": "s1", "shape": "image",
                  "image": ICON_SWITCH, "size": 30})
    nodes.append({"id": "scada", "label": f"scada\n{NODE_IPS['scada']}",
                  "shape": "image", "image": ICON_SCADA, "size": 34})
    nodes.append({"id": "ids", "label": "suricata IDS", "shape": "image",
                  "image": ICON_IDS, "size": 34})

    for plc in PLCS:
        nodes.append({"id": plc, "label": f"{plc}\n{NODE_IPS[plc]}",
                      "shape": "image", "image": ICON_PLC, "size": 30})
        edges.append({"from": plc, "to": "switch", "color": {"color": "#9aa5b1"}, "width": 1})

    edges.append({"from": "attacker", "to": "switch", "color": {"color": "#9aa5b1"}, "width": 1})
    edges.append({"from": "scada", "to": "switch", "color": {"color": "#9aa5b1"}, "width": 1})
    edges.append({"from": "ids", "to": "switch", "color": {"color": "#9aa5b1"},
                  "width": 1, "dashes": True})

    completed = state.get("completed_steps", {})
    active_stage = state.get("active_stage")
    active_detected = state.get("detected")

    # Show completed attack edges with their verdicts
    for i, (step_name, step_info) in enumerate(completed.items()):
        if step_name in ("recon", "fdi_attack", "dos_quiet", "dos_loud"):
            detected = step_info["detected"]
            color = "#2d5a4a" if detected else "#8a3a2a"
            label = f"{step_info['techniques']} - {'DETECTED' if detected else 'NOT DETECTED'}"
            # Offset each completed edge slightly so they don't overlap perfectly
            edges.append({
                "from": "attacker", "to": "plc1",
                "color": {"color": color},
                "width": 2,
                "label": label,
                "font": {"size": 10, "color": color},
                "dashes": [5, 5],  # dashed for completed
            })
            if detected:
                edges.append({"from": "switch", "to": "ids", "color": {"color": color}, "width": 2, "dashes": [5, 5]})

    # Show active (in-progress) attack edge - amber/yellow, solid, no verdict yet
    if active_stage in ("recon", "fdi_attack", "dos_quiet", "dos_loud"):
        # If we already have a verdict for this stage, show it
        if active_stage in completed:
            detected = completed[active_stage]["detected"]
            color = "#2d5a4a" if detected else "#8a3a2a"
            label = f"{state.get('techniques', '')} - {'DETECTED' if detected else 'NOT DETECTED'}"
        else:
            # In progress - amber color, no verdict yet
            color = "#e0a83d"
            label = f"{state.get('techniques', '')} - IN PROGRESS..."
        edges.append({"from": "attacker", "to": "plc1", "color": {"color": color},
                      "width": 4, "label": label, "font": {"size": 11, "color": color}})
        # Show IDS connection if detected or in-progress (monitoring)
        if active_stage in completed and completed[active_stage]["detected"]:
            edges.append({"from": "switch", "to": "ids", "color": {"color": color}, "width": 3})
        elif active_stage not in completed:
            # Show monitoring connection during active attack
            edges.append({"from": "switch", "to": "ids", "color": {"color": "#e0a83d"}, "width": 2, "dashes": [3, 3]})

    return nodes, edges


def build_log_rows():
    events = load_json(LOG_STORE) or []
    report = load_json(CYCLE_REPORT)
    rows = []
    for ev in events:
        source = "scada" if ev.get("stage") == "normal_traffic" else "attacker"
        rows.append({
            "Timestamp": ev.get("timestamp", ""),
            "Source": source,
            "Stage": ev.get("stage", ""),
            "Technique": ev.get("technique", ""),
            "Detail": ev.get("action", ""),
        })
    if report:
        for step in report.get("steps", []):
            verdict = "DETECTED" if step["detected"] else "NOT DETECTED"
            rows.append({
                "Timestamp": step["end"],
                "Source": "suricata",
                "Stage": step["name"],
                "Technique": "+".join(step["techniques"]),
                "Detail": verdict,
            })
    rows.sort(key=lambda r: r["Timestamp"] or "")
    return rows[-50:]  # last 50


# ---- Streamlit UI ----
st.set_page_config(page_title="ASCEND-PG Live Battle", layout="wide")
st.title("ASCEND-PG Testbed — Live Attack/Defense View")
st.caption(
    f"Polling `{LOG_STORE.name}` + `{CYCLE_REPORT.name}` from data/ "
    "(written by scripts/run_cycle.py). Small live window — Karthik owns the "
    "full Live Battle UI."
)

# Auto-refresh every 3 seconds
placeholder = st.empty()
refresh_interval = 3

with placeholder.container():
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Network Topology (Live)")
        state = determine_state()
        nodes, edges = build_nodes_edges(state)

        # vis-network HTML
        network_html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/10.1.0/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ margin: 0; background: #ffffff; }}
    #network {{ width: 100%; height: 500px; border: 1px solid #d0d7de; border-radius: 6px; }}
  </style>
</head>
<body>
  <div id="network"></div>
  <script>
    var nodes = new vis.DataSet({json.dumps(nodes)});
    var edges = new vis.DataSet({json.dumps(edges)});
    var container = document.getElementById('network');
    var data = {{ nodes: nodes, edges: edges }};
    var options = {{
      physics: {{ enabled: true, stabilization: {{ iterations: 80 }} }},
      interaction: {{ zoomView: true, dragView: true }},
      nodes: {{ font: {{ size: 12, color: '#1f2933' }} }},
      edges: {{ smooth: {{ type: 'continuous' }} }}
    }};
    new vis.Network(container, data, options);
  </script>
</body>
</html>
"""
        components.html(network_html, height=520, scrolling=False)

    with col2:
        st.subheader("Event Log (Live)")
        rows = build_log_rows()
        if rows:
            st.dataframe(rows, use_container_width=True, height=500)
        else:
            st.info("Waiting for events...")

    # Status bar - shows active/in-progress step
    state = determine_state()
    active = state.get("active_stage")
    detected = state.get("detected")
    techniques = state.get("techniques")
    completed = state.get("completed_steps", {})

    if active:
        if active in completed:
            verdict = "DETECTED" if completed[active]["detected"] else "NOT DETECTED"
            st.caption(f"Current step: **{active}** ({techniques}) → **{verdict}**  |  Updated: {datetime.now().strftime('%H:%M:%S')}")
        else:
            st.caption(f"Current step: **{active}** ({techniques}) → **IN PROGRESS...**  |  Updated: {datetime.now().strftime('%H:%M:%S')}")
    else:
        st.caption(f"Waiting for cycle to start...  |  Updated: {datetime.now().strftime('%H:%M:%S')}")

# Auto-rerun
time.sleep(refresh_interval)
st.rerun()
