"""Baseline grid simulation screen — auto-loads on page open."""

import os
import sys

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology
from testbed.visualize_topology import render_topology


st.set_page_config(page_title="Run Simulation | ASCEND-PG", layout="wide")
st.title("Baseline Grid Simulation")
st.caption("Normal IEEE-14 operating state before evaluating the trained Red/Blue components.")

# Auto-load simulation if not already in session
if not st.session_state.get("simulation_ready"):
    with st.spinner("Running IEEE-14 AC power flow and generating normal telemetry..."):
        case_name = st.session_state.get("config", {}).get("topology", {}).get("pandapower_case", "case14")
        net_obj, grid_df, traffic_df = build_baseline(case_name=case_name)
        topo_nodes, topo_edges = build_ot_topology(net_obj)
    st.session_state.update({
        "net_obj": net_obj,
        "grid_df": grid_df,
        "traffic_df": traffic_df,
        "topo_nodes": topo_nodes,
        "topo_edges": topo_edges,
        "simulation_ready": True,
    })

net_obj = st.session_state["net_obj"]
grid_df = st.session_state["grid_df"]
traffic_df = st.session_state["traffic_df"]

voltage_min = grid_df["voltage_pu"].min()
voltage_max = grid_df["voltage_pu"].max()
line_loading = net_obj.res_line["loading_percent"] if not net_obj.res_line.empty else pd.Series(dtype=float)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Electrical buses", len(grid_df))
col2.metric("Voltage range", f"{voltage_min:.3f}–{voltage_max:.3f} pu")
col3.metric("Lines", len(net_obj.line))
col4.metric("Max line loading", f"{line_loading.max():.1f}%" if not line_loading.empty else "N/A")

left, right = st.columns(2)
with left:
    st.subheader("Bus voltage profile")
    st.bar_chart(grid_df.set_index("bus_id")["voltage_pu"])
    st.dataframe(grid_df, use_container_width=True, hide_index=True)
with right:
    st.subheader("Line loading")
    if line_loading.empty:
        st.info("The selected grid has no line-loading results.")
    else:
        line_df = pd.DataFrame({"line_id": line_loading.index, "loading_percent": line_loading.values})
        st.bar_chart(line_df.set_index("line_id")["loading_percent"])
        st.dataframe(line_df, use_container_width=True, hide_index=True)

st.subheader("Normal baseline telemetry")
st.caption("This lightweight operational telemetry is separate from the 78-feature CIC flow dataset used by the trained detectors.")
st.dataframe(traffic_df.head(50), use_container_width=True, hide_index=True)

st.subheader("OT communication topology")
topology_html = render_topology(st.session_state["topo_nodes"], st.session_state["topo_edges"])
components.html(topology_html, height=680, scrolling=True)

if st.button("Proceed to Live Battle"):
    st.switch_page("pages/3_Live_Battle.py")
