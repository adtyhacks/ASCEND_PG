"""Baseline grid simulation screen — auto-loads on page open."""

import json
import os
import sys

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from testbed.grid_env import build_baseline
from testbed.visualize_topology import render_topology
from testbed.topology import get_topology
from testbed.run_store import create_run, update_run, visual_data


st.set_page_config(page_title="Run Simulation | ASCEND-PG", layout="wide")
st.title("Baseline Grid Simulation")
st.caption("Normal IEEE-14 operating state before evaluating the trained Red/Blue components.")

# Auto-load simulation if not already in session
if not st.session_state.get("simulation_ready"):
    with st.spinner("Running IEEE-14 AC power flow and generating normal telemetry..."):
        case_name = st.session_state.get("config", {}).get("topology", {}).get("pandapower_case", "case14")
        net_obj, grid_df, traffic_df = build_baseline(case_name=case_name)
        topology_snapshot = get_topology().canonical_snapshot()
        topo_nodes, topo_edges, _, _, _ = visual_data(topology_snapshot, [])
    st.session_state.update({
        "net_obj": net_obj,
        "grid_df": grid_df,
        "traffic_df": traffic_df,
        "topo_nodes": topo_nodes,
        "topo_edges": topo_edges,
        "canonical_topology": topology_snapshot,
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

st.divider()
st.subheader("Hardware-in-the-Loop Environment (CORE Emulator)")
st.caption("Visually inspect the physical topology, manipulate nodes, or launch the automated PPO attack sequences.")

from pathlib import Path
from testbed.core_runtime import core_request

col_core1, col_core2 = st.columns(2)
with col_core1:
    if st.button("Generate CORE topology", use_container_width=True):
        from testbed.generate_core_topo import generate_core_xml
        try:
            if st.session_state.get("config", {}).get("custom"):
                raise ValueError("CORE export currently supports IEEE-14/30 presets. Apply a preset before exporting; your custom topology is retained for software simulation.")
            case_num = st.session_state.get("grid_case", 14)
            xml_file = generate_core_xml(case=case_num, output_path=str(Path(PROJECT_ROOT) / "core_topology.xml"))
            st.success(f"Generated {xml_file}. Start the session below, then attach using core-gui.")
        except Exception as exc:
            st.error(str(exc))
    if st.button("Launch CORE", use_container_width=True):
        try:
            with st.spinner("Starting and validating CORE services..."):
                from testbed.generate_core_topo import generate_core_xml
                status = core_request("status")
                if status["state"] == "RUNTIME":
                    raise RuntimeError("An ASCEND-owned CORE session is already active; recover it from Live Battle or stop it before starting a new run")
                case_num = st.session_state.get("grid_case", 14)
                generate_core_xml(case=case_num, output_path=str(Path(PROJECT_ROOT) / "core_topology.xml"))
                active_run = create_run(st.session_state["canonical_topology"])
                result = core_request("start", xml=str(Path(PROJECT_ROOT) / "core_topology.xml"))
                runtime = json.loads((Path(PROJECT_ROOT) / "data" / "core-runtime" / "session.json").read_text(encoding="utf-8"))
                if str(runtime.get("id")) != str(result["session_id"]) or not runtime.get("generation_id"):
                    raise RuntimeError("CORE runtime identity was not persisted; refusing to create an unrecoverable run")
                active_run = update_run(
                    active_run["scenario_id"], active_run["run_id"],
                    core_session_id=result["session_id"], generation_id=runtime["generation_id"],
                    lifecycle_status="RUNNING",
                )
                active_run["path"] = str(Path(PROJECT_ROOT) / "data" / "runs" / active_run["scenario_id"] / active_run["run_id"])
                st.session_state["active_run"] = active_run
            st.success(f"Session {result['session_id']}: {result['state']} ({result['nodes']} nodes)")
        except Exception as exc:
            st.error(str(exc))
with col_core2:
    if st.button("Open CORE GUI", use_container_width=True):
        try:
            result = core_request("gui")
            st.success(f"CORE GUI started for session {result['session_id']} (PID {result['gui_pid']})")
        except Exception as exc:
            st.error(str(exc))
    if st.button("Start PPO watcher", use_container_width=True):
        try:
            with st.spinner("Waiting for the attacker watcher heartbeat..."):
                result = core_request("watcher")
            if result["watcher"] in ("IDLE", "BUSY"):
                st.success(f"Watcher ready in session {result['session_id']}")
            else:
                st.info(f"Watcher {result['watcher']} in session {result['session_id']}. Use Check CORE status to verify readiness.")
        except Exception as exc:
            st.error(str(exc))
    if st.button("Check CORE status", use_container_width=True):
        try:
            st.json(core_request("status"))
        except Exception as exc:
            st.error(str(exc))
    if st.button("Stop CORE session", use_container_width=True):
        try:
            core_request("stop")
            st.success("Managed CORE session stopped and cleaned up")
        except Exception as exc:
            st.error(str(exc))

if st.button("Proceed to Live Battle", type="primary"):



    st.switch_page("pages/3_Live_Battle.py")
