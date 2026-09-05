"""
ASCEND-PG — Live Battle & Defense Evaluation (Streamlit page)

Unified interface supporting two operational modes:
1. Adaptive AI Campaign (PPO + LSTM/Autoencoder Fusion):
   Executes and visualizes multi-stage PPO attack campaigns with live detector feedback,
   tactical decision rationales, plateau tracking, and topology compromise rendering.
2. Live Mininet Testbed Monitor:
   Polls real testbed logs (data/log_store.json + data/cycle_report.json) generated
   by scripts/run_cycle.py against the emulated ICS network.
"""

import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology
from testbed.visualize_topology import render_topology
from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES
from detection.fusion import DetectorFusion
from xai.attack_decision_explain import explain_step_decision
from metrics.dvs import PlateauTracker
from stable_baselines3 import PPO

_REPO = Path(PROJECT_ROOT)
LOG_STORE = _REPO / "data" / "log_store.json"
CYCLE_REPORT = _REPO / "data" / "cycle_report.json"
MODEL_PATH = _REPO / "models" / "rl_agent.zip"

st.set_page_config(page_title="Live Battle | ASCEND-PG", layout="wide")
st.title("Live Battle & Defense Evaluation")
st.caption("Evaluate the trained adaptive attacker against active ICS defenses.")

# Ensure baseline topology exists in session state
if "topo_nodes" not in st.session_state or "topo_edges" not in st.session_state:
    net_obj, grid_df, traffic_df = build_baseline()
    topo_nodes, topo_edges = build_ot_topology(net_obj)
    st.session_state.update({
        "net_obj": net_obj,
        "grid_df": grid_df,
        "traffic_df": traffic_df,
        "topo_nodes": topo_nodes,
        "topo_edges": topo_edges,
    })

tab_ai, tab_testbed = st.tabs(["Adaptive AI Campaign (PPO + Detectors)", "Mininet Testbed Live Monitor"])

# ==============================================================================
# TAB 1: Adaptive AI Campaign Mode
# ==============================================================================
with tab_ai:
    def _load_ppo_model():
        if not MODEL_PATH.exists():
            st.error(f"Trained PPO model not found at {MODEL_PATH}.")
            st.stop()
        return PPO.load(str(MODEL_PATH))

    def _new_campaign(use_real_detector: bool):
        env = AttackStrategyEnv(real_mode=use_real_detector)
        model = _load_ppo_model()
        obs, _ = env.reset()
        st.session_state["battle_env"] = env
        st.session_state["battle_model"] = model
        st.session_state["battle_obs"] = obs
        st.session_state["battle_active"] = True
        st.session_state["battle_events"] = []
        st.session_state["battle_explanations"] = []
        if "battle_plateau" not in st.session_state:
            st.session_state["battle_plateau"] = PlateauTracker(window_size=5, patience=3, min_delta=0.03)

    def _record_completed_campaign():
        events = st.session_state.get("battle_events", [])
        if not events:
            return
        evasion_rate = 1.0 - pd.DataFrame(events)["Detected"].mean()
        campaign_complete = any(e["Stage"] == 3 for e in events)
        st.session_state.setdefault("battle_campaigns", []).append({
            "events": list(events),
            "evasion_rate": float(evasion_rate),
            "campaign_complete": bool(campaign_complete),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        plateau = st.session_state["battle_plateau"]
        plateau_detected = plateau.update(float(evasion_rate))
        st.session_state["battle_results"] = {
            "campaigns": st.session_state["battle_campaigns"],
            "evasion_rate": float(evasion_rate),
            "plateau_detected": bool(plateau_detected),
            "last_campaign_complete": bool(campaign_complete),
        }

    def _step_campaign():
        if not st.session_state.get("battle_active"):
            return
        env = st.session_state["battle_env"]
        model = st.session_state["battle_model"]
        obs = st.session_state["battle_obs"]

        action, _ = model.predict(obs, deterministic=False)
        action_idx = int(action)
        explanation = explain_step_decision(model, env, obs, action_idx)

        next_obs, reward, terminated, truncated, info = env.step(action_idx)
        tech = MITRE_TECHNIQUES[action_idx]
        detected = not bool(info.get("evaded", False))
        detector_conf = float(info.get("detector_confidence", 0.0))

        targets = [n["id"] for n in st.session_state["topo_nodes"] if n["group"] in ("plc", "substation", "generator")]
        target_host = targets[len(st.session_state["battle_events"]) % len(targets)] if targets else "plc1"

        event = {
            "Timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "Step": len(st.session_state["battle_events"]) + 1,
            "MITRE ID": tech["id"],
            "Technique Name": tech["name"],
            "Stage": tech["stage"],
            "Target Host": target_host,
            "Detector Confidence": f"{detector_conf:.3f}",
            "Status": "Detected" if detected else "Compromised",
            "Detected": detected,
        }
        st.session_state["battle_events"].append(event)
        st.session_state["battle_explanations"].append(explanation)
        st.session_state["battle_obs"] = next_obs

        if terminated or truncated:
            st.session_state["battle_active"] = False
            _record_completed_campaign()

    config = st.session_state.get("config", {})
    use_detector_fusion = config.get("use_lstm", True) and config.get("use_autoencoder", True)

    controls = st.columns(3)
    with controls[0]:
        if st.button("Start New PPO Campaign", type="primary"):
            _new_campaign(use_detector_fusion)
            st.rerun()
    with controls[1]:
        next_disabled = not st.session_state.get("battle_active", False)
        if st.button("Run Next Tactic", disabled=next_disabled):
            _step_campaign()
            st.rerun()
    with controls[2]:
        if st.button("Run Campaign to Completion", disabled=not st.session_state.get("battle_active", False)):
            while st.session_state.get("battle_active", False):
                _step_campaign()
            st.rerun()

    events = st.session_state.get("battle_events", [])
    campaigns = st.session_state.get("battle_campaigns", [])
    latest = pd.DataFrame(events)
    current_evasion = 1.0 - (latest["Detected"].mean() if not latest.empty else 0.0)
    plateaued = st.session_state.get("battle_results", {}).get("plateau_detected", False)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Current step", len(events))
    m2.metric("Current evasion", f"{current_evasion:.0%}" if events else "—")
    m3.metric("Completed campaigns", len(campaigns))
    m4.metric("Plateau status", "Plateau detected" if plateaued else "Monitoring")

    if plateaued:
        st.warning("Defense-evasion plateau detected across completed campaigns. The report will include this DVS signal.")

    left, right = st.columns([1.15, 1])
    with left:
        st.subheader("Live battle event log")
        if latest.empty:
            st.info("Start a PPO campaign, then run tactics one at a time or to completion.")
        else:
            display_columns = ["Timestamp", "Step", "MITRE ID", "Technique Name", "Stage", "Target Host", "Detector Confidence", "Status"]
            st.dataframe(latest[display_columns], use_container_width=True, hide_index=True)
    with right:
        st.subheader("Compromise and defense topology")
        compromised = set()
        detected = set()
        for event in events:
            (detected if event["Detected"] else compromised).add(event["Target Host"])
        topology_html = render_topology(
            st.session_state["topo_nodes"], st.session_state["topo_edges"],
            compromised_ids=compromised, detected_ids=detected,
        )
        components.html(topology_html, height=600, scrolling=True)

    if events:
        with st.expander("Latest PPO tactical rationale", expanded=True):
            explanation = st.session_state["battle_explanations"][-1]
            st.write(explanation["rationale"])
            alternatives = pd.DataFrame(explanation["top_alternatives"])
            if not alternatives.empty:
                st.dataframe(alternatives[["id", "name", "stage_name", "probability"]], hide_index=True,
                             use_container_width=True)

    if campaigns:
        st.caption(f"Latest campaign: {len(campaigns[-1]['events'])} steps, "
                   f"evasion {campaigns[-1]['evasion_rate']:.0%}, "
                   f"completion {'yes' if campaigns[-1]['campaign_complete'] else 'no'}.")
        if st.button("Open Executive Report"):
            st.switch_page("pages/4_Report.py")


# ==============================================================================
# TAB 2: Mininet Testbed Live Monitor
# ==============================================================================
with tab_testbed:
    st.subheader("Live Mininet Testbed Monitor")
    st.caption("Reads live telemetry events from data/log_store.json and verdicts from data/cycle_report.json.")

    col_ctrl, col_auto = st.columns([2, 1])
    with col_ctrl:
        auto_refresh = st.checkbox("Auto-refresh testbed events (every 3s)", value=False)
    with col_auto:
        if st.button("Refresh Now"):
            st.rerun()

    if LOG_STORE.exists():
        try:
            raw_log = json.loads(LOG_STORE.read_text(encoding="utf-8"))
            if isinstance(raw_log, list) and raw_log:
                log_df = pd.DataFrame(raw_log)
                st.write(f"Total Logged Testbed Events: **{len(log_df)}**")
                st.dataframe(log_df, use_container_width=True, height=350)
            else:
                st.info("Log store exists but contains no events yet.")
        except Exception as err:
            st.warning(f"Could not parse log store: {err}")
    else:
        st.info(f"No live testbed log store found at `{LOG_STORE}`. Run `scripts/run_cycle.py` on WSL2.")

    if CYCLE_REPORT.exists():
        try:
            report_data = json.loads(CYCLE_REPORT.read_text(encoding="utf-8"))
            st.subheader("Latest Testbed Cycle Detection Report")
            st.json(report_data)
        except Exception as err:
            st.warning(f"Could not parse cycle report: {err}")

    if auto_refresh:
        time.sleep(3)
        st.rerun()
