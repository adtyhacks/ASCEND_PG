"""Interactive trained PPO versus fused-detector campaign dashboard."""

import os
import sys
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from strategic.rl_env import AttackStrategyEnv, PlateauTracker
from xai.attack_decision_explain import explain_action, load_rl_explainer
from testbed.visualize_topology import render_topology


st.set_page_config(page_title="Live Battle | ASCEND-PG", layout="wide")
st.title("Live Red vs. Blue Battle")
st.caption("PPO selects a MITRE ICS technique; the saved LSTM + autoencoder fusion produces the detection confidence.")

if not st.session_state.get("simulation_ready"):
    st.warning("Run the baseline simulation first so the battle can display the OT topology.")
    if st.button("Go to Run Simulation"):
        st.switch_page("pages/2_Run_Simulation.py")
    st.stop()


def _new_campaign(use_detector_fusion: bool) -> None:
    """Initialise a campaign without altering the pretrained PPO environment definition."""
    st.session_state["battle_env"] = AttackStrategyEnv(real_mode=use_detector_fusion)
    st.session_state["battle_model"] = load_rl_explainer()
    st.session_state["battle_obs"], _ = st.session_state["battle_env"].reset()
    st.session_state["battle_active"] = True
    st.session_state["battle_events"] = []
    st.session_state["battle_explanations"] = []
    if "battle_plateau" not in st.session_state:
        st.session_state["battle_plateau"] = PlateauTracker(patience=5)


def _record_completed_campaign() -> None:
    events = st.session_state.get("battle_events", [])
    if not events:
        return
    detected = sum(event["Detected"] for event in events)
    evasion_rate = 1.0 - detected / len(events)
    stages = [event["Stage Index"] for event in events if not event["Detected"]]
    summary = {
        "events": events.copy(),
        "evasion_rate": evasion_rate,
        "campaign_complete": bool(events[-1]["Campaign Complete"]),
        "max_stage": max(stages) if stages else 0,
        "reward": sum(event["Reward"] for event in events),
        "chain": [event["MITRE ID"] for event in events],
    }
    campaigns = st.session_state.setdefault("battle_campaigns", [])
    campaigns.append(summary)
    tracker = st.session_state["battle_plateau"]
    plateaued = tracker.update(evasion_rate)
    st.session_state["battle_results"] = {
        "campaigns": campaigns,
        "latest_events": events.copy(),
        "latest_explanations": st.session_state.get("battle_explanations", []).copy(),
        "plateau_detected": plateaued,
    }


def _step_campaign() -> None:
    env = st.session_state["battle_env"]
    model = st.session_state["battle_model"]
    obs = st.session_state["battle_obs"]
    action, _ = model.predict(obs, deterministic=True)
    action = int(action)
    explanation = explain_action(model, obs, action)
    next_obs, reward, terminated, truncated, info = env.step(action)

    rtu_nodes = [node["id"] for node in st.session_state["topo_nodes"] if node["id"].startswith("rtu_")]
    target_host = rtu_nodes[(env._step_count - 1) % len(rtu_nodes)] if rtu_nodes else "ot_gateway"
    event = {
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Step": env._step_count,
        "MITRE ID": info["technique_id"],
        "Technique Name": info["technique_name"],
        "Stage": explanation["chosen_technique"]["stage_name"],
        "Stage Index": info["stage"],
        "Target Host": target_host,
        "Detector Confidence": round(info["detection_confidence"], 4),
        "Status": "Caught" if info["detected"] else "Evaded",
        "Detected": bool(info["detected"]),
        "Reward": round(float(reward), 3),
        "Campaign Complete": bool(info["campaign_complete"]),
    }
    explanation.update({
        "step": env._step_count,
        "reward": float(reward),
        "detected": bool(info["detected"]),
        "detection_confidence": float(info["detection_confidence"]),
        "campaign_complete": bool(info["campaign_complete"]),
    })
    st.session_state["battle_events"].append(event)
    st.session_state["battle_explanations"].append(explanation)
    st.session_state["battle_obs"] = next_obs

    if terminated or truncated:
        st.session_state["battle_active"] = False
        _record_completed_campaign()


config = st.session_state.get("config", {})
use_detector_fusion = config.get("use_lstm", True) and config.get("use_autoencoder", True)
if use_detector_fusion:
    st.info("Detector-backed mode uses the saved LSTM + autoencoder fusion on the existing CIC-IDS flow dataset. "
            "It is not yet a live Mininet capture; that integration waits for Abinraj's captured dataset and executors.")
else:
    st.info("The saved fusion model requires both the LSTM and autoencoder. With either detector disabled, "
            "this campaign uses the PPO environment's calibrated mock detection mode.")

controls = st.columns(3)
with controls[0]:
    if st.button("Start New PPO Campaign", type="primary"):
        _new_campaign(use_detector_fusion)
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
if st.button("Reset Battle History"):
    for key in ("battle_env", "battle_model", "battle_obs", "battle_active", "battle_events",
                "battle_explanations", "battle_plateau", "battle_campaigns", "battle_results"):
        st.session_state.pop(key, None)
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
    components.html(topology_html, height=680, scrolling=True)

if events:
    with st.expander("Latest PPO tactical rationale", expanded=True):
        explanation = st.session_state["battle_explanations"][-1]
        st.write(explanation["rationale"])
        alternatives = pd.DataFrame(explanation["top_alternatives"])
        if not alternatives.empty:
            st.dataframe(alternatives[["id", "name", "stage_name", "probability"]], hide_index=True,
                         use_container_width=True)

if campaigns:
    latest_campaign = campaigns[-1]
    st.caption(f"Latest campaign: {len(latest_campaign['events'])} steps, "
               f"evasion {latest_campaign['evasion_rate']:.0%}, "
               f"completion {'yes' if latest_campaign['campaign_complete'] else 'no'}.")
    if st.button("Open Executive Report"):
        st.switch_page("pages/4_Report.py")
