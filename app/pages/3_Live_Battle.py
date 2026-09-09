"""
ASCEND-PG — Live Battle & Defense Evaluation (Streamlit page)

Unified interface for PPO-driven attack campaigns with three operational modes:
1. PPO + Real Testbed: PPO selects MITRE techniques, real attack scripts run
   on the Mininet testbed via file-based handoff to ppo_step_watcher.py.
2. PPO + Simulation: PPO selects techniques, detection evaluated via calibrated
   probabilistic model (no testbed required).
3. Mininet Testbed Only: Raw event viewer for live testbed monitoring.

File-based handoff protocol (PPO + Real Testbed mode):
  1. Streamlit writes:  data/pending_step.json
  2. Watcher on attacker reads it, executes attack, writes data/step_result.json
  3. Streamlit polls for result, feeds detection confidence back to PPO
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology
from testbed.visualize_topology import render_topology
from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES, NUM_TECHNIQUES
from xai.attack_decision_explain import explain_step_decision
from metrics.dvs import PlateauTracker
from stable_baselines3 import PPO
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME

_REPO = Path(PROJECT_ROOT)
DATA_DIR = _REPO / "data"
LOG_STORE = DATA_DIR / "log_store.json"
CYCLE_REPORT = DATA_DIR / "cycle_report.json"
MODEL_PATH = _REPO / "models" / "rl_agent.zip"

# File-based handoff paths
PENDING_STEP = DATA_DIR / "pending_step.json"
STEP_RESULT = DATA_DIR / "step_result.json"

# Technique IDs that have real testbed scripts (from testbed_executor.py)
REAL_TESTBED_TECHNIQUES = {
    "T0846", "T0888", "T0842", "T0830", "T0801", "T0814", "T0816",
    "T0836", "T0806", "T0835", "T0832", "T0815",
}

# Mininet host IP mapping
MININET_IPS = {
    "plc1": "10.0.0.1", "plc2": "10.0.0.2", "plc3": "10.0.0.3",
    "plc4": "10.0.0.4", "plc5": "10.0.0.5", "scada": "10.0.0.10",
}

st.set_page_config(page_title="Live Battle | ASCEND-PG", layout="wide")
st.title("Live Battle & Defense Evaluation")
st.caption("Evaluate the trained adaptive attacker against active ICS defenses.")

# Ensure baseline topology exists in session state
if "topo_nodes" not in st.session_state or "topo_edges" not in st.session_state:
    net_obj, grid_df, traffic_df = build_baseline()
    topo_nodes, topo_edges = build_ot_topology(net_obj)
    st.session_state.update({
        "net_obj": net_obj, "grid_df": grid_df, "traffic_df": traffic_df,
        "topo_nodes": topo_nodes, "topo_edges": topo_edges,
    })


# =============================================================================
# Helper functions
# =============================================================================

def _load_ppo_model():
    if not MODEL_PATH.exists():
        st.error(f"Trained PPO model not found at {MODEL_PATH}.")
        st.stop()
    return PPO.load(str(MODEL_PATH))


def _has_testbed_support(technique_id: str) -> bool:
    """Check if a technique has a real testbed attack script."""
    return technique_id in REAL_TESTBED_TECHNIQUES


def _format_log_detail(event: dict) -> str:
    """Format a log event into a short human-readable detail string."""
    action = event.get("action", "")
    parts = []

    status = event.get("status", "")
    if status:
        parts.append(status)

    if event.get("success") is True:
        parts.append("OK")
    elif event.get("success") is False:
        parts.append("FAIL")

    error = event.get("error", "")
    if error:
        parts.append(str(error)[:60])

    if "injection" in action or "inject" in action:
        addr = event.get("address", "")
        val = event.get("injected_value", event.get("value", ""))
        if addr != "" and val != "":
            parts.append(f"reg[{addr}]={val}")

    elif "mitm_intercept" in action:
        mode = event.get("mode", "")
        parts.append(f"mode={mode}")

    elif "dos_" in action or "conn_exhaust" in action:
        count = event.get("count", event.get("connections", ""))
        if count:
            parts.append(f"count={count}")

    elif "nmap_sweep_result" in action:
        hosts = event.get("hosts_found", [])
        parts.append(f"hosts={len(hosts)}")

    elif "fc_scan_complete" in action:
        supported = event.get("supported_count", 0)
        parts.append(f"supported={supported}")

    elif "poll_" in action:
        parts.append("SCADA poll")

    elif "step_start" in action or "step_end" in action:
        tech = event.get("technique", "")
        if tech:
            parts.append(tech)
        det = event.get("detection_method", "")
        if det and det != "suricata":
            parts.append(f"via {det}")

    elif "replay_" in action:
        frames = event.get("frames_captured", event.get("frames", ""))
        if frames:
            parts.append(f"frames={frames}")

    elif "monitor_snapshot" in action:
        changes = event.get("changes_detected", 0)
        parts.append(f"changes={changes}")

    elif "hybrid_detection" in action:
        method = event.get("detection_method", "")
        ml_conf = event.get("ml_confidence", 0.0)
        if method:
            parts.append(f"method={method}")
        if ml_conf > 0:
            parts.append(f"ml={ml_conf:.2f}")

    return " | ".join(parts) if parts else "-"


def _write_pending_step(technique_id: str, step_name: str):
    """Write a step command for the PPO watcher to execute."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_STEP.write_text(json.dumps({
        "technique_id": technique_id,
        "step_name": step_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), encoding="utf-8")


def _poll_step_result(timeout: float = 300.0, poll_interval: float = 0.5) -> dict | None:
    """Poll for the watcher's result file. Returns None on timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if STEP_RESULT.exists():
            try:
                data = json.loads(STEP_RESULT.read_text(encoding="utf-8"))
                STEP_RESULT.unlink(missing_ok=True)
                return data
            except (json.JSONDecodeError, OSError):
                pass
        time.sleep(poll_interval)
    return None


def _resolve_target_host(event_index: int) -> str:
    """Map an event index to a Mininet host for topology highlighting."""
    targets = [n["id"] for n in st.session_state["topo_nodes"]
               if n.get("type", "") in ("generation_substation", "distribution_substation",
                                          "rtu", "pmu", "plc", "generator")]
    return targets[event_index % len(targets)] if targets else "plc1"


def _new_campaign(use_real_testbed: bool):
    """Initialize a new PPO attack campaign."""
    env = AttackStrategyEnv(real_mode=False)  # We handle detection ourselves
    model = _load_ppo_model()
    obs, _ = env.reset()
    st.session_state["battle_env"] = env
    st.session_state["battle_model"] = model
    st.session_state["battle_obs"] = obs
    st.session_state["battle_active"] = True
    st.session_state["battle_events"] = []
    st.session_state["battle_explanations"] = []
    st.session_state["battle_reward"] = 0.0
    st.session_state["use_real_testbed"] = use_real_testbed
    if "battle_plateau" not in st.session_state:
        st.session_state["battle_plateau"] = PlateauTracker(patience=3, min_evasion_gain=0.03)
    # Clear any stale handoff files
    PENDING_STEP.unlink(missing_ok=True)
    STEP_RESULT.unlink(missing_ok=True)


def _record_completed_campaign():
    """Record campaign results for the DVS report."""
    events = st.session_state.get("battle_events", [])
    if not events:
        return
    evasion_rate = 1.0 - pd.DataFrame(events)["Detected"].mean()
    campaign_complete = any(e["Stage"] == 3 for e in events)

    stages_hit = [e["Stage"] for e in events if not e["Detected"]]
    max_stage = max(stages_hit) if stages_hit else 0

    chain = [{
        "technique_id": e["MITRE ID"],
        "technique_name": e["Technique Name"],
        "stage": e["Stage"],
        "detected": e["Detected"],
        "confidence": float(e["Detector Confidence"]),
    } for e in events]

    st.session_state.setdefault("battle_campaigns", []).append({
        "events": list(events),
        "evasion_rate": float(evasion_rate),
        "campaign_complete": bool(campaign_complete),
        "max_stage": int(max_stage),
        "reward": float(st.session_state.get("battle_reward", 0.0)),
        "chain": chain,
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

    try:
        history_file = DATA_DIR / "ppo_campaign_history.json"
        history_file.parent.mkdir(exist_ok=True)
        with open(history_file, "w") as f:
            json.dump(st.session_state["battle_campaigns"], f, indent=2)
    except Exception as e:
        print(f"Failed to export campaign history: {e}")


def _step_campaign_mock():
    """Execute one PPO step using calibrated detection (no testbed)."""
    if not st.session_state.get("battle_active"):
        return
    env = st.session_state["battle_env"]
    model = st.session_state["battle_model"]
    obs = st.session_state["battle_obs"]

    action, _ = model.predict(obs, deterministic=False)
    action_idx = int(action)
    explanation = explain_step_decision(model, obs, action_idx)

    next_obs, reward, terminated, truncated, info = env.step(action_idx)
    st.session_state["battle_reward"] += float(reward)
    tech = MITRE_TECHNIQUES[action_idx]
    detected = bool(info.get("detected", False))
    detector_conf = float(info.get("detection_confidence", 0.0))

    target_host = _resolve_target_host(len(st.session_state["battle_events"]))

    event = {
        "Timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "Step": len(st.session_state["battle_events"]) + 1,
        "MITRE ID": tech["id"],
        "Technique Name": tech["name"],
        "Stage": tech["stage"],
        "Target Host": target_host,
        "Detector Confidence": f"{detector_conf:.3f}",
        "ML Confidence": "0.000",
        "LSTM Score": "0.000",
        "AE Score": "0.000",
        "Detection Method": "calibrated",
        "Status": "Detected" if detected else "Compromised",
        "Detected": detected,
        "Mode": "Simulation",
    }
    st.session_state["battle_events"].append(event)
    st.session_state["battle_explanations"].append(explanation)
    st.session_state["battle_obs"] = next_obs

    if terminated or truncated:
        st.session_state["battle_active"] = False
        _record_completed_campaign()


def _step_campaign_real():
    """Execute one PPO step using real testbed attacks via file handoff."""
    if not st.session_state.get("battle_active"):
        return
    model = st.session_state["battle_model"]
    obs = st.session_state["battle_obs"]
    env = st.session_state["battle_env"]

    action, _ = model.predict(obs, deterministic=False)
    action_idx = int(action)
    explanation = explain_step_decision(model, obs, action_idx)
    tech = MITRE_TECHNIQUES[action_idx]
    technique_id = tech["id"]

    target_host = _resolve_target_host(len(st.session_state["battle_events"]))

    # Check if this technique has a real testbed script
    step_name = TECHNIQUE_TO_STEP_NAME.get(technique_id)
    has_testbed = step_name is not None

    if has_testbed and not PENDING_STEP.exists() and not STEP_RESULT.exists():
        _write_pending_step(technique_id, step_name)

        status_box = st.empty()
        status_box.info(f"Executing {technique_id} ({tech['name']}) on testbed...")
        result = _poll_step_result(timeout=300.0)
        status_box.empty()

        if result and result.get("success", False):
            detected = result.get("detected", False)
            detector_conf = result.get("ml_confidence", 1.0 if detected else 0.0)
            ml_confidence = result.get("ml_confidence", 0.0)
            ml_lstm = result.get("ml_lstm_confidence", 0.0)
            ml_ae = result.get("ml_ae_score", 0.0)
            detection_method = result.get("detection_method", "suricata")
            mode_label = f"Real ({detection_method})"
        else:
            error_msg = result.get("error", "timeout") if result else "timeout"
            status_box.warning(f"Testbed failed: {error_msg}. Using calibrated detection.")
            time.sleep(3)
            status_box.empty()
            _, mock_reward, mock_terminated, mock_truncated, mock_info = env.step(action_idx)
            detected = bool(mock_info.get("detected", False))
            detector_conf = float(mock_info.get("detection_confidence", 0.0))
            ml_confidence = 0.0
            ml_lstm = 0.0
            ml_ae = 0.0
            detection_method = "calibrated"
            mode_label = "Simulation (fallback)"
    else:
        _, mock_reward, mock_terminated, mock_truncated, mock_info = env.step(action_idx)
        st.session_state["battle_reward"] += float(mock_reward)
        detected = bool(mock_info.get("detected", False))
        detector_conf = float(mock_info.get("detection_confidence", 0.0))
        ml_confidence = 0.0
        ml_lstm = 0.0
        ml_ae = 0.0
        detection_method = "calibrated"
        mode_label = "Simulation" if not has_testbed else "Simulation (queued)"

    # Compute reward (same logic as rl_env.py)
    reward = -0.1
    if not detected:
        reward += 1.5 * (1.0 - detector_conf)
    else:
        reward -= 2.5 * detector_conf

    tech_stage = tech["stage"]
    if tech_stage == env._current_stage:
        env._completed_stages.add(tech_stage)
        reward += 3.0
        if env._current_stage < 3:
            env._current_stage += 1
    elif tech_stage in env._completed_stages:
        reward -= 1.5
    else:
        reward -= 1.0

    campaign_complete = len(env._completed_stages) == 4
    if campaign_complete:
        reward += 8.0 if not detected else 4.0

    st.session_state["battle_reward"] += float(reward)
    env._history.append(1 if detected else 0)
    env._last_action = action_idx
    env._last_confidence = detector_conf
    env._step_count += 1
    env._chain.append(technique_id)

    # Build next observation manually (mirrors rl_env._get_obs)
    recent = env._history[-5:]
    recent_evasion_rate = (sum(1 - x for x in recent) / len(recent)) if recent else 1.0
    one_hot_action = np.zeros(NUM_TECHNIQUES, dtype=np.float32)
    one_hot_action[action_idx] = 1.0
    stages_vec = np.zeros(4, dtype=np.float32)
    for s in env._completed_stages:
        if 0 <= s < 4:
            stages_vec[s] = 1.0
    next_obs = np.concatenate([
        [float(env._current_stage) / 3.0],
        [float(recent_evasion_rate)],
        [float(detector_conf)],
        one_hot_action,
        stages_vec,
    ]).astype(np.float32)

    event = {
        "Timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "Step": len(st.session_state["battle_events"]) + 1,
        "MITRE ID": technique_id,
        "Technique Name": tech["name"],
        "Stage": tech["stage"],
        "Target Host": target_host,
        "Detector Confidence": f"{detector_conf:.3f}",
        "ML Confidence": f"{ml_confidence:.3f}",
        "LSTM Score": f"{ml_lstm:.3f}",
        "AE Score": f"{ml_ae:.3f}",
        "Detection Method": detection_method,
        "Status": "Detected" if detected else "Compromised",
        "Detected": detected,
        "Mode": mode_label,
    }
    st.session_state["battle_events"].append(event)
    st.session_state["battle_explanations"].append(explanation)
    st.session_state["battle_obs"] = next_obs

    terminated = campaign_complete
    truncated = env._step_count >= 12

    if terminated or truncated:
        st.session_state["battle_active"] = False
        _record_completed_campaign()


# =============================================================================
# UI Layout
# =============================================================================

# --- Mode Selector ---
st.subheader("Operational Mode")
mode_col1, mode_col2, mode_col3 = st.columns(3)
with mode_col1:
    use_real = st.checkbox("Use Real Testbed", value=False,
                           help="Execute real attack scripts on the Mininet testbed. "
                                "Requires ppo_step_watcher.py running on the attacker host.")
with mode_col2:
    watcher_status = "Connected" if PENDING_STEP.exists() or STEP_RESULT.exists() else "Checking..."
    st.metric("Watcher Status", watcher_status)
with mode_col3:
    if use_real:
        watcher_ready = not PENDING_STEP.exists()
        if watcher_ready:
            st.success("Ready for steps")
        else:
            st.warning("Watcher busy")

# --- Hybrid Defense Status ---
if use_real:
    st.divider()
    with st.expander("Hybrid Defense Configuration", expanded=True):
        hcol1, hcol2, hcol3 = st.columns(3)
        with hcol1:
            st.markdown("**Suricata IDS**")
            st.caption("Signature-based detection (SIDs 9000001-9000010)")
            st.success("Active")
        with hcol2:
            st.markdown("**LSTM + Autoencoder**")
            st.caption("ML anomaly detection (78 CIC-IDS features)")
            ml_key = "_ml_status_shown"
            if ml_key not in st.session_state:
                try:
                    sys.path.insert(0, PROJECT_ROOT)
                    from defense.ml_detector import MLDetector
                    ml = MLDetector()
                    ml.load()
                    st.session_state[ml_key] = True
                except Exception:
                    st.session_state[ml_key] = False
            if st.session_state.get(ml_key):
                st.success("Models Loaded")
            else:
                st.warning("Models unavailable")
        with hcol3:
            st.markdown("**Detection Fusion**")
            st.caption("50% LSTM + 50% AE -> Combined verdict")
            st.info("Threshold: 0.50")

# --- Campaign Controls ---
st.subheader("Campaign Controls")
ctrl1, ctrl2, ctrl3, ctrl4 = st.columns(4)
with ctrl1:
    if st.button("Start New Campaign", type="primary"):
        _new_campaign(use_real_testbed=use_real)
        st.rerun()
with ctrl2:
    next_disabled = not st.session_state.get("battle_active", False)
    if st.button("Run Next Tactic", disabled=next_disabled):
        if use_real:
            _step_campaign_real()
        else:
            _step_campaign_mock()
        st.rerun()
with ctrl3:
    run_all_disabled = not st.session_state.get("battle_active", False)
    if st.button("Run to Completion", disabled=run_all_disabled):
        max_steps = 12
        step_count = 0
        while st.session_state.get("battle_active", False) and step_count < max_steps:
            if use_real:
                _step_campaign_real()
            else:
                _step_campaign_mock()
            step_count += 1
        st.rerun()
with ctrl4:
    if st.button("Open Executive Report"):
        st.switch_page("pages/4_Report.py")

# --- Metrics Row ---
events = st.session_state.get("battle_events", [])
campaigns = st.session_state.get("battle_campaigns", [])
latest = pd.DataFrame(events) if events else pd.DataFrame()
current_evasion = 1.0 - (latest["Detected"].mean() if not latest.empty else 0.0)
plateaued = st.session_state.get("battle_results", {}).get("plateau_detected", False)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Current step", len(events))
m2.metric("Evasion", f"{current_evasion:.0%}" if events else "---")
m3.metric("Campaigns", len(campaigns))
m4.metric("Plateau", "Detected" if plateaued else "Monitoring")
mode_text = "Real Testbed" if use_real else "Simulation"
m5.metric("Mode", mode_text)

if plateaued:
    st.warning("Defense-evasion plateau detected across completed campaigns. "
               "The report will include this DVS signal.")

# --- Main Content: Event Log ---
st.subheader("Live Battle Event Log")
if latest.empty:
    st.info("Start a campaign, then run tactics one at a time or to completion.")
else:
    display_cols = ["Timestamp", "Step", "MITRE ID", "Technique Name",
                    "Stage", "Target Host", "Detector Confidence",
                    "ML Confidence", "Detection Method", "Status", "Mode"]
    available_cols = [c for c in display_cols if c in latest.columns]
    st.dataframe(latest[available_cols].astype(str), width="stretch", hide_index=True)

# --- Topology (only when events exist) ---
if events:
    st.subheader("Compromise & Defense Topology")
    compromised = set()
    detected_nodes = set()
    for event in events:
        target = event["Target Host"]
        if event["Detected"]:
            detected_nodes.add(target)
        else:
            compromised.add(target)

    topology_html = render_topology(
        st.session_state["topo_nodes"], st.session_state["topo_edges"],
        compromised_ids=compromised, detected_ids=detected_nodes,
    )
    components.html(topology_html, height=500, scrolling=True)

# --- PPO Tactical Rationale ---
if events:
    with st.expander("Latest PPO Tactical Rationale", expanded=True):
        explanation = st.session_state["battle_explanations"][-1]
        st.write(explanation["rationale"])
        alternatives = pd.DataFrame(explanation["top_alternatives"])
        if not alternatives.empty:
            st.dataframe(alternatives[["id", "name", "stage_name", "probability"]].astype(str),
                         hide_index=True, width="stretch")

# --- Campaign Summary ---
if campaigns:
    latest_campaign = campaigns[-1]
    st.caption(f"Latest campaign: {len(latest_campaign['events'])} steps, "
               f"evasion {latest_campaign['evasion_rate']:.0%}, "
               f"completion {'yes' if latest_campaign['campaign_complete'] else 'no'}.")


# =============================================================================
# Section: Live Testbed Activity Log (real-time from data/log_store.json)
# =============================================================================
if use_real:
    st.divider()
    st.subheader("Live Testbed Activity")
    st.caption("Real-time events from attack scripts, SCADA client, and Suricata IDS. "
               "Polls data/log_store.json every 3 seconds.")

    log_ctrl1, log_ctrl2, log_ctrl3 = st.columns([2, 1, 1])
    with log_ctrl1:
        auto_refresh_log = st.checkbox("Auto-refresh logs (every 3s)", value=True,
                                        key="auto_refresh_live_log")
    with log_ctrl2:
        log_filter = st.selectbox("Filter by stage",
                                   ["All", "recon", "attack", "Impair Process Control",
                                    "normal_traffic"],
                                   key="log_stage_filter")
    with log_ctrl3:
        max_events = st.slider("Max events to show", 10, 200, 50, key="max_log_events")

    # Read and display live log events
    if LOG_STORE.exists():
        try:
            raw_logs = json.loads(LOG_STORE.read_text(encoding="utf-8"))
            if isinstance(raw_logs, list) and raw_logs:
                # Filter by stage if needed
                if log_filter != "All":
                    filtered = [e for e in raw_logs if e.get("stage", "") == log_filter]
                else:
                    filtered = raw_logs

                # Show most recent first, limit to max_events
                recent_events = list(reversed(filtered[-max_events:]))

                # Build display table
                log_rows = []
                for e in recent_events:
                    ts = e.get("timestamp", "")
                    if "T" in ts:
                        ts = ts.split("T")[1][:8]

                    log_rows.append({
                        "Time": ts,
                        "Stage": e.get("stage", "-"),
                        "Technique": e.get("technique", "-"),
                        "Action": e.get("action", "-"),
                        "Target": e.get("target", e.get("spoofed_source", "-")),
                        "Detail": _format_log_detail(e),
                    })

                log_df = pd.DataFrame(log_rows)
                st.write(f"**{len(filtered)}** events total, showing **{len(log_rows)}** most recent:")
                st.dataframe(log_df, use_container_width=True, hide_index=True, height=400)

                st.metric("Total events in log store", len(raw_logs))
            else:
                st.info("Log store exists but contains no events yet. "
                        "Events will appear here as attacks execute on the testbed.")
        except Exception as err:
            st.warning(f"Could not parse log store: {err}")
    else:
        st.info("No testbed log found. Events will appear here once attacks run on the testbed.")

    # Suricata cycle report (if available)
    if CYCLE_REPORT.exists():
        try:
            report_data = json.loads(CYCLE_REPORT.read_text(encoding="utf-8"))
            with st.expander("Latest Suricata Cycle Report", expanded=False):
                steps = report_data.get("steps", [])
                if steps:
                    formatted = []
                    for i, step in enumerate(steps, 1):
                        start_time = step.get("start", "").split(".")[0].replace("T", " ")
                        formatted.append({
                            "Step": i,
                            "Attack": step.get("name", "Unknown"),
                            "MITRE": ", ".join(step.get("techniques", [])),
                            "Status": "Detected" if step.get("detected") else "Evaded",
                            "Alerts": step.get("alert_count", 0),
                            "Time": start_time,
                        })
                    st.dataframe(pd.DataFrame(formatted), hide_index=True, width="stretch")
        except Exception:
            pass

    # Modbus Packet Log (realistic ICS traffic)
    MODBUS_LOG = DATA_DIR / "modbus_log.json"
    if MODBUS_LOG.exists():
        try:
            modbus_data = json.loads(MODBUS_LOG.read_text(encoding="utf-8"))
            if isinstance(modbus_data, list) and modbus_data:
                with st.expander(f"Modbus TCP Packet Log ({len(modbus_data)} packets)", expanded=True):
                    recent_modbus = modbus_data[-50:]
                    modbus_rows = []
                    for pkt in reversed(recent_modbus):
                        ts = pkt.get("timestamp", "")
                        if "T" in ts:
                            ts = ts.split("T")[1][:12]
                        modbus_rows.append({
                            "Time": ts,
                            "Src": pkt.get("src_ip", "-"),
                            "Dst": pkt.get("dst_ip", "-"),
                            "Direction": pkt.get("direction", "-"),
                            "Function": pkt.get("function_name", "-"),
                            "Unit": pkt.get("mbap_unit_id", "-"),
                            "Addr": pkt.get("start_address", "-"),
                            "Values": str(pkt.get("values", []))[:30],
                            "Exception": pkt.get("exception_code", "-"),
                            "Length": pkt.get("packet_length", 0),
                        })
                    st.dataframe(pd.DataFrame(modbus_rows), use_container_width=True, hide_index=True, height=350)
        except Exception:
            pass

    # Network Flow Log (NetFlow/IPFIX style)
    FLOW_LOG = DATA_DIR / "flow_log.json"
    if FLOW_LOG.exists():
        try:
            flow_data = json.loads(FLOW_LOG.read_text(encoding="utf-8"))
            if isinstance(flow_data, list) and flow_data:
                with st.expander(f"Network Flow Log ({len(flow_data)} flows)", expanded=True):
                    recent_flows = flow_data[-30:]
                    flow_rows = []
                    for flow in reversed(recent_flows):
                        flow_rows.append({
                            "Start": flow.get("timestamp", "-").split("T")[1][:8] if "T" in flow.get("timestamp", "") else "-",
                            "Src": flow.get("src_ip", "-"),
                            "Dst": flow.get("dst_ip", "-"),
                            "Sport": flow.get("src_port", "-"),
                            "Dport": flow.get("dst_port", "-"),
                            "Duration": f"{flow.get('duration_sec', 0):.3f}s",
                            "Packets": flow.get("total_packets", 0),
                            "Bytes": flow.get("total_bytes", 0),
                            "B/s": f"{flow.get('bytes_per_sec', 0):.0f}",
                            "SYN": flow.get("syn_count", 0),
                            "ACK": flow.get("ack_count", 0),
                            "RST": flow.get("rst_count", 0),
                            "FIN": flow.get("fin_count", 0),
                        })
                    st.dataframe(pd.DataFrame(flow_rows), use_container_width=True, hide_index=True, height=350)
        except Exception:
            pass

    # Auto-refresh every 3 seconds
    if auto_refresh_log:
        time.sleep(3)
        st.rerun()


# =============================================================================
# Section: Legacy Mininet Testbed Monitor (simulation mode only)
# =============================================================================
else:
    st.divider()
    with st.expander("Mininet Testbed Monitor (raw events)", expanded=False):
        st.caption("Reads telemetry from data/log_store.json.")

        col_ctrl, col_auto = st.columns([2, 1])
        with col_ctrl:
            auto_refresh = st.checkbox("Auto-refresh (every 3s)", value=False)
        with col_auto:
            if st.button("Refresh Now"):
                st.rerun()

        if LOG_STORE.exists():
            try:
                raw_log = json.loads(LOG_STORE.read_text(encoding="utf-8"))
                if isinstance(raw_log, list) and raw_log:
                    st.write(f"Total Events: **{len(raw_log)}**")
                    st.dataframe(pd.DataFrame(raw_log).astype(str), width="stretch", height=300)
                else:
                    st.info("Log store exists but contains no events yet.")
            except Exception as err:
                st.warning(f"Could not parse log store: {err}")
        else:
            st.info("No testbed log found. Run `scripts/start_testbed.py` on WSL2.")
