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
from testbed.cytoscape_topology import generate_cytoscape_json, generate_cytoscape_html
from testbed.visjs_topology import generate_vis_json, generate_vis_html
from testbed.export_gephi import export_graphml, export_gexf
from testbed.export_pkt import export_pkt_xml
from testbed.topology import get_topology
from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES, NUM_TECHNIQUES, MAX_BUSES
from xai.attack_decision_explain import explain_step_decision
from metrics.dvs import PlateauTracker
from stable_baselines3 import PPO
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME

_REPO = Path(PROJECT_ROOT)
DATA_DIR = _REPO / "data"
LOG_STORE = DATA_DIR / "log_store.json"
CYCLE_REPORT = DATA_DIR / "cycle_report.json"
MODEL_PATH = _REPO / "models" / "rl_agent.zip"


def _read_log_store():
    """Read log_store.json supporting both JSON array and JSONL formats."""
    if not LOG_STORE.exists():
        return []
    try:
        text = LOG_STORE.read_text(encoding="utf-8")
        text = text.strip()
        if not text:
            return []
        if text.startswith("["):
            return json.loads(text)
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, OSError):
        return []

# File-based handoff paths
PENDING_STEP = DATA_DIR / "pending_step.json"
STEP_RESULT = DATA_DIR / "step_result.json"

# Technique IDs that have real testbed scripts (from testbed_executor.py)
REAL_TESTBED_TECHNIQUES = {
    "T0846", "T0888", "T0842", "T0830", "T0801", "T0814", "T0816",
    "T0836", "T0806", "T0835", "T0832", "T0815",
    "T0886", "T0802", "T0869", "T0878", "T0881", "T0855",
}

# Mininet host IP mapping (loaded from topology)
_topo = get_topology()
MININET_IPS = {f"plc{i+1}": _topo.get_ip(i) for i in range(_topo.num_buses)}
MININET_IPS["scada"] = "10.0.0.20"

# Bus-to-IP and IP-to-host mappings
_ip_to_host = {v: k for k, v in MININET_IPS.items()}

def _bus_to_ip(bus: int) -> str:
    """Convert a bus index to its IP address."""
    topo = get_topology()
    if topo and 0 <= bus < topo.num_buses:
        return topo.get_ip(bus)
    return f"10.0.0.{bus + 1}"

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


def _write_pending_step(technique_id: str, step_name: str, target_ip: str = "10.0.0.1",
                        register_address: int = 40000, value_magnitude: float = 1.0,
                        target_bus: int = 0):
    """Write a step command for the PPO watcher to execute."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PENDING_STEP.write_text(json.dumps({
        "technique_id": technique_id,
        "step_name": step_name,
        "target_ip": target_ip,
        "register_address": register_address,
        "value_magnitude": value_magnitude,
        "target_bus": target_bus,
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


def _step_campaign_real():
    """Execute one PPO step using real testbed attacks via file handoff."""
    if not st.session_state.get("battle_active"):
        return
    model = st.session_state["battle_model"]
    obs = st.session_state["battle_obs"]
    env = st.session_state["battle_env"]

    action, _ = model.predict(obs, deterministic=False)
    # Multi-parameter action: [technique, register, value, target]
    action = np.asarray(action, dtype=np.int64).flatten()
    technique_idx = int(action[0])
    register_offset = int(action[1])
    value_level = int(action[2])
    target_bus = int(action[3]) % env._num_buses

    explanation = explain_step_decision(model, obs, technique_idx)
    tech = MITRE_TECHNIQUES[technique_idx]
    technique_id = tech["id"]

    # Resolve target IP from agent-selected bus
    target_ip = _bus_to_ip(target_bus)
    target_host = _ip_to_host.get(target_ip, f"PLC-{target_bus}")

    # Calculate actual register address and value magnitude
    from strategic.rl_env import REGISTER_BASES, VALUE_MAGNITUDES
    register_address = REGISTER_BASES.get(technique_id, 40000) + register_offset
    value_magnitude = float(VALUE_MAGNITUDES[value_level])

    # Check if this technique has a real testbed script
    step_name = TECHNIQUE_TO_STEP_NAME.get(technique_id)
    has_testbed = step_name is not None

    status_box = st.empty()

    if has_testbed and not PENDING_STEP.exists() and not STEP_RESULT.exists():
        _write_pending_step(technique_id, step_name, target_ip,
                           register_address=register_address,
                           value_magnitude=value_magnitude,
                           target_bus=target_bus)

        status_box.info(f"Executing {technique_id} ({tech['name']}) on testbed...")
        result = _poll_step_result(timeout=300.0)
        status_box.empty()

        if result and result.get("success", False):
            detected = result.get("detected", False)
            ml_confidence = result.get("ml_confidence", 0.0)
            ml_lstm = result.get("ml_lstm_confidence", 0.0)
            ml_ae = result.get("ml_ae_score", 0.0)
            detection_method = result.get("detection_method", "suricata")
            alert_count = result.get("alert_count", 0)
            if ml_confidence > 0:
                detector_conf = ml_confidence
            elif detection_method == "suricata" and alert_count > 0:
                detector_conf = min(1.0, 0.3 + alert_count * 0.05)
            elif detected:
                detector_conf = 0.5
            else:
                detector_conf = 0.0
            mode_label = f"Real ({detection_method})"
        else:
            error_msg = result.get("error", "timeout") if result else "timeout"
            status_box.error(f"Testbed failed: {error_msg}")
            time.sleep(3)
            status_box.empty()
            # Step failed — record failure, do NOT fall back to mock
            detected = False
            detector_conf = 0.0
            ml_confidence = 0.0
            ml_lstm = 0.0
            ml_ae = 0.0
            detection_method = "failed"
            mode_label = "Failed"
    else:
        # Technique has no testbed script — skip, do NOT fall back to mock
        status_box.warning(f"No testbed script for {technique_id}, skipping")
        time.sleep(2)
        status_box.empty()
        detected = False
        detector_conf = 0.0
        ml_confidence = 0.0
        ml_lstm = 0.0
        ml_ae = 0.0
        detection_method = "skipped"
        mode_label = "Skipped"

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
    env._last_action = action
    env._last_confidence = detector_conf
    env._last_register = register_offset
    env._last_value_mag = value_magnitude
    env._step_count += 1
    env._chain.append(technique_id)

    # Build next observation manually (mirrors rl_env._get_obs)
    recent = env._history[-5:]
    recent_evasion_rate = (sum(1 - x for x in recent) / len(recent)) if recent else 1.0
    one_hot_action = np.zeros(NUM_TECHNIQUES, dtype=np.float32)
    one_hot_action[technique_idx] = 1.0
    stages_vec = np.zeros(4, dtype=np.float32)
    for s in env._completed_stages:
        if 0 <= s < 4:
            stages_vec[s] = 1.0
    # Last action parameters (normalized)
    last_register_norm = register_offset / 50.0  # NUM_REGISTERS
    last_value_norm = (value_magnitude - 0.9) / 0.2  # VALUE_MAGNITUDES range
    last_target_norm = target_bus / env._num_buses

    # Topology features (from env state)
    voltages = env._voltages / 1.1
    degrees = env._degrees / env._max_degree
    bus_type_map = {3: 1.0, 1: 0.5, 2: 0.0}
    bus_types = np.array([bus_type_map.get(int(t), 0.0) for t in env._bus_types_arr], dtype=np.float32)
    compromised = np.zeros(MAX_BUSES, dtype=np.float32)
    for b in env._compromised_buses:
        if 0 <= b < MAX_BUSES:
            compromised[b] = 1.0
    frac_compromised = len(env._compromised_buses) / env._num_buses

    next_obs = np.concatenate([
        [float(env._current_stage) / 3.0],
        [float(recent_evasion_rate)],
        [float(detector_conf)],
        one_hot_action,
        stages_vec,
        [last_register_norm],
        [last_value_norm],
        [last_target_norm],
        voltages,
        degrees,
        bus_types,
        compromised,
        [frac_compromised],
        [0.0],  # attack_depth (simplified)
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
        "Register": register_address,
        "Value Magnitude": value_magnitude,
        "Target Bus": target_bus,
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
mode_col1, mode_col2 = st.columns(2)
with mode_col1:
    use_real = True  # Always use real testbed
    st.success("Real Testbed Mode — all attacks execute on Mininet")
with mode_col2:
    watcher_status = "Connected" if PENDING_STEP.exists() or STEP_RESULT.exists() else "Checking..."
    st.metric("Watcher Status", watcher_status)
    watcher_ready = not PENDING_STEP.exists()
    if watcher_ready:
        st.success("Ready for steps")
    else:
        st.warning("Watcher busy")

# --- Hybrid Defense Status ---
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
        _new_campaign(use_real_testbed=True)
        st.rerun()
with ctrl2:
    next_disabled = not st.session_state.get("battle_active", False)
    if st.button("Run Next Tactic", disabled=next_disabled):
        _step_campaign_real()
        st.rerun()
with ctrl3:
    run_all_disabled = not st.session_state.get("battle_active", False)
    if st.button("Run to Completion", disabled=run_all_disabled):
        max_steps = 12
        step_count = 0
        while st.session_state.get("battle_active", False) and step_count < max_steps:
            _step_campaign_real()
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

m1, m2, m3, m4 = st.columns(4)
m1.metric("Current step", len(events))
m2.metric("Evasion", f"{current_evasion:.0%}" if events else "---")
m3.metric("Campaigns", len(campaigns))
m4.metric("Plateau", "Detected" if plateaued else "Monitoring")

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

    # Visualization mode selector
    viz_col1, viz_col2, viz_col3 = st.columns([2, 1, 1])
    with viz_col1:
        viz_mode = st.selectbox("Visualization Mode",
                                ["Pyvis (Interactive)", "Cytoscape.js", "vis.js (Standalone)"],
                                key="viz_mode")
    with viz_col2:
        show_tooltips = st.checkbox("Show Tooltips", value=True, key="show_tooltips")

    def _target_to_topo_node(target_host):
        """Map event Target Host to topology node ID."""
        if target_host.startswith("plc"):
            num = target_host[3:]
            if num.isdigit():
                return f"rtu_{int(num) - 1}"
        elif target_host == "scada":
            return "scada_server"
        elif target_host == "hmi":
            return "hmi"
        elif target_host == "historian":
            return "historian"
        return target_host

    compromised = set()
    detected_nodes = set()
    attack_paths = []
    for event in events:
        target = event["Target Host"]
        topo_id = _target_to_topo_node(target)
        if event["Detected"]:
            detected_nodes.add(topo_id)
        else:
            compromised.add(topo_id)

    # Build attack path from event chain (non-detected targets in order)
    if len(events) > 1:
        path = []
        for evt in events:
            if not evt.get("Detected", True):
                path.append(_target_to_topo_node(evt["Target Host"]))
        if len(path) >= 2:
            attack_paths = [path]

    if viz_mode == "Pyvis (Interactive)":
        topology_html = render_topology(
            st.session_state["topo_nodes"], st.session_state["topo_edges"],
            compromised_ids=compromised, detected_ids=detected_nodes,
            live_events=events, attack_paths=attack_paths,
            show_tooltips=show_tooltips,
        )
        components.html(topology_html, height=500, scrolling=True)
    elif viz_mode == "Cytoscape.js":
        cyto_html = generate_cytoscape_html(
            st.session_state["topo_nodes"], st.session_state["topo_edges"],
            compromised_ids=compromised, detected_ids=detected_nodes,
            attack_paths=attack_paths,
        )
        components.html(cyto_html, height=500, scrolling=True)
    else:
        vis_html = generate_vis_html(
            st.session_state["topo_nodes"], st.session_state["topo_edges"],
            compromised_ids=compromised, detected_ids=detected_nodes,
            attack_paths=attack_paths,
        )
        components.html(vis_html, height=500, scrolling=True)

    # Export buttons
    with st.expander("Export Topology", expanded=False):
        exp_col1, exp_col2, exp_col3 = st.columns(3)
        with exp_col1:
            if st.button("Export Gephi (.graphml)"):
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(suffix=".graphml", delete=False) as tmp:
                        export_graphml(st.session_state["topo_nodes"],
                                       st.session_state["topo_edges"], tmp.name)
                    st.success("GraphML exported!")
                    with open(tmp.name, "rb") as f:
                        st.download_button("Download .graphml", f.read(),
                                           "ascend_pg_topology.graphml", "application/xml")
                finally:
                    if os.path.exists(tmp.name):
                        os.unlink(tmp.name)
        with exp_col2:
            if st.button("Export Gephi (.gexf)"):
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(suffix=".gexf", delete=False) as tmp:
                        export_gexf(st.session_state["topo_nodes"],
                                    st.session_state["topo_edges"], tmp.name)
                    st.success("GEXF exported!")
                    with open(tmp.name, "rb") as f:
                        st.download_button("Download .gexf", f.read(),
                                           "ascend_pg_topology.gexf", "application/xml")
                finally:
                    if os.path.exists(tmp.name):
                        os.unlink(tmp.name)
        with exp_col3:
            if st.button("Export Packet Tracer (.xml)"):
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
                        export_pkt_xml(st.session_state["topo_nodes"],
                                       st.session_state["topo_edges"], tmp.name)
                    st.success("Packet Tracer XML exported!")
                    with open(tmp.name, "rb") as f:
                        st.download_button("Download .xml", f.read(),
                                           "ascend_pg_pkt_topology.xml", "application/xml")
                finally:
                    if os.path.exists(tmp.name):
                        os.unlink(tmp.name)

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
# Section: Live Packet Sniffer (always active)
# =============================================================================
st.divider()
st.subheader("Live Packet Sniffer")
st.caption("Real-time packet flow — all Modbus TCP traffic, SCADA polls, attack packets, and IDS alerts. "
           "Auto-refreshes every 3 seconds.")

sniffer_ctrl1, sniffer_ctrl2, sniffer_ctrl3 = st.columns([2, 1, 1])
with sniffer_ctrl1:
    auto_refresh_log = st.checkbox("Auto-refresh (every 3s)", value=True,
                                    key="auto_refresh_sniffer")
with sniffer_ctrl2:
    proto_filter = st.selectbox("Protocol filter",
                                 ["All", "Modbus TCP", "SCADA Poll", "Attack", "IDS Alert"],
                                 key="proto_filter")
with sniffer_ctrl3:
    max_packets = st.slider("Max packets", 50, 500, 100, key="max_packets")

# Collect all packets from all sources
all_packets = []

# 1. From modbus_log.json (Modbus TCP packets)
MODBUS_LOG = DATA_DIR / "modbus_log.json"
if MODBUS_LOG.exists():
    try:
        modbus_data = json.loads(MODBUS_LOG.read_text(encoding="utf-8"))
        if isinstance(modbus_data, list):
            for pkt in modbus_data:
                ts = pkt.get("timestamp", "")
                if "T" in ts:
                    ts = ts.split("T")[1][:12]
                direction = pkt.get("direction", "->")
                src = pkt.get("src_ip", "-")
                dst = pkt.get("dst_ip", "-")
                func = pkt.get("function_name", "-")
                addr = pkt.get("start_address", "-")
                values = pkt.get("values", [])
                exc = pkt.get("exception_code", "-")
                length = pkt.get("packet_length", 0)
                unit = pkt.get("mbap_unit_id", "-")

                # Build info string like Wireshark
                if exc and exc != "-":
                    info = f"Exception {exc}"
                elif "Read" in func:
                    info = f"{func} Unit={unit} Addr={addr} Count={len(values) if values else 0}"
                elif "Write" in func:
                    info = f"{func} Unit={unit} Addr={addr} Values={str(values)[:20]}"
                else:
                    info = f"{func} Unit={unit} Addr={addr}"

                # Classify: SCADA poll vs generic Modbus TCP
                SCADA_IP = MININET_IPS.get("scada", "10.0.0.20")
                if src == SCADA_IP or dst == SCADA_IP:
                    proto_type = "SCADA Poll"
                    pkt_type = "scada_poll"
                else:
                    proto_type = "Modbus TCP"
                    pkt_type = "modbus"

                all_packets.append({
                    "Time": ts,
                    "Source": src,
                    "Destination": dst,
                    "Protocol": proto_type,
                    "Length": length,
                    "Info": info,
                    "_type": pkt_type,
                })
    except Exception:
        pass

# 2. From log_store.json (attack events, SCADA polls, IDS alerts)
raw_logs = _read_log_store()
for e in raw_logs:
    ts = e.get("timestamp", "")
    if "T" in ts:
        ts = ts.split("T")[1][:12]

    action = e.get("action", "")
    target = e.get("target", e.get("spoofed_source", "-"))
    stage = e.get("stage", "-")
    technique = e.get("technique", "-")

    # Determine protocol type
    if "poll_" in action or "scada" in action.lower():
        proto = "SCADA Poll"
        src = "10.0.0.20"
        dst = target
        info = f"{action} | {technique}"
    elif e.get("detected") is not None or "hybrid_detection" in action or "suricata" in action.lower():
        proto = "IDS Alert"
        src = "Suricata"
        dst = "-"
        method = e.get("detection_method", "-")
        conf = e.get("ml_confidence", e.get("confidence", 0))
        detected = e.get("detected", False)
        info = f"{technique} | {'DETECTED' if detected else 'clean'} | {method} conf={conf:.2f}"
    elif stage == "normal_traffic":
        proto = "SCADA Poll"
        src = "10.0.0.20"
        dst = target
        info = f"{action}"
    elif technique.startswith("T0") or stage != "-":
        is_modbus_op = action.startswith("fc") or "modbus" in action.lower()
        proto = "Modbus TCP" if is_modbus_op else "Attack"
        src = e.get("source_ip", "10.0.0.66")
        dst = target
        info = f"{technique} | {action}"
    else:
        proto = "Other"
        src = "-"
        dst = target
        info = f"{action} | {technique}"

    all_packets.append({
        "Time": ts,
        "Source": src,
        "Destination": dst,
        "Protocol": proto,
        "Length": 0,
        "Info": info,
        "_type": proto.lower().replace(" ", "_"),
    })

# 3. From flow_log.json (NetFlow/IPFIX)
FLOW_LOG = DATA_DIR / "flow_log.json"
if FLOW_LOG.exists():
    try:
        flow_data = json.loads(FLOW_LOG.read_text(encoding="utf-8"))
        if isinstance(flow_data, list):
            for flow in flow_data:
                ts = flow.get("timestamp", "")
                if "T" in ts:
                    ts = ts.split("T")[1][:12]
                all_packets.append({
                    "Time": ts,
                    "Source": flow.get("src_ip", "-"),
                    "Destination": flow.get("dst_ip", "-"),
                    "Protocol": "TCP",
                    "Length": flow.get("total_bytes", 0),
                    "Info": f"Sport={flow.get('src_port','-')} Dport={flow.get('dst_port','-')} "
                            f"Duration={flow.get('duration_sec',0):.3f}s "
                            f"Packets={flow.get('total_packets',0)}",
                    "_type": "flow",
                })
    except Exception:
        pass

# 4. From cycle_report.json (detection results from run_cycle)
CYCLE_REPORT = DATA_DIR / "cycle_report.json"
if CYCLE_REPORT.exists():
    try:
        cycle_data = json.loads(CYCLE_REPORT.read_text(encoding="utf-8"))
        steps = cycle_data if isinstance(cycle_data, list) else cycle_data.get("steps", [])
        for step in steps:
            ts = step.get("end_time", step.get("start_time", ""))
            if "T" in ts:
                ts = ts.split("T")[1][:12]
            detected = step.get("detected", False)
            method = step.get("detection_method", "suricata")
            ml_conf = step.get("ml_confidence", 0)
            techniques = "+".join(step.get("techniques", []))
            step_name = step.get("name", "-")
            alert_count = step.get("alert_count", 0)

            if detected:
                proto = "IDS Alert"
                src = "Suricata" if method == "suricata" else "ML"
                info = f"{techniques} | {step_name} | DETECTED | {method} alerts={alert_count} conf={ml_conf:.2f}"
            else:
                proto = "Attack"
                src = "10.0.0.66"
                info = f"{techniques} | {step_name} | EVASION | no alerts"

            all_packets.append({
                "Time": ts,
                "Source": src,
                "Destination": step.get("target", "-"),
                "Protocol": proto,
                "Length": 0,
                "Info": info,
                "_type": proto.lower().replace(" ", "_"),
            })
    except Exception:
        pass

# Sort by time (most recent last for sniffer view)
all_packets.sort(key=lambda x: x.get("Time", ""))

# Apply protocol filter
if proto_filter != "All":
    filter_map = {
        "Modbus TCP": "modbus",
        "SCADA Poll": "scada_poll",
        "Attack": "attack",
        "IDS Alert": "ids_alert",
    }
    filter_type = filter_map.get(proto_filter, "")
    if filter_type:
        all_packets = [p for p in all_packets if p["_type"] == filter_type]

# Limit to max
display_packets = all_packets[-max_packets:]

if display_packets:
    display_df = pd.DataFrame(display_packets)[["Time", "Source", "Destination", "Protocol", "Length", "Info"]]
    st.dataframe(display_df, use_container_width=True, hide_index=True, height=500)

    # Packet stats
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Packets", len(all_packets))
    col2.metric("Modbus TCP", sum(1 for p in all_packets if p["_type"] == "modbus"))
    col3.metric("SCADA Poll", sum(1 for p in all_packets if p["_type"] == "scada_poll"))
    col4.metric("Attacks", sum(1 for p in all_packets if p["_type"] == "attack"))
    col5.metric("IDS Alerts", sum(1 for p in all_packets if p["_type"] == "ids_alert"))
else:
    st.info("No packets yet. Start a campaign to see live packet flow.")

# Auto-refresh every 3 seconds
if auto_refresh_log:
    time.sleep(3)
    st.rerun()


# =============================================================================
# Section: Pentest Report Generation
# =============================================================================
st.divider()
st.subheader("Security Assessment Report")
st.caption("Generate a professional penetration test report from the campaign results.")

col_rpt1, col_rpt2 = st.columns(2)
with col_rpt1:
    report_format = st.radio("Report Format", ["HTML", "PDF"], horizontal=True)
with col_rpt2:
    report_action = st.button("Generate Report", type="primary", use_container_width=True)

if report_action:
    from reports.pentest_report import generate_report, render_html, render_pdf

    # Build campaign events from log store
    events = _read_log_store()

    if not events:
        st.warning("No campaign events found. Run a battle first to generate a report.")
    else:
        campaign_info = {
            "battle_mode": "real" if use_real else "simulation",
            "total_steps": len(events),
        }
        report = generate_report(events, campaign_info)

        if report_format == "HTML":
            html = render_html(report)
            st.success(f"Report generated: {len(events)} events, {report['risk_summary']['total']} findings")
            st.download_button(
                "Download HTML Report",
                data=html,
                file_name=f"ASCEND-PG_Pentest_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True,
            )
            components.html(html, height=800, scrolling=True)
        else:
            pdf_path = str(DATA_DIR / f"ASCEND-PG_Pentest_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            render_pdf(report, pdf_path)
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            st.success(f"PDF report generated: {len(events)} events, {report['risk_summary']['total']} findings")
            st.download_button(
                "Download PDF Report",
                data=pdf_bytes,
                file_name=f"ASCEND-PG_Pentest_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
