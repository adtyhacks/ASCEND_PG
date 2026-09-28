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
from testbed.visualize_topology import render_topology
from testbed.cytoscape_topology import generate_cytoscape_json, generate_cytoscape_html
from testbed.visjs_topology import generate_vis_json, generate_vis_html
from testbed.export_gephi import export_graphml, export_gexf
from testbed.export_pkt import export_pkt_xml
from testbed.topology import get_topology
from testbed.run_store import EventStoreReadError, append_event, metrics as run_metrics, read_events, recover_displayable_active_run, report_events, update_run, visual_data
from testbed.core_runtime import core_request
from testbed.ip_config import SCADA_IP, ATTACKER_IP, MONITOR_IP as IDS_IP, get_plc_ip
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
WATCHER_HEARTBEAT = DATA_DIR / "watcher_heartbeat.json"


def _read_log_store(path=LOG_STORE):
    """Read log_store.json supporting both JSON array and JSONL formats."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
        text = text.strip()
        if not text:
            return []
        try:
            document = json.loads(text)
            if isinstance(document, list):
                return [entry for entry in document if isinstance(entry, dict)]
        except json.JSONDecodeError:
            pass
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line in ("[", "]", ",", "[,"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    entries.append(obj)
            except json.JSONDecodeError:
                pass
        return entries
    except OSError:
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
MININET_IPS["scada"] = SCADA_IP
MININET_IPS["attacker"] = ATTACKER_IP
MININET_IPS["ids"] = IDS_IP

# Bus-to-IP and IP-to-host mappings
_ip_to_host = {v: k for k, v in MININET_IPS.items()}

def _bus_to_ip(bus: int) -> str:
    """Convert a bus index to its IP address."""
    topo = get_topology()
    if topo and 0 <= bus < topo.num_buses:
        return topo.get_ip(bus)
    return get_plc_ip(bus)

def _get_watcher_status() -> tuple[str, str]:
    """Check active heartbeat from ppo_step_watcher.py."""
    if not WATCHER_HEARTBEAT.exists():
        return "OFFLINE", "Heartbeat file missing"
    try:
        hb = json.loads(WATCHER_HEARTBEAT.read_text(encoding="utf-8"))
        if hb.get("session_id"):
            managed = json.loads((DATA_DIR / "core-runtime/session.json").read_text())
            if str(managed.get("id")) != str(hb["session_id"]):
                return "OFFLINE", "Heartbeat belongs to another CORE session"
        age = time.time() - hb.get("timestamp", 0)
        if age > 15.0:
            return "OFFLINE", f"Stale heartbeat ({int(age)}s ago)"
        status = hb.get("status", "IDLE")
        pid = hb.get("pid", "-")
        return status, f"PID {pid} active"
    except Exception as e:
        return "OFFLINE", str(e)

st.set_page_config(page_title="Live Battle | ASCEND-PG", layout="wide")
st.title("Live Battle & Defense Evaluation")
st.caption("Evaluate the trained adaptive attacker against active ICS defenses.")


def _read_run_events_for_ui(active_run: dict, category: str | None = None) -> list[dict]:
    """Keep the live page available while making stored JSONL damage explicit."""
    try:
        return read_events(active_run["scenario_id"], active_run["run_id"], category)
    except EventStoreReadError as exc:
        st.error(f"Event-store integrity warning: {exc}")
        st.code(
            f"run={active_run['run_id']} line={exc.line_number} "
            f"kind={exc.kind} raw={exc.raw_line!r}",
            language=None,
        )
        st.warning("Earlier valid events remain visible. The malformed raw evidence was preserved for investigation.")
        return exc.valid_events

# Ensure baseline topology exists in session state
if "topo_nodes" not in st.session_state or "topo_edges" not in st.session_state:
    net_obj, grid_df, traffic_df = build_baseline()
    canonical_topology = get_topology().canonical_snapshot()
    topo_nodes, topo_edges, _, _, _ = visual_data(canonical_topology, [])
    st.session_state.update({
        "net_obj": net_obj, "grid_df": grid_df, "traffic_df": traffic_df,
        "topo_nodes": topo_nodes, "topo_edges": topo_edges, "canonical_topology": canonical_topology,
    })


def _recover_owned_run() -> None:
    """Restore only the run bound to the currently owned CORE generation."""
    existing = st.session_state.get("active_run")
    if existing:
        try:
            read_events(existing["scenario_id"], existing["run_id"])
        except EventStoreReadError as exc:
            # A session-scoped value can survive page reruns.  Do not let a
            # previously selected diagnostic run continue to authorize or
            # present itself as the current campaign.
            st.session_state.pop("active_run", None)
            st.session_state.pop("recovered_campaign_request", None)
            st.session_state["active_run_recovery_integrity_error"] = exc
            st.session_state["active_run_recovery_message"] = (
                "No active displayable campaign. A stale diagnostic run has malformed event evidence."
            )
        return
    if st.session_state.get("active_run_recovery_checked"):
        return
    st.session_state["active_run_recovery_checked"] = True
    try:
        runtime = json.loads((DATA_DIR / "core-runtime" / "session.json").read_text(encoding="utf-8"))
        recovered, integrity_error = recover_displayable_active_run(runtime)
        if integrity_error:
            st.session_state["active_run_recovery_integrity_error"] = integrity_error
            st.session_state["active_run_recovery_message"] = (
                "No active displayable campaign. A stale diagnostic run has malformed event evidence."
            )
            return
        status = core_request("status")
        if (recovered and status.get("state") == "RUNTIME"
                and str(status.get("session_id")) == str(recovered["core_session_id"])):
            st.session_state["active_run"] = recovered
            st.session_state["recovered_campaign_request"] = recovered.get("campaign_request")
            st.session_state["active_run_recovery_message"] = f"Recovered active run {recovered['run_id']}"
            return
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        pass
    st.session_state["active_run_recovery_message"] = "No active ASCEND-owned run. Start one from Run Simulation."


_recover_owned_run()

integrity_error = st.session_state.get("active_run_recovery_integrity_error")
if integrity_error:
    st.warning("A stale diagnostic run was not recovered as the active campaign.")
    st.code(
        f"run={integrity_error.path.parent.name} line={integrity_error.line_number} "
        f"kind={integrity_error.kind} raw={integrity_error.raw_line!r}",
        language=None,
    )


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
                        target_bus: int = 0, target_node: str = "plc1",
                        attack_stage: int = 0, correlation_id: str = ""):
    """Write a step command for the PPO watcher to execute."""
    active_run = st.session_state.get("active_run")
    try:
        runtime = json.loads((DATA_DIR / "core-runtime" / "session.json").read_text(encoding="utf-8"))
        generation_id = runtime["generation_id"]
    except (OSError, ValueError, KeyError) as exc:
        raise RuntimeError("A managed CORE generation is required before dispatching a campaign step") from exc
    if not active_run:
        raise RuntimeError("An active run is required before dispatching a campaign step")
    if not correlation_id:
        raise RuntimeError("A correlation ID is required before dispatching a campaign step")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    pending_temp = PENDING_STEP.with_suffix(f".{os.getpid()}.tmp")
    request = {
        "technique_id": technique_id,
        "step_name": step_name,
        "target_ip": target_ip,
        "register_address": register_address,
        "value_magnitude": value_magnitude,
        "generation_id": generation_id,
        "campaign_id": active_run["run_id"],
        "run_id": active_run["run_id"],
        "scenario_id": active_run["scenario_id"],
        "correlation_id": correlation_id,
        "target_node": target_node,
        "attack_stage": attack_stage,
        "target_bus": target_bus,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    pending_temp.write_text(json.dumps(request), encoding="utf-8")
    pending_temp.replace(PENDING_STEP)
    return request


def _consume_step_result() -> dict | None:
    """Read at most one watcher result; never wait inside a Streamlit run."""
    active_run = st.session_state.get("active_run")
    try:
        runtime = json.loads((DATA_DIR / "core-runtime" / "session.json").read_text(encoding="utf-8"))
        expected_generation = runtime["generation_id"]
        expected_campaign = active_run["run_id"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("A managed CORE generation and active run are required to consume a campaign result") from exc
    if STEP_RESULT.exists():
        try:
            data = json.loads(STEP_RESULT.read_text(encoding="utf-8"))
            STEP_RESULT.unlink(missing_ok=True)
            if (data.get("generation_id") == expected_generation
                    and data.get("campaign_id") == expected_campaign):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _request_timed_out(request: dict, timeout_seconds: float = 180.0) -> bool:
    """Evaluate the existing bounded timeout from the persisted request time."""
    try:
        created = datetime.fromisoformat(request["timestamp"])
        return (datetime.now(timezone.utc) - created).total_seconds() >= timeout_seconds
    except (KeyError, TypeError, ValueError):
        return True


def _finalize_recovered_campaign() -> None:
    """Persist a real watcher result after a Streamlit-session recovery."""
    request = st.session_state.get("recovered_campaign_request")
    active_run = st.session_state.get("active_run")
    if not request or not active_run or request.get("state") != "REQUESTED":
        return
    result = _consume_step_result()
    if result is None:
        st.session_state["campaign_handoff_status"] = "CAMPAIGN TIMEOUT" if _request_timed_out(request) else "REQUESTED"
        return
    correlation_id = request["correlation_id"]
    events = _read_run_events_for_ui(active_run, "security")
    if not any(e.get("event_type") == "attack_finished" and e.get("correlation_id") == correlation_id for e in events):
        detected = bool(result.get("detected", False))
        evidence = {"step_name": request["step_name"], "return_status": result.get("status", "FAILED"),
                    "detection_method": result.get("detection_method", "none"),
                    "ml_confidence": float(result.get("ml_confidence", 0.0))}
        common = {"mitre_technique": request["technique_id"], "attack_stage": request.get("attack_stage", 0),
                  "campaign_id": request["campaign_id"], "generation_id": request["generation_id"],
                  "correlation_id": correlation_id, "evidence": evidence}
        append_event(active_run["scenario_id"], active_run["run_id"], category="security", event_type="attack_finished",
                     source_node="attacker", target_node=request["target_node"], severity="INFO",
                     result="compromised" if result.get("evaded") else "detected" if detected else "failed",
                     timestamp=result.get("end_time"), **common)
        if detected:
            append_event(active_run["scenario_id"], active_run["run_id"], category="security", event_type="detection",
                         source_node="ids_monitor", target_node=request["target_node"], severity="HIGH",
                         result="detected", timestamp=result.get("end_time"), **common)
    update_run(active_run["scenario_id"], active_run["run_id"],
               campaign_request={**request, "state": "COMPLETED", "completed_at": datetime.now(timezone.utc).isoformat()})
    st.session_state.pop("recovered_campaign_request", None)
    st.session_state["campaign_handoff_status"] = "COMPLETED"


_finalize_recovered_campaign()


def _resolve_target_host(event_index: int) -> str:
    """Map an event index to a Mininet host for topology highlighting."""
    targets = [n["id"] for n in st.session_state["topo_nodes"]
               if n.get("type", "") in ("generation_substation", "distribution_substation",
                                          "rtu", "pmu", "plc", "generator")]
    return targets[event_index % len(targets)] if targets else "plc1"


def _new_campaign(use_real_testbed: bool = True):
    """Initialize a new PPO attack campaign."""
    if not st.session_state.get("active_run"):
        try:
            runtime = json.loads((DATA_DIR / "core-runtime" / "session.json").read_text(encoding="utf-8"))
            recovered, integrity_error = recover_displayable_active_run(runtime)
            status = core_request("status")
            if integrity_error:
                st.session_state["active_run_recovery_integrity_error"] = integrity_error
                st.error(
                    "No valid active owned run exists: the matching diagnostic run has malformed event evidence. "
                    "Launch or recover CORE from Run Simulation before starting a campaign."
                )
                st.session_state["campaign_handoff_status"] = "NO VALID ACTIVE RUN"
                return False
            if not (recovered and status.get("state") == "RUNTIME"
                    and str(status.get("session_id")) == str(recovered["core_session_id"])):
                st.error(
                    "No valid active owned run exists. Launch or recover CORE from Run Simulation before starting a campaign."
                )
                st.session_state["campaign_handoff_status"] = "NO VALID ACTIVE RUN"
                return False
            st.session_state["active_run"] = recovered
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
            st.error(
                "No valid active owned run exists. Launch or recover CORE from Run Simulation before starting a campaign. "
                f"Details: {exc}"
            )
            st.session_state["campaign_handoff_status"] = "NO VALID ACTIVE RUN"
            return False
    topo = get_topology()
    case_num = 30 if topo and "30" in str(topo.case_name) else st.session_state.get("grid_case", 14)
    env = AttackStrategyEnv(case=case_num, real_mode=False)  # We handle testbed detection
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
    return True


def _record_completed_campaign():
    """Record campaign results for the DVS report."""
    events = st.session_state.get("battle_events", [])
    if not events:
        return
    executed = [e for e in events if e.get("Status") in ("Detected", "Compromised")]
    evasion_rate = (sum(1 for e in executed if not e.get("Detected", True)) / len(executed)) if executed else 0.0
    campaign_complete = any(e["Stage"] == 3 and not e["Detected"] for e in executed)

    stages_hit = [e["Stage"] for e in executed if not e["Detected"]]
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
    """Advance one campaign step without blocking the Streamlit execution."""
    if not st.session_state.get("battle_active"):
        return
    model = st.session_state["battle_model"]
    obs = st.session_state["battle_obs"]
    env = st.session_state["battle_env"]
    pending = st.session_state.get("pending_campaign_step")
    completed_request = None
    if pending:
        result = _consume_step_result()
        if result is None:
            if _request_timed_out(pending["request"]):
                st.session_state["campaign_handoff_status"] = "CAMPAIGN TIMEOUT"
            else:
                st.session_state["campaign_handoff_status"] = "REQUESTED"
            return
        action = np.asarray(pending["action"], dtype=np.int64)
        technique_idx = pending["technique_idx"]
        register_offset = pending["register_offset"]
        target_bus = pending["target_bus"]
        explanation = pending["explanation"]
        tech = MITRE_TECHNIQUES[technique_idx]
        technique_id = tech["id"]
        target_host = pending["target_host"]
        register_address = pending["register_address"]
        value_magnitude = pending["value_magnitude"]
        correlation_id = pending["request"]["correlation_id"]
        completed_request = pending["request"]
        st.session_state.pop("pending_campaign_step", None)
        st.session_state["campaign_handoff_status"] = "COMPLETED"
        status_str = result.get("status", "SUCCESS" if result.get("success") else "FAILED")
        detected = bool(result.get("detected", False))
        evaded = bool(result.get("evaded", False))
        success = bool(result.get("success", False))
        ml_confidence = float(result.get("ml_confidence", 0.0))
        ml_lstm = float(result.get("ml_lstm_confidence", 0.0))
        ml_ae = float(result.get("ml_ae_score", 0.0))
        detection_method = result.get("detection_method", "suricata")
        alert_count = int(result.get("alert_count", 0))
        detector_conf = (ml_confidence if ml_confidence > 0 else min(1.0, 0.3 + alert_count * 0.05)
                         if detection_method == "suricata" and alert_count > 0 else 0.5 if detected else 0.0)
        mode_label = f"Real ({detection_method})" if success else f"Failed ({status_str})"
    else:
        action, _ = model.predict(obs, deterministic=False)
        action = np.asarray(action, dtype=np.int64).flatten()
        technique_idx = int(action[0])
        register_offset = int(action[1])
        value_level = int(action[2])
        target_bus = int(action[3]) % env._num_buses
        explanation = explain_step_decision(model, obs, technique_idx)
        tech = MITRE_TECHNIQUES[technique_idx]
        technique_id = tech["id"]
        target_ip = _bus_to_ip(target_bus)
        target_host = _ip_to_host.get(target_ip, f"PLC-{target_bus}")
        from strategic.rl_env import REGISTER_BASES, VALUE_MAGNITUDES
        register_address = REGISTER_BASES.get(technique_id, 40000) + register_offset
        value_magnitude = float(VALUE_MAGNITUDES[value_level])
        step_name = TECHNIQUE_TO_STEP_NAME.get(technique_id)
        correlation_id = f"step-{len(st.session_state['battle_events']) + 1}"
        if step_name:
            request = _write_pending_step(technique_id, step_name, target_ip,
                                          register_address=register_address, value_magnitude=value_magnitude,
                                          target_bus=target_bus, target_node=target_host,
                                          attack_stage=tech["stage"], correlation_id=correlation_id)
            request["state"] = "REQUESTED"
            update_run(st.session_state["active_run"]["scenario_id"], st.session_state["active_run"]["run_id"],
                       campaign_request=request)
            st.session_state["pending_campaign_step"] = {
                "request": request, "action": action.tolist(), "technique_idx": technique_idx,
                "register_offset": register_offset, "target_bus": target_bus,
                "target_host": target_host, "register_address": register_address,
                "value_magnitude": value_magnitude, "explanation": explanation,
            }
            st.session_state["campaign_handoff_status"] = "REQUESTED"
            return
        result = None
        status_str, detected, evaded, success = "UNSUPPORTED", False, False, False
        detector_conf = ml_confidence = ml_lstm = ml_ae = 0.0
        detection_method, mode_label = "skipped", "Skipped"

    # Status classification for scientific rigor
    if detected:
        status_label = "Detected"
    elif evaded:
        status_label = "Compromised"
    elif status_str == "TIMEOUT":
        status_label = "Timeout"
    else:
        status_label = "Failed"

    # Update env state
    env._history.append(1 if detected else 0)
    env._last_action = action
    env._last_confidence = detector_conf
    env._last_register = register_offset
    env._last_value_mag = value_magnitude
    env._current_target_bus = target_bus
    if evaded:
        env._compromised_buses.add(target_bus)
    env._step_count += 1
    env._chain.append(technique_id)

    # Calculate step reward using centralized defensible method
    reward = env.calculate_step_reward(
        status=status_str,
        detected=detected,
        detection_conf=detector_conf,
        tech_stage=tech["stage"],
        target_bus=target_bus
    )
    st.session_state["battle_reward"] += float(reward)

    # Next observation directly from env
    next_obs = env._get_obs()

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
        "Status": status_label,
        "Detected": detected,
        "Mode": mode_label,
        "Register": register_address,
        "Value Magnitude": value_magnitude,
        "Target Bus": target_bus,
    }
    st.session_state["battle_events"].append(event)
    active_run = st.session_state.get("active_run")
    if active_run:
        common = {"mitre_technique": technique_id, "attack_stage": tech["stage"],
                  "campaign_id": active_run["run_id"],
                  "generation_id": result.get("generation_id") if result else None,
                  "correlation_id": result.get("correlation_id", correlation_id) if result else correlation_id, "evidence": {"step_name": TECHNIQUE_TO_STEP_NAME.get(technique_id, technique_id), "return_status": status_str,
                  "detection_method": detection_method, "ml_confidence": ml_confidence,
                  "detector_confidence": detector_conf}}
        append_event(active_run["scenario_id"], active_run["run_id"], category="security",
                     event_type="attack_finished", source_node="attacker", target_node=target_host,
                     severity="CRITICAL" if evaded else "INFO", result="compromised" if evaded else status_label.lower(), timestamp=result.get("end_time") if result else None, **common)
        if detected:
            append_event(active_run["scenario_id"], active_run["run_id"], category="security",
                         event_type="detection", source_node="ids_monitor", target_node=target_host,
                         severity="HIGH", result="detected", timestamp=result.get("end_time") if result else None, **common)
        st.session_state["last_campaign_identity"] = {
            "mitre_technique": technique_id, "attack_stage": tech["stage"],
            "correlation_id": common["correlation_id"], "campaign_id": active_run["run_id"],
            "generation_id": result.get("generation_id") if result else None,
        }
        if completed_request:
            update_run(active_run["scenario_id"], active_run["run_id"],
                       campaign_request={**completed_request, "state": "COMPLETED", "completed_at": datetime.now(timezone.utc).isoformat()})
    st.session_state["battle_explanations"].append(explanation)
    st.session_state["battle_obs"] = next_obs

    terminated = len(env._completed_stages) == 4
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
    st.success("Real Testbed Mode - Hardcoded (CORE/Physical Testbed)")
with mode_col2:
    w_status, w_detail = _get_watcher_status()
    st.metric("Watcher Status", w_status)
    if w_status == "IDLE":
        st.success(f"Ready ({w_detail})")
    elif w_status == "BUSY":
        st.warning(f"Executing step ({w_detail})")
    elif w_status == "ERROR":
        st.error(f"Error ({w_detail})")
    else:
        st.error(f"Offline ({w_detail}) — start ppo_step_watcher.py in WSL")

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
    if st.button("Start New PPO Campaign", type="primary"):
        st.session_state["auto_run_ppo"] = False
        st.session_state["ppo_batch_count"] = 0
        _new_campaign(use_real_testbed=True)
        st.rerun()

with ctrl2:
    next_disabled = not st.session_state.get("battle_active", False)
    if st.button("Run Full PPO Campaign", disabled=next_disabled, help="Automatically runs the rest of the current campaign"):
        st.session_state["auto_run_ppo"] = True
        st.rerun()

with ctrl3:
    if st.button("Run 5x PPO Campaigns", help="Automatically runs 5 back-to-back campaigns for data collection"):
        _new_campaign(use_real_testbed=True)
        st.session_state["ppo_batch_count"] = 5
        st.session_state["auto_run_ppo"] = True
        st.rerun()

with ctrl4:
    if st.button("Clear Event Logs"):
        st.session_state["auto_run_ppo"] = False
        st.session_state["ppo_batch_count"] = 0
        if PENDING_STEP.exists(): PENDING_STEP.unlink()
        if STEP_RESULT.exists(): STEP_RESULT.unlink()
        if LOG_STORE.exists(): LOG_STORE.unlink()
        if CYCLE_REPORT.exists(): CYCLE_REPORT.unlink()
        st.session_state["battle_active"] = False
        st.rerun()

st.subheader("Active Defense")
active_run = st.session_state.get("active_run")
defense_target = st.selectbox("CORE asset", [f"plc{i + 1}" for i in range(get_topology().num_buses)], key="defense_target")
d1, d2 = st.columns(2)
for label, action, column in (("Isolate selected PLC", "isolate", d1), ("Restore selected PLC", "restore", d2)):
    with column:
        if st.button(label, use_container_width=True):
            if not active_run:
                st.error("No active ASCEND-owned run. Start one from Run Simulation before applying a defense.")
                continue
            try:
                result = core_request("defend", target_node=defense_target, defense_action=action)
                append_event(active_run["scenario_id"], active_run["run_id"], category="security",
                             event_type="defense_action", source_node="ids_monitor", target_node=defense_target,
                             severity="ACTION", defense_action=action, result="applied",
                             evidence={"core_session_id": result["session_id"], "core_output": result.get("output", "")},
                             **st.session_state.get("last_campaign_identity", {}))
                if action == "isolate":
                    append_event(active_run["scenario_id"], active_run["run_id"], category="security",
                                 event_type="containment", source_node="ids_monitor", target_node=defense_target,
                                 severity="SUCCESS", defense_action=action, result="contained",
                                 evidence={"core_session_id": result["session_id"]})
                st.success(f"CORE applied {action} to {defense_target}")
            except Exception as exc:
                st.error(str(exc))

st.divider()

# --- Metrics Row ---
events = st.session_state.get("battle_events", [])
campaigns = st.session_state.get("battle_campaigns", [])
latest = pd.DataFrame(events) if events else pd.DataFrame()
executed = [e for e in events if e.get("Status") in ("Detected", "Compromised")]
current_evasion = (sum(1 for e in executed if not e.get("Detected", True)) / len(executed)) if executed else 0.0
plateaued = st.session_state.get("battle_results", {}).get("plateau_detected", False)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Current step", len(events))
m2.metric("Evasion", f"{current_evasion:.0%}" if executed else "---")
m3.metric("Campaigns", len(campaigns))
m4.metric("Plateau", "Detected" if plateaued else "Monitoring")

active_run = st.session_state.get("active_run")
if active_run:
    measured = run_metrics(active_run["scenario_id"], active_run["run_id"])
    st.caption("Measured run metrics")
    mc1, mc2, mc3, mc4 = st.columns(4)
    mc1.metric("Time to detection", f"{measured['time_to_detection_seconds']} s" if measured["time_to_detection_seconds"] is not None else "Not observed")
    mc2.metric("Time to response", f"{measured['time_to_response_seconds']} s" if measured["time_to_response_seconds"] is not None else "Not observed")
    mc3.metric("Time to containment", f"{measured['time_to_containment_seconds']} s" if measured["time_to_containment_seconds"] is not None else "Not observed")
    mc4.metric("Compromised assets", measured["compromised_assets"])

    structured = _read_run_events_for_ui(active_run)
    network_events = [e for e in structured if e["category"] == "network"]
    security_events = [e for e in structured if e["category"] == "security"]
    st.subheader("Network events (observed telemetry)")
    if network_events: st.dataframe(pd.DataFrame(network_events), use_container_width=True, hide_index=True)
    else: st.info("No packet telemetry has been recorded for this run yet. ASCEND does not fabricate network events.")
    st.subheader("Security events (backend evidence)")
    if security_events: st.dataframe(pd.DataFrame(security_events), use_container_width=True, hide_index=True)

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
                return f"plc{int(num)}"
        elif target_host == "scada":
            return "scada"
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

    if active_run:
        run_events = _read_run_events_for_ui(active_run, "security")
        nodes, graph_edges, compromised, detected_nodes, attack_paths = visual_data(st.session_state["canonical_topology"], run_events)
    if viz_mode == "Pyvis (Interactive)":
        topology_html = render_topology(
            nodes if active_run else st.session_state["topo_nodes"], graph_edges if active_run else st.session_state["topo_edges"],
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
raw_logs = _read_log_store() + _read_log_store(DATA_DIR / "core-runtime/scada.jsonl")
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
        src = SCADA_IP
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
        src = SCADA_IP
        dst = target
        info = f"{action}"
    elif technique.startswith("T0") or stage != "-":
        is_modbus_op = action.startswith("fc") or "modbus" in action.lower()
        proto = "Modbus TCP" if is_modbus_op else "Attack"
        src = e.get("source_ip", ATTACKER_IP)
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
                src = flow.get("src_ip", "-")
                dst = flow.get("dst_ip", "-")
                if src == SCADA_IP or dst == SCADA_IP:
                    proto = "SCADA Poll"
                    pkt_type = "scada_poll"
                elif src == ATTACKER_IP or dst == ATTACKER_IP:
                    proto = "Attack"
                    pkt_type = "attack"
                else:
                    proto = "TCP"
                    pkt_type = "flow"
                all_packets.append({
                    "Time": ts,
                    "Source": src,
                    "Destination": dst,
                    "Protocol": proto,
                    "Length": flow.get("total_bytes", 0),
                    "Info": f"Sport={flow.get('src_port','-')} Dport={flow.get('dst_port','-')} "
                            f"Duration={flow.get('duration_sec',0):.3f}s "
                            f"Packets={flow.get('total_packets',0)}",
                    "_type": pkt_type,
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
                src = ATTACKER_IP
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

# Persist only backend-observed packet/flow telemetry; deduplicate across Streamlit reruns.
if active_run:
    seen = st.session_state.setdefault("run_packet_fingerprints", set())
    for packet in all_packets:
        fingerprint = "|".join(str(packet.get(key, "")) for key in ("Time", "Source", "Destination", "Protocol", "Info"))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        append_event(active_run["scenario_id"], active_run["run_id"], category="network",
                     event_type=packet.get("_type", "flow"), source_node=packet.get("Source"),
                     target_node=packet.get("Destination"), severity="INFO",
                     evidence={"observed_timestamp": packet.get("Time"), "protocol": packet.get("Protocol"),
                               "length": packet.get("Length"), "summary": packet.get("Info")})

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

# Schedule refresh after the page finishes rendering, so report controls below
# remain reachable and a default page load does not enter an endless rerun loop.
log_rendered_at = time.monotonic()

@st.fragment(run_every=3 if auto_refresh_log else None)
def _refresh_live_log():
    if time.monotonic() - log_rendered_at >= 2.5:
        st.rerun()

_refresh_live_log()

# Automated PPO Loop Logic
if st.session_state.get("auto_run_ppo", False):
    if st.session_state.get("battle_active", False):
        _step_campaign_real()
        # A pending watcher request is advanced by the short periodic fragment;
        # do not spin or wait inside this execution.
        if not st.session_state.get("pending_campaign_step"):
            st.rerun()
    else:
        # Campaign ended. Check if we have batches left.
        batches_left = st.session_state.get("ppo_batch_count", 0)
        if batches_left > 1:
            st.session_state["ppo_batch_count"] = batches_left - 1
            _new_campaign(use_real_testbed=True)
            st.rerun()
        else:
            # All done!
            st.session_state["auto_run_ppo"] = False
            st.session_state["ppo_batch_count"] = 0
            st.toast("Automated PPO runs completed!", icon="✅")
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

    # Reports are built from the run event store, not presentation/session text.
    active_run = st.session_state.get("active_run")
    structured_events = _read_run_events_for_ui(active_run, "security") if active_run else []
    # The renderer accepts completed-attack records. Normalize this run's
    # canonical lifecycle events so one attack_finished record is correlated
    # with its matching detection instead of reporting raw events as findings.
    events = report_events(structured_events)

    if not events:
        st.warning("No campaign events found. Run a battle first to generate a report.")
    else:
        campaign_info = {
            "battle_mode": "real" if use_real else "simulation",
            "total_steps": len(events),
            "scenario_id": active_run["scenario_id"], "run_id": active_run["run_id"],
            "metrics": run_metrics(active_run["scenario_id"], active_run["run_id"]),
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
