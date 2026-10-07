"""Thin GUI client for ASCEND's existing generation-aware campaign handoff."""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from testbed import run_store
from testbed.core_runtime import core_request
from testbed.generate_core_topo import generate_core_xml
from testbed.topology import get_topology


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PENDING_STEP = DATA / "pending_step.json"
STEP_RESULT = DATA / "step_result.json"
HEARTBEAT = DATA / "watcher_heartbeat.json"
MODEL_PATH = ROOT / "models" / "rl_agent.zip"
REQUEST_TIMEOUT_SECONDS = 180.0


class CampaignError(RuntimeError):
    def __init__(self, code: str, message: str, status: int = 409):
        super().__init__(message)
        self.code, self.status = code, status


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CampaignController:
    """Keeps PPO objects in process; canonical run metadata remains the truth."""

    def __init__(self, *, request=core_request, topology=get_topology, model_path: Path = MODEL_PATH):
        self.request, self.topology, self.model_path = request, topology, model_path
        self._sessions: dict[str, dict[str, Any]] = {}
        self._full_runs: set[str] = set()
        self._initialization_timings: dict[str, dict[str, Any]] = {}
        # The checkpoint is inference-only.  Campaign state deliberately lives
        # elsewhere and is recreated for each owned run.
        self._cached_model: Any | None = None
        self._cached_model_identity: tuple[str, int, int] | None = None
        self._model_lock = threading.RLock()
        self._state_lock = threading.RLock()

    def _runtime(self) -> dict[str, Any]:
        runtime = _read_json(DATA / "core-runtime" / "session.json")
        if not runtime or runtime.get("id") is None or not runtime.get("generation_id", runtime.get("token")):
            raise CampaignError("core_unavailable", "No valid ASCEND-owned CORE generation is available.", 503)
        return runtime

    def start_core(self) -> dict[str, Any]:
        """Follow the existing Run Simulation launch sequence for one owned run."""
        from testbed.topology import TOPOLOGY_LOCK
        with self._state_lock, TOPOLOGY_LOCK:
            status = self.request("status")
            if status.get("state") == "RUNTIME":
                raise CampaignError("core_already_running", "An ASCEND-owned CORE session is already active.")
            topology = self.topology(); snapshot = topology.canonical_snapshot()
            xml = generate_core_xml(output_path=str(ROOT / "core_topology.xml"), topology=topology)
            run = run_store.create_run(snapshot)
            result = self.request("start", xml=str(xml))
            runtime = self._runtime()
            if str(runtime["id"]) != str(result["session_id"]):
                raise CampaignError("core_identity_invalid", "CORE did not persist the created owned session identity.", 503)
            updated = run_store.update_run(run["scenario_id"], run["run_id"], core_session_id=result["session_id"], generation_id=runtime.get("generation_id", runtime.get("token")), lifecycle_status="RUNNING")
            return {**result, "scenario_id": updated["scenario_id"], "run_id": updated["run_id"], "generation_id": updated["generation_id"]}

    def stop_core(self) -> dict[str, Any]:
        """Delegate ownership-scoped cleanup to the existing CORE helper."""
        with self._state_lock:
            result = self.request("stop")
            # Retain only the inference model across CORE generations.
            self._sessions.clear()
            self._full_runs.clear()
            self._initialization_timings.clear()
            return result

    def _active_run(self, runtime: dict[str, Any], *, displayable: bool = True) -> dict[str, Any]:
        if displayable:
            run, integrity_error = run_store.recover_displayable_active_run(runtime)
            if integrity_error:
                raise CampaignError("event_store_invalid", str(integrity_error), 409)
        else:
            run = run_store.recover_active_run(runtime)
        if not run:
            raise CampaignError("no_active_run", "No valid owned active run exists for this CORE generation.", 409)
        return run

    def _core_and_watcher(self, runtime: dict[str, Any], *, require_idle: bool) -> dict[str, Any]:
        status = self.request("status")
        if status.get("state") != "RUNTIME" or str(status.get("session_id")) != str(runtime["id"]):
            raise CampaignError("core_unavailable", "The owned CORE session is not in RUNTIME state.", 503)
        heartbeat = _read_json(HEARTBEAT)
        generation = runtime.get("generation_id", runtime.get("token"))
        if not heartbeat or str(heartbeat.get("session_id")) != str(runtime["id"]) or heartbeat.get("generation_id") != generation:
            raise CampaignError("watcher_unavailable", "No watcher heartbeat belongs to the owned CORE generation.", 503)
        if time.time() - float(heartbeat.get("timestamp", 0)) >= 15:
            raise CampaignError("watcher_unavailable", "Watcher heartbeat is stale.", 503)
        if require_idle and heartbeat.get("status") != "IDLE":
            raise CampaignError("watcher_unavailable", f"Watcher is {heartbeat.get('status', 'UNKNOWN')}, not IDLE.", 503)
        return {"core": status, "watcher": heartbeat}

    def _model_identity(self) -> tuple[str, int, int]:
        """Return an identity that invalidates a replaced checkpoint."""
        try:
            checkpoint = self.model_path.resolve(strict=True)
            stat = checkpoint.stat()
        except OSError as exc:
            raise CampaignError("ppo_unavailable", f"Trained PPO model is missing: {self.model_path}", 503) from exc
        return str(checkpoint), stat.st_mtime_ns, stat.st_size

    def _load_model(self, checkpoint: Path) -> tuple[Any, float, float]:
        """Load an inference-only PPO checkpoint and return diagnostic timings."""
        stage = time.monotonic()
        from stable_baselines3 import PPO
        import_seconds = time.monotonic() - stage
        stage = time.monotonic()
        model = PPO.load(str(checkpoint))
        return model, import_seconds, time.monotonic() - stage

    def _cached_ppo_model(self, timings: dict[str, Any]) -> Any:
        with self._model_lock:
            identity = self._model_identity()
            if self._cached_model is not None and self._cached_model_identity == identity:
                timings.update({"model_cache_hit": True, "stable_baselines_import_seconds": 0.0,
                                "ppo_model_load_seconds": 0.0, "model_cache_load_seconds": 0.0})
                return self._cached_model
            # A changed checkpoint must never silently use the previous model.
            self._cached_model = None
            self._cached_model_identity = None
            stage = time.monotonic()
            model, import_seconds, load_seconds = self._load_model(Path(identity[0]))
            timings.update({"model_cache_hit": False, "stable_baselines_import_seconds": import_seconds,
                            "ppo_model_load_seconds": load_seconds,
                            "model_cache_load_seconds": time.monotonic() - stage})
            # Only publish a fully loaded model. Exceptions leave the cache empty.
            self._cached_model = model
            self._cached_model_identity = identity
            return model

    def _create_environment(self, topology: Any) -> Any:
        """Build a new topology-bound environment for one campaign only."""
        from strategic.rl_env import AttackStrategyEnv

        return AttackStrategyEnv(topology=topology, real_mode=False)

    @staticmethod
    def _resolve_target(topology: Any, target_bus: int) -> tuple[str, str]:
        """Resolve a campaign target only when it exists in the canonical topology."""
        target_node = f"plc{target_bus + 1}"
        target_ip = topology.get_ip(target_bus)
        nodes = topology.canonical_snapshot().get("nodes", [])
        matching = [node for node in nodes if node.get("id") == target_node
                    and node.get("node_type", "plc") == "plc"]
        if not matching or matching[0].get("ip", target_ip) != target_ip:
            raise CampaignError(
                "invalid_campaign_target",
                f"Campaign target {target_node} ({target_ip}) is not present in the selected topology.",
            )
        return target_ip, target_node

    def _new_session(self, run: dict[str, Any]) -> dict[str, Any]:
        timings: dict[str, Any] = {}
        started = time.monotonic()
        topo = self.topology()
        stage = time.monotonic()
        env = self._create_environment(topo)
        timings["environment_construction_seconds"] = time.monotonic() - stage
        stage = time.monotonic()
        observation, _ = env.reset()
        timings["environment_reset_seconds"] = time.monotonic() - stage
        model = self._cached_ppo_model(timings)
        stage = time.monotonic()
        session = {"env": env, "model": model, "observation": observation, "current_step": 0}
        session["initialization_timings"] = timings
        timings["final_campaign_session_initialization_seconds"] = time.monotonic() - stage
        timings["total_seconds"] = time.monotonic() - started
        return session

    def start(self) -> dict[str, Any]:
        with self._state_lock:
            runtime = self._runtime(); run = self._active_run(runtime)
            if run["run_id"] in self._full_runs:
                raise CampaignError("campaign_already_running", "A full PPO campaign is already running.")
            self._core_and_watcher(runtime, require_idle=True)
            request = run.get("campaign_request") or {}
            if request.get("state") == "REQUESTED":
                raise CampaignError("campaign_already_running", "A campaign step is already requested.")
            # No mutable campaign state is published until all initialization succeeds.
            session = self._new_session(run)
            self._sessions.clear()
            self._sessions[run["run_id"]] = session
            self._initialization_timings.clear()
            self._initialization_timings[run["run_id"]] = dict(session.get("initialization_timings", {}))
            PENDING_STEP.unlink(missing_ok=True); STEP_RESULT.unlink(missing_ok=True)
            campaign = {"state": "READY", "campaign_id": run["run_id"], "scenario_id": run["scenario_id"],
                        "run_id": run["run_id"], "generation_id": runtime.get("generation_id", runtime.get("token")),
                        "current_step": 0, "started_at": _now()}
            run_store.update_run(run["scenario_id"], run["run_id"], campaign_request=campaign)
            return {**campaign, "initialization_timings": session.get("initialization_timings", {})}

    def _campaign(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        # Start performs the displayability gate once. Polling must not reread
        # an aggregate event store merely to return campaign metadata.
        runtime = self._runtime(); run = self._active_run(runtime, displayable=False)
        campaign = run.get("campaign_request") or {}
        if campaign.get("campaign_id") != run["run_id"] or campaign.get("generation_id") != runtime.get("generation_id", runtime.get("token")):
            raise CampaignError("campaign_not_started", "Start a campaign for the current CORE generation first.")
        return runtime, run, campaign

    def _select_step(self, session: dict[str, Any]) -> dict[str, Any]:
        """Use the existing PPO action and watcher technique mapping."""
        from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME
        from strategic.rl_env import MITRE_TECHNIQUES, REGISTER_BASES, VALUE_MAGNITUDES
        action, _ = session["model"].predict(session["observation"], deterministic=False)
        action = [int(value) for value in action]
        technique_index, register_offset, value_level = action[0], action[1], action[2]
        target_bus = action[3] % session["env"]._num_buses
        technique = MITRE_TECHNIQUES[technique_index]
        step_name = TECHNIQUE_TO_STEP_NAME.get(technique["id"])
        if not step_name:
            raise CampaignError("unsupported_technique", f"PPO selected {technique['id']}, which has no watcher step mapping.")
        return {"technique_id": technique["id"], "step_name": step_name, "target_bus": target_bus,
                "register_address": REGISTER_BASES.get(technique["id"], 40000) + register_offset,
                "value_magnitude": float(VALUE_MAGNITUDES[value_level]), "attack_stage": technique["stage"],
                "_action": action}

    def next_step(self) -> dict[str, Any]:
        with self._state_lock:
            runtime, run, campaign = self._campaign()
            if campaign.get("state") == "REQUESTED" or PENDING_STEP.exists():
                raise CampaignError("pending_step_exists", "A campaign step is already pending.")
            self._core_and_watcher(runtime, require_idle=True)
            session = self._sessions.get(run["run_id"])
            if session is None:
                session = self._new_session(run)
                self._sessions.clear()
                self._sessions[run["run_id"]] = session
                self._initialization_timings.clear()
                self._initialization_timings[run["run_id"]] = dict(session.get("initialization_timings", {}))
            step = self._select_step(session); target_bus = step["target_bus"]
            action = step.pop("_action")
            topology = self.topology(); target_ip, target_node = self._resolve_target(topology, target_bus)
            request = {**step, "target_ip": target_ip, "target_node": target_node,
                       "generation_id": runtime.get("generation_id", runtime.get("token")), "campaign_id": run["run_id"],
                       "run_id": run["run_id"], "scenario_id": run["scenario_id"],
                       "correlation_id": f"step-{session['current_step'] + 1}-{uuid.uuid4().hex[:12]}", "timestamp": _now(),
                       "state": "REQUESTED", "current_step": session["current_step"]}
            _atomic_json(PENDING_STEP, request)
            run_store.update_run(run["scenario_id"], run["run_id"], campaign_request=request)
            session["pending_action"] = {"correlation_id": request["correlation_id"], "action": action}
            return request

    def _complete(self, run: dict[str, Any], request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        correlation_id = request["correlation_id"]
        session = self._sessions.get(run["run_id"])
        pending_action = session.get("pending_action") if session else None
        if session and session.get("last_completed_correlation_id") != correlation_id:
            if not pending_action or pending_action["correlation_id"] != correlation_id:
                raise CampaignError("campaign_action_missing", "The completed result has no matching in-memory PPO action.")
        events = run_store.read_events(run["scenario_id"], run["run_id"], "security")
        if not any(event.get("event_type") == "attack_finished" and event.get("correlation_id") == correlation_id for event in events):
            detected = bool(result.get("detected", False))
            evidence = {"step_name": request["step_name"], "return_status": result.get("status", "FAILED"),
                        "detection_method": result.get("detection_method", "none"), "ml_confidence": float(result.get("ml_confidence", 0.0))}
            evidence["finding_evidence"] = deepcopy(result.get("finding_evidence"))
            common = {"mitre_technique": request["technique_id"], "attack_stage": request.get("attack_stage", 0),
                      "campaign_id": request["campaign_id"], "generation_id": request["generation_id"],
                      "correlation_id": correlation_id, "evidence": evidence}
            run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="attack_finished", source_node="attacker", target_node=request["target_node"], result="compromised" if result.get("evaded") else "detected" if detected else "failed", timestamp=result.get("end_time"), **common)
            if detected:
                run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="detection", source_node="ids_monitor", target_node=request["target_node"], result="detected", timestamp=result.get("end_time"), **common)
        if session and session.get("last_completed_correlation_id") != correlation_id:
            # Apply the real watcher result using the existing Streamlit semantics.
            # env.step() would independently evaluate an attack and must not be used.
            env = session["env"]
            action = pending_action["action"]
            detected = bool(result.get("detected", False))
            confidence = float(result.get("ml_confidence", 0.0))
            alert_count = int(result.get("alert_count", 0))
            detector_conf = (confidence if confidence > 0 else min(1.0, 0.3 + alert_count * 0.05)
                             if result.get("detection_method", "suricata") == "suricata" and alert_count > 0
                             else 0.5 if detected else 0.0)
            env._history.append(1 if detected else 0)
            env._last_action = action
            env._last_confidence = detector_conf
            env._last_register = action[1]
            env._last_value_mag = request["value_magnitude"]
            env._current_target_bus = request["target_bus"]
            if result.get("evaded", False):
                env._compromised_buses.add(request["target_bus"])
            env._step_count += 1
            env._chain.append(request["technique_id"])
            reward = env.calculate_step_reward(
                status=result.get("status", "SUCCESS" if result.get("success") else "FAILED"),
                detected=detected, detection_conf=detector_conf,
                tech_stage=request["attack_stage"], target_bus=request["target_bus"])
            session["reward"] = session.get("reward", 0.0) + float(reward)
            session["observation"] = env._get_obs()
            session["current_step"] += 1
            session["last_completed_correlation_id"] = correlation_id
        completed = {**request, "state": "COMPLETED", "completed_at": _now(), "latest_step_result": result,
                     "current_step": session["current_step"] if session else request.get("current_step", 0) + 1}
        run_store.update_run(run["scenario_id"], run["run_id"], campaign_request=completed)
        if session and session.get("last_completed_correlation_id") == correlation_id:
            # Remember the exact accepted payload only after canonical completion.
            # The watcher retains this handoff until a later result replaces it.
            session["last_completed_result"] = deepcopy(result)
        return completed

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            try:
                runtime, run, campaign = self._campaign()
            except CampaignError as exc:
                return {"state": "NONE", "error": {"code": exc.code, "message": str(exc)}}
            result = _read_json(STEP_RESULT)
            error = None
            if campaign.get("state") == "REQUESTED" and result:
                session = self._sessions.get(run["run_id"])
                already_consumed = (
                    session is not None and result == session.get("last_completed_result")
                    and result.get("generation_id") == campaign.get("generation_id")
                    and result.get("campaign_id") == campaign.get("campaign_id")
                )
                if not already_consumed:
                    if result.get("generation_id") != campaign.get("generation_id") or result.get("campaign_id") != campaign.get("campaign_id") or result.get("correlation_id") != campaign.get("correlation_id"):
                        error = {"code": "stale_result", "message": "Step result does not match the current campaign generation and correlation ID."}
                    else:
                        campaign = self._complete(run, campaign, result)
            if campaign.get("state") == "REQUESTED":
                try:
                    created = datetime.fromisoformat(campaign["timestamp"])
                    if (datetime.now(timezone.utc) - created).total_seconds() >= REQUEST_TIMEOUT_SECONDS:
                        error = {"code": "step_timeout", "message": "The watcher did not complete the step within the bounded timeout."}
                except (KeyError, ValueError, TypeError):
                    error = {"code": "step_timeout", "message": "The pending request timestamp is invalid."}
            heartbeat = _read_json(HEARTBEAT)
            return {"state": campaign.get("state", "NONE"), "scenario_id": run["scenario_id"], "run_id": run["run_id"],
                    "campaign_id": campaign.get("campaign_id"), "generation_id": campaign.get("generation_id"),
                    "current_step": campaign.get("current_step", 0), "pending_correlation_id": campaign.get("correlation_id") if campaign.get("state") == "REQUESTED" else None,
                    "watcher": heartbeat.get("status") if heartbeat else "OFFLINE", "steps_executed": heartbeat.get("steps_executed") if heartbeat else None,
                    "latest_step_result": campaign.get("latest_step_result"), "error": error,
                    "diagnostic_initialization_timings": self._initialization_timings.get(run["run_id"])}

    def defend(self, action: str, target_node: str) -> dict[str, Any]:
        with self._state_lock:
            if action not in {"isolate", "restore"}:
                raise CampaignError("invalid_defense", "Supported operations are isolate and restore.", 400)
            runtime, run, campaign = self._campaign(); self._core_and_watcher(runtime, require_idle=False)
            node_ids = {node["id"] for node in self.topology().canonical_snapshot()["nodes"]}
            if target_node not in node_ids or not target_node.startswith("plc"):
                raise CampaignError("invalid_target", "Defense target must be a canonical PLC in the active topology.", 400)
            result = self.request("defend", target_node=target_node, defense_action=action)
            identity = {key: campaign[key] for key in ("mitre_technique", "attack_stage", "correlation_id", "campaign_id", "generation_id") if key in campaign}
            run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="defense_action", source_node="ids_monitor", target_node=target_node, severity="ACTION", defense_action=action, result="applied", evidence={"core_session_id": result["session_id"], "core_output": result.get("output", "")}, **identity)
            if action == "isolate":
                run_store.append_event(run["scenario_id"], run["run_id"], category="security", event_type="containment", source_node="ids_monitor", target_node=target_node, severity="SUCCESS", defense_action=action, result="contained", evidence={"core_session_id": result["session_id"]}, **identity)
            return result

    def run_full(self, max_steps: int = 20) -> dict[str, Any]:
        with self._state_lock:
            runtime, run, campaign = self._campaign()
            if run["run_id"] in self._full_runs:
                raise CampaignError("campaign_already_running", "A full PPO campaign is already running.")
            if campaign.get("state") == "REQUESTED":
                raise CampaignError("pending_step_exists", "A campaign step is already pending.")
            self._core_and_watcher(runtime, require_idle=True)
            self._full_runs.add(run["run_id"])

        def worker() -> None:
            try:
                for _ in range(max_steps):
                    self.next_step()
                    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
                    while time.monotonic() < deadline:
                        state = self.status()
                        if state["state"] == "COMPLETED":
                            if (state.get("latest_step_result") or {}).get("success") is not True:
                                return
                            break
                        if state.get("error"):
                            return
                        time.sleep(0.5)
                    else:
                        return
            finally:
                with self._state_lock:
                    self._full_runs.discard(run["run_id"])

        threading.Thread(target=worker, name=f"ascend-gui-{run['run_id']}", daemon=True).start()
        return {"state": "RUNNING", "run_id": run["run_id"], "max_steps": max_steps}
