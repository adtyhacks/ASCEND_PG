"""Local append-only run store for ASCEND's single-user CORE workflows.

Only backend code writes this store.  UI components read it, which prevents a
browser view from becoming a source of security evidence.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import fcntl

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "data" / "runs"
VALID_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")


class EventStoreReadError(RuntimeError):
    """A JSONL record that cannot safely be interpreted as an event.

    ``valid_events`` retains the earlier, valid records for diagnostics.  The
    raw file is deliberately never edited or truncated while reporting this.
    """

    def __init__(self, path: Path, line_number: int, raw_line: str,
                 kind: str, valid_events: list[dict], cause: Exception):
        self.path = path
        self.line_number = line_number
        self.raw_line = raw_line
        self.kind = kind
        self.valid_events = valid_events
        self.cause = cause
        super().__init__(
            f"{kind} in event store {path} at line {line_number}: {cause}. "
            "The raw evidence was preserved; no event line was discarded."
        )

def _now() -> str: return datetime.now(timezone.utc).isoformat()
def _atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)
def _check(value: str, label: str) -> str:
    if not isinstance(value, str) or not VALID_ID.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value
def _path(scenario_id: str, run_id: str) -> Path:
    return RUNS / _check(scenario_id, "scenario ID") / _check(run_id, "run ID")


@contextmanager
def _event_lock(root: Path, mode: int):
    """Serialize one run's JSONL readers and writers without touching CORE locks."""
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".events.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), mode)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _append_jsonl(path: Path, event: dict) -> None:
    """Append exactly one complete JSON record and make it visible before unlock."""
    payload = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
    with path.open("ab", buffering=0) as out:
        out.write(payload)
        os.fsync(out.fileno())

def create_run(topology: dict, *, scenario_id: str | None = None, attack_config: dict | None = None,
               defense_config: dict | None = None) -> dict:
    scenario_id = scenario_id or f"scenario-{uuid.uuid4().hex[:12]}"
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    root = _path(scenario_id, run_id)
    created = _now()
    scenario = {"scenario_id": scenario_id, "created_at": created, "topology": topology,
                "attack_config": attack_config or {}, "defense_config": defense_config or {}}
    run = {"run_id": run_id, "scenario_id": scenario_id, "started_at": created, "ended_at": None,
           "status": "RUNNING", "topology_version": topology.get("topology_version"), "core_session_id": None}
    _atomic(root / "scenario.json", scenario); _atomic(root / "run.json", run)
    return {**run, "path": str(root)}

def update_run(scenario_id: str, run_id: str, **changes: Any) -> dict:
    path = _path(scenario_id, run_id) / "run.json"
    run = json.loads(path.read_text(encoding="utf-8")); run.update(changes); _atomic(path, run); return run

def recover_active_run(runtime: dict | None) -> dict | None:
    """Return the single run owned by the current CORE generation, if any.

    ``session.json`` remains the lifecycle authority.  Run metadata only
    associates a run with that already-owned session/generation; ambiguous or
    stale metadata is deliberately not recovered.
    """
    if not isinstance(runtime, dict):
        return None
    session_id = runtime.get("id")
    generation_id = runtime.get("generation_id", runtime.get("token"))
    if session_id is None or not generation_id or not RUNS.exists():
        return None
    matches: list[dict] = []
    for path in RUNS.glob("*/run-*/run.json"):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if (run.get("status") == "RUNNING"
                and run.get("lifecycle_status") == "RUNNING"
                and str(run.get("core_session_id")) == str(session_id)
                and run.get("generation_id") == generation_id
                and run.get("scenario_id") == path.parent.parent.name
                and run.get("run_id") == path.parent.name):
            matches.append({**run, "path": str(path.parent)})
    return matches[0] if len(matches) == 1 else None

def append_event(scenario_id: str, run_id: str, *, category: str, event_type: str,
                 source_node: str | None = None, target_node: str | None = None,
                 severity: str = "INFO", evidence: Any = None, timestamp: str | None = None,
                 **metadata: Any) -> dict:
    if category not in {"network", "security"}: raise ValueError("Event category must be network or security")
    root = _path(scenario_id, run_id); event = {"event_id": f"evt-{uuid.uuid4().hex}", "timestamp": timestamp or _now(),
        "scenario_id": scenario_id, "run_id": run_id, "category": category, "event_type": event_type,
        "source_node": source_node, "target_node": target_node, "severity": severity,
        "evidence": evidence, **metadata}
    name = "network_events.jsonl" if category == "network" else "security_events.jsonl"
    # The watcher and Streamlit can both append this run.  The per-run lock
    # keeps readers from seeing a write in progress and prevents writers from
    # producing an interleaved physical JSONL line.  It is unrelated to CORE's
    # lifecycle and ownership locks.
    with _event_lock(root, fcntl.LOCK_EX):
        if category == "security" and event_type in {"attack_started", "attack_finished", "detection"}:
            path = root / "security_events.jsonl"
            previous = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []
            start = _attack_start(previous, event)
            if event_type == "attack_started" and start is None:
                from metrics.attack_severity import resolve_attack_severity
                policy = resolve_attack_severity({"technique_id": event.get("mitre_technique"),
                                                 "step_name": (evidence or {}).get("step_name")})
                event["severity"] = event["attack_severity"] = policy["severity"]
                event["evidence"] = {**(evidence or {}), "severity_policy": policy}
            else:
                event["severity"] = event["attack_severity"] = _canonical_attack_severity(start, event)
        _append_jsonl(root / name, event)
        _append_jsonl(root / "events.jsonl", event)
    return event

def read_events(scenario_id: str, run_id: str, category: str | None = None) -> list[dict]:
    root = _path(scenario_id, run_id); name = {"network": "network_events.jsonl", "security": "security_events.jsonl"}.get(category, "events.jsonl")
    path = root / name
    with _event_lock(root, fcntl.LOCK_SH):
        if not path.exists():
            return []
        content = path.read_text(encoding="utf-8")

    events: list[dict] = []
    lines = content.splitlines(keepends=True)
    last_nonempty = max((index for index, line in enumerate(lines) if line.strip()), default=-1)
    for index, line in enumerate(lines):
        raw_line = line.rstrip("\r\n")
        if not raw_line.strip():
            continue
        try:
            events.append(json.loads(raw_line))
        except json.JSONDecodeError as exc:
            incomplete_trailing = (index == last_nonempty and not line.endswith(("\n", "\r")))
            kind = "incomplete trailing event data" if incomplete_trailing else "malformed event data"
            raise EventStoreReadError(path, index + 1, raw_line, kind, events, exc) from exc
    return events


def recover_displayable_active_run(runtime: dict | None) -> tuple[dict | None, EventStoreReadError | None]:
    """Recover an owned run only when its dashboard event stream is readable.

    This is a presentation/recovery gate.  It neither edits run evidence nor
    changes the underlying CORE ownership decision made by ``recover_active_run``.
    """
    run = recover_active_run(runtime)
    if not run:
        return None, None
    try:
        read_events(run["scenario_id"], run["run_id"])
    except EventStoreReadError as exc:
        return None, exc
    return run, None

def metrics(scenario_id: str, run_id: str) -> dict:
    events = read_events(scenario_id, run_id, "security")
    def at(kind: str):
        return next((e["timestamp"] for e in events if e["event_type"] == kind), None)
    def seconds(a, b):
        if not a or not b: return None
        return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds(), 3)
    start, detected, response, contained = at("attack_started"), at("detection"), at("defense_action"), at("containment")
    compromised = {e.get("target_node") for e in events if e["event_type"] == "attack_finished" and e.get("result") == "compromised"}
    data = {"attack_start_time": start, "detection_time": detected, "response_time": response, "containment_time": contained,
      "time_to_detection_seconds": seconds(start, detected), "time_to_response_seconds": seconds(detected, response),
      "time_to_containment_seconds": seconds(start, contained), "compromised_assets": len(compromised - {None}),
      "detected_events": sum(e["event_type"] == "detection" for e in events), "defensive_actions": sum(e["event_type"] == "defense_action" for e in events)}
    _atomic(_path(scenario_id, run_id) / "metrics.json", data); return data

def visual_data(topology: dict, events: list[dict]) -> tuple[list[dict], list[dict], set[str], set[str], list[list[str]]]:
    compromised, detected, isolated, path = set(), set(), set(), ["attacker"]
    started, finished, defense_state = {}, set(), {}
    for event in events:
        target = event.get("target_node")
        correlation_id = event.get("correlation_id")
        if event.get("event_type") == "attack_started" and target and correlation_id:
            started[correlation_id] = target
        if event.get("event_type") == "attack_finished" and correlation_id:
            finished.add(correlation_id)
        if event.get("event_type") == "attack_finished" and event.get("result") == "compromised" and target: compromised.add(target); path.append(target)
        if event.get("event_type") == "detection" and target: detected.add(target)
        if event.get("event_type") == "defense_action" and target:
            defense_state[target] = event.get("defense_action")
    attacking = set(started.values()) - {started[c] for c in finished if c in started}
    isolated = {target for target, action in defense_state.items() if action == "isolate"}
    restored = {target for target, action in defense_state.items() if action == "restore"}
    def state(node_id):
        if node_id in isolated: return "isolated"
        if node_id in restored: return "restored"
        if node_id in detected: return "detected"
        if node_id in attacking: return "attacking"
        return "normal"
    nodes = [{"id": n["id"], "label": n["hostname"], "type": n["node_type"], "state": state(n["id"])} for n in topology["nodes"]]
    edges = [{"from": e["from"], "to": e["to"], "type": e["type"], "protocol": e.get("protocol", "")} for e in topology["links"]]
    return nodes, edges, compromised, detected, [path] if len(path) > 1 else []

def _attack_identity(event: dict) -> tuple:
    return tuple(event.get(k) for k in ("scenario_id", "run_id", "generation_id", "correlation_id"))


def _attack_start(events: list[dict], event: dict) -> dict | None:
    if not event.get("correlation_id"):
        return None
    return next((candidate for candidate in events if candidate.get("event_type") == "attack_started"
                 and _attack_identity(candidate) == _attack_identity(event)), None)


def _canonical_attack_severity(start: dict | None, event: dict) -> str | None:
    # Historical start boundaries remain authoritative. Never use detector
    # severity or the legacy INFO finish default to invent attack severity.
    return (start.get("attack_severity") or start.get("severity")) if start else event.get("attack_severity")


def report_events(events: list[dict]) -> list[dict]:
    """Normalize one run's canonical events for the legacy report renderer."""
    def key(e):
        return _attack_identity(e)
    detections = {key(e): e for e in events if e.get("event_type") == "detection" and e.get("correlation_id")}
    starts = {}
    for event in events:
        if event.get("event_type") == "attack_started" and event.get("correlation_id"):
            starts.setdefault(key(event), event)
    normalized = []
    for event in events:
        if event.get("event_type") != "attack_finished":
            continue
        evidence = event.get("evidence") or {}
        detection = detections.get(key(event)) if event.get("correlation_id") else None
        detection_evidence = (detection or {}).get("evidence") or {}
        start = starts.get(key(event)) if event.get("correlation_id") else None
        detected = bool(detection) or str(event.get("result", "")).lower() == "detected"
        normalized.append({"Timestamp": event["timestamp"], "MITRE ID": event.get("mitre_technique", ""), "Technique Name": evidence.get("step_name", event.get("mitre_technique", "")), "Stage": event.get("attack_stage", 0), "Target Host": event.get("target_node", ""), "Detected": detected, "Detector Confidence": detection_evidence.get("ml_confidence", evidence.get("ml_confidence")), "Detection Method": (detection or {}).get("detection_method") or detection_evidence.get("detection_method") or evidence.get("detection_method", "unknown"), "Status": "Detected" if detected else event.get("result", "Unknown"), "Severity": _canonical_attack_severity(start, event), "Correlation ID": event.get("correlation_id"), "Canonical": True, "Evidence": {"attack": event, "detection": detection}, "Source IP": evidence.get("source_ip", "N/A")})
        normalized[-1]["Attack Severity"] = normalized[-1]["Severity"]
        normalized[-1]["Evidence"]["start"] = start
    return normalized
