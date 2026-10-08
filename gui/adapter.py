"""Thin, read-oriented adapter for ASCEND-PG's dedicated GUI."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from data.mitre_registry import TECHNIQUES
from metrics.attack_severity import resolve_attack_severity
from testbed import run_store
from testbed.core_runtime import core_request
from testbed.topology import get_topology as canonical_topology, load_case, set_topology, Topology, TOPOLOGY_LOCK
from gui.identity_presentation import aliases_for, saved_run_metadata


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
MAX_EVENT_LIMIT = 500
MAX_BACKGROUND_LIMIT = 100
MAX_BACKGROUND_BYTES = 2 * 1024 * 1024
_active_cache: dict[tuple[str, str], tuple[dict[str, Any] | None, str | None]] = {}


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _runtime_marker() -> dict[str, Any] | None:
    return _read_json(DATA / "core-runtime" / "session.json")


def get_system_status() -> dict[str, Any]:
    """Read CORE status through its existing read-only helper."""
    try:
        core = core_request("status")
        core_state = core.get("state", "UNKNOWN")
        watcher_state = core.get("watcher", "UNKNOWN")
        daemon = "AVAILABLE"
    except RuntimeError as exc:
        core, core_state, watcher_state, daemon = {"error": str(exc)}, "OFFLINE", "STOPPED", "UNAVAILABLE"
    # The status helper removes an obsolete ownership marker when its CORE
    # session no longer exists, so report marker state after reconciliation.
    runtime = _runtime_marker()
    return {
        "core": {"state": core_state, "daemon": daemon, "session_id": core.get("session_id")},
        "watcher": {"state": watcher_state},
        "generation": runtime.get("generation_id") if runtime else None,
        "runtime_marker": bool(runtime),
    }


def get_attack_catalogue() -> dict[str, Any]:
    """Return the canonical 18-attack catalogue and resolved capability severities."""
    attacks = []
    severity_counts: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for tech in TECHNIQUES:
        metadata = {"technique_id": tech["id"], "step_name": tech.get("default_step")}
        resolved = resolve_attack_severity(metadata)
        severity = resolved.get("severity", "HIGH").title()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts[severity] = 1

        attacks.append({
            "index": tech.get("index"),
            "technique_id": tech["id"],
            "name": tech.get("name"),
            "title": tech.get("name"),
            "tactic": tech.get("tactic"),
            "stage": tech.get("stage"),
            "default_step": tech.get("default_step"),
            "description": tech.get("description"),
            "script": tech.get("script"),
            "detect_sids": list(tech.get("detect_sids", [])),
            "severity": severity,
            "severity_reason": resolved.get("reason"),
            "severity_policy": resolved.get("policy"),
        })

    return {
        "total_attacks": len(attacks),
        "severity_distribution": severity_counts,
        "attacks": attacks,
    }


def get_active_run(*, verify_integrity: bool = False) -> dict[str, Any] | None:
    """Recover the current owned run without scanning its event history by default.

    ``recover_displayable_active_run`` remains available for the explicit
    integrity path.  It intentionally reads the aggregate event stream, so it
    must not become an incidental cost of loading every GUI page.
    """
    runtime = _runtime_marker()
    if not runtime:
        return None
    run = run_store.recover_active_run(runtime)
    if not run:
        return None
    if verify_integrity:
        key = (str(runtime.get("generation_id")), run["run_id"])
        if key not in _active_cache:
            displayable, integrity_error = run_store.recover_displayable_active_run(runtime)
            _active_cache[key] = (displayable, str(integrity_error) if integrity_error else None)
        displayable, integrity_error = _active_cache[key]
        if not displayable:
            return {"state": "REJECTED", "run_id": run["run_id"], "scenario_id": run["scenario_id"],
                    "integrity_error": integrity_error}
        run = displayable
    metrics = _read_json(Path(run["path"]) / "metrics.json")
    return {"state": "ACTIVE", "run": run, "metrics": metrics,
            "integrity_validated": verify_integrity}


def get_displayable_active_run() -> dict[str, Any] | None:
    """Explicit, cached canonical event-store validation for diagnostics."""
    return get_active_run(verify_integrity=True)


def get_topology() -> dict[str, Any]:
    """Load canonical topology and render its current state with the old PyVis view."""
    return _topology_view(canonical_topology(), [])


def _topology_view(
    topology_model, security_events: list[dict[str, Any]], known_visual_signature: str | None = None,
) -> dict[str, Any]:
    topology = topology_model.canonical_snapshot()
    nodes, edges, compromised, detected, attack_paths = run_store.visual_data(topology, security_events)
    visual = {"nodes": nodes, "edges": edges}
    visual_signature = hashlib.sha256(json.dumps(
        {"visual": visual, "compromised": sorted(compromised), "detected": sorted(detected), "attack_paths": attack_paths},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    pyvis_html = None
    if visual_signature != known_visual_signature:
        from testbed.visualize_topology import render_topology
        pyvis_html = render_topology(
            nodes, edges, compromised_ids=compromised, detected_ids=detected,
            attack_paths=attack_paths, show_tooltips=True,
        )
    return {
        "topology": topology,
        "visual": visual,
        "visual_signature": visual_signature,
        "pyvis_html": pyvis_html,
    }


def get_available_topologies() -> list[dict[str, str]]:
    """List preset references and validated custom definitions in the existing library."""
    options = []
    for path in sorted((DATA / "sample_topologies").glob("*.json")):
        try:
            source = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(source, dict):
            continue
        case = str(source.get("pandapower_case", "")).lower()
        if case not in {"case14", "case30"}:
            try:
                case = Topology.from_custom_dict(source).case_name
            except (ValueError, TypeError):
                continue
            if path.stem != case:
                continue
        options.append({
            "case_name": case,
            "name": str(source.get("name", case)),
            "description": str(source.get("description", "")),
        })
    return options


def select_topology(case_name: str) -> dict[str, Any]:
    """Select an existing preset through the shared canonical topology model."""
    with TOPOLOGY_LOCK:
        options = {item["case_name"]: item for item in get_available_topologies()}
        case = str(case_name).strip().lower()
        if case not in options:
            raise ValueError("Choose an available canonical topology.")
        _require_topology_editable()
        if case in {"case14", "case30"}:
            selected = load_case(case)
        else:
            selected = Topology.from_custom_dict(json.loads((DATA / "sample_topologies" / f"{case}.json").read_text()))
            set_topology(selected)
        _persist_topology_selection(selected)
        return {"configuration": get_network_configuration(), **_topology_view(selected, [])}


def _require_topology_editable() -> None:
    if not (DATA / "core-runtime" / "session.json").exists():
        return
    try:
        status = core_request("status")
    except RuntimeError as exc:
        raise ValueError(
            "Topology selection is unavailable while the managed CORE session state cannot be verified."
        ) from exc
    if status.get("state") == "STOPPED" and status.get("session_id") is None:
        # core_session.owned_session() has reconciled a marker whose recorded
        # session no longer exists. A reachable daemon alone does not lock the
        # canonical topology.
        return
    raise ValueError("Topology selection is available only when no managed CORE session is active.")


def _persist_topology_selection(selected: Topology) -> None:
    # Retain the selected definition across GUI restarts without altering run evidence.
    path = DATA / "topology_selection.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(selected.to_dict(), indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def save_custom_topology(definition: dict) -> dict[str, Any]:
    """Save/select the existing bus model, without operating CORE or a live run."""
    with TOPOLOGY_LOCK:
        _require_topology_editable()
        selected = Topology.from_custom_dict(definition)
        selected.to_pandapower()
        view = _topology_view(selected, [])
        directory = DATA / "sample_topologies"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{selected.case_name}.json"
        temporary = path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(selected.to_dict(), indent=2), encoding="utf-8")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        set_topology(selected)
        _persist_topology_selection(selected)
        return {"configuration": get_network_configuration(), **view}


def validate_custom_topology(definition: dict) -> dict[str, Any]:
    """Validate definition against existing topology schema without modifying state."""
    selected = Topology.from_custom_dict(definition)
    selected.to_pandapower()
    snapshot = selected.canonical_snapshot()
    return {
        "valid": True,
        "case_name": selected.case_name,
        "num_buses": selected.num_buses,
        "num_edges": len(selected.edges),
        "communication_nodes": len(snapshot["nodes"]),
        "communication_links": sum(bool(link.get("core_link")) for link in snapshot["links"]),
        "definition": definition,
    }


def get_custom_topology_template() -> dict[str, Any]:
    """Canonical downloadable template definition for custom topologies."""
    return {
        "case_name": "custom_template",
        "nodes": [
            {"bus_id": 0, "name": "Generator 1", "type": "slack", "vn_kv": 110.0, "voltage": 1.06, "pg": 40.0, "qg": 10.0, "pl": 0.0, "ql": 0.0, "plc_type": "generic_modbus"},
            {"bus_id": 1, "name": "Load Bus 2", "type": "pq", "vn_kv": 110.0, "voltage": 1.00, "pg": 0.0, "qg": 0.0, "pl": 25.0, "ql": 5.0, "plc_type": "generic_modbus"},
            {"bus_id": 2, "name": "Load Bus 3", "type": "pq", "vn_kv": 110.0, "voltage": 1.00, "pg": 0.0, "qg": 0.0, "pl": 35.0, "ql": 12.0, "plc_type": "generic_modbus"},
        ],
        "edges": [
            {"from": 0, "to": 1, "length_km": 1.0, "r_ohm_per_km": 0.1, "x_ohm_per_km": 0.1, "c_nf_per_km": 0.0, "max_i_ka": 0.4},
            {"from": 1, "to": 2, "length_km": 1.0, "r_ohm_per_km": 0.1, "x_ohm_per_km": 0.1, "c_nf_per_km": 0.0, "max_i_ka": 0.4},
        ],
    }


def get_network_configuration() -> dict[str, Any]:
    topology = canonical_topology().canonical_snapshot()
    types: dict[str, int] = {}
    for node in topology["nodes"]:
        node_type = node.get("node_type", "unknown")
        types[node_type] = types.get(node_type, 0) + 1
    return {"topology_version": topology.get("topology_version"), "case_name": topology.get("case_name"),
            "selected_case": topology.get("case_name"), "available_topologies": get_available_topologies(),
            "node_count": len(topology["nodes"]), "edge_count": len(topology["links"]), "node_types": types,
            "definition": canonical_topology().to_dict() if isinstance(canonical_topology(), Topology) else None}


def _recent_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    """Bounded tail reader for one canonical JSONL category file."""
    if not isinstance(limit, int) or limit < 1 or limit > MAX_EVENT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_EVENT_LIMIT}")
    if not path.exists():
        return []
    block_size = 64 * 1024
    with path.open("rb") as source:
        position = source.seek(0, 2)
        payload = b""
        while position > 0 and payload.count(b"\n") <= limit:
            size = min(block_size, position)
            position -= size
            source.seek(position)
            payload = source.read(size) + payload
    lines = payload.splitlines()
    if position > 0 and lines:
        lines = lines[1:]
    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed canonical event data in {path.name}: {exc}") from exc
        if isinstance(record, dict):
            records.append(record)
    return records


def get_recent_network_events(scenario_id: str, run_id: str, limit: int = 100) -> list[dict[str, Any]]:
    root = run_store._path(scenario_id, run_id)
    return _recent_jsonl(root / "network_events.jsonl", limit)


def get_recent_security_events(scenario_id: str, run_id: str, limit: int = 100) -> list[dict[str, Any]]:
    root = run_store._path(scenario_id, run_id)
    return _recent_jsonl(root / "security_events.jsonl", limit)


def _recent_tolerant_jsonl(path: Path, limit: int, max_bytes: int = MAX_BACKGROUND_BYTES) -> list[dict[str, Any]]:
    """Read a bounded tail of non-canonical telemetry, skipping malformed rows."""
    if not isinstance(limit, int) or limit < 1 or limit > MAX_BACKGROUND_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_BACKGROUND_LIMIT}")
    if not path.is_file():
        return []
    block_size = 64 * 1024
    with path.open("rb") as source:
        position = source.seek(0, 2)
        start = position
        payload = b""
        while position > 0 and start - position < max_bytes and payload.count(b"\n") <= limit:
            size = min(block_size, position, max_bytes - (start - position))
            if size <= 0:
                break
            position -= size
            source.seek(position)
            payload = source.read(size) + payload
    lines = payload.splitlines()
    if position > 0 and lines:
        lines = lines[1:]  # discard a possibly partial first record
    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _nonempty_string(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) and value else None


def _source_timestamp(record: dict[str, Any]) -> str | int | float | None:
    value = record.get("timestamp")
    return value if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None


def _normalize_scada_record(record: dict[str, Any]) -> dict[str, Any] | None:
    action = _nonempty_string(record, "action")
    stage = _nonempty_string(record, "stage")
    target = _nonempty_string(record, "target")
    if stage != "normal_traffic" and not (action and action.startswith("poll_")):
        return None
    return {
        "source_type": "SCADA poll log",
        "timestamp": _source_timestamp(record),
        "source_ip": None,
        "destination_ip": target,
        "protocol": None,
        "source_port": None,
        "destination_port": None,
        "observation": action,
        "stage": stage,
    }


def _normalize_suricata_flow(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("event_type") != "flow":
        return None
    source = _nonempty_string(record, "src_ip")
    destination = _nonempty_string(record, "dest_ip")
    if not source or not destination:
        return None
    flow = record.get("flow")
    flow_fields = {}
    if isinstance(flow, dict):
        flow_fields = {key: flow[key] for key in ("start", "end", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "alerted") if key in flow}
    result: dict[str, Any] = {
        "source_type": "Suricata EVE flow",
        "timestamp": _source_timestamp(record),
        "source_ip": source,
        "destination_ip": destination,
        "protocol": _nonempty_string(record, "proto"),
        "source_port": record.get("src_port") if isinstance(record.get("src_port"), int) and not isinstance(record.get("src_port"), bool) else None,
        "destination_port": record.get("dest_port") if isinstance(record.get("dest_port"), int) and not isinstance(record.get("dest_port"), bool) else None,
        "application_protocol": _nonempty_string(record, "app_proto"),
        "flow": flow_fields or None,
    }
    return result


def get_background_network_events(limit: int = 100) -> list[dict[str, Any]]:
    """Read background SCADA and Suricata flow observations, separate from run evidence."""
    if not isinstance(limit, int) or limit < 1 or limit > MAX_BACKGROUND_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_BACKGROUND_LIMIT}")
    runtime = DATA / "core-runtime"
    scada = [_normalize_scada_record(row) for row in _recent_tolerant_jsonl(runtime / "scada.jsonl", limit)]
    eve = [_normalize_suricata_flow(row) for row in _recent_tolerant_jsonl(runtime / "suricata" / "eve.json", limit)]
    observations = [row for row in (*scada, *eve) if row is not None]
    # Sort only by source-provided timestamps; missing timestamps remain last.
    timestamped = [row for row in observations if row.get("timestamp") is not None]
    untimestamped = [row for row in observations if row.get("timestamp") is None]
    timestamped.sort(key=lambda row: str(row["timestamp"]), reverse=True)
    return (timestamped + untimestamped)[:limit]


def get_runtime_diagnostics() -> dict[str, Any]:
    status = get_system_status()
    active = get_active_run()
    runs = saved_run_metadata()
    run = active.get("run") if active and active.get("state") == "ACTIVE" else None
    registry = aliases_for(runs)
    identity = registry.run_identity(run)
    # Runtime diagnostics can briefly lead run recovery during startup.  Use a
    # matching persisted run when possible without changing lifecycle state.
    if run is None:
        match = next((candidate for candidate in runs
                      if str(candidate.get("core_session_id")) == str(status["core"].get("session_id"))
                      and candidate.get("generation_id") == status.get("generation")), None)
        identity = registry.run_identity(match)
    return {**status, "active_run": active, "display_identity": identity}


def get_report_summary() -> dict[str, Any]:
    """Return existing report and bounded normalized-record metadata only."""
    active = get_active_run()
    if not active or active.get("state") != "ACTIVE":
        return {"available": False, "reason": "No active owned run", "normalized_records": 0}
    run = active["run"]
    report = Path(run["path"]) / "report.html"
    # report_events is the existing normalization boundary.  Bound its input
    # here so visiting Reports never loads an unbounded security history.
    normalized = run_store.report_events(
        get_recent_security_events(run["scenario_id"], run["run_id"], 100)
    )
    return {"available": report.is_file(), "path": str(report) if report.is_file() else None,
            "run_id": run["run_id"], "scenario_id": run["scenario_id"],
            "normalized_records": len(normalized), "normalized_events": normalized}


def get_live_battle_snapshot(limit: int = 100, visual_signature: str | None = None) -> dict[str, Any]:
    """Read independent bounded canonical evidence streams for Live Battle."""
    background_network = get_background_network_events(min(max(limit, 1), MAX_BACKGROUND_LIMIT))
    active = get_active_run()
    if not active or active.get("state") != "ACTIVE":
        topology = _topology_view(canonical_topology(), [], visual_signature)
        return {"active_run": active, "network_events": [], "security_events": [], "background_network": background_network,
                "network_event_count": 0, "security_event_count": 0, "campaign": None,
                "display_identity": {}, "campaign_display": {}, **topology, "limit": limit}
    run = active["run"]
    network_events = get_recent_network_events(run["scenario_id"], run["run_id"], limit)
    security_events = get_recent_security_events(run["scenario_id"], run["run_id"], limit)
    registry = aliases_for(saved_run_metadata(), security_events)
    from defense.detection_result import decorate_event
    presented_security = [decorate_event(registry.decorate_event(event)) for event in security_events]
    campaign = run.get("campaign_request") or {}
    campaign_display = {
        "Assessment": registry.assessment(run.get("run_id")),
        "State": campaign.get("state"),
        "Runtime": registry.runtime_generation(run.get("generation_id")),
        "Attack step": registry.attack_step(campaign),
        "Attack event": registry.attack_event(campaign.get("correlation_id"), run.get("run_id")),
        "Requested": campaign.get("requested_at"),
    }
    topology_view = _topology_view(canonical_topology(), security_events, visual_signature)
    return {"active_run": active, "limit": limit, "network_events": network_events, "background_network": background_network,
            "security_events": presented_security, "network_event_count": len(network_events),
            "security_event_count": len(security_events), "campaign": run.get("campaign_request"),
            "display_identity": registry.run_identity(run),
            "campaign_display": {key: value for key, value in campaign_display.items() if value not in (None, "")},
            **topology_view}
