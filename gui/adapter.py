"""Thin, read-oriented adapter for ASCEND-PG's dedicated GUI."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from testbed import run_store
from testbed.core_runtime import core_request
from testbed.topology import get_topology as canonical_topology, load_case


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
    runtime = _runtime_marker()
    try:
        core = core_request("status")
        core_state = core.get("state", "UNKNOWN")
        watcher_state = core.get("watcher", "UNKNOWN")
        daemon = "AVAILABLE"
    except RuntimeError as exc:
        core, core_state, watcher_state, daemon = {"error": str(exc)}, "OFFLINE", "STOPPED", "UNAVAILABLE"
    return {
        "core": {"state": core_state, "daemon": daemon, "session_id": core.get("session_id")},
        "watcher": {"state": watcher_state},
        "generation": runtime.get("generation_id") if runtime else None,
        "runtime_marker": bool(runtime),
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


def _topology_view(topology_model, security_events: list[dict[str, Any]]) -> dict[str, Any]:
    topology = topology_model.canonical_snapshot()
    nodes, edges, compromised, detected, attack_paths = run_store.visual_data(topology, security_events)
    from testbed.visualize_topology import render_topology

    return {
        "topology": topology,
        "visual": {"nodes": nodes, "edges": edges},
        "pyvis_html": render_topology(
            nodes, edges, compromised_ids=compromised, detected_ids=detected,
            attack_paths=attack_paths, show_tooltips=True,
        ),
    }


def get_available_topologies() -> list[dict[str, str]]:
    """Expose only the existing preset topology references supported by CORE."""
    options = []
    for path in sorted((DATA / "sample_topologies").glob("*.json")):
        try:
            source = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        case = str(source.get("pandapower_case", "")).lower()
        if case not in {"case14", "case30"}:
            continue
        options.append({
            "case_name": case,
            "name": str(source.get("name", case)),
            "description": str(source.get("description", "")),
        })
    return options


def select_topology(case_name: str) -> dict[str, Any]:
    """Select an existing preset through the shared canonical topology model."""
    options = {item["case_name"]: item for item in get_available_topologies()}
    case = str(case_name).strip().lower()
    if case not in options:
        raise ValueError("Choose an available canonical topology preset.")
    status = core_request("status")
    if status.get("state") == "RUNTIME":
        raise ValueError("Topology selection is available only before an owned CORE session is running.")
    selected = load_case(case)
    return {"configuration": get_network_configuration(), **_topology_view(selected, [])}


def get_network_configuration() -> dict[str, Any]:
    topology = canonical_topology().canonical_snapshot()
    types: dict[str, int] = {}
    for node in topology["nodes"]:
        node_type = node.get("node_type", "unknown")
        types[node_type] = types.get(node_type, 0) + 1
    return {"topology_version": topology.get("topology_version"), "case_name": topology.get("case_name"),
            "selected_case": topology.get("case_name"), "available_topologies": get_available_topologies(),
            "node_count": len(topology["nodes"]), "edge_count": len(topology["links"]), "node_types": types}


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
    return {**status, "active_run": get_active_run()}


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


def get_live_battle_snapshot(limit: int = 100) -> dict[str, Any]:
    """Read independent bounded canonical evidence streams for Live Battle."""
    background_network = get_background_network_events(min(max(limit, 1), MAX_BACKGROUND_LIMIT))
    active = get_active_run()
    if not active or active.get("state") != "ACTIVE":
        topology = get_topology()
        return {"active_run": active, "network_events": [], "security_events": [], "background_network": background_network,
                "network_event_count": 0, "security_event_count": 0, "campaign": None,
                **topology, "limit": limit}
    run = active["run"]
    network_events = get_recent_network_events(run["scenario_id"], run["run_id"], limit)
    security_events = get_recent_security_events(run["scenario_id"], run["run_id"], limit)
    topology_view = _topology_view(canonical_topology(), security_events)
    return {"active_run": active, "limit": limit, "network_events": network_events, "background_network": background_network,
            "security_events": security_events, "network_event_count": len(network_events),
            "security_event_count": len(security_events), "campaign": run.get("campaign_request"), **topology_view}
