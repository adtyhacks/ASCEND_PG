"""Read-only operational view of the canonical grid and retained telemetry."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
import math

from gui import adapter

FRESH_SECONDS = 120


def _time(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).timestamp()
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _number(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _total(nodes, field, case):
    values = [_number(node.get(field)) for node in nodes]
    if not values or any(value is None for value in values):
        return None
    # Current preset loader explicitly fills these fields with zero placeholders.
    if case in {'case14', 'case30'} and all(value == 0 for value in values):
        return None
    return sum(values)


def _flow_rate(rows, addresses, start, now):
    """Latest cumulative byte counters per flow / observed elapsed window."""
    latest = {}
    for row in rows:
        flow = row.get('flow')
        stamp = _time(row.get('timestamp'))
        if row.get('event_type') != 'flow' or not isinstance(flow, dict) or stamp is None or not start <= stamp <= now:
            continue
        if not isinstance(row.get('src_ip'), str) or not isinstance(row.get('dest_ip'), str) or row['src_ip'] not in addresses or row['dest_ip'] not in addresses:
            continue
        if any(type(flow.get(key)) is not int for key in ('bytes_toserver', 'bytes_toclient')):
            continue
        if row.get('flow_id') is not None and type(row['flow_id']) not in (int, str):
            continue
        if any(row.get(key) is not None and type(row[key]) is not int for key in ('src_port', 'dest_port')) or not isinstance(row.get('proto', ''), str):
            continue
        left, right = _time(flow.get('start')), _time(flow.get('end'))
        sent, received = _number(flow.get('bytes_toserver')), _number(flow.get('bytes_toclient'))
        if left is None or right is None or not start <= left < right <= now or sent is None or received is None or min(sent, received) < 0:
            continue
        identity = (row.get('flow_id'), left, row.get('src_ip'), row.get('dest_ip'), row.get('src_port'), row.get('dest_port'), row.get('proto'))
        if identity not in latest or stamp >= latest[identity][0]:
            latest[identity] = (stamp, left, right, sent + received)
    if not latest:
        return {'bits_per_second': None, 'bytes': None, 'window_seconds': None, 'flow_count': 0}
    window = max(value[2] for value in latest.values()) - min(value[1] for value in latest.values())
    total_bytes = sum(value[3] for value in latest.values())
    return {'bits_per_second': total_bytes * 8 / window, 'bytes': total_bytes,
            'window_seconds': window, 'flow_count': len(latest)}


_baseline_cache = {}


def get_baseline_grid(topology=None) -> dict:
    topo = topology or adapter.canonical_topology()
    norm_case = str(topo.case_name or "case14").strip().lower()
    cache_key = hashlib.sha256(json.dumps(topo.to_dict(), sort_keys=True).encode()).hexdigest()
    if cache_key in _baseline_cache:
        return _baseline_cache[cache_key]
    try:
        import pandas as pd
        net = topo.to_pandapower()
        grid_df = pd.DataFrame({"bus_id": net.res_bus.index, "voltage_pu": net.res_bus["vm_pu"].values,
                                "voltage_angle_deg": net.res_bus["va_degree"].values})
        rows, base = [], datetime(2026, 1, 1)
        for index, edge in enumerate(topo.edge_models):
            source, destination = int(edge["from"]), int(edge["to"])
            rows.append({"timestamp": base + timedelta(seconds=index + 1), "src_bus": source,
                          "dst_bus": destination, "packet_size_bytes": 256,
                          "voltage_pu": float(net.res_bus.at[source, "vm_pu"])})
        traffic_df = pd.DataFrame(rows, columns=["timestamp", "src_bus", "dst_bus", "packet_size_bytes", "voltage_pu"])
        simulation_source = topo.source
        voltage_min = float(grid_df["voltage_pu"].min())
        voltage_max = float(grid_df["voltage_pu"].max())
        line_loading = net.res_line["loading_percent"] if hasattr(net, "res_line") and not net.res_line.empty else pd.Series(dtype=float)
        max_loading = float(line_loading.max()) if not line_loading.empty and not pd.isna(line_loading.max()) else 0.0

        bus_voltages = [
            {
                "bus_id": int(row["bus_id"]),
                "voltage_pu": round(float(row["voltage_pu"]), 4),
                "voltage_angle_deg": round(float(row["voltage_angle_deg"]), 2),
            }
            for _, row in grid_df.iterrows()
        ]
        line_loadings = [
            {
                "line_id": int(idx),
                "loading_percent": round(float(val), 2),
            }
            for idx, val in line_loading.items()
        ]
        telemetry_rows = [
            {
                "timestamp": str(row["timestamp"])[:19],
                "src_bus": int(row["src_bus"]),
                "dst_bus": int(row["dst_bus"]),
                "packet_size_bytes": int(row["packet_size_bytes"]),
                "voltage_pu": round(float(row["voltage_pu"]), 4),
            }
            for _, row in traffic_df.head(50).iterrows()
        ]
        result = {
            "case_name": topo.case_name,
            "simulation_source": simulation_source,
            "summary": {
                "electrical_buses": len(grid_df),
                "voltage_range": f"{voltage_min:.3f}–{voltage_max:.3f} pu",
                "voltage_min": round(voltage_min, 4),
                "voltage_max": round(voltage_max, 4),
                "lines": len(net.line) if hasattr(net, "line") else len(line_loadings),
                "max_line_loading": round(max_loading, 1),
                "max_line_loading_pct": f"{max_loading:.1f}%",
            },
            "bus_voltages": bus_voltages,
            "line_loadings": line_loadings,
            "telemetry": telemetry_rows,
        }
        _baseline_cache[cache_key] = result
        return result
    except Exception as exc:
        return {
            "case_name": topo.case_name, "error": f"Baseline power flow could not be solved: {exc}",
            "summary": None, "bus_voltages": [], "line_loadings": [], "telemetry": [],
        }


def snapshot():
    """No polling, power-flow recalculation, collectors, or evidence writes."""
    topo = adapter.canonical_topology()
    canonical = topo.canonical_snapshot()
    active, marker = adapter.get_active_run(), adapter._runtime_marker()
    now = datetime.now(timezone.utc).timestamp()
    run = active.get('run') if active and active.get('state') == 'ACTIVE' else None
    starts = [value for value in [_time((marker or {}).get('created_at')), _time((run or {}).get('started_at'))] if value is not None]
    boundary = max([*starts, now - FRESH_SECONDS])
    scoped = bool(run and marker and starts and run.get('topology_version') == canonical['topology_version']
                  and str(run.get('core_session_id')) == str(marker.get('id'))
                  and run.get('generation_id') == marker.get('generation_id', marker.get('token')))
    observations, flows, detections = [], [], None
    if scoped:
        runtime = adapter.DATA / 'core-runtime'
        observations = adapter._recent_tolerant_jsonl(runtime / 'scada.jsonl', adapter.MAX_BACKGROUND_LIMIT)
        flows = adapter._recent_tolerant_jsonl(runtime / 'suricata/eve.json', adapter.MAX_BACKGROUND_LIMIT)
        events = adapter.get_recent_security_events(run['scenario_id'], run['run_id'], 100)
        detections = sum(event.get('event_type') == 'detection' and event.get('scenario_id') == run['scenario_id']
                         and event.get('run_id') == run['run_id'] and event.get('generation_id') == run['generation_id'] for event in events)
    latest = {}
    for row in observations:
        stamp, target = _time(row.get('timestamp')), row.get('target')
        if not isinstance(target, str):
            continue
        if stamp is None or not boundary <= stamp <= now or not (row.get('observation_type') == 'poll_result' or row.get('action') == 'poll_failed'):
            continue
        if row.get('observation_type') == 'poll_result':
            values = row.get('registers')
            if not isinstance(values, list) or not values or any(type(value) is not int or not 0 <= value <= 65535 for value in values):
                continue
        if target not in latest or stamp > latest[target][0]:
            latest[target] = (stamp, row)
    physical = None
    if scoped:
        try:
            from testbed.physical_feedback import load_state
            physical = load_state(topo, run)
        except Exception as exc:
            physical = {"physical_model_available": topo.physical_available, "power_flow_success": False, "error": str(exc)}
    components = []
    for node in topo.nodes:
        observed = latest.get(topo.get_ip(node['bus_id']))
        status = 'Not available'
        if observed:
            status = 'Monitoring' if observed[1].get('observation_type') == 'poll_result' else 'Offline'
        components.append({'name': node.get('name') or f"Bus {node['bus_id'] + 1}",
            'type': 'Generator' if node.get('type') in {'slack', 'pv', 'generator', 'gen'} else 'Load',
            'model_voltage_pu': (_number(physical.get('voltage_after', {}).get(str(node['bus_id']))) if physical is not None else _number(node.get('voltage'))),
            'model_generation_mw': _number(node.get('pg')), 'model_load_mw': _number(node.get('pl')),
            'measured_voltage_pu': None, 'measured_power_mw': None,
            'status': status, 'last_observed': observed[1].get('timestamp') if observed else None,
            'bus_id': node['bus_id'], 'ip': topo.get_ip(node['bus_id'])})
    if topo.case_name in {'case14', 'case30'}:
        for field in ('model_generation_mw', 'model_load_mw'):
            if all(row[field] == 0 for row in components):
                for row in components:
                    row[field] = None
    voltages = [row['model_voltage_pu'] for row in components]
    rate = _flow_rate(flows, {node['ip'] for node in canonical['nodes'] if node.get('ip')}, boundary, now)
    monitoring = sum(row['status'] == 'Monitoring' for row in components)
    offline = sum(row['status'] == 'Offline' for row in components)
    return {'case_name': topo.case_name, 'components': components, 'physical_feedback': physical, 'physical_model_available': topo.physical_available,
        'baseline_grid': get_baseline_grid(topo),
        'runtime_available': scoped,
        'grid': {'component_count': len(components), 'healthy': None, 'warning': None, 'critical': None,
                 'model_average_voltage_pu': sum(voltages)/len(voltages) if voltages and all(value is not None for value in voltages) else None,
                 'model_generation_mw': _total(topo.nodes, 'pg', topo.case_name),
                 'model_load_mw': _total(topo.nodes, 'pl', topo.case_name),
                 'model_reactive_generation_mvar': _total(topo.nodes, 'qg', topo.case_name),
                 'model_reactive_load_mvar': _total(topo.nodes, 'ql', topo.case_name),
                 'electrical_connections': len(topo.edges), 'measured_voltage_pu': None, 'measured_power_mw': None},
        'network': {'device_count': len(canonical['nodes']),
                    'connections': sum(link['core_link'] for link in canonical['links']),
                    'responding_components': monitoring if scoped else None,
                    'offline_components': offline if scoped else None,
                    'status': 'Monitoring' if monitoring else 'Offline' if scoped and offline == len(components) else 'Not available',
                    'bandwidth_capacity_bps': None, 'observed_traffic': rate, 'recent_detection_notices': detections},
        'provenance': {'electrical': ('Run-scoped Pandapower results driven by declared Modbus readbacks; simulated electrical state, not physical sensor measurements.' if physical and physical.get('power_flow_success') else 'Physical recalculation/readback failed; current voltages unavailable.' if physical is not None else 'Canonical topology model / baseline values; not live measurements. Custom model defaults may be present.'),
                       'scada': 'Latest retained SCADA holding-register read within the current assessment and 120 seconds. Monitoring means communication was observed; Offline means the latest read failed.',
                       'live_electrical': 'Not available: existing SCADA polls do not read the input-register voltage/power measurements. Electrical health classifications and line loading are not established.',
                       'power': 'Preset zero placeholders are not presented as calculated power. Custom generation/load values are model configuration, not measured output.',
                       'traffic': 'Suricata flow observations: 8 × latest byte totals per unique flow / elapsed observed window. Both endpoints must belong to the selected network; flows must begin after session/run start and within 120 seconds. This is an observed traffic rate, not bandwidth capacity or total network utilization.',
                       'scope': 'Live telemetry unavailable without a matching active assessment/session/topology. Recent detection notices cover the latest 100 run security events.'}}
