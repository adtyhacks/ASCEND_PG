"""Bounded passive evidence retention and dimension-specific verification.

No network queries or arbitrary reference-file reads. Record references resolve
inside the retained bundle. Evidence producers are trusted application code;
verification checks corroborating facts, not self-declared verified/adverse flags.
"""
import ast
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path

IDENTITY = ("scenario_id", "run_id", "generation_id", "correlation_id")
MAX_RECORDS = 256
MAX_CAPTURE = 131072


def stamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo else None
    except (AttributeError, TypeError, ValueError):
        return None


def passive_scada(path):
    """Read a bounded tail of already-written SCADA observations, never poll."""
    try:
        with Path(path).open("rb") as source:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - 524288))
            lines = source.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or (row.get("observation_type") != "poll_result" and row.get("action") != "poll_failed"):
            continue
        records.append({"kind": "state_read", "source": "passive_scada",
            "timestamp": row.get("timestamp"), "target": row.get("target"),
            "address": row.get("address"), "space": "holding", "count": row.get("count"),
            "available": row.get("observation_type") == "poll_result", "values": row.get("registers")})
    return records[-MAX_RECORDS:]


def attack_log_records(path, step_name):
    """Normalize existing structured ACK/count logs; counts do not prove impact."""
    actions = {"cmd_inject_coil": "coil_inject", "device_restart": "device_restart",
               "service_stop": "service_stop_end"}
    wanted = actions.get(step_name)
    if not wanted:
        return []
    try:
        with Path(path).open("rb") as source:
            source.seek(0, 2); source.seek(max(0, source.tell() - 524288))
            lines = source.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or row.get("action") != wanted:
            continue
        if step_name == "service_stop":
            records.append({"kind": "disruption_attempt", "source": "attack_log",
                "timestamp": row.get("timestamp"), "target": row.get("target"),
                "packets_sent": row.get("packets_sent"), "actor": "attacker"})
        else:
            if step_name == "cmd_inject_coil" and row.get("status") != "success":
                continue
            records.append({"kind": "write_ack", "source": "attack_log", "actor": "attacker",
                "timestamp": row.get("timestamp"), "target": row.get("target"),
                "address": row.get("address"), "space": "coil", "value": row.get("value"),
                "count": row.get("count", 1)})
    return records[-MAX_RECORDS:]


def retain_evidence(step_name, stdout, stderr, end_time, scada_records=(), attack_records=()):
    """Parse known module output only. ACKs are retained but are not impact."""
    text = (stdout or "")[:MAX_CAPTURE] + "\n" + (stderr or "")[:MAX_CAPTURE]
    records = list(scada_records) + list(attack_records)
    if step_name == "automated_collection":
        pattern = r"\[auto_collection\] (\d+\.\d+\.\d+\.\d+) (holding|input)\[(\d+):\d+\] = (\[[^\n]*\])"
        for match in re.finditer(pattern, text):
            try:
                values = ast.literal_eval(match[4])
                ipaddress.ip_address(match[1])
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                continue
            if not isinstance(values, list) or len(values) > 2048 or any(type(v) is not int or not 0 <= v <= 65535 for v in values):
                continue
            records.append({"kind": "collection_read", "source": "executor_output",
                "timestamp": end_time, "target": match[1], "space": match[2],
                "address": int(match[3]), "values": values, "count": len(values),
                "actor": "attacker", "timestamp_basis": "capture_end"})
    if step_name == "fdi_attack":
        for match in re.finditer(r"FDI SUCCESS: wrote value=(\d+) to register (\d+) on ([\d.]+):(\d+)", text):
            records.append({"kind": "write_ack", "source": "executor_output",
                "timestamp": end_time, "target": match[3], "space": "holding",
                "address": int(match[2]), "value": int(match[1]), "actor": "attacker",
                "timestamp_basis": "capture_end"})
    if step_name == "cmd_inject_coil":
        for match in re.finditer(r"COIL INJECTION SUCCESS: wrote value=(True|False) to (\d+) coil\(s\) at addr=(\d+) on ([\d.]+):(\d+)", text):
            records.append({"kind": "write_ack", "source": "executor_output",
                "timestamp": end_time, "target": match[4], "space": "coil",
                "address": int(match[3]), "value": match[1] == "True",
                "count": int(match[2]), "actor": "attacker", "timestamp_basis": "capture_end"})
    return {"version": "finding-evidence-v2", "records": records[-MAX_RECORDS:],
            "retention": {"record_limit": MAX_RECORDS, "capture_limit": MAX_CAPTURE,
                "capture_truncated": len(stdout or "") > MAX_CAPTURE or len(stderr or "") > MAX_CAPTURE}}


def bind_evidence(bundle, request, start, end):
    """Attach validated watcher identity and keep in-window observations only."""
    identity = {key: request.get(key) for key in IDENTITY}
    if not all(identity.values()) or not stamp(start) or not stamp(end):
        return {"version": "finding-evidence-v2", "records": [], "identity": identity}
    if (bundle or {}).get("identity") not in (None, identity):
        return {"version": "finding-evidence-v2", "records": [], "identity": identity}
    records = []
    for raw in (bundle or {}).get("records", [])[:MAX_RECORDS]:
        if not isinstance(raw, dict) or not stamp(raw.get("timestamp")) or not stamp(start) <= stamp(raw["timestamp"]) <= stamp(end):
            continue
        if any(raw.get(key) not in (None, identity[key]) for key in IDENTITY):
            continue
        row = {**raw, **identity, "step_id": identity["correlation_id"],
               "attack_window_start": start, "attack_window_end": end}
        row.pop("reference", None)
        row["reference"] = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
        records.append(row)
    return {**(bundle or {}), "identity": identity, "records": records}


def verify_impacts(bundle, expected_identity, start, end):
    """Return verified_adverse/verified_none/unknown, never infer physical/safety.

Integrity needs an attacker ACK bracketed by independent state reads, same target,
space and address, with the after value equal to the acknowledged write. Polling
availability needs successful baseline and two subsequent failed polls for the
same target/range. Attribution is temporal corroboration, not proof of causality.
Confidentiality needs retained data actually returned to the collection attack.
"""
    dimensions = ("integrity", "availability", "confidentiality", "operational_impact", "physical_impact", "safety_impact")
    result = {d: {"state": "unknown", "reason": "Qualifying evidence unavailable.", "references": []} for d in dimensions}
    if not isinstance(bundle, dict) or not all(expected_identity.get(k) for k in IDENTITY):
        return result
    if bundle.get("identity") != {k: expected_identity[k] for k in IDENTITY} or not stamp(start) or not stamp(end):
        return result
    records = []
    for row in bundle.get("records", [])[:MAX_RECORDS]:
        if not isinstance(row, dict) or any(row.get(k) != expected_identity[k] for k in IDENTITY):
            continue
        when = stamp(row.get("timestamp"))
        if not when or not stamp(start) <= when <= stamp(end):
            continue
        if (row.get("step_id") != expected_identity["correlation_id"]
            or stamp(row.get("attack_window_start")) != stamp(start)
            or stamp(row.get("attack_window_end")) != stamp(end)):
            continue
        try:
            ipaddress.ip_address(row.get("target"))
        except (ValueError, TypeError):
            continue
        check = {k: v for k, v in row.items() if k != "reference"}
        if row.get("reference") != hashlib.sha256(json.dumps(check, sort_keys=True, default=str).encode()).hexdigest():
            continue
        records.append(row)
    records.sort(key=lambda r: stamp(r["timestamp"]))
    reads = [r for r in records if r.get("kind") == "state_read" and r.get("source") == "passive_scada"]
    used_consequences = set()
    for action in records:
        if action.get("kind") != "write_ack" or action.get("source") not in ("executor_output", "attack_log") or action.get("actor") != "attacker":
            continue
        def same_range(row):
            return (row.get("target") == action.get("target") and row.get("space") == action.get("space")
                and type(row.get("address")) is int and type(action.get("address")) is int
                and row.get("available") is True
                and isinstance(row.get("values"), list) and type(action.get("address")) is int
                and all(type(v) in (int, bool) and 0 <= v <= 65535 for v in row["values"])
                and 0 <= action["address"] - row["address"] < len(row["values"]))
        def value(row):
            return row["values"][action["address"] - row["address"]]
        if action.get("timestamp_basis") == "capture_end":
            # Output lacks an exact write timestamp. Corroborate only a transition
            # from a different value to the ACKed value within the capture window.
            before = [r for r in reads if same_range(r) and value(r) != action.get("value")]
            after = [r for r in reads if same_range(r) and value(r) == action.get("value")]
        else:
            before = [r for r in reads if same_range(r) and stamp(r["timestamp"]) < stamp(action["timestamp"])]
            after = [r for r in reads if same_range(r) and stamp(r["timestamp"]) > stamp(action["timestamp"])]
        if not before or not after:
            continue
        a, b = before[-1], after[0]
        if stamp(a["timestamp"]) >= stamp(b["timestamp"]) or value(b) != action.get("value"):
            continue
        adverse = value(a) != value(b)
        result["integrity"] = {"state": "verified_adverse" if adverse else "verified_none",
            "references": [a["reference"], action["reference"], b["reference"]],
            "reason": "Attacker write corroborated by independent before/after state reads; observation scope only.",
            "attribution": "write_value_matched", "consequence": b["reference"],
            "observed_before": value(a), "observed_after": value(b), "units": "raw_modbus_value"}
        if adverse:
            used_consequences.add(b["reference"])
        break
    attempts = [r for r in records if r.get("kind") == "disruption_attempt" and r.get("source") == "attack_log"
                and r.get("actor") == "attacker" and type(r.get("packets_sent")) is int and r["packets_sent"] > 0]
    for before in reads:
        if before.get("available") is not True:
            continue
        if not any(r.get("target") == before.get("target") for r in attempts):
            continue
        following = [r for r in reads if r.get("target") == before.get("target")
            and r.get("address") == before.get("address") and r.get("count") == before.get("count")
            and stamp(r["timestamp"]) > stamp(before["timestamp"])]
        failed = [r for r in following if r.get("available") is False]
        if len(failed) >= 2 and not any(r.get("available") is True and stamp(failed[0]["timestamp"]) < stamp(r["timestamp"]) < stamp(failed[1]["timestamp"]) for r in following):
            controls = [r for r in reads if r.get("target") != before.get("target")
                and r.get("available") is True and r.get("count") == before.get("count")
                and stamp(failed[0]["timestamp"]) <= stamp(r["timestamp"]) <= stamp(failed[1]["timestamp"])]
            if not controls:
                continue
            consequence = failed[1]["reference"]
            if consequence in used_consequences:
                continue
            action = next(r for r in attempts if r.get("target") == before.get("target"))
            result["availability"] = {"state": "verified_adverse", "references": [before["reference"], action["reference"], failed[0]["reference"], consequence, controls[0]["reference"]],
                "reason": "Target-specific failed polls corroborated by baseline, disruption attempt and healthy control target; polling-level association, not proof of process failure.",
                "attribution": "target_specific_corroboration", "consequence": consequence,
                "observed_before": True, "observed_after": False, "units": "poll_success"}
            break
        if following and all(r.get("available") is True for r in following):
            result["availability"] = {"state": "verified_none", "references": [before["reference"], following[0]["reference"]],
                "reason": "No sustained polling disruption established in retained samples; not proof of continuous service health."}
    collected = [r for r in records if r.get("kind") == "collection_read" and r.get("source") == "executor_output"
        and r.get("actor") == "attacker" and isinstance(r.get("values"), list)
        and r.get("count") == len(r["values"]) and all(type(v) is int and 0 <= v <= 65535 for v in r["values"])]
    if collected:
        result["confidentiality"] = {"state": "verified_adverse" if any(r["values"] for r in collected) else "verified_none",
            "references": [r["reference"] for r in collected], "attribution": "attacker_retrieval",
            "reason": "Protocol data returned to collection attack; disclosure evidence, not physical/process impact.",
            "observed_value": sum(len(r["values"]) for r in collected), "units": "retrieved_values"}
    # Future explicit instrument records: current runtime produces none. Numeric
    # thresholds establish adverse excursions; coil/register labels cannot qualify.
    by_reference = {r["reference"]: r for r in records}
    for dimension, instrument in (("operational_impact", "process_sensor"),
                                   ("physical_impact", "physical_sensor"), ("safety_impact", "safety_sensor")):
        for row in records:
            if row.get("kind") != dimension or row.get("source") != "independent_instrument" or row.get("instrument_kind") != instrument:
                continue
            action = by_reference.get(row.get("action_reference"))
            if (not action or action.get("kind") != "write_ack" or action.get("actor") != "attacker"
                or action.get("target") != row.get("target") or stamp(action["timestamp"]) > stamp(row["timestamp"])
                or row.get("attribution_method") != "controlled_intervention"
                or not isinstance(row.get("units"), str) or not row["units"].strip()
                or not row.get("instrument_reference")):
                continue
            from math import isfinite
            numbers = [row.get(k) for k in ("observed_before", "observed_after", "safe_min", "safe_max")]
            try:
                valid = all(type(n) in (int, float) and isfinite(n) for n in numbers)
            except OverflowError:
                valid = False
            if not valid:
                continue
            before, after, lower, upper = numbers
            if lower > upper or not lower <= before <= upper:
                continue
            adverse = not lower <= after <= upper
            # A consequence reference may not earn points twice. Distinct instrument
            # outcomes are required for distinct process/physical/safety dimensions.
            consequence = row["instrument_reference"]
            if adverse and consequence in used_consequences:
                continue
            result[dimension] = {"state": "verified_adverse" if adverse else "verified_none",
                "references": [action["reference"], row["reference"]],
                "reason": "Controlled independent instrument observation against explicit safe limits.",
                "attribution": "controlled_intervention", "consequence": consequence,
                "observed_before": before, "observed_after": after, "units": row["units"]}
            if adverse:
                used_consequences.add(consequence)
            break
    for dimension, verdict in result.items():
        verdict.update(dimension=dimension, **expected_identity,
            step_id=expected_identity["correlation_id"], attack_window_start=start, attack_window_end=end,
            verified=verdict["state"] != "unknown", adverse=verdict["state"] == "verified_adverse")
        references = [by_reference[r] for r in verdict["references"] if r in by_reference]
        if references:
            verdict["timestamp"] = max((r["timestamp"] for r in references), key=stamp)
            verdict["source"] = sorted({r["source"] for r in references})
    return result
