"""Explicit environment projections. Sample data never reads runtime state."""
import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from data.mitre_registry import TECHNIQUES
from defense.detection_result import decorate_event

ROOT = Path(__file__).resolve().parents[1]


def rules_from_file(path):
    """Parse the rules used by CORE's -S argument, retaining shared SID coverage."""
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.lstrip().startswith("alert "):
            continue
        sid = re.search(r"sid:\s*(\d+);", line)
        message = re.search(r'msg:"([^\"]+)";', line)
        if sid and message:
            sid = int(sid.group(1))
            rows.append({"sid": sid, "name": message.group(1),
                         "technique": ", ".join(t["id"] for t in TECHNIQUES if sid in t["detect_sids"]),
                         "rule": line})
    return rows


def topology_summary(topology):
    nodes = topology.get("nodes", [])
    plcs = [n for n in nodes if n.get("node_type") == "plc"]
    switches = [n for n in nodes if n.get("node_type") in {"hub", "switch"}]
    ids = next((n for n in nodes if n.get("id") == "ids_monitor"), {})
    subnet = str(ipaddress.ip_network(plcs[0]["ip"] + "/24", strict=False)) if plcs else "Unavailable: no saved PLC addresses"
    return {"hosts": sum(n.get("node_type") not in {"hub", "switch"} for n in nodes),
            "plcs": len(plcs), "switch": ", ".join(f'{n["hostname"]} (CORE {n["node_type"]})' for n in switches) or "Unavailable",
            "network": subnet, "protocol": "Modbus/TCP (502)" if plcs else "Unavailable",
            "ids_interface": ", ".join(ids.get("interfaces", [])) or "Unavailable"}


@lru_cache(maxsize=1)
def sample_environment():
    # Fixed case, deliberately independent of get_topology()/selected topology.
    import json
    from testbed.visualize_topology import render_topology
    topology = json.loads((ROOT / "data/sample_topologies/ics_sample.json").read_text(encoding="utf-8"))["topology"]
    events = []
    for i, tid in enumerate(("T0886", "T0816", "T0832")):
        tech = next(t for t in TECHNIQUES if t["id"] == tid)
        events.append(decorate_event({"event_type": "attack_finished", "mitre_technique": tid,
            "technique_name": tech["name"], "target_node": f"plc{i + 1}", "result": "Sample scenario",
            "sample": True, "detected": None, "detection_evaluated": False,
            "evidence": {"step_name": tech["default_step"]}, "timestamp": None}))
    nodes = [{"id": n["id"], "label": n["hostname"], "type": n["node_type"]} for n in topology["nodes"]]
    edges = [{"from": e["from"], "to": e["to"], "type": e["type"]} for e in topology["links"]]
    return {"environment_mode": "sample", "label": "SAMPLE", "topology": topology,
            "topology_summary": topology_summary(topology), "rules": rules_from_file(ROOT / "detection/suricata/modbus_rules.rules"),
            "security_events": events, "pyvis_html": render_topology(nodes, edges)}


def campaign_environment(run):
    from testbed import run_store
    import json
    path = run_store._path(run["scenario_id"], run["run_id"]) / "scenario.json"
    topology = json.loads(path.read_text(encoding="utf-8")).get("topology", {}) if path.is_file() else {}
    return {"environment_mode": "campaign", "topology": topology,
            "topology_summary": topology_summary(topology) if topology else {},
            # A bundled rules file does not prove an active runtime loaded it.
            "rules": run.get("active_suricata_rules", []),
            "rules_reason": "Active rule snapshot unavailable for this campaign." if not run.get("active_suricata_rules") else "Saved active campaign rule snapshot."}
