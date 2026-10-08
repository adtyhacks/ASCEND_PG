"""Local imported design workspace, deliberately separate from live CORE topology."""
import json
import os
import tempfile
import hashlib
from copy import deepcopy
from pathlib import Path
from html import escape
from testbed.external_topology import parse_native, parse_gns3, validate, visual_data, normalize_saved_gns3, SCHEMA
from firewall.model import evaluate

PATH = Path(__file__).resolve().parents[1] / "data" / "imported_topology.json"


def candidate():
    if not PATH.exists():
        return None
    return validate(normalize_saved_gns3(json.loads(PATH.read_text(encoding="utf-8"))))


def _atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, suffix=".tmp", delete=False) as out:
            temporary = Path(out.name); json.dump(value, out, indent=2)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists(): temporary.unlink()


def current():
    """Only the explicitly active imported design is eligible for new run context."""
    from testbed.topology import get_topology
    return get_topology().exchange


def use_imported(data):
    from gui.adapter import _require_topology_editable
    _require_topology_editable()
    document = candidate()
    if not document: raise ValueError("Validate an imported topology first.")
    if data.get("revision") != revision(document):
        raise ValueError("Imported preview changed. Reload and validate before using it.")
    from testbed.topology import Topology, activate_topology
    activate_topology(Topology.from_exchange(document))
    return active()


def use_canonical():
    """Compatibility hook: the selector already activated the canonical object."""
    return None


def revision(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


def policies(document):
    """Device identity does not imply imported rules; fallback is explicitly modeled."""
    explicit = {p["id"]: p for p in document.get("firewalls", [])}
    result = []
    for device in document["network"]["devices"]:
        if device["type"] != "firewall": continue
        policy = deepcopy(explicit.get(device["id"], {"id": device["id"], "rules": [], "default_action": None, "evaluation_supported": False}))
        policy.setdefault("configuration_available", device["id"] in explicit)
        policy.setdefault("interfaces", deepcopy(device.get("interfaces", [])))
        policy["name"] = device.get("name", device["id"])
        policy.setdefault("configuration_origin", "imported" if policy["configuration_available"] else "configuration_unavailable")
        result.append(policy)
    return result


def active():
    from testbed.topology import get_topology
    topology = get_topology(); document = topology.exchange
    source = "external" if document else "canonical"
    if not document:
        snapshot = topology.canonical_snapshot()
        document = {"schema": SCHEMA, "name": topology.case_name, "network": {"devices": [
            {"id": n["id"], "name": n["hostname"], "type": "switch" if n["node_type"] == "hub" else n["node_type"],
             "ip": n.get("ip"), "interfaces": [{"id": p, "name": p} for p in n.get("interfaces", [])]} for n in snapshot["nodes"]]},
             "power_grid": {"buses": [], "lines": [], "generators": [], "loads": []}, "links": [], "mapping": [], "firewalls": []}
    return {"source": source, "canonical_source": topology.source, "revision": topology.revision, "preview_revision": revision(document), "document": document, "firewall_policies": policies(document),
            "pyvis_html": preview(document)["pyvis_html"] if source == "external" else None,
            "runtime_supported": topology.core_compatible, "capabilities": topology.capability_status(),
            "node_count": len(topology.canonical_snapshot()["nodes"]), "link_count": len(topology.canonical_snapshot()["links"])}


def preview(document):
    from testbed.visualize_topology import render_topology
    nodes, edges = visual_data(document)
    # Renderer interpolates tooltip labels as HTML. Uploaded text must stay text.
    nodes = [{**node, "label": escape(node["label"])} for node in nodes]
    edges = [{**edge, "protocol": escape(str(edge.get("protocol", "network")))} for edge in edges]
    return {"document": document, "revision": revision(document), "pyvis_html": render_topology(nodes, edges), "valid": True,
            "warnings": ["Import validation does not deploy CORE or install rules. Deployment compatibility is evaluated for the active canonical topology.", *document.get("metadata", {}).get("warnings", [])]}


def import_document(data):
    kind = data.get("format")
    filename = data.get("filename")
    if filename is not None and not isinstance(filename, str):
        raise ValueError("filename must be a string when provided.")
    if isinstance(filename, str) and filename.lower().endswith(".gns3"):
        kind = "gns3"
    if kind not in ("ascend", "gns3"):
        raise ValueError("format must be ascend or gns3.")
    if type(data.get("save", True)) is not bool:
        raise ValueError("save must be a Boolean.")
    document = (parse_gns3 if kind == "gns3" else parse_native)(data.get("document"))
    result = preview(document)  # Validate and render before replacing last successful import.
    if data.get("save", True):
        _atomic(PATH, document)
    return result


def workspace():
    document = candidate()
    return preview(document) if document else {"document": None, "valid": False, "pyvis_html": None, "warnings": []}


def decision(data):
    context = active(); document = context["document"]
    if data.get("revision") is not None and data["revision"] != context["revision"]:
        raise ValueError("Active topology changed. Reload firewall context.")
    policy = next((p for p in context["firewall_policies"] if p["id"] == data.get("firewall_id")), None)
    if policy is None:
        raise ValueError("Unknown firewall_id.")
    if not isinstance(data.get("traffic"), dict):
        raise ValueError("traffic must be an object.")
    traffic = dict(data["traffic"])
    for side in ("source", "destination"):
        device = next((d for d in document["network"]["devices"] if d["id"] == traffic.get(side)), None)
        # Derive zones from model metadata rather than trusting client-supplied identity.
        traffic[side + "_zone"] = device.get("zone") if device else None
        traffic[side + "_addresses"] = ([device["ip"]] if device and device.get("ip") else []) + [p["ip"] for p in (device or {}).get("interfaces", []) if p.get("ip")]
    valid_devices = {d["id"] for d in document["network"]["devices"]}
    if any(not isinstance(traffic.get(side), str) or traffic[side] not in valid_devices for side in ("source", "destination")):
        raise ValueError("Source and destination must belong to the active topology.")
    return {**evaluate(policy, traffic), "configuration_origin": policy["configuration_origin"], "revision": context["revision"]}
