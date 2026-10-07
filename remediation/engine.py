"""Structured deterministic advice using finding and imported policy context."""
from copy import deepcopy
from firewall.model import evaluate

MODBUS_TECHNIQUES = {"T0836", "T0835", "T0832", "T0815", "T0830", "T0806", "T0814", "T0869", "T0801", "T0802", "T0888"}


def recommend(finding, topology=None):
    if not isinstance(finding, dict):
        raise ValueError("Finding must be an object.")
    topology = topology or {}
    devices = topology.get("network", {}).get("devices", [])
    asset = finding.get("affected_asset", finding.get("target", "unknown"))
    # Exact IDs or explicit IP/name metadata only; never guess plc8 equals a GNS3 UUID.
    matches = [d for d in devices if asset in (d["id"], d.get("name"), d.get("ip"))]
    device = matches[0] if len(matches) == 1 else None
    target = device["id"] if device else asset
    technique = finding.get("attack_technique", finding.get("technique_id", "unknown"))
    protocol = str(finding.get("protocol", "tcp" if technique in MODBUS_TECHNIQUES else "unknown")).lower()
    port = finding.get("destination_port", 502 if technique in MODBUS_TECHNIQUES else None)
    path = finding.get("attack_path") or []
    path = path if isinstance(path, list) else []
    policies = topology.get("firewalls", []) if device else []
    current = {"asset_mapping": "matched" if device else "unavailable", "firewalls": deepcopy(policies),
               "firewall_devices": [{"id": d["id"], "name": d.get("name", d["id"])} for d in devices if device and d["type"] == "firewall"],
               "note": "Imported policy model only; firewall traversal and runtime enforcement are not established."}
    assessments = []
    if device and protocol in {"tcp", "udp", "icmp"}:
        attackers = [d for d in devices if d["type"] == "attacker"]
        for policy in policies:
            if policy.get("configuration_available") is False or policy.get("evaluation_supported") is False or policy.get("import_complete") is False:
                continue
            for attacker in attackers:
                verdict = evaluate(policy, {"source": attacker["id"], "destination": target, "protocol": protocol,
                    "destination_port": port, "source_zone": attacker.get("zone"), "destination_zone": device.get("zone")})
                assessments.append({"firewall_id": policy["id"], "source": attacker["id"], **verdict})
    current["modeled_attack_access"] = assessments
    allowed = any(row["allowed"] for row in assessments)
    denied = bool(assessments) and not allowed
    weakness = ("Imported policy model permits attacker access to the affected service; actual path/enforcement require verification." if allowed else
                "Imported policies deny modeled attacker access; investigate bypass paths or unapplied policy rather than claiming a missing deny rule." if denied else
                "Unauthorized service access is a hypothesis to investigate; effective firewall configuration is unavailable.")
    proposed = []
    if technique in MODBUS_TECHNIQUES or port == 502:
        authorized = [d for d in devices if d["type"] == "scada"] if device else []
        proposed = [{"rule_id": f"proposed-scada-{i}", "priority": i, "source": d["id"], "destination": target,
                     "protocol": "tcp", "source_port": "any", "destination_port": 502, "action": "allow"} for i, d in enumerate(authorized)]
        if authorized:
            proposed.append({"rule_id": "proposed-modbus-deny", "priority": len(authorized), "source": "any", "destination": target,
                             "protocol": "tcp", "source_port": "any", "destination_port": 502, "action": "deny"})
        change = ("Review existing rule order and restrict TCP/502 to verified authorized SCADA identities. Place specific allows before the deny and ahead of broader permits. "
                  "Confirm identity/IP bindings, firewall placement, and legitimate traffic before applying. "
                  "If policy already denies this traffic, verify deployment and alternate routes.")
        benefit = "If enforced on every relevant path, reduces unauthorized Modbus access while preserving approved SCADA polling. Does not establish physical recovery."
    else:
        change = finding.get("remediation") or "Review the affected service, reduce unnecessary access, and implement technique-specific monitoring."
        benefit = "Expected reduction of the identified attack surface; effectiveness must be measured by a controlled re-test."
    return {"finding": finding.get("id", finding.get("finding", "unidentified")), "severity": finding.get("severity", "Unavailable"),
            "affected_asset": asset, "attack_technique": technique, "attack_name": finding.get("technique_name"), "attack_path": deepcopy(path),
            "protocol": protocol, "service_port": port, "observed_weakness": weakness,
            "current_configuration": current, "recommended_change": change, "proposed_rules": proposed,
            "expected_security_benefit": benefit, "retest_procedure": [
                "Record baseline authorized SCADA connectivity and the original technique, target, parameters, and evidence IDs.",
                "Have an engineer review and deploy the proposed control; independently verify effective configuration/interface state.",
                "Repeat the same attack from the same source; collect firewall counters/logs, connectivity and target read-back evidence.",
                "Verify authorized SCADA still works and compare equivalent before/after outcomes. No voltage or physical recovery is inferred."],
            "status": "proposed_not_applied", "applied": False,
            "limitations": ["Recommendation only; no firewall deployment or automatic re-test.",
                "Imported topology is design context, not proof of the active CORE path."]}
