"""Two bounded ICMP probes in a dedicated canonical smoke topology only."""
from ipaddress import ip_interface
from firewall.runtime import counters, verify


def probe(c, session, plan, status, record):
    if not plan["canonical_document"].get("metadata", {}).get("controlled_firewall_smoke"):
        raise ValueError("Packet probes require the dedicated controlled firewall smoke topology.")
    if not verify(c, session, plan, status).get("enforced"):
        raise RuntimeError("Firewall installation is not currently verified.")
    by_id = {d["id"]: d for d in plan["devices"]}
    flows = (("allowed", "client", "destination", "allow-client"), ("denied", "denied_client", "destination", "deny-client"))
    results = []
    for expected, source, destination, rid in flows:
        if source not in by_id or destination not in by_id: raise ValueError("Smoke endpoint missing from active canonical topology.")
        src = str(ip_interface(by_id[source]["interfaces"][0]["ip"]).ip)
        dst = str(ip_interface(by_id[destination]["interfaces"][0]["ip"]).ip)
        index = next(i for i, rule in enumerate(plan["compiled"]["rules"]) if rule["rule_id"] == rid)
        rule = plan["compiled"]["rules"][index]
        if rule["action"] != ("accept" if expected == "allowed" else "drop") or rule["protocol"] != "icmp":
            raise ValueError("Controlled smoke rule semantics do not match the probe.")
        before = counters(c, session, plan)
        code, output = c.node_command(session.id, plan["node_ids"][source], f"timeout 5 ping -n -c 1 -W 2 -I {src} {dst}", shell=True)
        after = counters(c, session, plan)
        delta = after[f"ascend:{index}"] - before[f"ascend:{index}"]
        passed = delta > 0 and (code == 0 if expected == "allowed" else code == 1)
        result = {"expected": expected, "source": source, "destination": destination, "source_ip": src,
                  "destination_ip": dst, "exit_code": code, "output": output, "counter_delta": delta,
                  "rule_id": rid, "verified": passed, "generation_id": status["generation_id"], "revision": plan["revision"]}
        record("packet_allowed" if passed and expected == "allowed" else "packet_denied" if passed else "packet_verification_failed", result)
        results.append(result)
    return {"packet_enforcement_verified": all(r["verified"] for r in results), "probes": results}
