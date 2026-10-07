"""Namespace-scoped firewall operations, called only under CORE helper locks."""
import hashlib
import json
import os
import shlex
from ipaddress import ip_network
from firewall.compiler import nft_script


def _command(c, session, node_id, command):
    code, output = c.node_command(session.id, node_id, command, shell=True)
    if code: raise RuntimeError(f"CORE firewall command failed ({code}): {output}")
    return output


def _fingerprint(value):
    def clean(item):
        if isinstance(item, dict): return {k: clean(v) for k, v in item.items() if k not in ("handle", "packets", "bytes", "metainfo")}
        if isinstance(item, list): return [clean(v) for v in item if not isinstance(v, dict) or "metainfo" not in v]
        return item
    return hashlib.sha256(json.dumps(clean(value), sort_keys=True).encode()).hexdigest()


def _validate_rule(observed, expected):
    actual = {}
    expressions = observed.get("expr", [])
    if sum("counter" in e for e in expressions) != 1 or not expressions or not any(k in expressions[-1] for k in ("accept", "drop")):
        raise RuntimeError("Installed rule requires a counter and terminal verdict.")
    for expr in observed.get("expr", []):
        if "counter" in expr: continue
        if "accept" in expr or "drop" in expr:
            if "action" in actual: raise RuntimeError("Duplicate rule verdict.")
            actual["action"] = "accept" if "accept" in expr else "drop"
            continue
        match = expr.get("match", {})
        left = match.get("left", {}).get("payload", {})
        key = (left.get("protocol"), left.get("field"))
        if match.get("op") != "==" or key not in (("ip", "saddr"), ("ip", "daddr"), ("ip", "protocol"), ("tcp", "sport"), ("tcp", "dport"), ("udp", "sport"), ("udp", "dport")) or key in actual:
            raise RuntimeError("Unexpected or duplicate installed rule expression.")
        right = match["right"]
        if key[1] in ("saddr", "daddr"):
            if isinstance(right, dict) and "prefix" in right: right = f"{right['prefix']['addr']}/{right['prefix']['len']}"
            right = str(ip_network(right, strict=False))
        if key[1] == "protocol": right = {1: "icmp", 6: "tcp", 17: "udp"}.get(right, right)
        actual[key] = right
    wanted = {"action": expected["action"]}
    for side, field in (("source", "saddr"), ("destination", "daddr")):
        if expected.get(side): wanted[("ip", field)] = expected[side]
    protocol = expected.get("protocol", "any")
    if protocol != "any": wanted[("ip", "protocol")] = protocol
    for port, field in (("source_port", "sport"), ("destination_port", "dport")):
        if expected.get(port) not in (None, "any"): wanted[(protocol, field)] = expected[port]
    if actual != wanted: raise RuntimeError("Installed firewall rule semantics differ from canonical policy.")


def _observe(c, session, nid, compiled):
    value = json.loads(_command(c, session, nid, "nft -j list ruleset"))
    objects = value["nftables"]
    tables = [o["table"] for o in objects if "table" in o]
    if len(tables) != 1 or tables[0].get("name") != "ascend_fw" or tables[0].get("family") != "ip":
        raise RuntimeError("Unexpected nftables tables in firewall namespace.")
    chains = [o["chain"] for o in objects if "chain" in o]
    if len(chains) != 1 or chains[0].get("hook") != "forward" or chains[0].get("policy") != "drop" or chains[0].get("prio") != 0 or chains[0].get("type") != "filter":
        raise RuntimeError("Firewall forward hook/default guard is missing.")
    rules = [o["rule"] for o in objects if "rule" in o]
    if [r.get("comment") for r in rules] != [f"ascend:{i}" for i in range(len(compiled["rules"]))] + ["ascend:default"]:
        raise RuntimeError("Installed firewall rule count/order does not match compiled policy.")
    for observed, expected in zip(rules, compiled["rules"] + [{"action": compiled["default"]}]):
        _validate_rule(observed, expected)
    return value


def install(c, session, plan, generation, record):
    fw = plan["firewall_id"]; nid = plan["node_ids"][fw]
    name = next(d.get("name", d["id"]) for d in plan["devices"] if d["id"] == fw)
    status = {"firewall": name, "firewall_id": fw, "enforced": False, "backend": "nftables", "rules_installed": 0,
              "generation_id": generation, "session_id": session.id, "revision": plan["revision"], "policy_digest": plan["compiled"]["digest"]}
    try:
        # This check precedes every mutating node command. Never touch host nftables.
        namespace = _command(c, session, nid, "readlink /proc/self/ns/net").strip()
        if not namespace.startswith("net:[") or namespace == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("Firewall node is not an isolated network namespace.")
        status["namespace"] = namespace
        record("firewall_initialized", {**status, "namespace": namespace})
        _command(c, session, nid, "sysctl -qw net.ipv4.ip_forward=0")
        _command(c, session, nid, "command -v nft")
        existing = json.loads(_command(c, session, nid, "nft -j list ruleset"))
        if any(k != "metainfo" for item in existing.get("nftables", []) for k in item):
            raise RuntimeError("Firewall namespace has pre-existing rules; refusing to overwrite them.")
        script = nft_script(plan["compiled"])
        record("firewall_configuration_loaded", {**status, "compiled": plan["compiled"]})
        payload = shlex.quote(script)
        _command(c, session, nid, f"printf %s {payload} | nft -c -f -")
        _command(c, session, nid, f"printf %s {payload} | nft -f -")
        observed = _observe(c, session, nid, plan["compiled"])
        status.update(rules_installed=len(plan["compiled"]["rules"]), installed_fingerprint=_fingerprint(observed), namespace=namespace)
        record("firewall_rules_installed", status)
        _command(c, session, nid, "sysctl -qw net.ipv4.ip_forward=1")
        if _command(c, session, nid, "sysctl -n net.ipv4.ip_forward").strip() != "1":
            raise RuntimeError("Firewall forwarding did not become active.")
        status["enforced"] = True
    except Exception as exc:
        status["error"] = str(exc)
        # Only issue cleanup after proving the namespace is isolated.
        if status.get("namespace"):
            try: _command(c, session, nid, "sysctl -qw net.ipv4.ip_forward=0")
            except Exception as cleanup: status["error"] += f"; fail-closed forwarding shutdown failed: {cleanup}"
        record("firewall_installation_failed", status)
    record("firewall_enforcement_state", status)
    return status


def verify(c, session, plan, saved):
    status = dict(saved)
    if not saved.get("enforced"): return status
    isolated = False
    try:
        if saved.get("session_id") != session.id or saved.get("revision") != plan["revision"] or saved.get("policy_digest") != plan["compiled"]["digest"]:
            raise RuntimeError("Saved firewall installation belongs to a different runtime topology.")
        nid = plan["node_ids"][plan["firewall_id"]]
        if _command(c, session, nid, "readlink /proc/self/ns/net").strip() != saved["namespace"]:
            raise RuntimeError("Firewall namespace identity changed.")
        isolated = saved["namespace"] != os.readlink("/proc/self/ns/net")
        if not isolated: raise RuntimeError("Firewall is in the host namespace.")
        observed = _observe(c, session, nid, plan["compiled"])
        if _fingerprint(observed) != saved["installed_fingerprint"]: raise RuntimeError("Firewall rules changed after installation.")
        if _command(c, session, nid, "sysctl -n net.ipv4.ip_forward").strip() != "1": raise RuntimeError("Firewall forwarding is disabled.")
    except Exception as exc:
        status.update(enforced=False, error=str(exc))
        if isolated:
            try: _command(c, session, nid, "sysctl -qw net.ipv4.ip_forward=0")
            except Exception as cleanup: status["error"] += f"; fail-closed forwarding shutdown failed: {cleanup}"
    return status


def counters(c, session, plan):
    nid = plan["node_ids"][plan["firewall_id"]]
    observed = _observe(c, session, nid, plan["compiled"])
    return {o["rule"]["comment"]: sum(e["counter"]["packets"] for e in o["rule"]["expr"] if "counter" in e)
            for o in observed["nftables"] if "rule" in o}
