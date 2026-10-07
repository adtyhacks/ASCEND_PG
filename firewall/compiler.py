"""Strict stateless IPv4 policy compilation. No connection-state bypass rules."""
import hashlib
import json
from ipaddress import ip_interface, ip_network
from firewall.model import validate_policy


def compile_policy(policy, devices):
    validate_policy(policy)
    if policy.get("configuration_available") is False or policy.get("import_complete") is False or policy.get("evaluation_supported") is False:
        raise ValueError("Firewall configuration is unavailable, partial, or unsupported.")
    if policy.get("default_action") not in ("allow", "deny"):
        raise ValueError("Runtime firewall requires an explicit default policy.")
    by_id = {d["id"]: d for d in devices}
    def selector(value):
        if value.lower() == "any": return None
        if value in by_id:
            d = by_id[value]
            addresses = {str(ip_interface(p["ip"]).ip) for p in d.get("interfaces", []) if p.get("ip")}
            if d.get("ip"): addresses.add(str(ip_interface(d["ip"]).ip))
            if len(addresses) != 1: raise ValueError(f"Endpoint {value} requires exactly one explicit address.")
            value = addresses.pop()
        if value.startswith(("zone:", "object:")):
            raise ValueError("Runtime compilation requires resolved address selectors.")
        network = ip_network(value, strict=False)
        if network.version != 4: raise ValueError("Runtime compiler currently supports IPv4 only.")
        return str(network)
    rules = []
    for _, rule in sorted(enumerate(policy.get("rules", [])), key=lambda pair: (pair[1]["priority"], pair[0])):
        if rule.get("service") or rule.get("acl"):
            raise ValueError("Scoped ACL or service-reference policies cannot be flattened.")
        protocol = rule["protocol"].lower()
        ports = {key: rule.get(key) for key in ("source_port", "destination_port")}
        if protocol not in ("tcp", "udp") and any(p not in (None, "any") for p in ports.values()):
            raise ValueError("Port constraints require TCP or UDP; semantics cannot be broadened.")
        rules.append({"rule_id": rule["rule_id"], "source": selector(rule["source"]), "destination": selector(rule["destination"]),
                      "protocol": protocol, **ports, "action": "accept" if rule["action"] == "allow" else "drop"})
    compiled = {"rules": rules, "default": "accept" if policy["default_action"] == "allow" else "drop"}
    compiled["digest"] = hashlib.sha256(json.dumps(compiled, sort_keys=True).encode()).hexdigest()
    return compiled


def nft_script(compiled):
    lines = ["table ip ascend_fw {", " chain forward {", "  type filter hook forward priority 0; policy drop;"]
    for index, rule in enumerate(compiled["rules"]):
        terms = []
        for side, token in (("source", "saddr"), ("destination", "daddr")):
            if rule[side]: terms.append(f"ip {token} {rule[side]}")
        protocol = rule["protocol"]
        if protocol != "any": terms.append(f"ip protocol {protocol}")
        for key, token in (("source_port", "sport"), ("destination_port", "dport")):
            if rule[key] not in (None, "any"): terms.append(f"{protocol} {token} {rule[key]}")
        terms.extend(["counter", rule["action"], f'comment "ascend:{index}"'])
        lines.append("  " + " ".join(terms))
    # Explicit terminal rule counts default decisions without inventing a bypass.
    lines += [f'  counter {compiled["default"]} comment "ascend:default"', " }", "}"]
    return "\n".join(lines) + "\n"
