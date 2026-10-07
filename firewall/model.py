"""Deterministic first-match firewall policy with explicit default action."""
from ipaddress import ip_address, ip_network, ip_interface


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("Firewall policy must be an object.")
    if policy.get("default_action", "deny") not in ("allow", "deny") and not (policy.get("default_action") is None and policy.get("evaluation_supported") is False):
        raise ValueError("Firewall default_action must be allow or deny.")
    for field in ("configuration_available", "import_complete", "evaluation_supported"):
        if field in policy and type(policy[field]) is not bool:
            raise ValueError(f"Firewall {field} must be a Boolean.")
    for field in ("name", "hostname"):
        if field in policy and not isinstance(policy[field], str):
            raise ValueError(f"Firewall {field} must be a string.")
    if policy.get("configuration_available") is False and policy.get("rules"):
        raise ValueError("Unavailable firewall configuration cannot contain rules.")
    for field in ("interfaces", "zones", "address_objects", "services"):
        if field in policy:
            items = policy[field]
            if not isinstance(items, list) or any(not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] for item in items):
                raise ValueError(f"Firewall {field} must contain objects with IDs.")
            if len({item["id"] for item in items}) != len(items):
                raise ValueError(f"Firewall {field} IDs must be unique.")
            if field == "interfaces":
                from ipaddress import ip_interface
                for item in items:
                    if item.get("ip") is not None:
                        try: ip_interface(item["ip"])
                        except (ValueError, TypeError): raise ValueError("Invalid firewall interface address.") from None
    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Firewall rules must be a list.")
    ids = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each firewall rule must be an object.")
        rid = rule.get("rule_id")
        if not isinstance(rid, str) or not rid or rid in ids:
            raise ValueError("Firewall rule_id must be nonempty and unique within the policy.")
        ids.add(rid)
        if type(rule.get("priority")) is not int or rule["priority"] < 0:
            raise ValueError(f"Rule {rid}: priority must be a nonnegative integer.")
        if rule.get("action") not in ("allow", "deny"):
            raise ValueError(f"Rule {rid}: action must be allow or deny.")
        for field in ("source", "destination", "protocol"):
            if not isinstance(rule.get(field), str) or not rule[field].strip():
                raise ValueError(f"Rule {rid}: {field} must be a nonempty string.")
        if rule["protocol"].lower() not in {"any", "tcp", "udp", "icmp"}:
            raise ValueError(f"Rule {rid}: supported protocols are any, tcp, udp, icmp.")
        for field in ("source_port", "destination_port"):
            port = rule.get(field, "any")
            if port != "any" and port is not None and (type(port) is not int or not 0 <= port <= 65535):
                raise ValueError(f"Rule {rid}: {field} must be any, null, or an integer 0–65535.")
    return policy


def _endpoint(selector, endpoint, zone=None):
    if selector.lower() == "any":
        return True
    if selector.startswith("zone:"):
        return zone == selector[5:]
    if selector == endpoint:
        return True
    try:
        return ip_address(endpoint) in ip_network(selector, strict=False)
    except ValueError:
        return False


def evaluate(policy, traffic):
    """Endpoint selectors: device ID, IP/CIDR, any, or zone:<name>."""
    validate_policy(policy)
    if policy.get("evaluation_supported") is False or policy.get("configuration_available") is False or policy.get("import_complete") is False:
        raise ValueError("Firewall configuration unavailable or unsupported for model evaluation.")
    if not isinstance(traffic, dict):
        raise ValueError("Traffic must be an object.")
    for field in ("source", "destination", "protocol"):
        if not isinstance(traffic.get(field), str) or not traffic[field]:
            raise ValueError(f"Traffic {field} is required.")
    if traffic["protocol"].lower() not in {"tcp", "udp", "icmp"}:
        raise ValueError("Traffic protocol must be tcp, udp, or icmp.")
    for field in ("source_port", "destination_port"):
        value = traffic.get(field)
        if value is not None and (type(value) is not int or not 0 <= value <= 65535):
            raise ValueError(f"Traffic {field} must be an integer 0–65535.")
    for _, rule in sorted(enumerate(policy.get("rules", [])), key=lambda pair: (pair[1]["priority"], pair[0])):
        def matches(side):
            return _endpoint(rule[side], traffic[side], traffic.get(side + "_zone")) or any(
                _endpoint(rule[side], str(ip_interface(address).ip)) for address in traffic.get(side + "_addresses", []))
        if not matches("source"):
            continue
        if not matches("destination"):
            continue
        if rule["protocol"].lower() not in {"any", traffic["protocol"].lower()}:
            continue
        if any(rule.get(field) not in (None, "any", traffic.get(field)) for field in ("source_port", "destination_port")):
            continue
        return {"allowed": rule["action"] == "allow", "action": rule["action"], "matched_rule_id": rule["rule_id"], "enforced": False, "basis": "model_first_match"}
    action = policy.get("default_action", "deny")
    return {"allowed": action == "allow", "action": action, "matched_rule_id": None, "enforced": False, "basis": "model_default"}
