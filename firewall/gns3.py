"""Import supplied configuration only; never read paths or contact appliances."""
from copy import deepcopy
from ipaddress import ip_interface, ip_network
from firewall.model import normalize_policy


def _list(value, label):
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise ValueError(f"Firewall {label} must be a list of objects.")
    return deepcopy(value)


def _structured(value):
    if not isinstance(value, dict) or "rules" not in value:
        raise ValueError("firewall_configuration must be an object with an explicit rules list.")
    for key in ("interfaces", "zones", "address_objects", "services", "rules"):
        _list(value.get(key, []), key)
    result = normalize_policy(value, firewall_id="pending", name=value.get("hostname") or value.get("name") or "pending", require_explicit_ports=True)
    result.pop("id", None); result.pop("type", None); result.pop("name", None)
    if not value.get("hostname") and not value.get("name"):
        result["hostname"] = None
    # References are retained, not expanded into invented rules.
    if result["default_action"] is None or any(r.get("service") or any(str(r.get(k, "")).startswith("object:") for k in ("source", "destination")) for r in result["rules"]):
        result["evaluation_supported"] = False
    return result


def _asa(text):
    """Focused ASA extended ACL subset; interface scope is retained, not simulated."""
    result = dict(hostname=None, interfaces=[], zones=[], address_objects=[], services=[],
                  rules=[], default_action=None, default_policy=None, import_complete=True,
                  evaluation_supported=False, warnings=[])
    interface = None
    bindings = []
    def address(tokens):
        token = tokens.pop(0)
        if token in ("any", "any4"): return "any"
        if token == "host": return str(ip_network(tokens.pop(0)))
        return str(ip_network(f"{token}/{tokens.pop(0)}", strict=False))
    def port(tokens):
        if tokens and tokens[0] == "eq":
            tokens.pop(0)
            number = int(tokens.pop(0))
            if not 0 <= number <= 65535: raise ValueError("port out of range")
            return number
        return "any"
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", ":")): continue
        tokens = line.split()
        try:
            if tokens[0] == "hostname" and len(tokens) == 2:
                result["hostname"] = tokens[1]
            elif tokens[0] == "interface" and len(tokens) == 2:
                interface = {"id": tokens[1], "name": tokens[1]}
                result["interfaces"].append(interface)
            elif interface is not None and tokens[0] == "nameif" and len(tokens) == 2:
                interface["zone"] = tokens[1]
                result["zones"].append({"id": tokens[1], "interfaces": [interface["id"]]})
            elif interface is not None and tokens[:2] == ["ip", "address"]:
                if len(tokens) != 4: raise ValueError("unsupported interface address")
                interface["ip"] = str(ip_interface(f"{tokens[2]}/{tokens[3]}"))
            elif tokens[0] == "access-group":
                if len(tokens) != 5 or tokens[3] != "interface": raise ValueError("unsupported ACL binding")
                bindings.append({"acl": tokens[1], "direction": tokens[2], "interface": tokens[4]})
            elif tokens[0] == "access-list":
                acl = tokens[1]; tail = tokens[2:]
                priority = len(result["rules"])
                if tail[0] == "remark": continue
                if tail[0] == "line": priority = int(tail[1]); tail = tail[2:]
                if tail.pop(0) != "extended": raise ValueError("unsupported ACL kind")
                action, protocol = tail.pop(0), tail.pop(0)
                if action not in ("permit", "deny") or protocol not in ("ip", "tcp", "udp", "icmp"):
                    raise ValueError("unsupported ACL action/protocol")
                source = address(tail); source_port = port(tail)
                destination = address(tail); destination_port = port(tail)
                if tail: raise ValueError("unsupported ACL modifiers/ports")
                result["rules"].append({"rule_id": f"{acl}:{line_number}", "acl": acl,
                    "priority": priority, "order": len(result["rules"]), "action": "allow" if action == "permit" else "deny",
                    "protocol": "any" if protocol == "ip" else protocol, "source": source, "destination": destination,
                    "source_port": source_port, "destination_port": destination_port,
                    "original_source_metadata": {"line": line_number, "text": raw}})
            elif tokens[0] in ("object", "object-group", "nat", "ipv6"):
                raise ValueError("unsupported object/NAT/IPv6 syntax")
        except (ValueError, IndexError):
            result["import_complete"] = False
            result["warnings"].append(f"Unsupported ASA configuration at line {line_number}; retained in source metadata.")
        if not raw.startswith((" ", "\t")) and tokens[0] != "interface": interface = None
    result["acl_bindings"] = bindings
    result["warnings"].append("ASA ACL/interface scope and implicit defaults are not evaluated by the flat ASCEND policy model.")
    return result


def import_configuration(node, device):
    """Explicit extension first, then actual inline startup content. Never UUID/image inference."""
    properties = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    candidates = [("node.firewall_configuration", node.get("firewall_configuration")),
                  ("node.properties.firewall_configuration", properties.get("firewall_configuration"))]
    for field in ("appliance", "template"):
        for prefix, parent in (("node", node), ("node.properties", properties)):
            metadata = parent.get(field)
            if isinstance(metadata, dict): candidates.append((f"{prefix}.{field}.firewall_configuration", metadata.get("firewall_configuration")))
    source, payload = next(((s, p) for s, p in candidates if p is not None), (None, None))
    base = {"id": device["id"], "type": "firewall", "name": device["name"], "hostname": device["name"],
            "configuration_available": False, "import_complete": False, "evaluation_supported": False,
            "interfaces": [], "zones": [], "address_objects": [], "services": [], "rules": [],
            "default_action": None, "default_policy": None}
    if source:
        config = _structured(payload)
    else:
        source, payload = next(((f"node.properties.{key}", properties[key]) for key in
            ("startup_config_content", "running_config_content") if isinstance(properties.get(key), str) and properties[key].strip()), (None, None))
        if source is None: return base
        # ASA syntax evidence is required; a firewall name alone does not select a parser.
        if any(line.strip().startswith("access-list ") for line in payload.splitlines()) and any(line.strip().startswith("access-group ") for line in payload.splitlines()):
            config = _asa(payload)
        else:
            config = {"import_complete": False, "evaluation_supported": False,
                      "warnings": ["Inline configuration exists, but its vendor syntax is unsupported."]}
    base.update(config)
    base["hostname"] = config.get("hostname") or device["name"]
    base["configuration_available"] = True
    base["original_source_metadata"] = {"source": source, "payload": deepcopy(payload)}
    return base
