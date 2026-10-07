"""Validated declarative capabilities from implemented modules; no execution."""
import ast
import math
from pathlib import Path


def supported_attacks():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "scripts/testbed_executor.py").read_text())
    for statement in tree.body:
        if isinstance(statement, ast.AnnAssign) and getattr(statement.target, "id", None) == "TECHNIQUE_TO_STEP_NAME":
            mapping = ast.literal_eval(statement.value)
            return set(mapping) | set(mapping.values())
    raise ValueError("Attack implementation registry unavailable.")


DETECTIONS = {"modbus_reads", "modbus_writes", "coil_changes", "network_flow_monitoring", "suricata", "ml_flow_detection"}
PARAMETERS = {"bus": {"vn_kv"}, "res_bus": {"vm_pu", "va_degree"}, "ext_grid": {"vm_pu"},
              "gen": {"p_mw", "vm_pu"}, "load": {"p_mw", "q_mvar"}, "line": {"in_service"}}
REGISTER_TYPES = {"holding_register", "input_register", "coil", "discrete_input"}


def validate_semantics(owner, bus_ids, counts, device_id=None):
    for field, allowed in (("attack_capabilities", supported_attacks()), ("detection_capabilities", DETECTIONS)):
        values = owner.get(field, [])
        if not isinstance(values, list) or any(not isinstance(value, str) or value not in allowed for value in values) or len(values) != len(set(values)):
            raise ValueError(f"Unsupported or duplicate {field} declaration.")
    plc = owner.get("plc")
    if plc is None: return
    if not isinstance(plc, dict): raise ValueError("plc must be an object.")
    if plc.get("id", device_id) != device_id:
        raise ValueError("PLC ID must match its device ID.")
    if type(plc.get("bus_id")) not in (int, str) or plc["bus_id"] not in bus_ids: raise ValueError("PLC references an unknown bus_id.")
    for key, default, maximum in (("modbus_port", 502, 65535), ("unit_id", 1, 247)):
        value = plc.get(key, default)
        if type(value) is not int or not 1 <= value <= maximum: raise ValueError(f"Invalid PLC {key}.")
    definitions = plc.get("registers", [])
    if not isinstance(definitions, list): raise ValueError("PLC registers must be an array.")
    seen = set()
    for register in definitions:
        if not isinstance(register, dict): raise ValueError("Register definition must be an object.")
        kind, address = register.get("type"), register.get("address")
        if not isinstance(kind, str) or kind not in REGISTER_TYPES or type(address) is not int or not 0 <= address <= 4095:
            raise ValueError("Registers require a supported type and client-offset address 0–4095.")
        if (kind, address) in seen: raise ValueError("Duplicate register type/address.")
        seen.add((kind, address))
        for field in ("name", "semantic", "unit"):
            if not isinstance(register.get(field), str) or not register[field].strip(): raise ValueError(f"Register {field} required.")
        if register.get("data_type") not in ("uint16", "bool") or (kind in {"coil", "discrete_input"}) != (register["data_type"] == "bool"):
            raise ValueError("Register data_type must match its uint16/bool data space.")
        scale = register.get("scale")
        if type(scale) not in (int, float) or not math.isfinite(scale) or scale <= 0: raise ValueError("Register scale must be finite and positive.")
        if type(register.get("attackable")) is not bool: raise ValueError("Register attackable must be Boolean.")
        if kind in {"input_register", "discrete_input"} and register["attackable"]:
            raise ValueError("Read-only register spaces cannot declare direct-write attackability.")
        initial = register.get("initial_value", False if kind in {"coil", "discrete_input"} else 0)
        if kind in {"coil", "discrete_input"}:
            if type(initial) is not bool: raise ValueError("Boolean register initial_value required.")
        elif type(initial) is not int or not 0 <= initial <= 65535: raise ValueError("uint16 initial_value required.")
        mapping = register.get("physical_mapping")
        if mapping is not None:
            if not isinstance(mapping, dict) or mapping.get("model") != "pandapower": raise ValueError("Unsupported physical mapping model.")
            element, parameter, index = mapping.get("element"), mapping.get("parameter"), mapping.get("index")
            if not isinstance(element, str) or element not in PARAMETERS or not isinstance(parameter, str) or parameter not in PARAMETERS[element]: raise ValueError("Unsupported Pandapower element/parameter mapping.")
            if type(index) is not int or not 0 <= index < counts.get(element, 0): raise ValueError("Physical mapping index is not present in this topology.")
            if element == "res_bus" and kind not in {"input_register"}: raise ValueError("Power-flow result mappings must be read-only input registers.")


def validate_bus(node):
    low, high = node.get("voltage_min_pu", 0.9), node.get("voltage_max_pu", 1.1)
    if any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (low, high)) or low > high:
        raise ValueError("Voltage limits must be finite positive values with min <= max.")
    if "voltage_pu" in node and "voltage" in node and node["voltage_pu"] != node["voltage"]:
        raise ValueError("Conflicting voltage and voltage_pu definitions.")
