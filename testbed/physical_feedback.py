"""Run-scoped Modbus readback → declared Pandapower parameters → solved voltages."""
from copy import deepcopy
import json
import math
from pathlib import Path
import tempfile
import time

SEMANTICS = {
    "generator_active_power": ("gen", "p_mw"),
    "generator_voltage_setpoint": ("gen", "vm_pu"),
    "slack_voltage_setpoint": ("ext_grid", "vm_pu"),
    "load_active_power": ("load", "p_mw"),
    "load_reactive_power": ("load", "q_mvar"),
    "line_in_service": ("line", "in_service"),
    "bus_nominal_voltage": ("bus", "vn_kv"),
}


def mappings(topology, bus=None):
    result = []
    for node in topology.nodes:
        for register in node.get("plc", {}).get("registers", []):
            mapping = register.get("physical_mapping", {})
            if register["type"] not in ("holding_register", "coil") or not mapping: continue
            expected = SEMANTICS.get(register["semantic"])
            if expected != (mapping.get("element"), mapping.get("parameter")):
                raise ValueError(f"Unsupported/mismatched writable physical semantic: {register['semantic']}.")
            if (mapping["parameter"] == "in_service") != (register["data_type"] == "bool"):
                raise ValueError("Physical Boolean mappings require a Boolean coil; numeric mappings require uint16.")
            result.append({"bus_id": node["bus_id"], "ip": topology.get_ip(node["bus_id"]),
                           "port": node.get("plc", {}).get("modbus_port", 502), "unit_id": node.get("plc", {}).get("unit_id", 1), **deepcopy(register)})
    seen = set()
    for register in result:
        m = register["physical_mapping"]; key = (m["element"], m["index"], m["parameter"])
        if key in seen: raise ValueError("Multiple writable registers map to the same physical parameter.")
        seen.add(key)
    return [r for r in result if bus is None or r["bus_id"] == bus]


def read_register(register):
    from pymodbus.client import ModbusTcpClient
    client = ModbusTcpClient(register["ip"], port=register["port"], timeout=2, retries=0)
    try:
        if not client.connect(): raise RuntimeError("Mapped PLC is unreachable.")
        if register["type"] == "coil":
            response = client.read_coils(register["address"], count=1, device_id=register["unit_id"])
            if response.isError(): raise RuntimeError(str(response))
            return bool(response.bits[0])
        response = client.read_holding_registers(register["address"], count=1, device_id=register["unit_id"])
        if response.isError(): raise RuntimeError(str(response))
        return response.registers[0]
    finally:
        client.close()


def _snapshot(net):
    def values(table, columns):
        return {str(i): {c: float(row[c]) for c in columns if c in row and math.isfinite(float(row[c]))}
                for i, row in net[table].iterrows()}
    voltages = {str(i): float(value) for i, value in net.res_bus.vm_pu.items()}
    if not net.converged or not voltages or any(not math.isfinite(v) or v <= 0 for v in voltages.values()):
        raise RuntimeError("Power flow has no complete finite positive voltage solution.")
    return {"voltages": voltages, "min_voltage": min(voltages.values()), "power_flow_success": True,
            "generator_output": values("res_gen", ["p_mw", "q_mvar"]), "slack_output": values("res_ext_grid", ["p_mw", "q_mvar"]),
            "generator_parameters": values("gen", ["p_mw", "vm_pu"]), "load_values": values("load", ["p_mw", "q_mvar"]),
            "line_loading": values("res_line", ["loading_percent"])}


class PhysicalFeedback:
    def __init__(self, topology, identity, state_path=None, reader=read_register):
        self.topology = topology; self.identity = dict(identity); self.reader = reader
        self.path = Path(state_path) if state_path else None
        self.scope = {**self.identity, "topology_revision": topology.revision}
        self.net = None; self.error = None
        if not topology.physical_available: return
        try:
            import pandapower as pp
            saved = json.loads(self.path.read_text()) if self.path and self.path.exists() else None
            if saved and any(saved.get(k) != v for k, v in self.scope.items()):
                raise ValueError("Physical state belongs to a different run/generation/topology.")
            if saved:
                if saved.get("power_flow_success") is not True: raise ValueError("Previous physical update failed; restart the assessment before continuing PPO.")
                self.net = pp.from_json_string(saved["model_json"])
            else:
                self.net = topology.to_pandapower()
            _snapshot(self.net)
        except Exception as exc:
            self.error = str(exc)

    def before(self, bus):
        evidence = {**self.scope, "physical_model_available": self.topology.physical_available,
                    "power_flow_success": None, "voltage_before": {}, "voltage_after": {}, "voltage_delta": {},
                    "min_voltage_before": None, "min_voltage_after": None, "affected_buses": [], "physical_state_change": []}
        if not self.topology.physical_available: return evidence
        try:
            if self.error: raise RuntimeError(self.error)
            if self.identity.get("topology_revision", self.topology.revision) != self.topology.revision: raise ValueError("Active topology changed.")
            selected = mappings(self.topology, bus)
            evidence["mapped_registers"] = [{**r, "raw_before": self.reader(r)} for r in selected]
            # The verified pre-attack readback is the baseline physical input.
            for r in evidence["mapped_registers"]:
                self._set(r, r["raw_before"])
            if selected:
                from testbed.topology import run_power_flow
                run_power_flow(self.net)
            baseline = _snapshot(self.net)
            evidence.update(power_flow_success=True, voltage_before=baseline["voltages"],
                            min_voltage_before=baseline["min_voltage"], physical_before=baseline)
        except Exception as exc:
            evidence.update(power_flow_success=False, error=str(exc))
        return evidence

    def _set(self, register, raw):
        if register["data_type"] == "bool":
            if type(raw) is not bool: raise ValueError("Boolean readback required.")
            value = raw
        else:
            if type(raw) is not int or not 0 <= raw <= 65535: raise ValueError("uint16 readback required.")
            value = raw / register["scale"]
        mapping = register["physical_mapping"]; table = self.net[mapping["element"]]
        if mapping["index"] not in table.index: raise ValueError("Physical mapping index is absent from the active network.")
        previous = table.at[mapping["index"], mapping["parameter"]]
        table.at[mapping["index"], mapping["parameter"]] = value
        return value, bool(previous) if register["data_type"] == "bool" else float(previous)

    def after(self, before, validator=None):
        evidence = deepcopy(before)
        if self.topology.physical_available and before.get("power_flow_success"):
            try:
                changes = []
                evidence["physical_state_change"] = changes
                for r in before.get("mapped_registers", []):
                    raw = self.reader(r)
                    if raw == r["raw_before"]: continue
                    value, previous = self._set(r, raw)
                    changes.append({"bus_id": r["bus_id"], "register_type": r["type"], "address": r["address"], "semantic": r["semantic"],
                                    "mapping": r["physical_mapping"], "raw_before": r["raw_before"], "raw_after": raw,
                                    "value_before": previous, "value_after": value, "unit": r["unit"]})
                evidence["physical_state_change"] = changes
                if changes:
                    from testbed.topology import run_power_flow
                    run_power_flow(self.net)
                solved = _snapshot(self.net)
                delta = {i: solved["voltages"][i] - before["voltage_before"][i] for i in solved["voltages"]}
                evidence.update(power_flow_success=True, voltage_after=solved["voltages"], voltage_delta=delta,
                                min_voltage_after=solved["min_voltage"], affected_buses=[i for i, d in delta.items() if abs(d) > 1e-8], physical_after=solved)
            except Exception as exc:
                evidence.update(power_flow_success=False, error=str(exc), voltage_after={}, voltage_delta={}, min_voltage_after=None, affected_buses=[])
        evidence["timestamp"] = time.time()
        if validator is not None: validator()
        self.topology.apply_physical_state(evidence)
        state = dict(evidence)
        if self.net is not None:
            import pandapower as pp
            state["model_json"] = pp.to_json(self.net)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent, delete=False) as stream:
                json.dump(state, stream, allow_nan=False); temporary = Path(stream.name)
            temporary.replace(self.path)
        return evidence


def prepare_step(pending):
    from testbed.topology import get_topology
    from testbed import run_store
    topology = get_topology()
    validate_runtime(topology, pending)
    identity = {k: pending[k] for k in ("scenario_id", "run_id", "generation_id")}
    feedback = PhysicalFeedback(topology, identity, run_store._path(pending["scenario_id"], pending["run_id"]) / "physical_state.json")
    return feedback, feedback.before(pending["target_bus"])


def validate_runtime(topology, pending):
    from testbed import run_store
    from testbed.topology import get_topology
    from testbed.core_runtime import ROOT
    marker = json.loads((ROOT / "data/core-runtime/session.json").read_text())
    if pending.get("generation_id") != marker.get("generation_id", marker.get("token")):
        raise ValueError("Physical feedback request has a stale CORE generation.")
    run = json.loads((run_store._path(pending["scenario_id"], pending["run_id"]) / "run.json").read_text())
    if run["topology_version"] != topology.revision or get_topology().revision != topology.revision or run.get("generation_id") != pending["generation_id"] or str(run.get("core_session_id")) != str(marker["id"]):
        raise ValueError("Physical feedback request does not match the active canonical run.")
    if topology.get_ip(pending["target_bus"]) != pending["target_ip"]:
        raise ValueError("Physical feedback target does not match the active canonical bus.")


def finish_step(feedback, before, pending):
    from testbed import run_store
    validate_runtime(feedback.topology, pending)
    evidence = feedback.after(before, validator=lambda: validate_runtime(feedback.topology, pending))
    run_store.append_event(pending["scenario_id"], pending["run_id"], category="network", event_type="physical_state_updated",
                           target_node=pending.get("target_node"), correlation_id=pending["correlation_id"], generation_id=pending["generation_id"], evidence=evidence)
    return evidence


def load_state(topology, run):
    from testbed import run_store
    path = run_store._path(run["scenario_id"], run["run_id"]) / "physical_state.json"
    if not path.exists():
        current = topology.physical_state
        if current and current.get("run_id") and any(current.get(k) != run.get(k) for k in ("scenario_id", "run_id", "generation_id")):
            topology.physical_state = None
        return None
    state = json.loads(path.read_text())
    if any(state.get(k) != run.get(k) for k in ("scenario_id", "run_id", "generation_id")) or state.get("topology_revision") != topology.revision:
        raise ValueError("Retained physical state does not match this run/generation/topology.")
    topology.apply_physical_state(state)
    return {k: v for k, v in state.items() if k != "model_json"}
