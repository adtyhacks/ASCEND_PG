"""
ASCEND-PG — Dynamic Topology Loader & Single Source of Truth

Parses CSV files or builds IEEE topologies directly from Pandapower
(IEEE-14 and IEEE-30). Provides adjacency matrices, bus metadata,
and device info for all components (RL env, PLC server, CORE testbed, UI, reporting).
"""

import csv
import os
import math
import re
import json
import hashlib
import threading
from copy import deepcopy
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Dict, Any, Union, Optional

from testbed.ip_config import get_plc_ip, SCADA_IP, ATTACKER_IP, MONITOR_IP

# Type mapping
TYPE_MAP = {
    "slack": 3, "slack_bus": 3, "gen": 3, "generator": 3,
    "pv": 1, "PV": 1, "voltage_control": 1,
    "pq": 2, "PQ": 2, "load": 2
}

PLC_TEMPLATES = [
    "siemens_s7_1200", "siemens_s7_1500", "allen_bradley_compactlogix",
    "schneider_modicon_m340", "generic_modbus"
]

# Serialize canonical selection with GUI CORE generation, not CORE ownership.
TOPOLOGY_LOCK = threading.RLock()
SELECTION_PATH = Path(__file__).resolve().parents[1] / "data" / "topology_selection.json"

def run_power_flow(net):
    """Run pandapower with its current pandas-3 writable-result compatibility gap."""
    import pandas as pd
    import pandapower as pp
    if int(pd.__version__.split(".", 1)[0]) < 3:
        pp.runpp(net)
        return
    series_values = pd.Series.values
    frame_values = pd.DataFrame.values
    def writable(descriptor, owner):
        def getter(value):
            result = descriptor.__get__(value, owner)
            if not result.flags.writeable:
                result.setflags(write=True)
            return result
        return property(getter)
    with TOPOLOGY_LOCK:
        try:
            pd.Series.values = writable(series_values, pd.Series)
            pd.DataFrame.values = writable(frame_values, pd.DataFrame)
            pp.runpp(net)
        finally:
            pd.Series.values = series_values
            pd.DataFrame.values = frame_values

class Topology:
    """
    Represents an ICS network topology parsed from CSV, defaults, or Pandapower.

    Attributes:
        num_buses: Number of nodes (PLCs)
        nodes: List of node dicts with bus_id, name, type, voltage, ip, plc_type, bus_role
        edges: List of (from_bus, to_bus) tuples
        adj: Adjacency matrix (num_buses x num_buses)
        bus_types: List of type codes (3=slack, 1=PV, 2=PQ)
        voltages: List of voltage pu values
        bus_degrees: List of connection counts
        gen_buses: List of generator bus indices
        ip_map: Dict mapping bus_id -> IP address
        name_map: Dict mapping bus_id -> name
        max_degree: Maximum bus degree in the topology
        case_name: Case identifier (e.g. 'case14', 'case30', 'custom')
    """

    def __init__(self, nodes: list = None, edges: list = None, case_name: str = "case14"):
        if nodes is None or edges is None:
            if nodes is not None or edges is not None: raise ValueError("Both nodes and edges are required.")
            self.__dict__ = deepcopy(get_topology().__dict__)
            return
        if any(not isinstance(n, dict) or type(n.get("bus_id")) is not int or n["bus_id"] != i for i, n in enumerate(nodes)):
            raise ValueError("Internal bus IDs must be unique ordered indices starting at zero.")

        self.nodes = nodes
        self.edge_models = []
        self.edges = []
        for edge in edges:
            if isinstance(edge, dict):
                model = dict(edge)
                left, right = int(model["from"]), int(model["to"])
            else:
                left, right = int(edge[0]), int(edge[1])
                model = {"from": left, "to": right}
            self.edges.append((left, right))
            if left == right or not 0 <= left < len(nodes) or not 0 <= right < len(nodes): raise ValueError("Electrical link references invalid buses.")
            self.edge_models.append(model)
        self.num_buses = len(nodes)
        self.case_name = case_name
        self.exchange = None
        self.custom_definition = None
        self.source = "ieee" if case_name in {"case14", "case30"} else "custom"
        self.power_model_json = None

        # Build lookup dicts
        self.ip_map: Dict[int, str] = {}
        self.name_map: Dict[int, str] = {}
        self.bus_types: List[int] = []
        self.physical_state = None
        self._definition_voltages: List[float] = []
        self.bus_id_set = set()

        for node in nodes:
            bid = int(node["bus_id"])
            self.bus_id_set.add(bid)
            self.ip_map[bid] = node.get("ip", get_plc_ip(bid))
            self.name_map[bid] = node.get("name", f"Bus{bid + 1}")
            self.bus_types.append(TYPE_MAP.get(str(node.get("type", "pq")).lower(), 2))
            self._definition_voltages.append(float(node.get("voltage", 1.0)))

        # Build adjacency matrix
        self.adj = [[0.0] * self.num_buses for _ in range(self.num_buses)]
        for i, j in self.edges:
            if i < self.num_buses and j < self.num_buses:
                self.adj[i][j] = 1.0
                self.adj[j][i] = 1.0

        # Bus degrees
        self.bus_degrees = [sum(row) for row in self.adj]
        self.max_degree = max(self.bus_degrees) if self.bus_degrees else 1

        # Generator bus indices (slack + PV)
        self.gen_buses = [i for i, t in enumerate(self.bus_types) if t in (1, 3)]

        # Compute BFS depth from generators for each bus
        self._depth_from_gens = self._bfs_depth_from_generators()

    def _bfs_depth_from_generators(self) -> list:
        """Compute shortest hop distance from each bus to nearest generator."""
        depth = [float("inf")] * self.num_buses
        queue = list(self.gen_buses)
        for g in queue:
            depth[g] = 0

        while queue:
            current = queue.pop(0)
            for neighbor in range(self.num_buses):
                if self.adj[current][neighbor] == 1.0 and depth[neighbor] == float("inf"):
                    depth[neighbor] = depth[current] + 1
                    queue.append(neighbor)

        max_d = max((d for d in depth if d != float("inf")), default=0)
        return [d if d != float("inf") else max_d + 1 for d in depth]

    def get_depth(self, bus_id: int) -> int:
        """Get BFS depth of a bus from nearest generator."""
        if 0 <= bus_id < self.num_buses:
            return int(self._depth_from_gens[bus_id])
        return 0

    def get_neighbors(self, bus_id: int) -> list:
        """Get list of connected bus IDs."""
        if bus_id >= self.num_buses:
            return []
        return [j for j in range(self.num_buses) if self.adj[bus_id][j] == 1.0]

    def is_generator(self, bus_id: int) -> bool:
        """Check if a bus is a generator (slack or PV)."""
        return bus_id in self.gen_buses

    def get_ip(self, bus_id: int) -> str:
        """Get IP address for a bus."""
        return self.ip_map.get(bus_id, get_plc_ip(bus_id))

    def get_bus_id_by_ip(self, ip: str) -> int:
        """Reverse lookup: IP -> bus_id."""
        for bid, addr in self.ip_map.items():
            if addr == ip:
                return bid
        return -1

    def to_dict(self) -> dict:
        """Serialize topology to a dict (for JSON storage)."""
        if self.exchange is not None:
            result = {"canonical_schema": "ascend.canonical/v1", "case_name": self.case_name, "source": self.source, "exchange": deepcopy(self.exchange)}
            if self.custom_definition is not None:
                result["custom_definition"] = deepcopy(self.custom_definition)
            return result
        return {
            "canonical_schema": "ascend.canonical/v1", "source": self.source, "power_model_json": self.power_model_json,
            "case_name": self.case_name,
            "num_buses": self.num_buses,
            "nodes": self.nodes,
            "edges": [dict(e) for e in self.edge_models],
            "bus_types": self.bus_types,
            "voltages": self._definition_voltages,
            "bus_degrees": self.bus_degrees,
            "gen_buses": self.gen_buses,
            "ip_map": {str(k): v for k, v in self.ip_map.items()},
        }

    def canonical_snapshot(self) -> dict:
        """Return the one topology projection consumed by CORE, the UI and runs.

        The electrical bus data remains the source of truth.  CORE-only hosts are
        added here because they are part of every generated CORE scenario, rather
        than being recreated independently by a visualisation module.
        """
        if self.exchange is not None:
            from testbed.external_topology import visual_data
            document = self.exchange
            mapped = {m["device"]: i for i, bus in enumerate(document["power_grid"].get("buses", [])) for m in document.get("mapping", []) if m["bus"] == bus["id"]}
            nodes = [{"id": d["id"], "hostname": d.get("name", d["id"]), "node_type": "hub" if d["type"] == "switch" else d["type"],
                      "ip": d.get("ip"), "interfaces": [p["name"] for p in d.get("interfaces", [])], "bus_id": mapped.get(d["id"]), "role": d["type"], "services": []} for d in document["network"]["devices"]]
            links = [{"from": link["endpoints"][0]["device"], "to": link["endpoints"][1]["device"], "type": "comm", "protocol": "TCP/IP", "core_link": True} for link in document["links"]]
            for line in document["power_grid"].get("lines", []):
                mapping = {m["bus"]: m["device"] for m in document.get("mapping", [])}
                if line["from_bus"] in mapping and line["to_bus"] in mapping:
                    links.append({"from": mapping[line["from_bus"]], "to": mapping[line["to_bus"]], "type": "power_line", "protocol": "electrical", "core_link": False})
            return {"schema": "ascend.topology/v1", "source": self.source, "case_name": self.case_name, "topology_version": self.revision, "nodes": nodes, "links": links}
        nodes = [
            {"id": "hub", "hostname": "s1", "node_type": "hub", "role": "network", "zone": "network", "ip": None, "interfaces": [], "services": [], "operating_system": "CORE", "core_id": 1},
            {"id": "scada", "hostname": "scada", "node_type": "scada", "role": "operator", "zone": "operations", "ip": SCADA_IP, "interfaces": ["eth0"], "services": ["Modbus/TCP client"], "operating_system": "Linux", "core_id": 2},
            {"id": "attacker", "hostname": "attacker", "node_type": "attacker", "role": "red-team", "zone": "external", "ip": ATTACKER_IP, "interfaces": ["eth0"], "services": [], "operating_system": "Linux", "core_id": 3, "security": {"designation": "attacker"}},
            {"id": "ids_monitor", "hostname": "ids_monitor", "node_type": "ids", "role": "defender", "zone": "monitoring", "ip": MONITOR_IP, "interfaces": ["eth0"], "services": ["Suricata"], "operating_system": "Linux", "core_id": 4, "security": {"designation": "defender"}},
        ]
        links = []
        for node in self.nodes:
            bus_id = int(node["bus_id"])
            node_id = f"plc{bus_id + 1}"
            nodes.append({
                "id": node_id, "hostname": node_id, "node_type": "plc",
                "role": node.get("bus_role", "load"), "zone": "field",
                "ip": self.get_ip(bus_id), "interfaces": ["eth0"],
                "services": ["Modbus/TCP"], "operating_system": "Linux",
                "core_id": bus_id + 5, "bus_id": bus_id,
                "plc_type": node.get("plc_type", "generic_modbus"),
                "security": {"designation": "asset"},
            })
            links.append({"from": "hub", "to": node_id, "type": "comm", "protocol": "TCP/IP", "core_link": True})
        for device in ("scada", "attacker", "ids_monitor"):
            links.append({"from": "hub", "to": device, "type": "comm", "protocol": "TCP/IP", "core_link": True})
        for left, right in self.edges:
            links.append({"from": f"plc{left + 1}", "to": f"plc{right + 1}", "type": "power_line", "protocol": "electrical", "core_link": False})
        version_payload = json.dumps({"nodes": self.nodes, "edges": self.edge_models}, sort_keys=True, separators=(",", ":"))
        return {"schema": "ascend.topology/v1", "case_name": self.case_name,
                "topology_version": self.revision,
                "nodes": nodes, "links": links}

    @classmethod
    def from_dict(cls, data: dict) -> "Topology":
        """Load topology from a serialized dict."""
        if not isinstance(data, dict): raise ValueError("Topology must be an object.")
        if "exchange" in data:
            result = cls.from_exchange(data["exchange"])
            result.case_name = data.get("case_name", result.case_name)
            result.source = data.get("source", result.source)
            result.custom_definition = deepcopy(data.get("custom_definition"))
            return result
        case_name = data.get("case_name", "custom")
        if case_name in {"case14", "case30"} and not data.get("power_model_json") and "canonical_schema" not in data:
            # Legacy preset selections stored a case name alongside a lossy bus
            # projection. Resolve the explicitly selected IEEE source before
            # validating that projection as a custom electrical definition.
            return cls.from_pandapower(case_name)
        nodes = data.get("nodes", [])
        edges_raw = data.get("edges", [])
        validated = cls.from_custom_dict({**data, "case_name": "custom_validation" if case_name in {"case14", "case30"} else case_name})
        validated.case_name = case_name
        validated.source = "ieee" if case_name in {"case14", "case30"} else "custom"
        validated.power_model_json = data.get("power_model_json")
        if validated.power_model_json:
            import pandapower as pp
            net = pp.from_json_string(validated.power_model_json)
            if list(net.bus.index) != list(range(validated.num_buses)):
                raise ValueError("Stored physical network conflicts with canonical bus IDs.")
            modeled_edges = {tuple(sorted((int(row.from_bus), int(row.to_bus)))) for _, row in net.line.iterrows()}
            modeled_edges |= {tuple(sorted((int(row.hv_bus), int(row.lv_bus)))) for _, row in net.trafo.iterrows()}
            if modeled_edges != {tuple(sorted(edge)) for edge in validated.edges}:
                raise ValueError("Stored physical network conflicts with canonical electrical links.")
            for node in validated.nodes:
                bid = node["bus_id"]
                if not math.isclose(node["voltage"], float(net.res_bus.at[bid, "vm_pu"]), abs_tol=1e-6):
                    raise ValueError("Stored voltage projection conflicts with the canonical physical network.")
            from testbed.capabilities import validate_semantics
            counts = {key: len(net[key]) for key in ("bus", "res_bus", "gen", "ext_grid", "load", "line")}
            for node in validated.nodes: validate_semantics(node, set(range(validated.num_buses)), counts, f"plc{node['bus_id']+1}")
        return validated

    @property
    def revision(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()

    @property
    def voltages(self):
        if self.physical_state is not None:
            if self.physical_state.get("power_flow_success") is not True:
                raise ValueError("Live physical voltage observation unavailable: power flow/readback failed.")
            return [self.physical_state["voltage_after"][str(i)] for i in range(self.num_buses)]
        return self._definition_voltages

    def apply_physical_state(self, state):
        if state.get("topology_revision") != self.revision:
            raise ValueError("Physical state does not match this canonical topology.")
        if state.get("power_flow_success") is True:
            values = state.get("voltage_after", {})
            if set(values) != {str(i) for i in range(self.num_buses)} or any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in values.values()):
                raise ValueError("Incomplete/nonfinite canonical physical voltage state.")
        self.physical_state = deepcopy(state)

    @property
    def physical_available(self):
        return self.num_buses > 0 and sum(n.get("type") == "slack" for n in self.nodes) == 1 and all(n.get("type") in {"slack", "pv", "pq"} for n in self.nodes)

    @property
    def core_compatible(self):
        if self.exchange and any(d["type"] == "firewall" for d in self.exchange["network"]["devices"]):
            from testbed.firewall_topology import build_plan
            try: build_plan(self.exchange, self.revision)
            except (ValueError, TypeError, KeyError): return False
            return True
        if not self.physical_available: return False
        if self.exchange is not None:
            expected = {"hub", "scada", "attacker", "ids_monitor"} | {f"plc{i + 1}" for i in range(self.num_buses)}
            devices = {d["id"]: d for d in self.exchange["network"]["devices"]}
            links = {frozenset(e["device"] for e in link["endpoints"]) for link in self.exchange["links"]}
            if set(devices) != expected or links != {frozenset(("hub", name)) for name in expected - {"hub"}}: return False
            if len(self.exchange["links"]) != self.num_buses + 3: return False
            for name, dtype, address in (("hub", "switch", None), ("scada", "scada", SCADA_IP), ("attacker", "attacker", ATTACKER_IP), ("ids_monitor", "ids", MONITOR_IP)):
                if devices[name]["type"] != dtype or devices[name].get("ip") != address: return False
            if any(d.get("name", d["id"]) != ("s1" if d["id"] == "hub" else d["id"]) for d in devices.values()): return False
            if any(d["id"] != "hub" and [p.get("name") for p in d.get("interfaces", [])] != ["eth0"] for d in devices.values()): return False
            if any(devices[f"plc{i+1}"].get("type") != "plc" or devices[f"plc{i+1}"].get("ip") != get_plc_ip(i) for i in range(self.num_buses)): return False
        return all(n.get("ip") == get_plc_ip(i) and n.get("plc", {}).get("modbus_port", 502) == 502 and n.get("plc", {}).get("unit_id", 1) == 1 for i, n in enumerate(self.nodes))

    @property
    def ppo_compatible(self):
        # The existing policy uses legacy register bases. Explicit client-offset
        # layouts cannot honestly be advertised as policy-compatible without an adapter.
        return self.core_compatible and not (self.exchange and any(d["type"] == "firewall" for d in self.exchange["network"]["devices"])) and 1 <= self.num_buses <= 50 and all(r["address"] < 50 for n in self.nodes for r in n.get("plc", {}).get("registers", []))

    def capability_status(self):
        return {"source": self.source, "revision": self.revision, "physical_model": "Available" if self.physical_available else "Not available",
                "core_testbed": "Not built" if self.core_compatible else "Invalid", "ppo": "Compatible" if self.ppo_compatible else "Not compatible",
                "ppo_reason": "Existing fixed observation/action projection supported; explicit registers use client offsets." if self.ppo_compatible else "No compatible electrical/CORE projection, or declared registers exceed the fixed 50-address action range.",
                "reason": ("Addressed routed firewall projection supported; imported devices use Linux endpoints." if self.exchange and any(d["type"] == "firewall" for d in self.exchange["network"]["devices"]) else "Existing hub/Modbus projection supported.") if self.core_compatible else "This graph, firewall configuration, interface addressing or PLC service metadata is not supported by the current CORE executor; no preset is substituted."}

    @classmethod
    def from_exchange(cls, document):
        from testbed.external_topology import validate
        document = deepcopy(validate(document))
        buses = document["power_grid"].get("buses", [])
        ids = {bus["id"]: i for i, bus in enumerate(buses)}
        devices = {d["id"]: d for d in document["network"]["devices"]}
        mapping = {m["bus"]: m["device"] for m in document.get("mapping", [])}
        nodes = []
        for bus in buses:
            i = ids[bus["id"]]; device = devices.get(mapping.get(bus["id"]), {})
            loads = [x for x in document["power_grid"].get("loads", []) if x["bus"] == bus["id"]]
            gens = [x for x in document["power_grid"].get("generators", []) if x["bus"] == bus["id"]]
            nodes.append({"bus_id": i, "name": bus.get("name", bus["id"]), "type": bus.get("type", "unmodeled"), "voltage": bus.get("voltage_pu", 1.0), "vn_kv": bus.get("vn_kv", 110.0),
                          "pg": sum(g.get("p_mw", 0) for g in gens), "qg": sum(g.get("q_mvar", 0) for g in gens), "pl": sum(l.get("p_mw", 0) for l in loads), "ql": sum(l.get("q_mvar", 0) for l in loads),
                          "ip": device.get("ip"), "plc_type": device.get("plc_type", "generic_modbus"), **({"plc": device["plc"]} if "plc" in device else {})})
        edges = [{"from": ids[line["from_bus"]], "to": ids[line["to_bus"]], **{k: v for k, v in line.items() if k in {"length_km", "r_ohm_per_km", "x_ohm_per_km", "c_nf_per_km", "max_i_ka"}}} for line in document["power_grid"].get("lines", [])]
        source = document.get("metadata", {}).get("source")
        case_name = str(document.get("name", "network")) if source == "custom" else "imported_" + str(document.get("name", "network"))
        result = cls(nodes, edges, case_name)
        result.exchange = document
        result.source = source if source in {"gns3", "custom"} else "ascend"
        if result.physical_available:
            cls.from_custom_dict({"case_name": "custom_import_validation", "nodes": [{**n, "ip": get_plc_ip(i), **({"plc": {**n["plc"], "id": f"plc{i+1}", "bus_id": i, "ip": get_plc_ip(i)}} if n.get("plc") else {})} for i, n in enumerate(nodes)], "edges": edges})
        return result

    @classmethod
    def from_custom_dict(cls, data: dict) -> "Topology":
        """Validate the existing bus/edge representation for the CORE GUI workflow."""
        from testbed.ip_config import MAX_PLC_COUNT
        if not isinstance(data, dict):
            raise ValueError("Custom topology must be a JSON object.")
        case = data.get("case_name", "custom_grid")
        if not isinstance(case, str) or not re.fullmatch(r"custom_[a-z0-9_]{1,40}", case):
            raise ValueError("case_name must start with custom_ and contain lowercase letters, digits or underscores.")
        source = data.get("nodes")
        if not isinstance(source, list) or not 1 <= len(source) <= MAX_PLC_COUNT:
            raise ValueError(f"Custom topology needs 1–{MAX_PLC_COUNT} PLC buses.")
        nodes = []
        slack_count = 0
        for bus_id, item in enumerate(source):
            if not isinstance(item, dict) or type(item.get("bus_id")) is not int or item["bus_id"] != bus_id:
                raise ValueError("Nodes must have ordered, consecutive bus_id values starting at 0.")
            node = dict(item)
            from testbed.capabilities import validate_bus
            validate_bus(node)
            if "voltage_pu" in node: node["voltage"] = node["voltage_pu"]
            name = node.get("name", f"Bus{bus_id + 1}")
            if not isinstance(name, str) or not name.strip() or len(name) > 80:
                raise ValueError("Each bus name must be a nonempty string of at most 80 characters.")
            kind = node.get("type", "pq")
            if not isinstance(kind, str) or kind not in {"slack", "pv", "pq"}:
                raise ValueError("Bus type must be slack, pv or pq.")
            slack_count += kind == "slack"
            ip = get_plc_ip(bus_id)
            if node.get("ip", ip) != ip:
                raise ValueError(f"Bus {bus_id} must use canonical address {ip}.")
            plc_type = node.get("plc_type", "generic_modbus")
            if not isinstance(plc_type, str) or plc_type not in PLC_TEMPLATES:
                raise ValueError("Unknown PLC template.")
            node.update(name=name, type=kind, ip=ip, plc_type=plc_type,
                        bus_role=node.get("bus_role", "generator" if kind in {"slack", "pv"} else "load"))
            for key, default in (("voltage", 1.0), ("vn_kv", 110.0), ("pg", 0.0), ("qg", 0.0), ("pl", 0.0), ("ql", 0.0)):
                value = node.get(key, default)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or (key in {"voltage", "vn_kv"} and value <= 0):
                    raise ValueError(f"{key} must be a finite number; voltage must be positive.")
                node[key] = float(value)
            nodes.append(node)
        if slack_count != 1:
            raise ValueError("Custom electrical topology must contain exactly one slack bus.")
        source_edges = data.get("edges", [])
        if not isinstance(source_edges, list):
            raise ValueError("edges must be an array of bus pairs.")
        edges, seen = [], set()
        line_defaults = {"length_km": 1.0, "r_ohm_per_km": 0.1, "x_ohm_per_km": 0.1,
                         "c_nf_per_km": 0.0, "max_i_ka": 0.4}
        for edge in source_edges:
            pair = [edge.get("from"), edge.get("to")] if isinstance(edge, dict) else edge
            if not isinstance(pair, (list, tuple)) or len(pair) != 2 or any(type(i) is not int or not 0 <= i < len(nodes) for i in pair):
                raise ValueError("Every edge must reference two existing integer bus IDs.")
            key = tuple(sorted(pair))
            if pair[0] == pair[1] or key in seen:
                raise ValueError("Self-links and duplicate electrical links are not allowed.")
            seen.add(key)
            line = {"from": pair[0], "to": pair[1]}
            for field, default in line_defaults.items():
                value = edge.get(field, default) if isinstance(edge, dict) else default
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 and field != "c_nf_per_km" or value < 0:
                    raise ValueError(f"{field} must be a finite non-negative number (and positive except capacitance).")
                line[field] = float(value)
            edges.append(line)
        if len(nodes) > 1:
            reached, pending = {0}, [0]
            adjacency = defaultdict(set)
            for edge in edges:
                adjacency[edge["from"]].add(edge["to"]); adjacency[edge["to"]].add(edge["from"])
            while pending:
                current = pending.pop()
                for neighbor in adjacency[current] - reached:
                    reached.add(neighbor); pending.append(neighbor)
            if len(reached) != len(nodes):
                raise ValueError("Every bus must be connected to the electrical network.")
        from testbed.capabilities import validate_semantics
        counts = {"bus": len(nodes), "res_bus": len(nodes), "gen": sum(n["type"] == "pv" for n in nodes), "ext_grid": slack_count,
                  "load": sum(bool(n["pl"] or n["ql"]) for n in nodes), "line": len(edges)}
        for node in nodes:
            validate_semantics(node, set(range(len(nodes))), counts, f"plc{node['bus_id']+1}")
            if node.get("plc") and (node["plc"]["bus_id"] != node["bus_id"] or node["plc"].get("ip", node["ip"]) != node["ip"]):
                raise ValueError("PLC metadata conflicts with its bus/IP mapping.")
        validate_semantics(data, set(range(len(nodes))), counts)
        return cls(nodes=nodes, edges=edges, case_name=case)

    def to_pandapower(self):
        """Build the electrical simulation from this canonical topology."""
        import pandapower as pp
        if not self.physical_available: raise ValueError("Active topology has no supported electrical model.")
        if self.power_model_json:
            net = pp.from_json_string(self.power_model_json)
            run_power_flow(net)
            return net
        net = pp.create_empty_network()
        buses = {}
        for node in self.nodes:
            bid = int(node["bus_id"])
            buses[bid] = pp.create_bus(net, vn_kv=float(node.get("vn_kv", 110.0)), name=node.get("name", f"Bus {bid + 1}"))
            kind = str(node.get("type", "pq")).lower()
            if kind == "slack":
                pp.create_ext_grid(net, buses[bid], vm_pu=float(node.get("voltage", 1.0)), name=f"Slack {bid + 1}")
            elif kind == "pv":
                pp.create_gen(net, buses[bid], p_mw=float(node.get("pg", 0.0)), vm_pu=float(node.get("voltage", 1.0)), name=f"Generator {bid + 1}")
            load_p, load_q = float(node.get("pl", 0.0)), float(node.get("ql", 0.0))
            if load_p or load_q:
                pp.create_load(net, buses[bid], p_mw=load_p, q_mvar=load_q, name=f"Load {bid + 1}")
        for index, line in enumerate(self.edge_models):
            pp.create_line_from_parameters(net, buses[int(line["from"])], buses[int(line["to"])],
                length_km=float(line.get("length_km", 1.0)), r_ohm_per_km=float(line.get("r_ohm_per_km", 0.1)),
                x_ohm_per_km=float(line.get("x_ohm_per_km", 0.1)), c_nf_per_km=float(line.get("c_nf_per_km", 0.0)),
                max_i_ka=float(line.get("max_i_ka", 0.4)), name=f"Line {index + 1}")
        run_power_flow(net)
        return net

    @classmethod
    def from_pandapower(cls, case: Union[str, int] = "case14") -> "Topology":
        """Build Topology directly from standard Pandapower cases (case14 or case30)."""
        import pandapower.networks as pn
        import pandapower as pp

        case_str = str(case).lower().replace("ieee", "").replace("-", "").strip()
        if case_str not in {"14", "30", "case14", "case30"}: raise ValueError("Supported IEEE sources are case14 and case30.")
        if "30" in case_str:
            net = pn.case30()
            canonical_name = "case30"
        else:
            net = pn.case14()
            canonical_name = "case14"

        try:
            run_power_flow(net)
            solved = True
        except Exception as exc:
            raise ValueError(f"Selected electrical source power flow failed: {exc}") from exc

        slack_buses = set(net.ext_grid["bus"].tolist()) if hasattr(net, "ext_grid") else set()
        gen_buses = set(net.gen["bus"].tolist()) if hasattr(net, "gen") else set()

        nodes = []
        for i in net.bus.index:
            bid = int(i)
            if bid in slack_buses:
                btype = "slack"
                role = "generator"
            elif bid in gen_buses:
                btype = "pv"
                role = "generator"
            else:
                btype = "pq"
                role = "load"

            if solved and hasattr(net, "res_bus") and not net.res_bus.empty and bid in net.res_bus.index:
                voltage = float(net.res_bus.at[bid, "vm_pu"])
            else:
                voltage = float(net.bus.at[bid, "vn_kv"] / net.bus.at[bid, "vn_kv"]) if net.bus.at[bid, "vn_kv"] else 1.0

            plc_template = PLC_TEMPLATES[bid % len(PLC_TEMPLATES)]

            nodes.append({
                "bus_id": bid,
                "name": f"Bus{bid + 1}",
                "type": btype,
                "voltage": voltage,
                "ip": get_plc_ip(bid),
                "plc_type": plc_template,
                "bus_role": role,
                "vn_kv": float(net.bus.at[bid, "vn_kv"]),
                "pg": float(net.gen.loc[net.gen.bus == bid, "p_mw"].sum()) + (float(net.res_ext_grid.loc[net.ext_grid.bus == bid, "p_mw"].sum()) if solved else 0.0),
                "qg": (float(net.res_gen.loc[net.gen.bus == bid, "q_mvar"].sum()) + float(net.res_ext_grid.loc[net.ext_grid.bus == bid, "q_mvar"].sum())) if solved else 0.0,
                "pl": float(net.load.loc[net.load.bus == bid, "p_mw"].sum()),
                "ql": float(net.load.loc[net.load.bus == bid, "q_mvar"].sum()),
            })

        edges = []
        if hasattr(net, "line") and not net.line.empty:
            for _, line in net.line.iterrows():
                u, v = int(line["from_bus"]), int(line["to_bus"])
                if (u, v) not in edges and (v, u) not in edges:
                    edges.append((u, v))

        if hasattr(net, "trafo") and not net.trafo.empty:
            for _, trafo in net.trafo.iterrows():
                u, v = int(trafo["hv_bus"]), int(trafo["lv_bus"])
                if (u, v) not in edges and (v, u) not in edges:
                    edges.append((u, v))

        result = cls(nodes=nodes, edges=edges, case_name=canonical_name)
        result.power_model_json = pp.to_json(net)
        return result


def load_topology_from_csv(nodes_csv: str, edges_csv: str) -> Topology:
    """Load topology from two CSV files."""
    nodes = []
    with open(nodes_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cleaned = {k.strip(): v.strip() for k, v in row.items()}
            bid = int(cleaned.get("bus_id", "0"))
            nodes.append({
                "bus_id": bid,
                "name": cleaned.get("name", f"Bus{bid + 1}"),
                "type": cleaned.get("type", "pq"),
                "voltage": float(cleaned.get("voltage", 1.0)),
                "ip": cleaned.get("ip", get_plc_ip(bid)),
                "plc_type": cleaned.get("plc_type", "generic_modbus"),
                "bus_role": cleaned.get("bus_role", cleaned.get("type", "pq")),
                "pg": float(cleaned.get("pg", 0.0)),
                "qg": float(cleaned.get("qg", 0.0)),
                "pl": float(cleaned.get("pl", 0.0)),
                "ql": float(cleaned.get("ql", 0.0)),
            })

    edges = []
    with open(edges_csv, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            edges.append((
                int(row.get("from_bus", row.get("from_bus ", "0")).strip()),
                int(row.get("to_bus", row.get("to_bus ", "0")).strip()),
            ))

    return Topology(nodes=nodes, edges=edges, case_name="custom_csv")


def load_topology_from_dir(path: str) -> Topology:
    """Load topology from a directory containing nodes.csv and edges.csv."""
    p = Path(path)
    nodes_csv = p / "nodes.csv"
    edges_csv = p / "edges.csv"

    if nodes_csv.exists() and edges_csv.exists():
        return load_topology_from_csv(str(nodes_csv), str(edges_csv))
    return load_case(14)


def save_topology_csv(topo: Topology, output_dir: str):
    """Save topology to CSV files."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    with open(out / "nodes.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["bus_id", "name", "type", "voltage", "ip",
                                               "plc_type", "bus_role", "pg", "qg", "pl", "ql"])
        writer.writeheader()
        for node in topo.nodes:
            writer.writerow(node)

    with open(out / "edges.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["from_bus", "to_bus"])
        writer.writeheader()
        for edge in topo.edges:
            writer.writerow({"from_bus": edge[0], "to_bus": edge[1]})


# --- Global Singleton Management ---
_current_topology: Optional[Topology] = None
_selection_fingerprint = None

def _fingerprint():
    return (str(SELECTION_PATH), SELECTION_PATH.stat().st_mtime_ns, SELECTION_PATH.stat().st_size) if SELECTION_PATH.exists() else (str(SELECTION_PATH), None)

def activate_topology(topo):
    """Persist one complete canonical selection; rebuild projections from it."""
    import tempfile
    with TOPOLOGY_LOCK:
        SELECTION_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=SELECTION_PATH.parent, suffix=".tmp", delete=False) as out:
                temporary = Path(out.name); json.dump(topo.to_dict(), out, indent=2)
            os.replace(temporary, SELECTION_PATH)
        finally:
            if temporary and temporary.exists(): temporary.unlink()
        set_topology(topo)

def get_topology() -> Topology:
    """Get the current global topology. Defaults to IEEE-14 if uninitialized."""
    global _current_topology, _selection_fingerprint
    signature = _fingerprint()
    if _selection_fingerprint is not None and _selection_fingerprint != signature:
        _current_topology = None
    if _current_topology is None:
        if SELECTION_PATH.exists():
            import json
            data = json.loads(SELECTION_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Saved topology selection must be an object.")
            _current_topology = Topology.from_dict(data)
            # Read-only compatibility migration of the previous split source.
            legacy_source = SELECTION_PATH.with_name("topology_source.json")
            if "canonical_schema" not in data and legacy_source.exists():
                legacy = json.loads(legacy_source.read_text(encoding="utf-8"))
                if legacy.get("source") == "external": _current_topology = Topology.from_exchange(legacy["document"])
        else:
            legacy_source = SELECTION_PATH.with_name("topology_source.json")
            legacy = json.loads(legacy_source.read_text(encoding="utf-8")) if legacy_source.exists() else {}
            _current_topology = Topology.from_exchange(legacy["document"]) if legacy.get("source") == "external" else Topology.from_pandapower("case14")
        _selection_fingerprint = signature
    return _current_topology

def set_topology(topo: Topology):
    """Set the global active topology."""
    global _current_topology, _selection_fingerprint
    _current_topology = topo
    _selection_fingerprint = _fingerprint()

def load_case(case: Union[str, int]) -> Topology:
    """Load a specific standard case (14 or 30) and set as global topology."""
    topo = Topology.from_pandapower(case)
    set_topology(topo)
    return topo

def load_topology(path: Optional[str] = None) -> Topology:
    """
    Load topology from path, case name, or defaults.
    If path in ('14', '30', 'case14', 'case30'), loads corresponding Pandapower case.
    If path is a directory, looks for nodes.csv + edges.csv.
    If path is a JSON file, loads from dict.
    """
    global _current_topology

    if path is None or str(path).strip() == "":
        return get_topology()

    path_str = str(path).strip().lower()
    if path_str in ("14", "30", "case14", "case30", "ieee14", "ieee30"):
        return load_case(path_str)

    p = Path(path)
    if p.is_dir():
        _current_topology = load_topology_from_dir(str(p))
    elif p.suffix == ".json" and p.exists():
        import json
        data = json.loads(p.read_text(encoding="utf-8"))
        if "pandapower_case" in data:
            _current_topology = load_case(data["pandapower_case"])
        else:
            _current_topology = Topology.from_dict(data)
    else:
        raise ValueError(f"Topology path does not exist or is unsupported: {path}")

    return _current_topology
