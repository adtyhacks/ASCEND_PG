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
import threading
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
            # Build default IEEE-14
            default_topo = Topology.from_pandapower("case14")
            nodes = default_topo.nodes
            edges = default_topo.edges

        self.nodes = nodes
        self.edges = edges
        self.num_buses = len(nodes)
        self.case_name = case_name

        # Build lookup dicts
        self.ip_map: Dict[int, str] = {}
        self.name_map: Dict[int, str] = {}
        self.bus_types: List[int] = []
        self.voltages: List[float] = []
        self.bus_id_set = set()

        for node in nodes:
            bid = int(node["bus_id"])
            self.bus_id_set.add(bid)
            self.ip_map[bid] = node.get("ip", get_plc_ip(bid))
            self.name_map[bid] = node.get("name", f"Bus{bid + 1}")
            self.bus_types.append(TYPE_MAP.get(str(node.get("type", "pq")).lower(), 2))
            self.voltages.append(float(node.get("voltage", 1.0)))

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
        return {
            "case_name": self.case_name,
            "num_buses": self.num_buses,
            "nodes": self.nodes,
            "edges": [{"from": e[0], "to": e[1]} for e in self.edges],
            "bus_types": self.bus_types,
            "voltages": self.voltages,
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
        return {"schema": "ascend.topology/v1", "case_name": self.case_name,
                "topology_version": f"{self.case_name}:{self.num_buses}",
                "nodes": nodes, "links": links}

    @classmethod
    def from_dict(cls, data: dict) -> "Topology":
        """Load topology from a serialized dict."""
        nodes = data.get("nodes", [])
        edges_raw = data.get("edges", [])
        edges = [(e["from"], e["to"]) if isinstance(e, dict) else tuple(e) for e in edges_raw]
        case_name = data.get("case_name", "custom")
        return cls(nodes=nodes, edges=edges, case_name=case_name)

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
        for bus_id, item in enumerate(source):
            if not isinstance(item, dict) or type(item.get("bus_id")) is not int or item["bus_id"] != bus_id:
                raise ValueError("Nodes must have ordered, consecutive bus_id values starting at 0.")
            node = dict(item)
            name = node.get("name", f"Bus{bus_id + 1}")
            if not isinstance(name, str) or not name.strip() or len(name) > 80:
                raise ValueError("Each bus name must be a nonempty string of at most 80 characters.")
            kind = node.get("type", "pq")
            if not isinstance(kind, str) or kind not in {"slack", "pv", "pq"}:
                raise ValueError("Bus type must be slack, pv or pq.")
            ip = get_plc_ip(bus_id)
            if node.get("ip", ip) != ip:
                raise ValueError(f"Bus {bus_id} must use canonical address {ip}.")
            plc_type = node.get("plc_type", "generic_modbus")
            if not isinstance(plc_type, str) or plc_type not in PLC_TEMPLATES:
                raise ValueError("Unknown PLC template.")
            node.update(name=name, type=kind, ip=ip, plc_type=plc_type,
                        bus_role=node.get("bus_role", "generator" if kind in {"slack", "pv"} else "load"))
            for key, default in (("voltage", 1.0), ("pg", 0.0), ("qg", 0.0), ("pl", 0.0), ("ql", 0.0)):
                value = node.get(key, default)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or (key == "voltage" and value <= 0):
                    raise ValueError(f"{key} must be a finite number; voltage must be positive.")
                node[key] = float(value)
            nodes.append(node)
        source_edges = data.get("edges", [])
        if not isinstance(source_edges, list):
            raise ValueError("edges must be an array of bus pairs.")
        edges, seen = [], set()
        for edge in source_edges:
            pair = [edge.get("from"), edge.get("to")] if isinstance(edge, dict) else edge
            if not isinstance(pair, (list, tuple)) or len(pair) != 2 or any(type(i) is not int or not 0 <= i < len(nodes) for i in pair):
                raise ValueError("Every edge must reference two existing integer bus IDs.")
            key = tuple(sorted(pair))
            if pair[0] == pair[1] or key in seen:
                raise ValueError("Self-links and duplicate electrical links are not allowed.")
            seen.add(key)
            edges.append(tuple(pair))
        return cls(nodes=nodes, edges=edges, case_name=case)

    @classmethod
    def from_pandapower(cls, case: Union[str, int] = "case14") -> "Topology":
        """Build Topology directly from standard Pandapower cases (case14 or case30)."""
        import pandapower.networks as pn
        import pandapower as pp

        case_str = str(case).lower().replace("ieee", "").replace("-", "").strip()
        if "30" in case_str:
            net = pn.case30()
            canonical_name = "case30"
        else:
            net = pn.case14()
            canonical_name = "case14"

        try:
            pp.runpp(net)
            solved = True
        except Exception:
            solved = False

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
                "pg": 0.0,
                "qg": 0.0,
                "pl": 0.0,
                "ql": 0.0,
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

        return cls(nodes=nodes, edges=edges, case_name=canonical_name)


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

def get_topology() -> Topology:
    """Get the current global topology. Defaults to IEEE-14 if uninitialized."""
    global _current_topology
    if _current_topology is None:
        if SELECTION_PATH.exists():
            import json
            data = json.loads(SELECTION_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Saved topology selection must be an object.")
            case = data.get("case_name")
            if case in {"case14", "case30"}:
                selected = Topology.from_custom_dict({**data, "case_name": "custom_validation"})
                if selected.num_buses != int(case.replace("case", "")):
                    raise ValueError("Saved preset bus count does not match its case.")
                selected.case_name = case
            else:
                selected = Topology.from_custom_dict(data)
            _current_topology = selected
        else:
            _current_topology = Topology.from_pandapower("case14")
    return _current_topology

def set_topology(topo: Topology):
    """Set the global active topology."""
    global _current_topology
    _current_topology = topo

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
        _current_topology = load_case(14)

    return _current_topology
