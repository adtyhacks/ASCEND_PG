"""
ASCEND-PG — Dynamic Topology Loader

Parses CSV files describing custom ICS network topologies and provides
adjacency matrices, bus metadata, and device info for all components
(RL env, PLC server, Mininet testbed).

CSV Format (two files):

  nodes.csv:
    bus_id,name,type,voltage,ip,plc_type,bus_role,pg,qg,pl,ql
    0,Bus1,slack,1.060,10.0.0.1,siemens_s7_1200,generator,232.4,-16.9,0.0,0.0
    1,Bus2,pv,1.045,10.0.0.2,allen_bradley_compactlogix,generator,40.0,42.4,21.7,12.7
    ...

  edges.csv:
    from_bus,to_bus,line_name
    0,1,L1-2
    0,2,L1-3
    ...

Optional columns in nodes.csv:
  - plc_type: PLC template name (default: generic_modbus)
  - bus_role: generator, load, substation (default: from type)
  - pg, qg, pl, ql: power flow values (optional)
"""

import csv
import os
from collections import defaultdict
from pathlib import Path

# Defaults if no CSV provided (IEEE-14)
DEFAULT_NODES = [
    {"bus_id": 0, "name": "Bus1", "type": "slack", "voltage": 1.060, "ip": "10.0.0.1",
     "plc_type": "siemens_s7_1200", "bus_role": "generator", "pg": 232.4, "qg": -16.9, "pl": 0.0, "ql": 0.0},
    {"bus_id": 1, "name": "Bus2", "type": "PV", "voltage": 1.045, "ip": "10.0.0.2",
     "plc_type": "siemens_s7_1500", "bus_role": "generator", "pg": 40.0, "qg": 42.4, "pl": 21.7, "ql": 12.7},
    {"bus_id": 2, "name": "Bus3", "type": "PV", "voltage": 1.010, "ip": "10.0.0.3",
     "plc_type": "allen_bradley_compactlogix", "bus_role": "generator", "pg": 0.0, "qg": 23.4, "pl": 94.2, "ql": 19.0},
    {"bus_id": 3, "name": "Bus4", "type": "PV", "voltage": 1.070, "ip": "10.0.0.4",
     "plc_type": "schneider_modicon_m340", "bus_role": "generator", "pg": 0.0, "qg": -6.3, "pl": 11.2, "ql": 7.5},
    {"bus_id": 4, "name": "Bus5", "type": "PV", "voltage": 1.080, "ip": "10.0.0.5",
     "plc_type": "siemens_s7_1200", "bus_role": "generator", "pg": 0.0, "qg": 17.4, "pl": 0.0, "ql": 0.0},
    {"bus_id": 5, "name": "Bus6", "type": "PQ", "voltage": 1.019, "ip": "10.0.0.6",
     "plc_type": "allen_bradley_compactlogix", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 47.8, "ql": -3.9},
    {"bus_id": 6, "name": "Bus7", "type": "PQ", "voltage": 1.020, "ip": "10.0.0.7",
     "plc_type": "schneider_modicon_m340", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 7.6, "ql": 1.6},
    {"bus_id": 7, "name": "Bus8", "type": "PQ", "voltage": 1.062, "ip": "10.0.0.8",
     "plc_type": "generic_modbus", "bus_role": "substation", "pg": 0.0, "qg": 0.0, "pl": 0.0, "ql": 0.0},
    {"bus_id": 8, "name": "Bus9", "type": "PQ", "voltage": 1.056, "ip": "10.0.0.9",
     "plc_type": "siemens_s7_1500", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 29.5, "ql": 16.6},
    {"bus_id": 9, "name": "Bus10", "type": "PQ", "voltage": 1.051, "ip": "10.0.0.10",
     "plc_type": "generic_modbus", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 9.0, "ql": 5.8},
    {"bus_id": 10, "name": "Bus11", "type": "PQ", "voltage": 1.057, "ip": "10.0.0.11",
     "plc_type": "allen_bradley_compactlogix", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 3.5, "ql": 1.8},
    {"bus_id": 11, "name": "Bus12", "type": "PQ", "voltage": 1.055, "ip": "10.0.0.12",
     "plc_type": "schneider_modicon_m340", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 6.1, "ql": 1.6},
    {"bus_id": 12, "name": "Bus13", "type": "PQ", "voltage": 1.050, "ip": "10.0.0.13",
     "plc_type": "siemens_s7_1200", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 13.5, "ql": 5.8},
    {"bus_id": 13, "name": "Bus14", "type": "PQ", "voltage": 1.036, "ip": "10.0.0.14",
     "plc_type": "generic_modbus", "bus_role": "load", "pg": 0.0, "qg": 0.0, "pl": 14.9, "ql": 5.0},
]

DEFAULT_EDGES = [
    (0, 1), (0, 2), (0, 4),
    (1, 2), (1, 3), (1, 4),
    (2, 3),
    (3, 6),
    (4, 5), (4, 6), (4, 7),
    (5, 8),
    (6, 9),
    (7, 8), (7, 9), (7, 10),
    (8, 9),
    (8, 11), (8, 12),
    (9, 10),
    (10, 11),
    (11, 12),
    (11, 13),
]

# Type mapping
TYPE_MAP = {"slack": 3, "slack_bus": 3, "gen": 3, "generator": 3,
            "pv": 1, "PV": 1, "voltage_control": 1,
            "pq": 2, "PQ": 2, "load": 2}


class Topology:
    """
    Represents an ICS network topology parsed from CSV or defaults.

    Attributes:
        num_buses: Number of nodes (PLCs)
        nodes: List of node dicts with bus_id, name, type, voltage, ip
        edges: List of (from_bus, to_bus) tuples
        adj: Adjacency matrix (num_buses x num_buses)
        bus_types: List of type codes (3=slack, 1=PV, 2=PQ)
        voltages: List of voltage pu values
        bus_degrees: List of connection counts
        gen_buses: List of generator bus indices
        ip_map: Dict mapping bus_id -> IP address
        name_map: Dict mapping bus_id -> name
        max_degree: Maximum bus degree in the topology
    """

    def __init__(self, nodes: list = None, edges: list = None):
        if nodes is None:
            nodes = DEFAULT_NODES.copy()
        if edges is None:
            edges = DEFAULT_EDGES.copy()

        self.nodes = nodes
        self.edges = edges
        self.num_buses = len(nodes)

        # Build lookup dicts
        self.ip_map = {}
        self.name_map = {}
        self.bus_types = []
        self.voltages = []
        self.bus_id_set = set()

        for node in nodes:
            bid = int(node["bus_id"])
            self.bus_id_set.add(bid)
            self.ip_map[bid] = node.get("ip", f"10.0.0.{bid + 1}")
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

        # Replace inf with max depth + 1 for unreachable
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
        return self.ip_map.get(bus_id, f"10.0.0.{bus_id + 1}")

    def get_bus_id_by_ip(self, ip: str) -> int:
        """Reverse lookup: IP -> bus_id."""
        for bid, addr in self.ip_map.items():
            if addr == ip:
                return bid
        return -1

    def to_dict(self) -> dict:
        """Serialize topology to a dict (for JSON storage)."""
        return {
            "num_buses": self.num_buses,
            "nodes": self.nodes,
            "edges": [{"from": e[0], "to": e[1]} for e in self.edges],
            "bus_types": self.bus_types,
            "voltages": self.voltages,
            "bus_degrees": self.bus_degrees,
            "gen_buses": self.gen_buses,
            "ip_map": {str(k): v for k, v in self.ip_map.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Topology":
        """Load topology from a serialized dict."""
        nodes = data.get("nodes", DEFAULT_NODES)
        edges_raw = data.get("edges", DEFAULT_EDGES)
        edges = [(e["from"], e["to"]) if isinstance(e, dict) else tuple(e) for e in edges_raw]
        return cls(nodes=nodes, edges=edges)


def load_topology_from_csv(nodes_csv: str, edges_csv: str) -> Topology:
    """
    Load topology from two CSV files.

    nodes.csv columns: bus_id, name, type, voltage, ip
    edges.csv columns: from_bus, to_bus, [line_name]

    Returns:
        Topology instance
    """
    nodes = []
    with open(nodes_csv, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Strip whitespace from keys
            cleaned = {k.strip(): v.strip() for k, v in row.items()}
            nodes.append({
                "bus_id": int(cleaned.get("bus_id", "0")),
                "name": cleaned.get("name", f"Bus{cleaned.get('bus_id', '0')}"),
                "type": cleaned.get("type", "pq"),
                "voltage": float(cleaned.get("voltage", 1.0)),
                "ip": cleaned.get("ip", ""),
                "plc_type": cleaned.get("plc_type", "generic_modbus"),
                "bus_role": cleaned.get("bus_role", cleaned.get("type", "pq")),
                "pg": float(cleaned.get("pg", 0.0)),
                "qg": float(cleaned.get("qg", 0.0)),
                "pl": float(cleaned.get("pl", 0.0)),
                "ql": float(cleaned.get("ql", 0.0)),
            })

    edges = []
    with open(edges_csv, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            edges.append((
                int(row.get("from_bus", row.get("from_bus ", "0")).strip()),
                int(row.get("to_bus", row.get("to_bus ", "0")).strip()),
            ))

    return Topology(nodes=nodes, edges=edges)


def load_topology_from_dir(path: str) -> Topology:
    """
    Load topology from a directory containing nodes.csv and edges.csv.
    Falls back to IEEE-14 defaults if files don't exist.
    """
    path = Path(path)
    nodes_csv = path / "nodes.csv"
    edges_csv = path / "edges.csv"

    if nodes_csv.exists() and edges_csv.exists():
        return load_topology_from_csv(str(nodes_csv), str(edges_csv))

    return Topology()  # IEEE-14 defaults


def save_topology_csv(topo: Topology, output_dir: str):
    """Save topology to CSV files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "nodes.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["bus_id", "name", "type", "voltage", "ip",
                                               "plc_type", "bus_role", "pg", "qg", "pl", "ql"])
        writer.writeheader()
        for node in topo.nodes:
            writer.writerow(node)

    with open(output_dir / "edges.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["from_bus", "to_bus"])
        writer.writeheader()
        for edge in topo.edges:
            writer.writerow({"from_bus": edge[0], "to_bus": edge[1]})


# Singleton for global access
_current_topology: Topology = None


def get_topology() -> Topology:
    """Get the current global topology."""
    global _current_topology
    if _current_topology is None:
        _current_topology = Topology()
    return _current_topology


def set_topology(topo: Topology):
    """Set the global topology."""
    global _current_topology
    _current_topology = topo


def load_topology(path: str = None) -> Topology:
    """
    Load topology from path or use defaults.
    If path is a directory, looks for nodes.csv + edges.csv.
    If path is a JSON file, loads from dict.
    """
    global _current_topology

    if path is None:
        _current_topology = Topology()
        return _current_topology

    path = Path(path)
    if path.is_dir():
        _current_topology = load_topology_from_dir(str(path))
    elif path.suffix == ".json":
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        _current_topology = Topology.from_dict(data)
    else:
        _current_topology = Topology()

    return _current_topology
