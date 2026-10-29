#!/usr/bin/env python3
"""Test the topology loader with CSV and defaults."""
import sys
from pathlib import Path
import numpy as np
import tempfile
import atexit

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from testbed.topology import Topology, load_topology, load_topology_from_csv, save_topology_csv, set_topology, get_topology

# Test 1: Default IEEE-14
print("=== Test 1: Default IEEE-14 topology ===")
topo = Topology()
print(f"Buses: {topo.num_buses}, Edges: {len(topo.edges)}")
print(f"Generators: {topo.gen_buses}")
print(f"Bus degrees: {topo.bus_degrees}")
print(f"Max degree: {topo.max_degree}")
print(f"Depth from gens: {topo._depth_from_gens}")
print(f"IP map: {topo.ip_map}")
print()

# Ensure CSV files exist by exporting default topology
temporary_topology = tempfile.TemporaryDirectory()
atexit.register(temporary_topology.cleanup)
topology_directory = Path(temporary_topology.name)
save_topology_csv(topo, str(topology_directory))

# Test 2: Load from CSV
print("=== Test 2: Load from CSV files ===")
topo_csv = load_topology_from_csv(
    str(topology_directory / "nodes.csv"),
    str(topology_directory / "edges.csv")
)
print(f"Buses: {topo_csv.num_buses}, Edges: {len(topo_csv.edges)}")
print(f"Bus types: {topo_csv.bus_types}")
print(f"Voltages: {topo_csv.voltages[:3]}...")
print()

# Test 3: Load from directory
print("=== Test 3: Load from directory ===")
topo_dir = load_topology(str(topology_directory))
print(f"Buses: {topo_dir.num_buses}, Edges: {len(topo_dir.edges)}")
print()

# Test 4: Custom small topology
print("=== Test 4: Custom 5-bus topology ===")
custom_nodes = [
    {"bus_id": 0, "name": "Generator", "type": "slack", "voltage": 1.05, "ip": "10.0.0.1"},
    {"bus_id": 1, "name": "Substation1", "type": "pq", "voltage": 1.02, "ip": "10.0.0.2"},
    {"bus_id": 2, "name": "Substation2", "type": "pq", "voltage": 1.01, "ip": "10.0.0.3"},
    {"bus_id": 3, "name": "Substation3", "type": "pq", "voltage": 1.00, "ip": "10.0.0.4"},
    {"bus_id": 4, "name": "Substation4", "type": "pq", "voltage": 0.99, "ip": "10.0.0.5"},
]
custom_edges = [(0, 1), (0, 2), (1, 2), (2, 3), (3, 4)]
custom_topo = Topology(nodes=custom_nodes, edges=custom_edges)
print(f"Buses: {custom_topo.num_buses}, Edges: {len(custom_topo.edges)}")
print(f"Generators: {custom_topo.gen_buses}")
print(f"Bus degrees: {custom_topo.bus_degrees}")
print(f"Depth from gens: {custom_topo._depth_from_gens}")
print(f"Neighbors of bus 2: {custom_topo.get_neighbors(2)}")
print(f"Is generator bus 0: {custom_topo.is_generator(0)}")
print(f"Is generator bus 1: {custom_topo.is_generator(1)}")
print()

# Test 5: RL env with custom topology
print("=== Test 5: RL env with custom 5-bus topology ===")
set_topology(custom_topo)
from strategic.rl_env import AttackStrategyEnv
env = AttackStrategyEnv(topology=custom_topo)
print(f"Obs dim: {env.obs_dim}")
print(f"Num buses: {env._num_buses}")
obs, _ = env.reset()
print(f"Observation shape: {obs.shape}")
action = np.array([0, 10, 5, 1], dtype=np.int64)
step_obs, reward, terminated, truncated, info = env.step(action)
print(f"Step reward: {reward:.2f}, target_bus: {info.get('target_bus', 'N/A')}, "
      f"register: {info.get('register_address')}, value: {info.get('value_magnitude', 0):.3f}")

print()
print("ALL TESTS PASSED")
