#!/usr/bin/env python3
"""Test standalone simulation page."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology

net, grid, traffic = build_baseline()
topo_nodes, topo_edges = build_ot_topology(net)
print(f"Buses: {len(grid)}")
print(f"Lines: {len(net.line)}")
print(f"Traffic rows: {len(traffic)}")
print(f"Topo nodes: {len(topo_nodes)}")
print(f"Topo edges: {len(topo_edges)}")
print("OK - Simulation page works standalone")
