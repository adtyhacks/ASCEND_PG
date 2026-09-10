#!/usr/bin/env python3
"""Full integration test: topology + PLC server + templates + attacks."""
import sys
import numpy as np
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from testbed.topology import Topology, load_topology, set_topology
from testbed.plc_server import build_context
from testbed.plc_templates import get_plc_template, build_register_map, build_device_id
from testbed.scada_client import poll_plc
from strategic.rl_env import AttackStrategyEnv

print("=== Full Integration Test ===\n")

# 1. Load IEEE-14 topology
print("1. Loading IEEE-14 topology...")
topo = Topology()
set_topology(topo)
print(f"   Buses: {topo.num_buses}, Generators: {topo.gen_buses}")

# 2. Build PLC contexts for all buses
print("\n2. Building PLC contexts with templates...")
for i in range(min(5, topo.num_buses)):
    ctx = build_context(i)
    node = topo.nodes[i]
    tpl = get_plc_template(node.get("plc_type", "generic_modbus"))
    print(f"   Bus {i}: {tpl.vendor} {tpl.model} ({node.get('bus_role', 'unknown')})")

# 3. Test register maps
print("\n3. Register map verification...")
for role in ["generator", "load", "substation"]:
    rmap = build_register_map(role, 0)
    print(f"   {role}: DI={len(rmap.discrete_inputs)}, CO={len(rmap.coils)}, "
          f"IR={len(rmap.input_registers)}, HR={len(rmap.holding_registers)}")

# 4. Test RL env
print("\n4. RL env with topology...")
env = AttackStrategyEnv(topology=topo)
obs, _ = env.reset()
print(f"   obs_dim={env.obs_dim}, shape={obs.shape}")
from stable_baselines3 import PPO
model = PPO.load("/home/adty17/ascend-pg-webapp/models/rl_agent.zip")
for i in range(3):
    action, _ = model.predict(obs, deterministic=True)
    action = np.asarray(action, dtype=np.int64).flatten()
    action[3] = action[3] % env._num_buses
    obs, r, term, trunc, info = env.step(action)
    print(f"   Step {i}: tech={action[0]}, reg={info.get('register_address')}, "
          f"val={info.get('value_magnitude', 0):.3f}, target={info.get('target_bus', '?')}, "
          f"reward={r:.2f}")
    if term or trunc:
        break

# 5. Test with 30-bus custom topology
print("\n5. Custom 30-bus topology...")
nodes30 = []
for i in range(30):
    if i == 0:
        ntype, v, role, plc = "slack", 1.06, "generator", "siemens_s7_1200"
    elif i < 6:
        ntype, v, role, plc = "pv", 1.04-i*0.003, "generator", "siemens_s7_1500"
    elif i < 20:
        ntype, v, role, plc = "pq", 1.02-(i-6)*0.002, "load", "allen_bradley_compactlogix"
    else:
        ntype, v, role, plc = "pq", 1.0-(i-20)*0.001, "load", "schneider_modicon_m340"
    nodes30.append({"bus_id": i, "name": f"Bus{i+1}", "type": ntype,
                    "voltage": max(v, 0.95), "ip": f"10.0.{i//256}.{i%256+1}",
                    "plc_type": plc, "bus_role": role,
                    "pg": 100 if role=="generator" else 0,
                    "qg": 50 if role=="generator" else 0,
                    "pl": 50 if role=="load" else 0, "ql": 20 if role=="load" else 0})
edges30 = [(i, (i+1) % 30) for i in range(30)] + [(0, 10), (5, 20)]
topo30 = Topology(nodes=nodes30, edges=edges30)
set_topology(topo30)

# Build contexts for all 30 buses
print(f"   Building 30 PLC contexts...")
for i in range(30):
    ctx = build_context(i)
print(f"   30 PLCs built OK")

# 6. Test topology CSV export
print("\n6. Testing CSV export...")
from testbed.topology import save_topology_csv
import tempfile, os
with tempfile.TemporaryDirectory() as tmpdir:
    save_topology_csv(topo30, tmpdir)
    nodes_path = os.path.join(tmpdir, "nodes.csv")
    edges_path = os.path.join(tmpdir, "edges.csv")
    with open(nodes_path) as f:
        lines = f.readlines()
    print(f"   nodes.csv: {len(lines)} lines (header + {len(lines)-1} buses)")
    print(f"   Header: {lines[0].strip()}")
    print(f"   Sample: {lines[1].strip()}")
    topo_reload = load_topology(tmpdir)
    print(f"   Reloaded: {topo_reload.num_buses} buses, {len(topo_reload.edges)} edges")

print("\n=== ALL INTEGRATION TESTS PASSED ===")
