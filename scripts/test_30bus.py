#!/usr/bin/env python3
"""Test with 30-bus topology."""
import sys
import numpy as np
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from testbed.topology import Topology, set_topology
from strategic.rl_env import AttackStrategyEnv
from stable_baselines3 import PPO

model = PPO.load("/home/adty17/ascend-pg-webapp/models/rl_agent.zip")

# 30-bus topology: 6 generators, 24 load buses, 40 edges
nodes = []
for i in range(30):
    if i == 0:
        ntype, v = "slack", 1.06
    elif i < 6:
        ntype, v = "pv", 1.04 - i*0.003
    else:
        ntype, v = "pq", 1.02 - (i-6)*0.002
    nodes.append({"bus_id": i, "name": f"Bus{i+1}", "type": ntype,
                  "voltage": max(v, 0.95), "ip": f"10.0.{i//256}.{i%256+1}"})

# Ring + cross-ties topology
edges = [(i, (i+1) % 30) for i in range(30)]  # ring
edges += [(0, 10), (5, 20), (10, 20), (3, 15), (8, 25)]  # cross-ties

topo = Topology(nodes=nodes, edges=edges)
env = AttackStrategyEnv(topology=topo)

print(f"30-Bus Topology Test")
print(f"  Buses: {topo.num_buses}")
print(f"  Edges: {len(topo.edges)}")
print(f"  Generators: {topo.gen_buses}")
print(f"  Obs dim: {env.obs_dim} (fixed)")

# Run 5 episodes
total_completions = 0
total_evasion = 0
for ep in range(5):
    obs, _ = env.reset()
    steps, evasions, total_r = 0, 0, 0.0
    while True:
        action, _ = model.predict(obs, deterministic=True)
        action = np.asarray(action, dtype=np.int64).flatten()
        obs, r, terminated, truncated, info = env.step(action)
        total_r += r; steps += 1
        if not info["detected"]: evasions += 1
        if terminated or truncated: break
    complete = info.get("campaign_complete", False)
    if complete: total_completions += 1
    total_evasion += evasions/steps
    print(f"  Ep {ep+1}: steps={steps}, reward={total_r:.2f}, "
          f"evasion={evasions/steps:.0%}, complete={complete}")

print(f"\n  Completion rate: {total_completions}/5 ({total_completions/5:.0%})")
print(f"  Avg evasion: {total_evasion/5:.0%}")
print(f"\n  SAME MODEL, NO RETRAINING NEEDED")
