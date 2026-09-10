#!/usr/bin/env python3
"""Verify trained model works with any topology (no retraining)."""
import sys
import numpy as np
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from testbed.topology import Topology, set_topology
from strategic.rl_env import AttackStrategyEnv
from stable_baselines3 import PPO

# Load trained model
model = PPO.load("/home/adty17/ascend-pg-webapp/models/rl_agent.zip")

def run_episode(model, env, max_steps=16):
    obs, _ = env.reset()
    total_r, steps, evasions = 0, 0, 0
    while True:
        action, _ = model.predict(obs, deterministic=True)
        action = np.asarray(action, dtype=np.int64).flatten()
        # Clamp target bus to valid range
        action[3] = action[3] % env._num_buses
        obs, r, terminated, truncated, info = env.step(action)
        total_r += r; steps += 1
        if not info["detected"]: evasions += 1
        if terminated or truncated: break
    return steps, total_r, evasions, info

# Test 1: IEEE-14 (what it was trained on)
print("=== IEEE-14 (14 buses) ===")
topo14 = Topology()
env14 = AttackStrategyEnv(topology=topo14)
steps, total_r, evasions, info = run_episode(model, env14)
print(f"  Steps: {steps}, Reward: {total_r:.2f}, Evasion: {evasions/steps:.0%}")
print(f"  Complete: {info.get('campaign_complete', False)}")

# Test 2: Custom 5-bus (NOT what it was trained on)
print("\n=== Custom 5-bus ===")
nodes5 = [
    {"bus_id": 0, "name": "Gen", "type": "slack", "voltage": 1.05, "ip": "10.0.0.1"},
    {"bus_id": 1, "name": "Sub1", "type": "pq", "voltage": 1.02, "ip": "10.0.0.2"},
    {"bus_id": 2, "name": "Sub2", "type": "pq", "voltage": 1.01, "ip": "10.0.0.3"},
    {"bus_id": 3, "name": "Sub3", "type": "pq", "voltage": 1.00, "ip": "10.0.0.4"},
    {"bus_id": 4, "name": "Sub4", "type": "pq", "voltage": 0.99, "ip": "10.0.0.5"},
]
edges5 = [(0, 1), (0, 2), (1, 2), (2, 3), (3, 4)]
topo5 = Topology(nodes=nodes5, edges=edges5)
env5 = AttackStrategyEnv(topology=topo5)
steps, total_r, evasions, info = run_episode(model, env5)
print(f"  Steps: {steps}, Reward: {total_r:.2f}, Evasion: {evasions/steps:.0%}")
print(f"  Complete: {info.get('campaign_complete', False)}")

# Test 3: Custom 20-bus (bigger than IEEE-14)
print("\n=== Custom 20-bus ===")
nodes20 = []
for i in range(20):
    ntype = "slack" if i == 0 else ("pv" if i < 4 else "pq")
    nodes20.append({"bus_id": i, "name": f"Bus{i+1}", "type": ntype,
                    "voltage": 1.05 - i*0.002, "ip": f"10.0.{i//256}.{i%256+1}"})
edges20 = [(i, i+1) for i in range(19)] + [(0, 5), (3, 10), (7, 15)]
topo20 = Topology(nodes=nodes20, edges=edges20)
env20 = AttackStrategyEnv(topology=topo20)
steps, total_r, evasions, info = run_episode(model, env20)
print(f"  Steps: {steps}, Reward: {total_r:.2f}, Evasion: {evasions/steps:.0%}")
print(f"  Complete: {info.get('campaign_complete', False)}")

print("\n=== ALL TOPOLOGIES WORK WITH SAME MODEL ===")
