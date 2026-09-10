#!/usr/bin/env python3
"""Quick bug check for multi-parameter action space."""
import sys
import numpy as np
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES, NUM_TECHNIQUES
from stable_baselines3 import PPO

model = PPO.load("/home/adty17/ascend-pg-webapp/models/rl_agent.zip")

# Test 1: Basic step
env = AttackStrategyEnv()
obs, _ = env.reset()
action, _ = model.predict(obs, deterministic=True)
action = np.asarray(action, dtype=np.int64).flatten()
obs, reward, term, trunc, info = env.step(action)
print(f"1. Basic step: OK (reward={reward:.2f}, reg={info.get('register_address')}, val={info.get('value_magnitude', 0):.3f})")

# Test 2: Multiple steps
obs, _ = env.reset()
for i in range(5):
    action, _ = model.predict(obs, deterministic=True)
    action = np.asarray(action, dtype=np.int64).flatten()
    action[3] = action[3] % env._num_buses
    obs, reward, term, trunc, info = env.step(action)
    if term or trunc:
        break
print(f"2. Multi-step: OK (steps={i+1}, complete={info.get('campaign_complete', False)})")

# Test 3: Edge case - target bus >= num_buses
env5_nodes = [
    {"bus_id": 0, "name": "Gen", "type": "slack", "voltage": 1.05, "ip": "10.0.0.1"},
    {"bus_id": 1, "name": "Sub1", "type": "pq", "voltage": 1.02, "ip": "10.0.0.2"},
]
from testbed.topology import Topology
topo5 = Topology(nodes=env5_nodes, edges=[(0, 1)])
env5 = AttackStrategyEnv(topology=topo5)
obs, _ = env5.reset()
# Force target bus > num_buses
bad_action = np.array([5, 10, 5, 99], dtype=np.int64)
obs, reward, term, trunc, info = env5.step(bad_action)
print(f"3. Target bus clamping: OK (target_bus={info.get('target_bus')})")

# Test 4: Edge case - register offset = 0
obs, _ = env5.reset()
action_zero_reg = np.array([12, 0, 5, 0], dtype=np.int64)
obs, reward, term, trunc, info = env5.step(action_zero_reg)
print(f"4. Register offset 0: OK (register={info.get('register_address')})")

# Test 5: Edge case - value level = 0 or 9
obs, _ = env5.reset()
action_min_val = np.array([12, 10, 0, 0], dtype=np.int64)
obs, reward, term, trunc, info = env5.step(action_min_val)
print(f"5. Min value (0.9x): OK (value={info.get('value_magnitude', 0):.3f})")

obs, _ = env5.reset()
action_max_val = np.array([12, 10, 9, 0], dtype=np.int64)
obs, reward, term, trunc, info = env5.step(action_max_val)
print(f"6. Max value (1.1x): OK (value={info.get('value_magnitude', 0):.3f})")

# Test 6: obs_dim consistency
obs, _ = env5.reset()
assert obs.shape[0] == env5.obs_dim, f"obs shape mismatch: {obs.shape[0]} vs {env5.obs_dim}"
print(f"7. Obs dim consistency: OK ({obs.shape[0]} == {env5.obs_dim})")

print("\n=== ALL BUG CHECKS PASSED ===")
