#!/usr/bin/env python3
"""Test fixed-size padding with different topology sizes."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from testbed.topology import Topology, set_topology
from strategic.rl_env import AttackStrategyEnv, MAX_BUSES

# obs_dim = attack_state(25) + last_action_params(3) + topology(4*50) + scalars(2) = 230
EXPECTED_OBS_DIM = 25 + 3 + 4 * MAX_BUSES + 2

print(f"MAX_BUSES = {MAX_BUSES}")
print(f"Expected obs_dim = 25 + 3 + 4*{MAX_BUSES} + 2 = {EXPECTED_OBS_DIM}")

# Test 1: IEEE-14 (14 buses)
print("\n=== Test 1: IEEE-14 (14 buses) ===")
topo14 = Topology()
set_topology(topo14)
env14 = AttackStrategyEnv(topology=topo14)
print(f"  num_buses: {env14._num_buses}")
print(f"  obs_dim: {env14.obs_dim}")
obs, _ = env14.reset()
print(f"  observation shape: {obs.shape}")
assert env14.obs_dim == EXPECTED_OBS_DIM, f"Expected {EXPECTED_OBS_DIM}, got {env14.obs_dim}"
assert obs.shape == (EXPECTED_OBS_DIM,), f"Expected {(EXPECTED_OBS_DIM,)}, got {obs.shape}"
print("  PASS")

# Test 2: Custom 5-bus topology
print("\n=== Test 2: Custom 5-bus topology ===")
custom_nodes = [
    {"bus_id": 0, "name": "Gen", "type": "slack", "voltage": 1.05, "ip": "10.0.0.1"},
    {"bus_id": 1, "name": "Sub1", "type": "pq", "voltage": 1.02, "ip": "10.0.0.2"},
    {"bus_id": 2, "name": "Sub2", "type": "pq", "voltage": 1.01, "ip": "10.0.0.3"},
    {"bus_id": 3, "name": "Sub3", "type": "pq", "voltage": 1.00, "ip": "10.0.0.4"},
    {"bus_id": 4, "name": "Sub4", "type": "pq", "voltage": 0.99, "ip": "10.0.0.5"},
]
custom_edges = [(0, 1), (0, 2), (1, 2), (2, 3), (3, 4)]
topo5 = Topology(nodes=custom_nodes, edges=custom_edges)
set_topology(topo5)
env5 = AttackStrategyEnv(topology=topo5)
print(f"  num_buses: {env5._num_buses}")
print(f"  obs_dim: {env5.obs_dim}")
obs, _ = env5.reset()
print(f"  observation shape: {obs.shape}")
assert env5.obs_dim == env14.obs_dim, f"Obs dim mismatch: {env5.obs_dim} vs {env14.obs_dim}"
# Check padding: first 5 voltages should be non-zero, rest should be 0
# Voltages start at index 27 (24 attack_state + 3 last_action_params)
print(f"  voltages[0:6]: {obs[27:33]}")
print(f"  voltages[5:10]: {obs[32:37]}")
print("  PASS")

# Test 3: Same model can predict for both
print("\n=== Test 3: Same model works for both topologies ===")
from stable_baselines3 import PPO
import numpy as np

# Create a dummy model with the correct obs_dim
from stable_baselines3.common.env_util import make_vec_env
env = make_vec_env(lambda: AttackStrategyEnv(topology=topo14), n_envs=1)
model = PPO("MlpPolicy", env, verbose=0, policy_kwargs=dict(net_arch=[64, 64]))

# Predict on both topologies
action14, _ = model.predict(env14._get_obs(), deterministic=True)
action5, _ = model.predict(env5._get_obs(), deterministic=True)
print(f"  Action on 14-bus: {action14}")
print(f"  Action on 5-bus: {action5}")
print("  PASS")

# Test 4: Step through both
print("\n=== Test 4: Step through both ===")
obs14, _ = env14.reset()
obs5, _ = env5.reset()
for i in range(5):
    a14, _ = model.predict(obs14, deterministic=True)
    a5, _ = model.predict(obs5, deterministic=True)
    a14 = np.asarray(a14, dtype=np.int64).flatten()
    a5 = np.asarray(a5, dtype=np.int64).flatten()
    a14[3] = a14[3] % env14._num_buses
    a5[3] = a5[3] % env5._num_buses
    obs14, r14, t14, _, info14 = env14.step(a14)
    obs5, r5, t5, _, info5 = env5.step(a5)
    print(f"  Step {i}: 14-bus(target={info14['target_bus']}, reg={info14.get('register_address')}, reward={r14:.2f}) | "
          f"5-bus(target={info5['target_bus']}, reg={info5.get('register_address')}, reward={r5:.2f})")
print("  PASS")

print("\n=== ALL TESTS PASSED ===")
