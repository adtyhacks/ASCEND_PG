import sys
sys.path.insert(0, '/home/adty17/ascend-pg-webapp')

# Test topology
from testbed.topology import get_topology
topo = get_topology()
PLC_IPS = [topo.get_ip(i) for i in range(topo.num_buses)]
BUS_NAMES = topo.name_map
BUS_TYPES = {i: topo.bus_types[i] for i in range(topo.num_buses)}
print(f"PLCs: {len(PLC_IPS)} ({PLC_IPS[0]} - {PLC_IPS[-1]})")
print(f"Bus names: {len(BUS_NAMES)}")
print(f"Bus types: {len(BUS_TYPES)}")

# Test RL env
from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES
env = AttackStrategyEnv()
print(f"\nRL env obs_dim: {env.obs_dim}")
print(f"Techniques: {len(MITRE_TECHNIQUES)}")
print(f"Buses: {env._num_buses}")
print(f"Lines: {len(topo.edges)}")

# Test observation
obs, _ = env.reset()
print(f"Observation shape: {obs.shape}")
print(f"Observation sample: {obs[:5]}...")

# Test step with multi-discrete action
import random
import numpy as np
action = np.array([
    random.randint(0, len(MITRE_TECHNIQUES)-1),  # technique
    random.randint(0, 49),                         # register offset
    random.randint(0, 9),                          # value level
    random.randint(0, env._num_buses-1),           # target bus
], dtype=np.int64)
obs2, reward, term, trunc, info = env.step(action)
print(f"Step tech={action[0]}: reward={reward:.2f}, "
      f"register={info.get('register_address')}, "
      f"value={info.get('value_magnitude', 0):.3f}, "
      f"target_bus={info.get('target_bus')}, "
      f"compromised={len(info.get('compromised_buses', []))}")

# Test PLC server
from testbed.plc_server import IEEE14_BUS_DATA, IEEE14_LINES, build_context
print(f"\nPLC server: {len(IEEE14_BUS_DATA)} buses, {len(IEEE14_LINES)} lines")
ctx = build_context(bus_id=0)
print(f"Context built for bus 0: OK")

# Test executor
from scripts.testbed_executor import TECHNIQUE_TO_STEP_NAME, build_step
print(f"\nExecutor: {len(TECHNIQUE_TO_STEP_NAME)} techniques")
step = build_step("T0836", target_ip="10.0.0.5", register_address=40010, value_magnitude=1.05)
print(f"FDI step target: {step['args'][1] if step else 'N/A'}, "
      f"register: {step['args'][-2] if step else 'N/A'}")

print("\n=== ALL IMPORTS OK ===")
