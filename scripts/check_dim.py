#!/usr/bin/env python3
"""Quick check on obs_dim."""
import sys
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")
from strategic.rl_env import MAX_BUSES, AttackStrategyEnv
print("MAX_BUSES:", MAX_BUSES)
env = AttackStrategyEnv()
print("obs_dim:", env.obs_dim)
print("Expected:", 24 + 5 * MAX_BUSES)
