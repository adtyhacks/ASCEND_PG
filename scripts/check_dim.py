#!/usr/bin/env python3
"""Quick check on obs_dim."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from strategic.rl_env import MAX_BUSES, AttackStrategyEnv
print("MAX_BUSES:", MAX_BUSES)
env = AttackStrategyEnv()
print("obs_dim:", env.obs_dim)
print("Expected:", env.obs_dim)
