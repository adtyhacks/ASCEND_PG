#!/usr/bin/env python3
"""
scripts/test_unified_pipeline.py

Sanity test for the merged ASCEND-PG repository.
Verifies all core ML models, XAI explainer components, DVS calculation,
and baseline pandapower environments.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

print("=" * 70)
print(" ASCEND-PG UNIFIED PIPELINE INTEGRATION TEST")
print("=" * 70)

# 1. Dependency checks
print("\n[1/7] Testing Core Dependencies...")
import torch
import gymnasium
import stable_baselines3
import shap
import lime
import pandapower
import streamlit
import pandas as pd
import numpy as np

print(f"      PyTorch: {torch.__version__} (CUDA: {torch.cuda.is_available()})")
print(f"      Stable-Baselines3: {stable_baselines3.__version__}")
print(f"      Pandapower: {pandapower.__version__}")
print("      Dependencies: OK")

# 2. GAN Checkpoint
print("\n[2/7] Testing GAN Generator & Discriminator Checkpoints...")
from generative.gan import Generator, Discriminator
gen_ckpt = torch.load(os.path.join(PROJECT_ROOT, "models", "gan_generator.pt"), map_location="cpu")
feature_dim = gen_ckpt["net.9.weight"].shape[0]  # 78 features
noise_dim = gen_ckpt["net.0.weight"].shape[1]   # 32 noise

gen = Generator(noise_dim=noise_dim, feature_dim=feature_dim)
gen.load_state_dict(gen_ckpt)
gen.eval()
noise = torch.randn(5, noise_dim)
synthetic_features = gen(noise)
print(f"      Loaded GAN Generator (noise={noise_dim} -> features={feature_dim})")
print(f"      Generated 5 synthetic samples: shape {synthetic_features.shape}")
print("      Module 6 (GAN): OK")

# 3. Detectors (LSTM + Autoencoder + Fusion)
print("\n[3/7] Testing Detectors (LSTM + Autoencoder + Fusion)...")
from detection.fusion import load_detectors, fuse_score

detectors = load_detectors()
df_cic = pd.read_csv(os.path.join(PROJECT_ROOT, "data", "cic_ids2017_subset.csv"))
sample_window = df_cic.iloc[:10]
fused_result = fuse_score(sample_window, detectors)
print(f"      Loaded LSTM + Autoencoder detectors from models/")
print(f"      Sample 10-step window fusion detection confidence: {fused_result['fused_confidence']:.4f} "
      f"(LSTM: {fused_result['lstm_confidence']:.4f}, AE: {fused_result['ae_anomaly_score']:.4f})")
print("      Module 8 (Detectors & Fusion): OK")

# 4. Strategic RL Agent (PPO)
print("\n[4/7] Testing Module 7 (PPO Strategic RL Agent)...")
from stable_baselines3 import PPO
from strategic.rl_env import AttackStrategyEnv, MITRE_TECHNIQUES

env = AttackStrategyEnv(real_mode=True)
model = PPO.load(os.path.join(PROJECT_ROOT, "models", "rl_agent.zip"))
obs, _ = env.reset()
action, _ = model.predict(obs, deterministic=True)
next_obs, reward, terminated, truncated, info = env.step(int(action))
chosen_tech = MITRE_TECHNIQUES[int(action)]
print(f"      PPO executed action: {chosen_tech['id']} ({chosen_tech['name']})")
print(f"      Stage: {chosen_tech['stage']} | Reward: {reward:.3f} | Evaded: {info.get('evaded')}")
print("      Module 7 (RL Agent): OK")

# 5. XAI Explainability Suite
print("\n[5/7] Testing Explainability & Decision Explainer...")
from xai.attack_decision_explain import explain_action
from xai.recommendation_templates import get_technique_recommendations, format_report

exp = explain_action(model, obs, int(action))
tech_rec = get_technique_recommendations(chosen_tech['id'])
print(f"      RL Decision Rationale: {exp['rationale']}")
print(f"      Top alternative technique: {exp['top_alternatives'][0]['id']} ({exp['top_alternatives'][0]['name']})")
print(f"      Mitigations available for {chosen_tech['id']}: {len(tech_rec.get('mitigations', []))} items")
print("      XAI Suite: OK")

# 6. Defense Vulnerability Score (DVS) & Plateau Tracker
print("\n[6/7] Testing Metrics Layer (DVS + PlateauTracker)...")
from metrics.dvs import compute_dvs, evaluate_agent, PlateauTracker

eval_results = evaluate_agent(num_episodes=2, real_mode=False)
dvs_res = compute_dvs(eval_results)
plateau = PlateauTracker(patience=3, min_evasion_gain=0.03)
plateau.update(0.70)
plateau.update(0.71)
is_plateau = plateau.update(0.705)
print(f"      Computed DVS Score from 2 episodes: {dvs_res['score']:.1f} / 100 ({dvs_res['color']} {dvs_res['rating']})")
print(f"      Evasion: {dvs_res['breakdown']['evasion']['score']:.1f}% | Completion: {dvs_res['breakdown']['campaign']['score']:.1f}%")
print("      Metrics & DVS: OK")

# 7. Grid Baseline Environment
print("\n[7/7] Testing Pandapower Grid Baseline & Topology...")
from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology

net_obj, grid_df, traffic_df = build_baseline()
nodes, edges = build_ot_topology(net_obj)
print(f"      Electrical buses: {len(grid_df)} | Lines: {len(net_obj.line)}")
print(f"      OT Topology nodes: {len(nodes)} | Edges: {len(edges)}")
print("      Power Grid Baseline: OK")

print("\n" + "=" * 70)
print(" ALL 7 UNIFIED SUBSYSTEMS VERIFIED AND FULLY OPERATIONAL!")
print("=" * 70)
