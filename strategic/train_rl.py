"""
Module 7 — Trains a PPO agent for MITRE ATT&CK Multi-Stage Intrusion Chaining.

The RL agent learns to formulate adaptive, multi-stage attack sequences across
4 tactical stages (Reconnaissance -> Collection -> Tampering -> Impact) while
maximizing evasion against the defense layer (LSTM + Autoencoder fusion).

Owner: Andikumar (training track, Modules 6-8)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env

from rl_env import (
    AttackStrategyEnv,
    MITRE_TECHNIQUES,
    PlateauTracker,
    NUM_TECHNIQUES,
)

MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rl_agent.zip")
TOTAL_TIMESTEPS = 30_000


def train(real_mode: bool = False):
    print(f"Initializing RL Environment (real_mode={real_mode}, 17 MITRE Techniques)...")
    env = make_vec_env(lambda: AttackStrategyEnv(real_mode=real_mode), n_envs=4)

    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        policy_kwargs=dict(net_arch=[128, 128]),
        learning_rate=3e-4,
        gamma=0.99,
        clip_range=0.2,
        ent_coef=0.01,  # encourages exploration across all 17 techniques
    )

    print(f"Training PPO agent for {TOTAL_TIMESTEPS} timesteps...")
    model.learn(total_timesteps=TOTAL_TIMESTEPS)

    os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
    model.save(MODEL_SAVE_PATH)
    print(f"\nSaved trained multi-stage RL agent to {MODEL_SAVE_PATH}")

    evaluate_agent(model, real_mode=real_mode, n_episodes=20)


def evaluate_agent(model, real_mode: bool = False, n_episodes: int = 20):
    """
    Evaluates the trained agent's ability to chain multi-stage attack paths
    and demonstrates the plateau-based stopping condition.
    """
    env = AttackStrategyEnv(real_mode=real_mode)
    plateau_tracker = PlateauTracker(patience=5, min_evasion_gain=0.02)

    campaigns_completed = 0
    total_rewards = []
    evasion_rates = []
    sample_chains = []

    for ep in range(1, n_episodes + 1):
        obs, _ = env.reset()
        done = False
        ep_reward = 0.0
        actions_taken = []
        evasions = 0
        steps = 0

        while not done:
            action, _ = model.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, info = env.step(int(action))
            ep_reward += reward
            steps += 1
            if not info["detected"]:
                evasions += 1
            actions_taken.append(f"{info['technique_id']} ({info['technique_name']})")
            done = terminated or truncated

        if info.get("campaign_complete", False):
            campaigns_completed += 1

        ep_evasion_rate = evasions / max(1, steps)
        evasion_rates.append(ep_evasion_rate)
        total_rewards.append(ep_reward)
        is_plateaued = plateau_tracker.update(ep_evasion_rate)

        if len(sample_chains) < 3:
            sample_chains.append((actions_taken, ep_evasion_rate, info.get("campaign_complete", False)))

    print("\n" + "=" * 60)
    print(f"--- Evaluation Results ({n_episodes} Episodes) ---")
    print(f"Campaign Completion Rate: {campaigns_completed / n_episodes * 100:.1f}% ({campaigns_completed}/{n_episodes})")
    print(f"Average Episode Reward:   {sum(total_rewards) / n_episodes:.2f}")
    print(f"Average Evasion Rate:     {sum(evasion_rates) / n_episodes * 100:.1f}%")
    print(f"Plateau Status (N=5):     {'Plateau Detected (Defenses Saturated)' if is_plateaued else 'Progressing'}")
    print("=" * 60)

    print("\n--- Sample Learned Attack Chains ---")
    for i, (chain, ev_rate, complete) in enumerate(sample_chains, 1):
        status = "Completed [Recon->Access->Tamper->Impact]" if complete else "Partial Chain"
        print(f"\nChain #{i} ({status}, Evasion: {ev_rate*100:.0f}%):")
        for step_idx, step_desc in enumerate(chain, 1):
            print(f"  Stage {step_idx}: {step_desc}")


if __name__ == "__main__":
    train(real_mode=False)
