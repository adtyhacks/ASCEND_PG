"""
Module 7 - Trains a topology-aware PPO agent for MITRE ATT&CK Multi-Stage
Intrusion Chaining on ICS networks.

The RL agent learns to:
- Understand network topology (bus connectivity, generator locations, voltage profiles)
- Formulate adaptive, multi-stage attack sequences across 4 tactical stages
- Maximize evasion against the hybrid defense layer (Suricata + ML fusion)
- Perform lateral movement along network adjacency for maximum impact

Usage:
    # Train with default IEEE-14 topology
    python3 train_rl.py

    # Train with custom topology
    python3 train_rl.py --topology /path/to/csv/dir

    # Resume training from checkpoint
    python3 train_rl.py --resume

    # Quick test run
    python3 train_rl.py --quick
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback, CheckpointCallback
from stable_baselines3.common.vec_env import VecNormalize

from rl_env import AttackStrategyEnv, PlateauTracker, NUM_TECHNIQUES, NUM_STAGES, MAX_BUSES
from testbed.topology import load_topology, get_topology, Topology


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODEL_DIR / "rl_agent.zip"
NORM_PATH = MODEL_DIR / "rl_agent_norm.pkl"
LOG_DIR = PROJECT_ROOT / "data" / "training_logs"


class TrainingCallback(BaseCallback):
    """Custom callback for logging and early stopping."""

    def __init__(self, eval_interval=1000, patience=10, verbose=1):
        super().__init__(verbose)
        self.eval_interval = eval_interval
        self.patience = patience
        self.best_evasion = 0.0
        self.no_improve_count = 0
        self.episode_rewards = []
        self.episode_evasions = []
        self.log_data = []

    def _on_step(self) -> bool:
        # Log every eval_interval steps
        if self.n_calls % self.eval_interval == 0:
            # Get info from last step
            info = self.locals.get("infos", [{}])
            if info and len(info) > 0:
                last_info = info[-1]
                reward = self.locals.get("rewards", [0])[-1]
                detected = last_info.get("detected", False)

                self.episode_rewards.append(float(reward))
                self.episode_evasions.append(0 if detected else 1)

                # Calculate recent metrics
                recent_n = min(100, len(self.episode_evasions))
                if recent_n > 0:
                    avg_evasion = sum(self.episode_evasions[-recent_n:]) / recent_n
                    avg_reward = sum(self.episode_rewards[-recent_n:]) / recent_n

                    self.log_data.append({
                        "step": self.n_calls,
                        "avg_reward": avg_reward,
                        "evasion_rate": avg_evasion,
                        "total_evasions": sum(self.episode_evasions),
                    })

                    if self.verbose > 0:
                        print(f"  Step {self.n_calls:>6d} | "
                              f"Reward: {avg_reward:>7.3f} | "
                              f"Evasion: {avg_evasion:.1%} | "
                              f"Best: {self.best_evasion:.1%}")

                    # Early stopping check
                    if avg_evasion > self.best_evasion + 0.01:
                        self.best_evasion = avg_evasion
                        self.no_improve_count = 0
                    else:
                        self.no_improve_count += 1

                    if self.no_improve_count >= self.patience:
                        print(f"\n  Early stopping: No improvement for {self.patience} evaluations")
                        return False

        return True

    def _on_training_end(self):
        # Save training log
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / f"training_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(log_path, "w") as f:
            json.dump(self.log_data, f, indent=2)
        if self.verbose > 0:
            print(f"  Training log saved to {log_path}")


def train(topology_dir: str = None, resume: bool = False,
          quick: bool = False, timesteps: int = None,
          real_mode: bool = False, n_envs: int = 4):
    """
    Train a topology-aware PPO agent.

    Args:
        topology_dir: Path to directory with nodes.csv/edges.csv (None = IEEE-14)
        resume: Resume training from existing model checkpoint
        quick: Quick test run (5k timesteps)
        timesteps: Override total timesteps
        real_mode: Use real detection models instead of mock
        n_envs: Number of parallel environments
    """
    # Load topology
    if topology_dir:
        topo = load_topology(topology_dir)
        print(f"Loaded custom topology: {topo.num_buses} buses, {len(topo.edges)} edges")
    else:
        topo = get_topology()
        print(f"Using default IEEE-14 topology: {topo.num_buses} buses, {len(topo.edges)} edges")

    # FIXED observation dim: always MAX_BUSES slots (zero-padded for smaller topologies)
    obs_dim = (1 + 1 + 1 + NUM_TECHNIQUES + NUM_STAGES  # attack state
               + MAX_BUSES                               # voltages (padded)
               + MAX_BUSES                               # degrees (padded)
               + MAX_BUSES                               # bus types (padded)
               + MAX_BUSES                               # compromised (padded)
               + 1 + 1)                                  # frac_compromised, attack_depth

    print(f"\nTopology-Aware PPO Training")
    print(f"  Observation dim: {obs_dim} (fixed, MAX_BUSES={MAX_BUSES})")
    print(f"  Actual buses in topology: {topo.num_buses}")
    print(f"  Generator buses: {topo.gen_buses}")
    print(f"  Action space: {NUM_TECHNIQUES} MITRE techniques")
    print(f"  Parallel envs: {n_envs}")

    # Timesteps
    if quick:
        total_timesteps = 5_000
    elif timesteps:
        total_timesteps = timesteps
    else:
        # Scale timesteps with topology size
        base_timesteps = 30_000
        total_timesteps = base_timesteps * max(1, topo.num_buses // 5)

    print(f"  Total timesteps: {total_timesteps:,}")

    # Create vectorized env
    def make_env():
        return AttackStrategyEnv(real_mode=real_mode, topology=topo)

    env = make_vec_env(make_env, n_envs=n_envs)

    # Network architecture: obs_dim is fixed at ~229 regardless of topology
    # Larger network for multi-parameter action space (technique + register + value + target)
    net_arch = [256, 256, 128]

    print(f"  Network architecture: {net_arch}")
    # Access underlying env through Monitor -> DummyVecEnv
    inner_env = env.envs[0]
    if hasattr(inner_env, 'env'):
        inner_env = inner_env.env  # unwrap Monitor
    print(f"  Action space: MultiDiscrete([17, 50, 10, {inner_env._num_buses}])")
    print(f"  Observation dim: {inner_env.obs_dim}")

    # Load or create model
    if resume and MODEL_PATH.exists():
        print(f"\nResuming from {MODEL_PATH}")
        model = PPO.load(str(MODEL_PATH), env=env)
    else:
        model = PPO(
            "MlpPolicy",
            env,
            verbose=1,
            policy_kwargs=dict(net_arch=net_arch),
            learning_rate=3e-4,
            gamma=0.99,
            clip_range=0.2,
            ent_coef=0.01,
            n_steps=2048,
            batch_size=64,
            n_epochs=10,
        )

    # Callbacks
    callback = TrainingCallback(eval_interval=500, patience=15)
    checkpoint_callback = CheckpointCallback(
        save_freq=5000,
        save_path=str(MODEL_DIR / "checkpoints"),
        name_prefix="ppo_topo",
    )

    # Train
    print(f"\nTraining PPO agent...")
    start_time = time.time()
    model.learn(
        total_timesteps=total_timesteps,
        callback=[callback, checkpoint_callback],
        progress_bar=False,
    )
    elapsed = time.time() - start_time

    # Save final model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save(str(MODEL_PATH))
    print(f"\nModel saved to {MODEL_PATH}")
    print(f"Training time: {elapsed:.1f}s ({total_timesteps / elapsed:.0f} timesteps/sec)")

    # Evaluate
    print("\n" + "=" * 60)
    print("Final Evaluation")
    print("=" * 60)
    evaluate_agent(model, topology=topo, real_mode=real_mode, n_episodes=20)

    return model


def evaluate_agent(model, topology: Topology = None, real_mode: bool = False,
                   n_episodes: int = 20):
    """Evaluate the trained agent."""
    if topology is None:
        topology = get_topology()

    env = AttackStrategyEnv(real_mode=real_mode, topology=topology)
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
            obs, reward, terminated, truncated, info = env.step(action)
            ep_reward += reward
            steps += 1
            if not info["detected"]:
                evasions += 1
            actions_taken.append(
                f"{info['technique_id']} ({info['technique_name']}) "
                f"Reg={info['register_address']} Val={info['value_magnitude']:.3f} "
                f"Target=Bus{info['target_bus']}"
            )
            done = terminated or truncated

        if info.get("campaign_complete", False):
            campaigns_completed += 1

        ep_evasion_rate = evasions / max(1, steps)
        evasion_rates.append(ep_evasion_rate)
        total_rewards.append(ep_reward)
        is_plateaued = plateau_tracker.update(ep_evasion_rate)

        if len(sample_chains) < 3:
            sample_chains.append((actions_taken, ep_evasion_rate,
                                  info.get("campaign_complete", False)))

    print(f"\nEvaluation Results ({n_episodes} Episodes)")
    print(f"  Campaign Completion: {campaigns_completed / n_episodes * 100:.1f}% "
          f"({campaigns_completed}/{n_episodes})")
    print(f"  Average Reward:      {sum(total_rewards) / n_episodes:.2f}")
    print(f"  Average Evasion:     {sum(evasion_rates) / n_episodes * 100:.1f}%")
    print(f"  Plateau Status:      "
          f"{'Saturated' if is_plateaued else 'Progressing'}")

    print("\nSample Attack Chains:")
    for i, (chain, ev_rate, complete) in enumerate(sample_chains, 1):
        status = "Complete" if complete else "Partial"
        print(f"\n  Chain #{i} ({status}, Evasion: {ev_rate * 100:.0f}%):")
        for j, desc in enumerate(chain, 1):
            print(f"    {j}. {desc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train topology-aware PPO agent")
    parser.add_argument("--topology", type=str, default=None,
                        help="Path to topology directory with nodes.csv/edges.csv")
    parser.add_argument("--resume", action="store_true",
                        help="Resume training from checkpoint")
    parser.add_argument("--quick", action="store_true",
                        help="Quick test run (5k timesteps)")
    parser.add_argument("--timesteps", type=int, default=None,
                        help="Override total timesteps")
    parser.add_argument("--real-mode", action="store_true",
                        help="Use real detection models")
    parser.add_argument("--n-envs", type=int, default=4,
                        help="Number of parallel environments")
    args = parser.parse_args()

    train(
        topology_dir=args.topology,
        resume=args.resume,
        quick=args.quick,
        timesteps=args.timesteps,
        real_mode=args.real_mode,
        n_envs=args.n_envs,
    )
