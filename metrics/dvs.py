"""
Metrics — Defense Vulnerability Score (DVS).

A composite score in [0, 100] quantifying how vulnerable the ICS defense
posture is, based on multi-stage RL evaluation results.

DVS = w1*E + w2*C + w3*S + w4*P
Where:
  E = Evasion Score:    avg_evasion_rate * 100
  C = Campaign Score:   completion_rate * 100
  S = Stage Depth:      (avg_max_stage / 3) * 100
  P = Plateau Score:    100 if plateau detected, 50 otherwise
  Weights: w1=0.30, w2=0.30, w3=0.25, w4=0.15

Rating Bands:
  0-25:   🟢 Robust     (defenses withstand most attacks)
  26-50:  🟡 Moderate   (some attack paths succeed)
  51-75:  🟠 Vulnerable (majority of campaigns succeed)
  76-100: 🔴 Critical   (defenses comprehensively bypassed)

Owner: Andikumar (training track)
"""

import os
import sys

# Ensure UTF-8 stdout on Windows console
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "strategic"))

import numpy as np
from stable_baselines3 import PPO

from rl_env import (
    AttackStrategyEnv,
    MITRE_TECHNIQUES,
    NUM_STAGES,
    PlateauTracker,
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rl_agent.zip")

# DVS weights
W_EVASION = 0.30
W_CAMPAIGN = 0.30
W_STAGE_DEPTH = 0.25
W_PLATEAU = 0.15

RATING_BANDS = [
    (25, "Robust", "🟢", "Defenses withstand most attack campaigns."),
    (50, "Moderate", "🟡", "Some multi-stage attack paths succeed; targeted hardening needed."),
    (75, "Vulnerable", "🟠", "Majority of campaigns complete successfully; significant defense gaps."),
    (100, "Critical", "🔴", "Defenses comprehensively bypassed; immediate remediation required."),
]


def _get_rating(score: float) -> dict:
    """Maps a DVS score to a rating band."""
    for threshold, name, color, description in RATING_BANDS:
        if score <= threshold:
            return {"rating": name, "color": color, "description": description}
    return {"rating": "Critical", "color": "🔴", "description": RATING_BANDS[-1][3]}


def evaluate_agent(model_path: str = None, num_episodes: int = 20,
                   real_mode: bool = False) -> dict:
    """
    Runs the trained RL agent through multiple episodes and collects
    evaluation statistics needed for DVS computation.

    Args:
        model_path: Path to trained RL agent (.zip)
        num_episodes: Number of evaluation episodes
        real_mode: Whether to use real detector fusion or mock mode

    Returns:
        dict with evasion_rates, completion_count, max_stages_reached,
        plateau_detected, episode_rewards, chains
    """
    if model_path is None:
        model_path = MODEL_PATH

    model = PPO.load(model_path)
    env = AttackStrategyEnv(real_mode=real_mode)
    plateau_tracker = PlateauTracker(patience=5)

    evasion_rates = []
    completion_count = 0
    max_stages_reached = []
    episode_rewards = []
    chains = []

    for ep in range(num_episodes):
        obs, info = env.reset()
        total_reward = 0.0
        detected_count = 0
        step_count = 0
        chain = []

        done = False
        while not done:
            action, _ = model.predict(obs, deterministic=True)
            action = np.asarray(action, dtype=np.int64).flatten()
            obs, reward, terminated, truncated, info = env.step(action)
            total_reward += reward
            step_count += 1

            if info.get("detected", False):
                detected_count += 1

            chain.append({
                "technique_id": info.get("technique_id", ""),
                "technique_name": info.get("technique_name", ""),
                "stage": info.get("stage", 0),
                "detected": info.get("detected", False),
                "confidence": info.get("detection_confidence", 0.0),
            })

            done = terminated or truncated

        # Per-episode metrics
        evasion_rate = 1.0 - (detected_count / step_count) if step_count > 0 else 0.0
        evasion_rates.append(evasion_rate)
        episode_rewards.append(total_reward)
        chains.append(chain)

        if info.get("campaign_complete", False):
            completion_count += 1

        # Track max stage reached in this episode
        stages_hit = set()
        for step_info in chain:
            if not step_info["detected"]:
                stages_hit.add(step_info["stage"])
        max_stage = max(stages_hit) if stages_hit else 0
        max_stages_reached.append(max_stage)

        plateau_tracker.update(evasion_rate)

    return {
        "num_episodes": num_episodes,
        "evasion_rates": evasion_rates,
        "avg_evasion_rate": float(np.mean(evasion_rates)),
        "completion_count": completion_count,
        "completion_rate": completion_count / num_episodes,
        "max_stages_reached": max_stages_reached,
        "avg_max_stage": float(np.mean(max_stages_reached)),
        "plateau_detected": plateau_tracker.stagnant_count >= plateau_tracker.patience,
        "episode_rewards": episode_rewards,
        "avg_reward": float(np.mean(episode_rewards)),
        "chains": chains,
    }


def compute_dvs(eval_results: dict) -> dict:
    """
    Computes the Defense Vulnerability Score from evaluation results.

    Args:
        eval_results: dict from evaluate_agent()

    Returns:
        dict with score, rating, color, breakdown, description
    """
    # Sub-scores (each in [0, 100])
    evasion_score = eval_results["avg_evasion_rate"] * 100
    campaign_score = eval_results["completion_rate"] * 100
    stage_depth_score = (eval_results["avg_max_stage"] / (NUM_STAGES - 1)) * 100
    plateau_score = 100.0 if eval_results["plateau_detected"] else 50.0

    # Weighted composite
    dvs = (
        W_EVASION * evasion_score
        + W_CAMPAIGN * campaign_score
        + W_STAGE_DEPTH * stage_depth_score
        + W_PLATEAU * plateau_score
    )
    dvs = float(np.clip(dvs, 0, 100))

    rating_info = _get_rating(dvs)

    breakdown = {
        "evasion": {
            "score": round(evasion_score, 1),
            "weight": W_EVASION,
            "weighted": round(W_EVASION * evasion_score, 1),
            "detail": f"Average evasion rate: {eval_results['avg_evasion_rate']:.1%}",
        },
        "campaign": {
            "score": round(campaign_score, 1),
            "weight": W_CAMPAIGN,
            "weighted": round(W_CAMPAIGN * campaign_score, 1),
            "detail": f"Campaign completion: {eval_results['completion_count']}/{eval_results['num_episodes']}",
        },
        "stage_depth": {
            "score": round(stage_depth_score, 1),
            "weight": W_STAGE_DEPTH,
            "weighted": round(W_STAGE_DEPTH * stage_depth_score, 1),
            "detail": f"Avg max stage reached: {eval_results['avg_max_stage']:.1f}/{NUM_STAGES - 1}",
        },
        "plateau": {
            "score": round(plateau_score, 1),
            "weight": W_PLATEAU,
            "weighted": round(W_PLATEAU * plateau_score, 1),
            "detail": f"Plateau {'detected' if eval_results['plateau_detected'] else 'not detected'}",
        },
    }

    return {
        "score": round(dvs, 1),
        "rating": rating_info["rating"],
        "color": rating_info["color"],
        "description": rating_info["description"],
        "breakdown": breakdown,
        "eval_summary": {
            "num_episodes": eval_results["num_episodes"],
            "avg_evasion_rate": round(eval_results["avg_evasion_rate"], 3),
            "completion_rate": round(eval_results["completion_rate"], 3),
            "avg_max_stage": round(eval_results["avg_max_stage"], 2),
            "avg_reward": round(eval_results["avg_reward"], 2),
            "plateau_detected": eval_results["plateau_detected"],
        },
    }


def run_dvs_evaluation(model_path: str = None, num_episodes: int = 20) -> dict:
    """
    End-to-end DVS computation: loads the RL agent, runs evaluation episodes,
    computes DVS score and breakdown.

    Args:
        model_path: Path to trained RL agent
        num_episodes: Number of evaluation episodes

    Returns:
        Full DVS result dict
    """
    eval_results = evaluate_agent(model_path, num_episodes)
    dvs_result = compute_dvs(eval_results)
    return dvs_result


def run_dvs_demo():
    """Self-test: runs full DVS evaluation and prints formatted report."""
    print("=" * 60)
    print("Defense Vulnerability Score (DVS) Evaluation")
    print("=" * 60)

    if not os.path.exists(MODEL_PATH):
        print(f"ERROR: Trained model not found at {MODEL_PATH}")
        print("Run strategic/train_rl.py first.")
        return

    print(f"\nRunning {20}-episode evaluation...")
    result = run_dvs_evaluation(num_episodes=20)

    print(f"\n{'=' * 60}")
    print(f"  DVS Score: {result['color']} {result['score']:.1f} / 100 — {result['rating']}")
    print(f"  {result['description']}")
    print(f"{'=' * 60}")

    print(f"\n--- Score Breakdown ---")
    print(f"{'Component':<20} {'Sub-Score':>10} {'Weight':>8} {'Weighted':>10} {'Detail'}")
    print("-" * 80)
    for name, comp in result["breakdown"].items():
        print(f"{name:<20} {comp['score']:>10.1f} {comp['weight']:>8.2f} {comp['weighted']:>10.1f}   {comp['detail']}")

    print(f"\n--- Evaluation Summary ---")
    summary = result["eval_summary"]
    print(f"  Episodes:           {summary['num_episodes']}")
    print(f"  Avg Evasion Rate:   {summary['avg_evasion_rate']:.1%}")
    print(f"  Completion Rate:    {summary['completion_rate']:.1%}")
    print(f"  Avg Max Stage:      {summary['avg_max_stage']:.2f} / {NUM_STAGES - 1}")
    print(f"  Avg Reward:         {summary['avg_reward']:.2f}")
    print(f"  Plateau Detected:   {summary['plateau_detected']}")

    print("\n[OK] DVS evaluation complete.")
    return result


if __name__ == "__main__":
    run_dvs_demo()
