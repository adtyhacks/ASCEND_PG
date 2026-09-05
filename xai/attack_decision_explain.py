"""
XAI — RL Attack Decision Explainer (Module 7).

Explains WHY the PPO agent chose a specific MITRE ATT&CK for ICS technique
at each step of a multi-stage intrusion chain. Uses the policy network's own
action probability distribution and value estimates — no external XAI library
needed since the policy's logits are themselves the explanation.

For each step, produces:
  - The chosen technique and its selection probability
  - Full probability distribution over all 17 techniques
  - Top alternative techniques the agent considered
  - The critic's value estimate (expected future reward from this state)
  - Human-readable rationale string

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
import torch
from stable_baselines3 import PPO

from rl_env import (
    AttackStrategyEnv,
    MITRE_TECHNIQUES,
    NUM_TECHNIQUES,
    NUM_STAGES,
)

STAGE_NAMES = ["Recon & Discovery", "Lateral Movement & C2", "Inhibit & Impair", "Impact"]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rl_agent.zip")


def load_rl_explainer(model_path: str = None) -> PPO:
    """Loads the trained PPO agent."""
    if model_path is None:
        model_path = MODEL_PATH
    model = PPO.load(model_path)
    return model


def explain_action(model: PPO, obs: np.ndarray, chosen_action: int,
                   env_info: dict = None) -> dict:
    """
    Explains why the PPO agent chose a specific action given an observation.
    """
    return _explain_action_impl(model, obs, chosen_action, env_info)


# Alias for backward compatibility across Streamlit pages
explain_step_decision = explain_action


def _explain_action_impl(model: PPO, obs: np.ndarray, chosen_action: int,
                         env_info: dict = None) -> dict:
    """
    Args:
        model: Trained PPO model
        obs: Current observation vector (24-dim)
        chosen_action: The action (technique index) that was selected
        env_info: Optional info dict from the environment step

    Returns:
        dict with full explanation of the decision
    """
    obs_tensor = torch.tensor(obs, dtype=torch.float32).unsqueeze(0).to(model.device)

    with torch.no_grad():
        # Get policy distribution and value estimate
        features = model.policy.extract_features(obs_tensor, model.policy.features_extractor)
        latent_pi, latent_vf = model.policy.mlp_extractor(features)
        action_logits = model.policy.action_net(latent_pi)
        value_estimate = model.policy.value_net(latent_vf).item()

        # Convert logits to probabilities
        action_probs = torch.softmax(action_logits, dim=-1).cpu().numpy().flatten()

    # Build technique probability table
    technique_probs = []
    for i, tech in enumerate(MITRE_TECHNIQUES):
        technique_probs.append({
            "index": i,
            "id": tech["id"],
            "name": tech["name"],
            "stage": tech["stage"],
            "stage_name": STAGE_NAMES[tech["stage"]],
            "probability": float(action_probs[i]),
        })

    # Sort by probability for alternatives ranking
    sorted_by_prob = sorted(technique_probs, key=lambda x: x["probability"], reverse=True)
    top_alternatives = [t for t in sorted_by_prob if t["index"] != chosen_action][:3]

    # Decode observation state
    current_stage = int(round(obs[0] * (NUM_STAGES - 1)))
    evasion_rate = float(obs[1])
    last_confidence = float(obs[2])
    completed_stages = [i for i in range(NUM_STAGES) if obs[20 + i] > 0.5]

    chosen_tech = MITRE_TECHNIQUES[chosen_action]
    chosen_prob = float(action_probs[chosen_action])

    # Build human-readable rationale
    rationale_parts = []
    rationale_parts.append(
        f"Agent chose {chosen_tech['id']} ({chosen_tech['name']}) with "
        f"{chosen_prob:.1%} probability, targeting Stage {chosen_tech['stage']} "
        f"({STAGE_NAMES[chosen_tech['stage']]})."
    )

    if completed_stages:
        completed_str = ", ".join(f"Stage {s} ({STAGE_NAMES[s]})" for s in completed_stages)
        rationale_parts.append(f"Completed stages: [{completed_str}].")
    else:
        rationale_parts.append("No stages completed yet.")

    rationale_parts.append(f"Current target: Stage {current_stage} ({STAGE_NAMES[current_stage]}).")

    if chosen_tech["stage"] == current_stage:
        rationale_parts.append("[+] This technique advances the attack to the next tactical stage.")
    elif chosen_tech["stage"] in completed_stages:
        rationale_parts.append("[!] This technique targets an already-completed stage (redundant).")
    else:
        rationale_parts.append("[!] This technique targets a future stage (out-of-order).")

    rationale_parts.append(f"Recent evasion rate: {evasion_rate:.1%}. Last detector confidence: {last_confidence:.2f}.")
    rationale_parts.append(f"Critic value estimate: {value_estimate:.2f} (expected future reward).")

    if top_alternatives:
        alt = top_alternatives[0]
        rationale_parts.append(
            f"Top alternative: {alt['id']} ({alt['name']}) at {alt['probability']:.1%}."
        )

    return {
        "chosen_technique": {
            "index": chosen_action,
            "id": chosen_tech["id"],
            "name": chosen_tech["name"],
            "stage": chosen_tech["stage"],
            "stage_name": STAGE_NAMES[chosen_tech["stage"]],
        },
        "chosen_probability": chosen_prob,
        "action_probabilities": technique_probs,
        "top_alternatives": top_alternatives,
        "value_estimate": value_estimate,
        "state": {
            "current_stage": current_stage,
            "current_stage_name": STAGE_NAMES[current_stage],
            "evasion_rate": evasion_rate,
            "last_confidence": last_confidence,
            "completed_stages": completed_stages,
        },
        "rationale": " ".join(rationale_parts),
    }


def explain_chain(model: PPO, env: AttackStrategyEnv = None,
                  max_steps: int = 12) -> list:
    """
    Runs a full attack episode and returns per-step decision explanations.

    Args:
        model: Trained PPO agent
        env: Optional AttackStrategyEnv instance (creates mock-mode one if None)
        max_steps: Maximum steps per episode

    Returns:
        List of per-step explanation dicts
    """
    if env is None:
        env = AttackStrategyEnv(real_mode=False)

    obs, info = env.reset()
    explanations = []

    for step_num in range(max_steps):
        # Get the agent's action
        action, _states = model.predict(obs, deterministic=True)
        action = int(action)

        # Explain the decision BEFORE stepping
        explanation = explain_action(model, obs, action)
        explanation["step"] = step_num + 1

        # Step the environment
        obs, reward, terminated, truncated, info = env.step(action)
        explanation["reward"] = float(reward)
        explanation["detected"] = info.get("detected", False)
        explanation["detection_confidence"] = info.get("detection_confidence", 0.0)
        explanation["campaign_complete"] = info.get("campaign_complete", False)

        explanations.append(explanation)

        if terminated or truncated:
            break

    return explanations


def run_decision_demo():
    """Self-test: runs a full attack chain with per-step explanations."""
    print("=" * 60)
    print("RL Attack Decision Explainer")
    print("=" * 60)

    if not os.path.exists(MODEL_PATH):
        print(f"ERROR: Trained model not found at {MODEL_PATH}")
        print("Run strategic/train_rl.py first.")
        return

    model = load_rl_explainer()
    env = AttackStrategyEnv(real_mode=False)

    print(f"\nRunning attack episode with per-step explanations...\n")

    chain_explanations = explain_chain(model, env)

    for exp in chain_explanations:
        tech = exp["chosen_technique"]
        print(f"Step {exp['step']}: {tech['id']} ({tech['name']})")
        print(f"  Stage Target: {tech['stage']} ({tech['stage_name']})")
        print(f"  Selection Probability: {exp['chosen_probability']:.1%}")
        print(f"  Value Estimate: {exp['value_estimate']:.2f}")
        print(f"  Reward: {exp['reward']:.2f}")
        print(f"  Detected: {exp['detected']} (conf: {exp['detection_confidence']:.3f})")
        print(f"  Campaign Complete: {exp['campaign_complete']}")

        if exp["top_alternatives"]:
            alts = ", ".join(
                f"{a['id']} ({a['probability']:.1%})"
                for a in exp["top_alternatives"]
            )
            print(f"  Alternatives: {alts}")

        print(f"  Rationale: {exp['rationale']}")
        print()

    # Summary
    total_steps = len(chain_explanations)
    completed = chain_explanations[-1]["campaign_complete"] if chain_explanations else False
    detected_steps = sum(1 for e in chain_explanations if e["detected"])
    evasion_rate = 1.0 - (detected_steps / total_steps) if total_steps > 0 else 0.0

    print("=" * 60)
    print(f"Chain Summary: {total_steps} steps, "
          f"{'COMPLETED' if completed else 'PARTIAL'}, "
          f"Evasion: {evasion_rate:.0%}")
    print("=" * 60)
    print("\n[OK] RL decision explainer working correctly.")


if __name__ == "__main__":
    run_decision_demo()
