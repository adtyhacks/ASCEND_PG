"""
Module 7 — Multi-Stage MITRE ATT&CK for ICS RL Environment.

Simulates an adversary chaining multi-stage intrusion paths against the ICS testbed
and defense layer across 4 tactical stages:
  Stage 0: Initial Access & Discovery (Reconnaissance)
  Stage 1: Lateral Movement, Collection & C2
  Stage 2: Inhibit Response & Impair Process Control (Tampering)
  Stage 3: Impact (Manipulation / Denial of View)

Supports:
- 17 MITRE ATT&CK for ICS techniques (discrete action space)
- Real-mode detector evaluation via detection/fusion.py (LSTM + Autoencoder)
- Mock-mode calibrated evaluation
- Plateau detection tracking to signal when defenses have exhausted discoverable vulnerabilities

Owner: Andikumar (training track, Modules 6-8)
"""

import json
import os
import random
import sys

import gymnasium as gym
import numpy as np
import pandas as pd
from gymnasium import spaces

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))

# 17 MITRE ATT&CK for ICS techniques organized by tactical stage
MITRE_TECHNIQUES = [
    # Stage 0: Initial Access & Discovery
    {"id": "T0886", "name": "Remote Services", "stage": 0, "mock_prob": 0.50},
    {"id": "T0846", "name": "Remote System Discovery", "stage": 0, "mock_prob": 0.70},
    {"id": "T0888", "name": "Remote System Info Discovery", "stage": 0, "mock_prob": 0.45},
    {"id": "T0842", "name": "Network Sniffing", "stage": 0, "mock_prob": 0.25},
    # Stage 1: Lateral Movement & Collection & C2
    {"id": "T0830", "name": "Adversary-in-the-Middle", "stage": 1, "mock_prob": 0.55},
    {"id": "T0801", "name": "Monitor Process State", "stage": 1, "mock_prob": 0.35},
    {"id": "T0802", "name": "Automated Collection", "stage": 1, "mock_prob": 0.60},
    {"id": "T0869", "name": "Standard App Layer Protocol", "stage": 1, "mock_prob": 0.40},
    # Stage 2: Inhibit Response & Impair Process Control
    {"id": "T0814", "name": "Denial of Service", "stage": 2, "mock_prob": 0.85},
    {"id": "T0878", "name": "Alarm Suppression", "stage": 2, "mock_prob": 0.60},
    {"id": "T0816", "name": "Device Restart/Shutdown", "stage": 2, "mock_prob": 0.75},
    {"id": "T0881", "name": "Service Stop", "stage": 2, "mock_prob": 0.70},
    {"id": "T0836", "name": "Modify Parameter (FDI)", "stage": 2, "mock_prob": 0.65},
    {"id": "T0835", "name": "Manipulate I/O Image", "stage": 2, "mock_prob": 0.65},
    {"id": "T0806", "name": "Brute Force I/O", "stage": 2, "mock_prob": 0.80},
    # Stage 3: Impact
    {"id": "T0832", "name": "Manipulation of View (Replay)", "stage": 3, "mock_prob": 0.40},
    {"id": "T0815", "name": "Denial of View", "stage": 3, "mock_prob": 0.70},
]

TECHNIQUE_IDS = [t["id"] for t in MITRE_TECHNIQUES]
NUM_TECHNIQUES = len(TECHNIQUES := MITRE_TECHNIQUES)
NUM_STAGES = 4
MAX_STEPS_PER_CHAIN = 12


class AttackStrategyEnv(gym.Env):
    """
    Gymnasium environment for training an RL agent to formulate multi-stage attack paths.
    Observation Vector (dim = 24):
      - [0]: Current target stage (normalized [0, 1])
      - [1]: Recent evasion rate across past 5 actions [0, 1]
      - [2]: Last observed detector confidence [0, 1]
      - [3..19]: One-hot vector of last executed technique (17 dims)
      - [20..23]: Multi-hot vector of completed tactical stages (4 dims)
    """

    metadata = {"render_modes": []}

    def __init__(self, real_mode: bool = False, dataset_path: str = None):
        super().__init__()
        self.real_mode = real_mode
        self.action_space = spaces.Discrete(NUM_TECHNIQUES)
        self.obs_dim = 1 + 1 + 1 + NUM_TECHNIQUES + NUM_STAGES
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(self.obs_dim,), dtype=np.float32
        )

        self._history = []
        self._last_action = 0
        self._last_confidence = 0.0
        self._current_stage = 0
        self._completed_stages = set()
        self._step_count = 0
        self._chain = []

        # Real-mode detector initialization
        self.detectors = None
        self.flow_samples = None
        if self.real_mode:
            self._init_real_detector(dataset_path)

    def _init_real_detector(self, dataset_path: str = None):
        """Loads trained LSTM & Autoencoder detector models and baseline flow data."""
        try:
            from fusion import load_detectors, WINDOW_SIZE
            self.detectors = load_detectors()
            self.window_size = WINDOW_SIZE

            if dataset_path is None:
                dataset_path = os.path.join(
                    os.path.dirname(__file__), "..", "data", "cic_ids2017_subset.csv"
                )
            if os.path.exists(dataset_path):
                df = pd.read_csv(dataset_path)
                label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
                if label_col:
                    self.flow_samples = df.drop(columns=[label_col])
                else:
                    self.flow_samples = df
        except Exception as e:
            print(f"[Warning] Failed to initialize real detector: {e}. Falling back to mock mode.")
            self.real_mode = False

    def _get_obs(self) -> np.ndarray:
        recent = self._history[-5:]
        recent_evasion_rate = (sum(1 - x for x in recent) / len(recent)) if recent else 1.0

        one_hot_action = np.zeros(NUM_TECHNIQUES, dtype=np.float32)
        one_hot_action[self._last_action] = 1.0

        stages_vec = np.zeros(NUM_STAGES, dtype=np.float32)
        for s in self._completed_stages:
            if 0 <= s < NUM_STAGES:
                stages_vec[s] = 1.0

        obs = np.concatenate([
            [float(self._current_stage) / (NUM_STAGES - 1)],
            [float(recent_evasion_rate)],
            [float(self._last_confidence)],
            one_hot_action,
            stages_vec,
        ]).astype(np.float32)
        return obs

    def _evaluate_attack(self, technique: dict) -> float:
        """Returns detection confidence score in [0.0, 1.0]."""
        if self.real_mode and self.detectors is not None and self.flow_samples is not None:
            try:
                from fusion import fuse_score
                # Sample a random window of flows to evaluate
                max_start = len(self.flow_samples) - self.window_size
                start_idx = random.randint(0, max(0, max_start))
                window_df = self.flow_samples.iloc[start_idx : start_idx + self.window_size]
                res = fuse_score(window_df, self.detectors)
                return float(res["fused_confidence"])
            except Exception:
                pass

        # Mock mode: calibrated probability with stochastic noise
        base_p = technique["mock_prob"]
        noisy_p = float(np.clip(np.random.normal(base_p, 0.08), 0.05, 0.95))
        return noisy_p

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._history = []
        self._last_action = 0
        self._last_confidence = 0.0
        self._current_stage = 0
        self._completed_stages = set()
        self._step_count = 0
        self._chain = []
        return self._get_obs(), {}

    def step(self, action: int):
        technique = MITRE_TECHNIQUES[action]
        tech_stage = technique["stage"]

        detection_conf = self._evaluate_attack(technique)
        detected = detection_conf > 0.50

        self._history.append(1 if detected else 0)
        self._last_action = action
        self._last_confidence = detection_conf
        self._step_count += 1
        self._chain.append(technique["id"])

        # --- Reward Calculation ---
        reward = -0.1  # small step cost to incentivize efficient path finding

        # 1. Evasion / Detection feedback
        if not detected:
            reward += 1.5 * (1.0 - detection_conf)
        else:
            reward -= 2.5 * detection_conf

        # 2. Tactical Stage Progression Incentive
        if tech_stage == self._current_stage:
            # Technique advances the required tactical stage (e.g. Recon -> Access -> Tamper -> Impact)
            self._completed_stages.add(tech_stage)
            reward += 3.0  # substantial progression bonus
            if self._current_stage < NUM_STAGES - 1:
                self._current_stage += 1
        elif tech_stage in self._completed_stages:
            # Redundancy penalty: repeating already completed stages stalls the attack
            reward -= 1.5
        else:
            # Out-of-order execution penalty (attempting impact without access/recon)
            reward -= 1.0

        # 3. Campaign Completion Bonus
        campaign_complete = len(self._completed_stages) == NUM_STAGES
        if campaign_complete:
            reward += 8.0 if not detected else 4.0

        terminated = campaign_complete
        truncated = self._step_count >= MAX_STEPS_PER_CHAIN

        info = {
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "stage": tech_stage,
            "detection_confidence": detection_conf,
            "detected": detected,
            "campaign_complete": campaign_complete,
            "chain": list(self._chain),
        }

        return self._get_obs(), float(reward), terminated, truncated, info


class PlateauTracker:
    """
    Tracks consecutive attack–defend cycles to detect when defense visibility plateaus
    (i.e., when no new attack variants or stages bypass defenses over N attempts).
    """

    def __init__(self, patience: int = 5, min_evasion_gain: float = 0.02):
        self.patience = patience
        self.min_evasion_gain = min_evasion_gain
        self.best_evasion_rate = 0.0
        self.stagnant_count = 0
        self.history = []

    def update(self, episode_evasion_rate: float) -> bool:
        """
        Updates the tracker with the latest episode evasion rate.
        Returns True if the detection rate has plateaued, False otherwise.
        """
        self.history.append(episode_evasion_rate)
        if episode_evasion_rate > (self.best_evasion_rate + self.min_evasion_gain):
            self.best_evasion_rate = episode_evasion_rate
            self.stagnant_count = 0
        else:
            self.stagnant_count += 1

        is_plateaued = self.stagnant_count >= self.patience
        return is_plateaued
