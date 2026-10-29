"""
Module 7 — Multi-Stage MITRE ATT&CK for ICS RL Environment.

Topology-aware RL agent that understands IEEE-14 bus connectivity,
voltage profiles, and bus types before selecting attack techniques.

Observation space includes:
  - Attack state (stage, evasion, confidence, technique, completed stages)
  - IEEE-14 topology features (voltages, connectivity, bus types, compromise status)

Action space (multi-parameter):
  - Technique: which MITRE ATT&CK technique to use (17 options)
  - Register offset: which register to target (0-49 from base address)
  - Value magnitude: scale factor for write values (0.9x-1.1x)
  - Target PLC: which bus to attack (0-MAX_BUSES)

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

# 18 MITRE ATT&CK for ICS techniques organized by tactical stage
from data.mitre_registry import get_rl_techniques
MITRE_TECHNIQUES = get_rl_techniques()

TECHNIQUE_IDS = [t["id"] for t in MITRE_TECHNIQUES]
NUM_TECHNIQUES = len(TECHNIQUES := MITRE_TECHNIQUES)
NUM_STAGES = 4
MAX_STEPS_PER_CHAIN = 16

# Multi-parameter action space dimensions
NUM_REGISTERS = 50       # register offsets 0-49
NUM_VALUE_LEVELS = 10    # value magnitude levels (0.9x to 1.1x)
NUM_PARAM_DIMS = 4       # technique, register, value, target

# Register base addresses by technique type
REGISTER_BASES = {
    "T0836": 40000,  # FDI: holding registers
    "T0835": 1,      # I/O image: coils
    "T0816": 99,     # restart coil
    "T0801": 30000,  # input registers (read)
    "T0802": 30000,  # input registers (read)
    "T0806": 40000,  # brute force: all registers
    "T0881": 1,      # service stop: coils
    "T0878": 40000,  # alarm suppression: holding registers
    "T0830": 40000,  # AITM: holding registers
    "T0832": 30000,  # replay: input registers
    "T0815": 30000,  # denial of view: input registers
    "T0855": 40000,  # command injection: holding registers
}

# Value magnitude range: 0.9x to 1.1x in 10 steps
VALUE_MAGNITUDES = np.linspace(0.90, 1.10, NUM_VALUE_LEVELS)

# --- Topology (loaded dynamically or from defaults) ---
from testbed.topology import Topology, get_topology, load_topology, set_topology

# Fixed observation size: one model works for ANY topology up to MAX_BUSES
MAX_BUSES = 50

# Defaults (IEEE-14) used when no topology is loaded
IEEE14_LINES = [
    (0, 1), (0, 2), (0, 4),
    (1, 2), (1, 3), (1, 4),
    (2, 3),
    (3, 6),
    (4, 5), (4, 6), (4, 7),
    (5, 8),
    (6, 9),
    (7, 8), (7, 9), (7, 10),
    (8, 9),
    (8, 11), (8, 12),
    (9, 10),
    (10, 11),
    (11, 12),
    (11, 13),
]
IEEE14_BUS_TYPES = [3, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2]
IEEE14_VOLTAGES = [1.060, 1.045, 1.010, 1.070, 1.080,
                   1.019, 1.020, 1.062, 1.056, 1.051,
                   1.057, 1.055, 1.050, 1.036]
IEEE14_BUS_DEGREES = [3, 4, 3, 2, 5, 2, 3, 3, 4, 3, 2, 3, 3, 2]


def _get_topology_arrays():
    """Get topology arrays from the loaded topology or defaults."""
    topo = get_topology()
    if topo and topo.num_buses > 0:
        return topo.num_buses, topo.edges, topo.bus_types, topo.voltages, topo.bus_degrees, topo.gen_buses
    return (14, IEEE14_LINES, IEEE14_BUS_TYPES,
            IEEE14_VOLTAGES, IEEE14_BUS_DEGREES,
            [i for i, t in enumerate(IEEE14_BUS_TYPES) if t in (1, 3)])


class AttackStrategyEnv(gym.Env):
    """
    Topology-aware RL environment for multi-stage ICS attack campaigns.

    Action space (multi-discrete):
      - Technique: which MITRE ATT&CK technique to use (17 options)
      - Register offset: which register to target (0-49 from base address)
      - Value magnitude: scale factor for write values (0.9x-1.1x, 10 levels)
      - Target PLC: which bus to attack (0-MAX_BUSES)

    Observation Vector (dim = 226):
      Attack state (24):
        - [0]: Current target stage (normalized)
        - [1]: Recent evasion rate
        - [2]: Last detector confidence
        - [3..19]: One-hot last technique (17)
        - [20..23]: Multi-hot completed stages (4)

      Topology features (200):
        - [24..73]: Bus voltages (50) — normalized, zero-padded
        - [74..123]: Bus connectivity degree (50) — normalized, zero-padded
        - [124..173]: Bus type encoding (50) — slack=1, PV=0.5, PQ=0
        - [174..223]: Compromised bus status (50) — 1=compromised, 0=safe

      Scalars (2):
        - [224]: Fraction of buses compromised
        - [225]: Attack depth — min distance from generator buses
    """

    metadata = {"render_modes": []}

    def __init__(self, real_mode: bool = False, dataset_path: str = None,
                 topology: Topology = None, case: int = None):
        super().__init__()
        self.real_mode = real_mode

        # Multi-discrete action space: [technique, register, value, target]
        self.action_space = spaces.MultiDiscrete([
            NUM_TECHNIQUES,   # 18 techniques
            NUM_REGISTERS,    # 50 register offsets
            NUM_VALUE_LEVELS, # 10 value magnitudes
            MAX_BUSES,        # target PLC (bus index)
        ])

        # Load topology
        if case is not None:
            from testbed.topology import load_case
            topology = load_case(case)
        if topology is not None:
            set_topology(topology)
        topo = get_topology()
        self._topo = topo
        self._num_buses = topo.num_buses  # Actual buses in this topology

        # FIXED observation dim: always MAX_BUSES slots (zero-padded for smaller topologies)
        self.obs_dim = (1 + 1 + 1 + NUM_TECHNIQUES + NUM_STAGES  # attack state: 24
                        + 3                                        # last action params (register, value, target)
                        + MAX_BUSES                               # voltages (padded)
                        + MAX_BUSES                               # degrees (padded)
                        + MAX_BUSES                               # bus types (padded)
                        + MAX_BUSES                               # compromised (padded)
                        + 1 + 1)                                  # frac_compromised, attack_depth
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(self.obs_dim,), dtype=np.float32
        )

        # Build adjacency matrix for pathfinding (size = actual buses)
        self._adj = np.zeros((self._num_buses, self._num_buses), dtype=np.float32)
        for i, j in topo.edges:
            if i < self._num_buses and j < self._num_buses:
                self._adj[i][j] = 1.0
                self._adj[j][i] = 1.0

        # Precompute generator bus indices
        self._gen_buses = topo.gen_buses

        # Precompute topology arrays (padded to MAX_BUSES)
        self._voltages = np.zeros(MAX_BUSES, dtype=np.float32)
        self._degrees = np.zeros(MAX_BUSES, dtype=np.float32)
        self._bus_types_arr = np.zeros(MAX_BUSES, dtype=np.float32)

        for i in range(min(self._num_buses, MAX_BUSES)):
            self._voltages[i] = topo.voltages[i]
            self._degrees[i] = topo.bus_degrees[i]
            self._bus_types_arr[i] = topo.bus_types[i]

        self._max_degree = max(topo.max_degree, 1)

        self._history = []
        self._last_action = np.array([0, 0, 5, 0], dtype=np.int64)
        self._last_confidence = 0.0
        self._current_stage = 0
        self._completed_stages = set()
        self._step_count = 0
        self._chain = []
        self._compromised_buses = set()
        self._current_target_bus = 0
        self._last_register = 0
        self._last_value_mag = 1.0

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

        # One-hot last technique (17 dims)
        last_tech_idx = int(self._last_action[0])
        one_hot_action = np.zeros(NUM_TECHNIQUES, dtype=np.float32)
        if 0 <= last_tech_idx < NUM_TECHNIQUES:
            one_hot_action[last_tech_idx] = 1.0

        # Multi-hot completed stages (4 dims)
        stages_vec = np.zeros(NUM_STAGES, dtype=np.float32)
        for s in self._completed_stages:
            if 0 <= s < NUM_STAGES:
                stages_vec[s] = 1.0

        # Last action parameters (3 dims)
        last_register = self._last_register / NUM_REGISTERS  # normalized 0-1
        last_value_mag = (self._last_value_mag - 0.9) / 0.2  # normalized 0-1
        last_target = self._current_target_bus / self._num_buses  # normalized 0-1

        # --- Topology features ---
        voltages = self._voltages / 1.1
        degrees = self._degrees / self._max_degree
        bus_type_map = {3: 1.0, 1: 0.5, 2: 0.0}
        bus_types = np.array([bus_type_map.get(int(t), 0.0) for t in self._bus_types_arr],
                             dtype=np.float32)

        # Compromised bus status (padded to MAX_BUSES)
        compromised = np.zeros(MAX_BUSES, dtype=np.float32)
        for b in self._compromised_buses:
            if 0 <= b < MAX_BUSES:
                compromised[b] = 1.0

        frac_compromised = len(self._compromised_buses) / self._num_buses
        attack_depth = self._compute_attack_depth()

        obs = np.concatenate([
            # Attack state (24 dims)
            [float(self._current_stage) / (NUM_STAGES - 1)],
            [float(recent_evasion_rate)],
            [float(self._last_confidence)],
            one_hot_action,
            stages_vec,
            # Last action parameters (3 dims)
            [last_register],
            [last_value_mag],
            [last_target],
            # Topology features (200 dims, padded)
            voltages,
            degrees,
            bus_types,
            compromised,
            [frac_compromised],
            [attack_depth],
        ]).astype(np.float32)
        return obs

    def _compute_attack_depth(self) -> float:
        """Compute min hop distance from compromised buses to nearest generator.
        Returns normalized value in [0, 1]."""
        if not self._compromised_buses or not self._gen_buses:
            return 0.0

        # BFS from all generator buses
        from collections import deque
        dist = [-1] * self._num_buses
        queue = deque()
        for g in self._gen_buses:
            dist[g] = 0
            queue.append(g)

        while queue:
            node = queue.popleft()
            for neighbor in range(self._num_buses):
                if self._adj[node][neighbor] > 0 and dist[neighbor] == -1:
                    dist[neighbor] = dist[node] + 1
                    queue.append(neighbor)

        # Max distance from compromised bus to nearest gen
        max_depth = 0
        for b in self._compromised_buses:
            if 0 <= b < self._num_buses and dist[b] > 0:
                max_depth = max(max_depth, dist[b])

        return min(max_depth / 5.0, 1.0)  # normalize by max possible depth

    def _evaluate_attack(self, technique: dict, register_offset: int,
                         value_magnitude: float, target_bus: int) -> float:
        """Returns detection confidence score in [0.0, 1.0].
        
        Detection probability is influenced by:
        - Technique base risk (from mock_prob)
        - Register access pattern (certain registers are more monitored)
        - Value magnitude (larger deviations are更容易 detected)
        - Target bus type (generators are more heavily monitored)
        """
        if self.real_mode and self.detectors is not None and self.flow_samples is not None:
            try:
                from fusion import fuse_score
                max_start = len(self.flow_samples) - self.window_size
                start_idx = random.randint(0, max(0, max_start))
                window_df = self.flow_samples.iloc[start_idx : start_idx + self.window_size]
                res = fuse_score(window_df, self.detectors)
                return float(res["fused_confidence"])
            except Exception:
                pass

        # Mock mode: calibrated probability with parameter-aware noise
        base_p = technique["mock_prob"]

        # Factor 1: Register offset risk (lower offsets = more critical registers)
        register_risk = 1.0 - (register_offset / NUM_REGISTERS) * 0.3  # 0.7-1.0

        # Factor 2: Value magnitude risk (larger deviations = higher detection)
        value_deviation = abs(value_magnitude - 1.0)  # 0.0-0.1
        value_risk = 1.0 + value_deviation * 5.0  # 1.0-1.5

        # Factor 3: Target bus risk (generators are more monitored)
        target_risk = 1.2 if target_bus in self._gen_buses else 1.0

        # Combined risk multiplier
        risk_multiplier = register_risk * value_risk * target_risk
        adjusted_p = base_p * risk_multiplier

        noisy_p = float(np.clip(np.random.normal(adjusted_p, 0.08), 0.05, 0.95))
        return noisy_p

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._history = []
        self._last_action = np.array([0, 0, 5, 0], dtype=np.int64)
        self._last_confidence = 0.0
        self._current_stage = 0
        self._completed_stages = set()
        self._step_count = 0
        self._chain = []
        self._compromised_buses = set()
        self._current_target_bus = random.randint(0, self._num_buses - 1)
        self._last_register = 0
        self._last_value_mag = 1.0
        return self._get_obs(), {}

    def calculate_step_reward(self, status: str, detected: bool, detection_conf: float,
                              tech_stage: int, target_bus: int) -> float:
        """Centralized research-defensible reward calculation.
        Distinguishes EXECUTED+DETECTED, EXECUTED+UNDETECTED, FAILED, TIMEOUT, and INVALID.
        """
        reward = -0.1  # base step cost

        if status == "TIMEOUT":
            return reward - 3.0
        if status in ("FAILED", "EXECUTION_ERROR", "INVALID", "UNSUPPORTED"):
            return reward - 2.5

        if detected is None:
            return reward  # unavailable evaluation cannot establish evasion/progress

        if detected:
            reward -= 2.5 * max(detection_conf, 0.5)
        else:
            # Verified Evasion
            reward += 1.5 * (1.0 - detection_conf)

            if tech_stage == self._current_stage:
                self._completed_stages.add(tech_stage)
                reward += 3.0
                if self._current_stage < NUM_STAGES - 1:
                    self._current_stage += 1
            elif tech_stage in self._completed_stages:
                reward -= 1.5
            else:
                reward -= 1.0

            if target_bus in self._gen_buses:
                reward += 0.5
            if len(self._compromised_buses) > len(self._chain) - 1:
                reward += 0.3

            if len(self._completed_stages) == NUM_STAGES:
                reward += 8.0
                reward += len(self._compromised_buses) * 0.2

        return float(reward)

    def step(self, action):
        # Unpack multi-parameter action
        action = np.asarray(action, dtype=np.int64).flatten()
        technique_idx = int(action[0])
        register_offset = int(action[1])
        value_level = int(action[2])
        target_bus = int(action[3]) % self._num_buses

        technique = MITRE_TECHNIQUES[technique_idx]
        tech_stage = technique["stage"]
        value_magnitude = float(VALUE_MAGNITUDES[value_level])

        detection_conf = self._evaluate_attack(technique, register_offset,
                                                value_magnitude, target_bus)
        detected = detection_conf > 0.50

        self._history.append(1 if detected else 0)
        self._last_action = action
        self._last_confidence = detection_conf
        self._step_count += 1
        self._chain.append(technique["id"])
        self._last_register = register_offset
        self._last_value_mag = value_magnitude

        # Use agent-selected target bus
        self._compromised_buses.add(target_bus)
        neighbors = [j for j in range(self._num_buses) if self._adj[target_bus][j] > 0]
        if neighbors:
            self._current_target_bus = random.choice(neighbors)
        else:
            self._current_target_bus = random.randint(0, self._num_buses - 1)

        # Centralized reward calculation
        status = "DETECTED" if detected else "UNDETECTED"
        reward = self.calculate_step_reward(status, detected, detection_conf, tech_stage, target_bus)

        campaign_complete = len(self._completed_stages) == NUM_STAGES
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
            "target_bus": target_bus,
            "compromised_buses": list(self._compromised_buses),
            # Multi-parameter action info
            "register_offset": register_offset,
            "register_address": REGISTER_BASES.get(technique["id"], 40000) + register_offset,
            "value_magnitude": value_magnitude,
            "value_level": value_level,
        }

        return self._get_obs(), float(reward), terminated, truncated, info


from metrics.dvs_score import PlateauTracker
