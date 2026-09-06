# CODEX_HANDOFF.md — Comprehensive Project Handoff & Technical Context

> **Target Audience:** OpenAI Codex / Autonomous AI Coding Agent  
> **Origin:** Handed off from Antigravity (Google DeepMind) on 2026-09-04  
> **Branch:** `adty` | **Repository:** `https://github.com/root-FURY127/ascend-pg-webapp`  
> **Workspace Root:** `c:\project` (containing `ASCENDPG_PROJECT_MASTER (Abin2) (2).md` and `ascend-pg-webapp/`)  
> **Active Developer:** Andikumar (Training, Strategic RL, XAI, and Web Application Track)  
> **Teammates:** Abinraj (Testbed Track on Mininet/WSL2), Karthik  

---

## 1. PROJECT OVERVIEW

### 1.1 Project Identity & Name
- **Project Name:** **ASCEND-PG** (Adaptive Security Co-Simulation and Emulation for Network Defense in Power Grids)
- **Current Phase:** **Version 2.1 — MITRE-Driven Adaptive Attack Framework & Real Tools Rebuild**
- **Repository Path:** `c:\project\ascend-pg-webapp`

### 1.2 What the Project Does & Problem It Solves
Modern Power Grid Industrial Control Systems (ICS) and Operational Technology (OT) networks rely on legacy protocols (e.g., Modbus TCP, DNP3) that lack built-in cryptographic authentication, making them vulnerable to sophisticated multi-stage cyber attacks (e.g., False Data Injection, Denial of Service, Replay attacks, and unauthorized register modification).

Existing defensive solutions typically evaluate security against static, isolated attack scripts. In contrast, **ASCEND-PG creates an adaptive, adversarial co-simulation and emulation platform**:
1. **Power Grid Modeling:** Emulates an IEEE-14 bus electrical network with real power-flow physics using `pandapower`.
2. **OT Network Emulation:** Maps electrical buses to substations equipped with PMUs (Phasor Measurement Units), RTUs (Remote Terminal Units), PLCs (Programmable Logic Controllers), and a central SCADA Control Center communicating over Modbus TCP via `pymodbus` and Mininet.
3. **Adaptive Adversarial AI (Red Team):** 
   - A Reinforcement Learning (RL) agent (Stable-Baselines3 PPO) adaptively chains multi-stage cyber attack paths selecting from **17 MITRE ATT&CK for ICS techniques** across 4 tactical intrusion stages (*Reconnaissance $\rightarrow$ Lateral Movement $\rightarrow$ Impair Process Control $\rightarrow$ Impact*).
   - A Generative Adversarial Network (GAN) mutates continuous tabular network flow parameters to evade detection.
   - The attack cycle terminates when defense evasion plateaus (**Plateau Stop Condition**), demonstrating saturation of discoverable vulnerabilities.
4. **Multi-Modal Anomaly Detection (Blue Team):** A hybrid defense layer fusing a supervised **LSTM temporal sequence detector** (recognizes multi-step patterns) and an unsupervised **Bottleneck Autoencoder anomaly detector** (flags novel zero-day perturbations).
5. **Explainable AI (XAI) & Defensive Metrics:** Evaluates the defense posture via a composite **Defense Vulnerability Score (DVS $\in [0, 100]$)**, explains detector decisions via **SHAP** and **LIME**, explains RL tactical attack path decisions via policy logits/rationale, and generates prioritized **ICS hardening recommendations**.
6. **Interactive Multi-Page Web Interface:** A Streamlit web dashboard providing topology visualization, live battle monitoring with full timestamped event logging, and an executive assessment report.

### 1.3 Project Background & Evaluation Context
- **Version 1 (MVP) Rejection:** An initial version of this major project was presented to the college academic evaluation panel. The panel **rejected** the demo because:
  1. It used purely synthetic, in-memory numpy packet arrays rather than a real, published network emulation tool.
  2. The attacker and detector were simple rule-based threshold heuristics rather than genuinely trained machine learning / deep learning models.
- **Version 2 / 2.1 Pivot:** The team completely redesigned the system to satisfy the panel's non-negotiable requirements:
  - Genuine Modbus TCP traffic over emulated topologies (`mininet_topology.py`, `plc_server.py`, `scada_client.py`).
  - Genuinely trained deep learning models saved as PyTorch checkpoints (`.pt`) and SB3 models (`.zip`).
  - Strict grounding in the **MITRE ATT&CK for ICS matrix** (17 techniques, 9 tactics).
  - Clear team member attribution in the master tracking document [`ASCENDPG_PROJECT_MASTER (Abin2) (2).md`](file:///c:/project/ASCENDPG_PROJECT_MASTER%20(Abin2)%20(2).md).

### 1.4 Two-Machine Work Division
The project is divided across two hardware tracks:
1. **Testbed Track (Abinraj):** Ryzen 5 CPU + Vega 11 integrated graphics on Windows 11 with WSL2 Ubuntu 22.04. Runs Mininet, MiniCPS, OVS, and pymodbus PLC servers/clients. (No GPU required).
2. **Training, Strategic RL, XAI & App Track (Andikumar - THIS MACHINE):** Ryzen 5 5600H CPU + NVIDIA GeForce RTX 3050 Laptop GPU (4GB VRAM), 16GB RAM, native Windows 11. Implemented, trained, and verified Modules 6, 7, 8a, 8b, 8c, and the XAI & Metrics layer.

### 1.5 Current Overall Status
- **ML Training Track:** **100% Complete & Verified.** (GAN, LSTM, Autoencoder, Fusion, PPO Multi-Stage Agent trained on GPU and saved in `models/`).
- **XAI & Metrics Layer:** **100% Complete & Verified.** (SHAP explainer, LIME explainer, RL decision explainer, DVS metric calculator, recommendation templates running natively on Windows).
- **Frontend (Streamlit):** **Partially Implemented.** `app/Home.py` (Phase 1 baseline) and `app/pages/1_Configure_Network.py` exist. Pages `2_Run_Simulation.py`, `3_Live_Battle.py`, and `4_Report.py` are currently 0-byte placeholders waiting to be wired to the trained models and XAI pipeline.

---

## 2. COMPLETE PROJECT STRUCTURE

```
c:\project\
├── ASCENDPG_PROJECT_MASTER (Abin2) (2).md   # Comprehensive project tracking log (Sessions 1-16)
├── CODEX_HANDOFF.md                         # THIS FILE (handoff specification for Codex)
└── ascend-pg-webapp\                         # Primary Git Repository (Branch: adty)
    ├── .git/                                # Git directory
    ├── .gitignore                           # Ignores venv/, __pycache__/, data/raw/, etc.
    ├── requirements.txt                     # Pinned project dependencies with CUDA 12.4 index
    ├── main.py                              # [Placeholder - 0 bytes] Optional entrypoint
    │
    ├── app/                                 # Streamlit Multi-Page Web Application
    │   ├── Home.py                          # Phase 1 MVP baseline: loads IEEE-14, injects rules, pyvis viz
    │   └── pages/                           # Streamlit multi-page directory
    │       ├── 1_Configure_Network.py       # [Complete] Preset/custom topology & detector settings
    │       ├── 2_Run_Simulation.py          # [Empty - 0 bytes] Grid power-flow simulation page
    │       ├── 3_Live_Battle.py             # [Empty - 0 bytes] Live Red vs Blue simulation & event log
    │       └── 4_Report.py                  # [Empty - 0 bytes] Executive XAI dashboard & DVS report
    │
    ├── data/                                # Data files and mappings
    │   ├── cic_ids2017_subset.csv           # [Complete - 10,002 rows, 79 cols] Balanced training subset
    │   ├── episode_log.csv                  # Historical episode log
    │   ├── mitre_ics_map.json               # [Complete - 17 techniques] Complete MITRE ICS catalog mapping
    │   ├── raw/                             # [Git Ignored] Full CIC-IDS-2017 raw day-by-day CSV files
    │   └── sample_topologies/               # Pre-configured grid topology JSON definitions
    │       ├── ieee14_default.json          # IEEE-14 bus default configuration
    │       └── ieee30_default.json          # IEEE-30 bus default configuration
    │
    ├── detection/                           # Module 8: Defense & Detection Layer
    │   ├── lstm_detector.py                 # [Complete] Supervised LSTM temporal sequence classifier
    │   ├── autoencoder_detector.py          # [Complete] Unsupervised bottleneck autoencoder for anomalies
    │   ├── fusion.py                        # [Complete] Dual-model confidence fusion layer
    │   └── rule_based_detector.py           # [Complete] Phase 1 z-score baseline (for report comparison)
    │
    ├── generative/                          # Module 6: Generative Attack Layer
    │   ├── gan.py                           # [Complete] PyTorch MLP Generator & Discriminator models
    │   ├── train_gan.py                     # [Complete] Mixed precision AMP training loop (200 epochs)
    │   ├── check_gan_output.py              # [Complete] Post-training distribution & mode-collapse validation
    │   └── rule_based_attack_generator.py   # [Complete] Phase 1 baseline injection (FDI, DoS, Replay, MITM)
    │
    ├── metrics/                             # Defense Assessment & Scoring
    │   └── dvs.py                           # [Complete] Defense Vulnerability Score (DVS) calculator
    │
    ├── models/                              # Saved Trained Weights & Checkpoints
    │   ├── autoencoder_detector.pt          # PyTorch checkpoint: Autoencoder weights + scaling metadata
    │   ├── autoencoder_threshold.json       # JSON: 95th-percentile anomaly threshold (0.00238)
    │   ├── gan_discriminator.pt             # PyTorch checkpoint: Trained Discriminator weights
    │   ├── gan_generator.pt                 # PyTorch checkpoint: Trained Generator weights
    │   ├── lstm_detector.pt                 # PyTorch checkpoint: LSTM weights + scaling metadata
    │   └── rl_agent.zip                     # Stable-Baselines3 PPO zip: 30k-step trained multi-stage agent
    │
    ├── scripts/                             # Utility & Data Pipeline Scripts
    │   └── prepare_dataset.py               # Downloads, merges, cleans, and stratifies CIC-IDS-2017
    │
    ├── standardization/                     # MITRE ATT&CK Standardization Layer
    │   └── mitre_mapper.py                  # [Empty - 0 bytes] Legacy static lookup placeholder
    │
    ├── strategic/                           # Module 7: Reinforcement Learning Strategic Layer
    │   ├── rl_env.py                        # [Complete] Gymnasium env (17 techniques, 4 stages, PlateauTracker)
    │   ├── train_rl.py                      # [Complete] PPO multi-environment training (32,768 steps) & eval
    │   └── rule_based_attacker.py           # [Complete] Phase 1 adaptive attacker baseline
    │
    ├── testbed/                             # Module 3: Testbed & Power Grid Simulation
    │   ├── grid_env.py                      # [Complete] pandapower IEEE-14 bus network flow solver
    │   ├── network_topology.py              # [Complete] Maps electrical buses to OT device nodes & links
    │   ├── visualize_topology.py            # [Complete] pyvis physics-based HTML network diagram renderer
    │   ├── mininet_topology.py              # [Complete] Mininet 7-host topology (5 PLCs, 1 SCADA, 1 Attacker)
    │   ├── plc_server.py                    # [Complete] Real Modbus TCP PLC server (pymodbus 3.14.x)
    │   └── scada_client.py                  # [Complete] Real Modbus TCP polling client (pymodbus 3.14.x)
    │
    └── xai/                                 # Explainable AI (XAI) Layer
        ├── shap_explain.py                  # [Complete] SHAP KernelExplainer for LSTM temporal sequences
        ├── lime_explain.py                  # [Complete] LIME TabularExplainer for Autoencoder anomalies
        ├── attack_decision_explain.py       # [Complete] RL policy logits, value, & tactical rationale explainer
        └── recommendation_templates.py      # [Complete] ICS hardening countermeasures & markdown reporter
```

---

## 3. TECHNOLOGY STACK & VERSIONS

All packages are installed in the native Windows Python environment:
- **Operating System:** Windows 11 Home 64-bit (Build 26100), native execution (PowerShell / Command Prompt).
- **Hardware:** AMD Ryzen 5 5600H (6 cores / 12 threads), 16GB DDR4 RAM, NVIDIA GeForce RTX 3050 Laptop GPU (4GB GDDR6 VRAM, Driver Version 566.07 / CUDA 12.7).
- **Python Version:** `3.12.4` (64-bit).
- **Deep Learning / Tensor Framework:** `torch 2.6.0+cu124` (installed with CUDA 12.4 support; `torch.cuda.is_available() == True`).
- **Reinforcement Learning:** `gymnasium 1.3.0`, `stable-baselines3 2.9.0` (PPO with MlpPolicy).
- **Explainable AI (XAI):** `shap 0.52.0`, `lime 0.2.0.1`.
- **Power Grid Physics Simulation:** `pandapower 3.5.4`.
- **Industrial Protocols:** `pymodbus 3.14.x` (Used in `testbed/plc_server.py` and `testbed/scada_client.py`).
- **Web Application Framework:** `streamlit 1.60.0`.
- **Visualization:** `pyvis 0.3.2`, `plotly 6.9.0`, `matplotlib 3.11.1`, `altair 6.2.2`.
- **Data Processing & ML:** `pandas 2.3.3`, `numpy 2.4.6`, `scikit-learn 1.9.0`, `scipy 1.18.0`.
- **Reporting & Document Generation:** `jinja2 3.1.6`, `weasyprint 69.0`.

---

## 4. CURRENT IMPLEMENTATION (WHAT WORKS)

### 4.1 Module 6: Tabular GAN Parameter Mutation (`generative/`)
- **Files:** [`generative/gan.py`](file:///c:/project/ascend-pg-webapp/generative/gan.py), [`generative/train_gan.py`](file:///c:/project/ascend-pg-webapp/generative/train_gan.py), [`generative/check_gan_output.py`](file:///c:/project/ascend-pg-webapp/generative/check_gan_output.py)
- **Status:** **Fully operational.** Trained for 200 epochs on GPU. Weights saved in `models/gan_generator.pt` and `models/gan_discriminator.pt`.
- **Architecture:** 
  - **Generator:** MLP taking a 32-dim Gaussian noise vector $z \sim \mathcal{N}(0, I)$, projecting through `[Linear(32->256), LeakyReLU(0.2), BatchNorm1d(256)]` $\rightarrow$ `[Linear(256->512), LeakyReLU(0.2), BatchNorm1d(512)]` $\rightarrow$ `[Linear(512->256), LeakyReLU(0.2), BatchNorm1d(256)]` $\rightarrow$ `[Linear(256->78), Tanh()]`. Output scaled to $[-1, 1]$.
  - **Discriminator:** MLP taking a 78-dim flow feature vector, projecting through `[Linear(78->512), LeakyReLU(0.2), Dropout(0.3)]` $\rightarrow$ `[Linear(512->256), LeakyReLU(0.2), Dropout(0.3)]` $\rightarrow$ `Linear(256->1)`. Outputs unnormalized logits.
- **Loss & Precision:** Trained using mixed precision (`torch.amp.autocast('cuda')` and `torch.amp.GradScaler('cuda')`) with `nn.BCEWithLogitsLoss()`.
- **Validation:** [`check_gan_output.py`](file:///c:/project/ascend-pg-webapp/generative/check_gan_output.py) validates that synthetic flow samples span realistic feature distributions without mode collapse.

### 4.2 Module 8: Multi-Modal Detection Layer (`detection/`)
- **Files:** [`detection/lstm_detector.py`](file:///c:/project/ascend-pg-webapp/detection/lstm_detector.py), [`detection/autoencoder_detector.py`](file:///c:/project/ascend-pg-webapp/detection/autoencoder_detector.py), [`detection/fusion.py`](file:///c:/project/ascend-pg-webapp/detection/fusion.py)
- **Status:** **Fully operational.** Models saved in `models/lstm_detector.pt`, `models/autoencoder_detector.pt`, and `models/autoencoder_threshold.json`.
- **8a. Supervised LSTM Detector:**
  - Operates on temporal sliding windows of `WINDOW_SIZE = 10` consecutive flow rows.
  - Architecture: `nn.LSTM(input_size=78, hidden_size=64, num_layers=1, batch_first=True)` followed by final-step classification head `[Linear(64->32), ReLU(), Linear(32->1), Sigmoid()]`.
  - Achieved on held-out test split: **Accuracy: 87.8%**, **Precision: 91.1%**, **Recall: 94.4%**, **F1 Score: 92.7%**.
  - Checkpoint stores `state_dict`, `feature_dim: 78`, and train-fitted min-max `scaling` dictionary (`col_min`, `col_max`, `feature_cols`).
- **8b. Unsupervised Autoencoder Anomaly Detector:**
  - Bottleneck architecture: `[Linear(78->32), ReLU(), Linear(32->8), ReLU()]` $\rightarrow$ `[Linear(8->32), ReLU(), Linear(32->78)]`.
  - Trained exclusively on 8,311 clean `BENIGN` flows using `nn.MSELoss()`.
  - Computes per-row reconstruction error $\|x - \hat{x}\|^2_2$. The 95th-percentile of benign training errors (`0.002385`) is saved as the anomaly threshold in `models/autoencoder_threshold.json`.
- **8c. Fusion Layer:**
  - `load_detectors()` loads both models to GPU/CPU and parses the threshold.
  - `fuse_score(window_df, detectors)` takes a 10-row DataFrame, scales it via the training parameters, computes LSTM confidence and Autoencoder max reconstruction anomaly score, and outputs:
    $$\text{fused\_confidence} = 0.5 \cdot \text{confidence}_{\text{LSTM}} + 0.5 \cdot \text{score}_{\text{AE}}$$

### 4.3 Module 7: Strategic Multi-Stage MITRE RL Agent (`strategic/`)
- **Files:** [`strategic/rl_env.py`](file:///c:/project/ascend-pg-webapp/strategic/rl_env.py), [`strategic/train_rl.py`](file:///c:/project/ascend-pg-webapp/strategic/train_rl.py)
- **Status:** **Fully operational.** Trained for 32,768 timesteps using PPO. Saved in `models/rl_agent.zip`.
- **Action Space:** Discrete over **17 MITRE ATT&CK for ICS techniques** (indices 0–16):
  - *Stage 0 (Reconnaissance & Discovery):* `T0886` Remote Services, `T0846` Remote System Discovery, `T0888` Remote System Info Discovery, `T0842` Network Sniffing.
  - *Stage 1 (Lateral Movement & C2 & Collection):* `T0830` Adversary-in-the-Middle, `T0801` Monitor Process State, `T0802` Automated Collection, `T0869` Standard Application Layer Protocol.
  - *Stage 2 (Inhibit Response & Impair Control):* `T0814` Denial of Service, `T0878` Alarm Suppression, `T0816` Device Restart/Shutdown, `T0881` Service Stop, `T0836` Modify Parameter (FDI), `T0835` Manipulate I/O Image, `T0806` Brute Force I/O.
  - *Stage 3 (Impact):* `T0832` Manipulation of View (Replay), `T0815` Denial of View.
- **Observation Space (24 dimensions, Box $[0, 1]$):**
  - `obs[0]`: Normalized required target stage $\in [0.0, 1.0]$.
  - `obs[1]`: Recent 5-step evasion rate $\in [0.0, 1.0]$.
  - `obs[2]`: Last observed detector confidence $\in [0.0, 1.0]$.
  - `obs[3..19]`: 17-dimensional one-hot vector of last executed technique.
  - `obs[20..23]`: 4-dimensional multi-hot vector of completed tactical stages.
- **Reward Function:**
  - Base step cost: $-0.1$.
  - Evasion reward: $+1.5 \times (1.0 - \text{conf})$ if undetected; Detection penalty: $-2.5 \times \text{conf}$ if detected.
  - Tactical progression incentive: $+3.0$ when technique advances to the required next stage.
  - Redundancy penalty: $-1.5$ for repeating an already mastered stage.
  - Out-of-order penalty: $-1.0$ for jumping ahead without prerequisites.
  - Campaign completion bonus: $+8.0$ if all 4 stages completed undetected ($+4.0$ if detected).
- **Dual-Mode Evaluation:**
  - `real_mode=False`: Calibrated stochastic mock mode with normal noise based on technique base probability.
  - `real_mode=True`: Samples flow windows and calls [`detection/fusion.py`](file:///c:/project/ascend-pg-webapp/detection/fusion.py) directly.
- **Termination & Plateau Tracking:**
  - Terminated when all 4 stages completed; Truncated at 12 steps.
  - `PlateauTracker`: Evaluates moving evasion gain across consecutive episodes; detects defense saturation when evasion stagnates for $N \ge 5$ episodes.
- **Achieved Evaluation Metrics (20 episodes):**
  - **Campaign Completion Rate: 100.0%** (20/20 episodes).
  - **Average Evasion Rate: 75.0%**.
  - **Average Episode Reward: 21.00**.
  - Learned optimal intrusion chain: `T0842 (Sniffing)` $\rightarrow$ `T0801 (Monitor Process State)` $\rightarrow$ `T0836 (Modify Parameter FDI)` $\rightarrow$ `T0832 (Manipulation of View Replay)`.

### 4.4 Explainability (XAI) & Defensive Metrics Layer (`xai/`, `metrics/`)
- **Files:** [`xai/shap_explain.py`](file:///c:/project/ascend-pg-webapp/xai/shap_explain.py), [`xai/lime_explain.py`](file:///c:/project/ascend-pg-webapp/xai/lime_explain.py), [`xai/attack_decision_explain.py`](file:///c:/project/ascend-pg-webapp/xai/attack_decision_explain.py), [`metrics/dvs.py`](file:///c:/project/ascend-pg-webapp/metrics/dvs.py), [`xai/recommendation_templates.py`](file:///c:/project/ascend-pg-webapp/xai/recommendation_templates.py)
- **Status:** **Fully operational.** Verified natively on Windows with UTF-8 console compatibility.
- **SHAP Explainer (`shap_explain.py`):** Wraps LSTM in a flattened window prediction function, uses `shap.KernelExplainer` with 10 k-means background summaries, and aggregates $|SHAP|$ scores across the 10 timesteps to identify key features (e.g., `Bwd Header Length`, `ACK Flag Count`, `PSH Flag Count`).
- **LIME Explainer (`lime_explain.py`):** Uses `LimeTabularExplainer` to interpret autoencoder reconstruction error against the 95th-percentile anomaly cutoff, distinguishing normal flows (`0.000518` MSE) from attack flows (`0.035658` MSE).
- **RL Attack Decision Explainer (`attack_decision_explain.py`):** Queries the trained PPO policy network for action logits, softmax probability distribution over all 17 techniques, and critic value estimates. Translates state into human-readable tactical decision rationale with top-3 alternative rankings.
- **Defense Vulnerability Score (`metrics/dvs.py`):** Computes a composite vulnerability score $\in [0, 100]$:
  $$\text{DVS} = 0.30 \cdot (\text{Evasion} \times 100) + 0.30 \cdot (\text{Campaign} \times 100) + 0.25 \cdot \left(\frac{\text{AvgMaxStage}}{3} \times 100\right) + 0.15 \cdot \text{Plateau}$$
  Tested on 20 episodes of the PPO policy: **DVS = 90.8 / 100 — Critical Rating** (Evasion: 75%, Completion: 100%, Stage Depth: 93.3%, Plateau: 100%).
- **Admin Recommendations (`recommendation_templates.py`):** Maps DVS sub-scores and MITRE technique IDs to actionable ICS hardening advice (firewall ACLs, TLS Modbus, DPI, SIS cross-checks, Dynamic ARP Inspection, alarm auditing).

---

## 5. MACHINE LEARNING / AI SPECIFICATIONS

### 5.1 Trained Model Artifacts
All model weights are located in `c:\project\ascend-pg-webapp\models\`:

| File | Type | Framework | Size | Description |
|---|---|---|---|---|
| `lstm_detector.pt` | Checkpoint Dict | PyTorch | 162 KB | Supervised LSTM weights + scaling parameters |
| `autoencoder_detector.pt` | Checkpoint Dict | PyTorch | 29 KB | Unsupervised Autoencoder weights + scaling parameters |
| `autoencoder_threshold.json` | JSON | Standard | 54 B | Anomaly cutoff threshold: `{"threshold": 0.00238477...}` |
| `gan_generator.pt` | `state_dict` | PyTorch | 1.19 MB | Tabular Generator weights ($z_{32} \rightarrow x_{78}$) |
| `gan_discriminator.pt` | `state_dict` | PyTorch | 691 KB | Tabular Discriminator weights ($x_{78} \rightarrow \text{logit}$) |
| `rl_agent.zip` | SB3 Model Archive | Stable-Baselines3 | 532 KB | Trained PPO policy & value network (17 MITRE techniques) |

### 5.2 Preprocessing & Feature Scaling Pattern
- **Min-Max Scaling:** Both the LSTM and Autoencoder require strict min-max scaling to $[0, 1]$ computed **only from training data** to avoid test-set information leakage:
  $$x_{\text{scaled}} = \frac{x - \text{col\_min}}{\max(\text{col\_max} - \text{col\_min}, 10^{-6})}$$
- **Checkpoint Metadata:** Checkpoints contain a `"scaling"` dictionary with keys:
  - `"col_min"`: List of floats (length 78)
  - `"col_max"`: List of floats (length 78)
  - `"feature_cols"`: List of string column names (length 78)
- **Inference Loading Routine:**
  ```python
  import torch
  checkpoint = torch.load("models/lstm_detector.pt", map_location="cuda")
  scaling = checkpoint["scaling"]
  # Scale new DataFrame df[scaling["feature_cols"]] using col_min and col_max
  ```

---

## 6. DATASET INFORMATION

- **File Path:** `c:\project\ascend-pg-webapp\data\cic_ids2017_subset.csv`
- **Total Records:** 10,002 rows $\times$ 79 columns (78 numerical flow features + 1 `Label` column).
- **Class Distribution:**
  - `BENIGN`: 8,311 samples (83.1%)
  - `DoS Hulk`: 686 samples (6.9%)
  - `DDoS`: 508 samples (5.1%)
  - `PortScan`: 360 samples (3.6%)
  - `DoS GoldenEye`: 41 samples
  - `FTP-Patator`: 24 samples
  - `DoS slowloris`: 21 samples
  - `DoS Slowhttptest`: 21 samples
  - `SSH-Patator`: 13 samples
  - `Bot`: 8 samples
  - `Web Attack \ufffd Brute Force`: 6 samples
  - `Web Attack \ufffd XSS`: 3 samples
- **Important Features (78 total):**
  Includes `Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Fwd Packet Length Max`, `Bwd Packet Length Mean`, `Flow Bytes/s`, `Flow Packets/s`, `Flow IAT Mean`, `Fwd IAT Total`, `Bwd IAT Mean`, `Fwd PSH Flags`, `Bwd Header Length`, `ACK Flag Count`, `Init_Win_bytes_forward`, `Init_Win_bytes_backward`, `Idle Mean`, etc.
- **Preprocessing Note:** In Session 14, the rows were shuffled with a fixed seed before temporal windowing so that train/test splits contain balanced attack distributions.

---

## 7. APPLICATION DATA FLOW

```
1. Configuration (app/pages/1_Configure_Network.py)
   ├── Selects Grid Topology (IEEE-14 / IEEE-30)
   ├── Configures Defense Parameters (Enable LSTM, Autoencoder, tau_high, tau_low)
   └── Saves configuration dictionary into st.session_state["config"]
          ↓
2. Physical Grid Simulation (app/pages/2_Run_Simulation.py - PENDING IMPLEMENTATION)
   ├── Executes pandapower power-flow (pp.runpp) on IEEE-14 bus network
   ├── Generates baseline telemetry dataframe (voltage_pu, packet_size, timestamps)
   └── Maps electrical topology to OT assets (Substations, PMUs, RTUs, SCADA)
          ↓
3. Live Red vs. Blue Battle (app/pages/3_Live_Battle.py - PENDING IMPLEMENTATION)
   ├── Loads trained RL agent (models/rl_agent.zip) & Detection Layer (models/)
   ├── Step 1..N: RL selects MITRE technique from 17 available actions
   ├── GAN mutates concrete packet parameters / telemetry setpoints
   ├── Fusion Layer (LSTM + Autoencoder) scores window of flows
   ├── Updates live pyvis graph: Compomised nodes (Red) / Defended nodes (Green)
   ├── Appends timestamped log entry to Live Battle Event Table
   └── Terminates when PlateauTracker detects defense visibility saturation
          ↓
4. Executive Assessment & Reporting (app/pages/4_Report.py - PENDING IMPLEMENTATION)
   ├── Calls metrics/dvs.py to compute Defense Vulnerability Score (0-100)
   ├── Calls xai/shap_explain.py to generate SHAP feature importance plot
   ├── Calls xai/lime_explain.py to show local anomaly feature contributions
   ├── Calls xai/attack_decision_explain.py to show tactical intrusion decision tree
   └── Renders executive markdown report with prioritized ICS countermeasures
```

---

## 8. FRONTEND DETAILS (STREAMLIT WEB APPLICATION)

### 8.1 Existing Pages
1. **`app/Home.py`:**
   - Entrypoint for the Streamlit app (`streamlit run app/Home.py`).
   - Demonstrates the Phase 1 MVP baseline: loads IEEE-14 pandapower testbed, allows manual selection of rule-based attacks (FDI, DoS, Replay, MITM), runs `RuleBasedDetector` z-score evaluation, and renders the pyvis interactive network diagram.
2. **`app/pages/1_Configure_Network.py`:**
   - Lets users choose grid presets (`data/sample_topologies/*.json`) or upload custom CSV topologies.
   - Configures toggles for LSTM, Autoencoder, network segmentation, detection confidence thresholds ($\tau_{high}, \tau_{low}$), and episode count.
   - Saves settings to `st.session_state["config"]`.

### 8.2 Pages Requiring Implementation (Empty Placeholders)
1. **`app/pages/2_Run_Simulation.py` (0 bytes):**
   - Needs to load the selected topology from `st.session_state["config"]`.
   - Run `pandapower` AC power flow calculation (`pp.runpp`).
   - Display electrical bus voltages, line loading percentages, and baseline traffic telemetry.
   - Render the baseline OT device network diagram using `testbed/visualize_topology.py`.
2. **`app/pages/3_Live_Battle.py` (0 bytes):**
   - **Crucial Requirement from Session 13:** Must display the **Live Battle Event Log Table** side-by-side with the pyvis interactive network diagram.
   - Every attack step must log: `[Timestamp, Step #, MITRE ID, Technique Name, Target Stage, Compromised Node, Detection Conf, Status (Evasive/Detected)]`.
   - Execute the trained PPO agent (`models/rl_agent.zip`) stepping through `strategic/rl_env.py` (with real detector fusion).
   - Display a live metric card showing current evasion rate and plateau status.
3. **`app/pages/4_Report.py` (0 bytes):**
   - Displays the overall **DVS Score Gauge (0–100)** and rating card.
   - Shows the 4 sub-scores (Evasion, Campaign Completion, Stage Depth, Plateau).
   - Embeds the interactive SHAP feature importance bar chart and LIME local explanation table.
   - Displays the RL Attack Path Decision Rationale.
   - Provides a "Download Executive Report (Markdown/PDF)" button using `xai/recommendation_templates.py`.

---

## 9. CONFIGURATION & ENVIRONMENT VARIABLES

No external API keys or cloud databases are required for core execution. All components run locally and deterministically.
- `DEVICE`: Detected automatically as `cuda` if an NVIDIA GPU is present; otherwise falls back to `cpu`.
- `DATA_PATH`: Defaults to `data/cic_ids2017_subset.csv`. (When Abinraj transfers real Mininet captures, repoint to `data/captured_flows/labeled_flows.csv`).
- Optional Kaggle API: Only needed if re-downloading the raw 8GB CIC-IDS-2017 dataset from scratch (`C:\Users\<user>\.kaggle\kaggle.json`). The balanced 10,002-row subset is already committed to `data/cic_ids2017_subset.csv`.

---

## 10. HOW TO RUN & VERIFY THE PROJECT

### 10.1 Environment Activation
From PowerShell in the repository directory:
```powershell
cd c:\project\ascend-pg-webapp
```
*(If using the active Python environment directly, `python` points to Python 3.12.4 with CUDA PyTorch installed).*

### 10.2 Verifying Completed Components

1. **Verify RL Strategic Layer & Attack Decision Explainer:**
   ```powershell
   python xai/attack_decision_explain.py
   ```
   *Expected Output:* Runs an attack episode, outputs step-by-step decision rationale for techniques across 4 stages, and prints `[OK] RL decision explainer working correctly.`

2. **Verify Defense Vulnerability Score (DVS) Pipeline:**
   ```powershell
   python metrics/dvs.py
   ```
   *Expected Output:* Runs a 20-episode evaluation of the PPO agent, computes sub-scores, prints `DVS Score: 90.8 / 100 - Critical`, and exits with `[OK] DVS evaluation complete.`

3. **Verify LIME Autoencoder Anomaly Explainer:**
   ```powershell
   python xai/lime_explain.py
   ```
   *Expected Output:* Evaluates benign and attack flow rows, computes reconstruction MSE against threshold `0.00238`, displays positive/negative feature weights, and prints `[OK] LIME explainer working correctly.`

4. **Verify SHAP LSTM Sequence Explainer:**
   ```powershell
   python xai/shap_explain.py
   ```
   *Expected Output:* Evaluates a 10-step flow window, computes KernelExplainer SHAP feature importance across timesteps, and prints `[OK] SHAP explainer working correctly.`

5. **Verify Recommendation Templates & Executive Report:**
   ```powershell
   python xai/recommendation_templates.py
   ```
   *Expected Output:* Formats an executive assessment report with MITRE mitigations and prints `[OK] Recommendation templates working correctly.`

6. **Verify GAN Synthetic Generation:**
   ```powershell
   python generative/check_gan_output.py
   ```
   *Expected Output:* Generates 500 synthetic flow samples, verifies standard deviation spread (no mode collapse), and checks range validity.

7. **Launch the Streamlit Web Application:**
   ```powershell
   streamlit run app/Home.py
   ```
   *Expected Output:* Starts local web server at `http://localhost:8501`.

---

## 11. GIT & REPOSITORY STATUS

- **Active Branch:** `adty`
- **Remote:** `origin https://github.com/root-FURY127/ascend-pg-webapp (push/fetch)`
- **Latest Commit:** `67b17f6 Add project files and trained models`
- **Working Tree:** Clean (all files, trained model binaries, and scripts are committed).
- **Tracked Binary Weights in Git:**
  - `models/lstm_detector.pt` (162 KB)
  - `models/autoencoder_detector.pt` (29.5 KB)
  - `models/autoencoder_threshold.json` (54 B)
  - `models/gan_generator.pt` (1.19 MB)
  - `models/gan_discriminator.pt` (691 KB)
  - `models/rl_agent.zip` (532 KB)

---

## 12. WHAT HAS ALREADY BEEN DONE (CHECKLIST)

### Fully Completed [x]
- `[x]` PyTorch CUDA 12.4 installation verified on NVIDIA GeForce RTX 3050 Laptop GPU.
- `[x]` Balanced training dataset `data/cic_ids2017_subset.csv` (10,002 rows, 79 cols).
- `[x]` Module 6 Tabular GAN architecture (`generative/gan.py`) and mixed-precision training (`generative/train_gan.py`).
- `[x]` GAN trained weights saved (`models/gan_generator.pt`, `models/gan_discriminator.pt`) and validated (`check_gan_output.py`).
- `[x]` Module 8a Supervised LSTM temporal detector (`detection/lstm_detector.py`) achieving 87.8% accuracy, 92.7% F1 score (`models/lstm_detector.pt`).
- `[x]` Module 8b Unsupervised Bottleneck Autoencoder anomaly detector (`detection/autoencoder_detector.py`, `models/autoencoder_detector.pt`, `models/autoencoder_threshold.json`).
- `[x]` Module 8c Detection Fusion layer (`detection/fusion.py`) combining LSTM and Autoencoder scores.
- `[x]` Module 7 Multi-Stage Gymnasium Environment (`strategic/rl_env.py`) supporting 17 MITRE ATT&CK for ICS techniques, 4 intrusion stages, progression reward shaping, `PlateauTracker`, and real detector fusion.
- `[x]` Module 7 PPO Agent trained for 32,768 timesteps (`strategic/train_rl.py`, `models/rl_agent.zip`) achieving 100% campaign completion rate and 75% evasion rate.
- `[x]` SHAP Explainer for temporal LSTM sequences (`xai/shap_explain.py`).
- `[x]` LIME Explainer for Autoencoder anomalies (`xai/lime_explain.py`).
- `[x]` RL Attack Decision Explainer (`xai/attack_decision_explain.py`) generating human-readable rationale and alternative rankings.
- `[x]` Defense Vulnerability Score calculator (`metrics/dvs.py`) computing composite score (DVS = 90.8 / 100 Critical).
- `[x]` Admin Hardening Recommendation Templates (`xai/recommendation_templates.py`) mapped to MITRE mitigations.
- `[x]` Project Master Document [`ASCENDPG_PROJECT_MASTER (Abin2) (2).md`](file:///c:/project/ASCENDPG_PROJECT_MASTER%20(Abin2)%20(2).md) updated through Session 16 attributed to Andikumar.

### Partially Completed [-]
- `[-]` Streamlit Multi-Page Web App: `app/Home.py` and `app/pages/1_Configure_Network.py` exist, but pages 2, 3, and 4 are empty placeholders.

### Not Started [ ]
- `[ ]` Wire `app/pages/2_Run_Simulation.py` to run pandapower simulation and display baseline electrical/network state.
- `[ ]` Wire `app/pages/3_Live_Battle.py` to run the live RL agent vs. Fusion defense loop with the required timestamped event log table and pyvis topology highlighting.
- `[ ]` Wire `app/pages/4_Report.py` to display the interactive DVS gauge, SHAP bar charts, LIME explanations, and downloadable report.
- `[ ]` Implement dynamic MITRE STIX fetcher (`standardization/mitre_fetcher.py`).

---

## 13. PRIORITIZED REMAINING WORK FOR CODEX

### Priority 0 (P0 — Critical): Complete the 3 Streamlit Web App Pages

#### Task P0.1: Build `app/pages/2_Run_Simulation.py`
- **Purpose:** Provide a dedicated screen where the user executes baseline grid power-flow simulation and inspects normal operational state before launching attacks.
- **Implementation:**
  - Read configuration from `st.session_state.get("config", {})`.
  - Call `testbed/grid_env.py:build_baseline()` to solve power flow with `pandapower`.
  - Store `net_obj`, `grid_df`, and `traffic_df` in `st.session_state`.
  - Render an interactive summary of bus voltages, line loading, and normal Modbus/DNP3 traffic samples.
  - Render the initial safe OT device topology using `testbed/visualize_topology.py:render_topology()`.
  - Provide a "Proceed to Live Battle $\rightarrow$" button navigating to Page 3.

#### Task P0.2: Build `app/pages/3_Live_Battle.py` (MANDATORY REQUIREMENT)
- **Purpose:** Interactive Live Red vs. Blue battle dashboard.
- **Mandatory Requirements:**
  1. **Live Battle Event Log Table:** A timestamped table displaying every attack step:
     `Timestamp | Step | MITRE ID | Technique Name | Stage | Target Host | Detector Confidence | Status (Evaded/Caught)`
  2. **Live Visual Topology:** Render `render_topology()` highlighting compromised nodes in red border (`#ff3b30`) and defended nodes in green border (`#34c759`).
  3. **Multi-Stage RL Stepping:** Instantiate `strategic/rl_env.py:AttackStrategyEnv(real_mode=True)` and load `models/rl_agent.zip`. Step through the 4 tactical stages.
  4. **Plateau Detection Indicator:** Display an alert banner when `PlateauTracker` signals that defense evasion has plateaued.
  5. Store battle history in `st.session_state["battle_results"]` for Page 4.

#### Task P0.3: Build `app/pages/4_Report.py`
- **Purpose:** Executive XAI & Defense Vulnerability Assessment Dashboard.
- **Implementation:**
  - Call `metrics/dvs.py:compute_dvs()` using battle episode metrics to render the DVS Score Gauge (0–100, rating, color indicator).
  - Display the 4 sub-score progress bars (Evasion, Campaign Completion, Penetration Depth, Plateau).
  - Integrate `xai/shap_explain.py` to render a Plotly or Matplotlib horizontal bar chart of the top-10 contributing features.
  - Integrate `xai/lime_explain.py` to show local anomaly feature contributions for flagged flows.
  - Integrate `xai/attack_decision_explain.py` to display the tactical decision rationale and top-3 alternative techniques considered by the PPO policy.
  - Call `xai/recommendation_templates.py:format_report()` and provide a `st.download_button` for downloading the complete markdown report.

---

### Priority 1 (P1 — High): Build MITRE Dynamic Fetcher Layer (`standardization/`)
- **File to Create:** `standardization/mitre_fetcher.py`
- **Purpose:** Fetch the live MITRE ATT&CK for ICS catalog from the official GitHub `attack-stix-data` repository (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json`) at runtime, cache it locally to `data/mitre_ics_catalog.json`, and fall back to `data/mitre_ics_map.json` if offline.
- **File to Create:** `standardization/executor_registry.py` mapping technique IDs to runnable execution handlers.

---

## 14. KNOWN QUIRKS, WARNINGS, & WORKAROUNDS

1. **Windows Console Unicode Encoding (`UnicodeEncodeError`):**
   - *Symptom:* Printing non-ASCII characters like `✓`, `⚠`, or emoji icons `🟢`, `🔴` on standard Windows Command Prompt / PowerShell crashes with `'charmap' codec can't encode character`.
   - *Fix Applied:* All Python scripts in `xai/` and `metrics/` include:
     ```python
     try:
         if hasattr(sys.stdout, "reconfigure"):
             sys.stdout.reconfigure(encoding="utf-8")
     except Exception:
         pass
     ```
   - *Rule for Codex:* Maintain this block or use ASCII-safe markers (`[+]`, `[!]`, `[OK]`, `[Critical]`) when writing console scripts.

2. **Global Package Collision (`gan 0.0.1`):**
   - *Symptom:* Running `from gan import ...` inside `generative/` can import an unrelated dummy package named `gan` installed in site-packages, causing `ImportError: cannot import name 'build_models'`.
   - *Fix Applied:* Scripts must include:
     ```python
     import sys, os
     sys.path.insert(0, os.path.dirname(__file__))
     ```
   - *Rule for Codex:* Never remove `sys.path.insert(0, os.path.dirname(__file__))` from scripts located in subdirectories.

3. **Stable-Baselines3 PPO GPU Warning:**
   - *Symptom:* `UserWarning: You are trying to run PPO on the GPU, but it is primarily intended to run on the CPU when not using a CNN policy...`
   - *Explanation:* This is an advisory warning from Stable-Baselines3. The PPO policy trains and infers correctly on CUDA. It can be safely ignored.

4. **PyTorch 2.6 AMP Autocast with BCELoss:**
   - *Symptom:* PyTorch 2.6+ deprecates `nn.BCELoss` under AMP autocast for numerical stability reasons.
   - *Fix Applied:* The Discriminator in `generative/gan.py` outputs raw linear logits, and `generative/train_gan.py` uses `nn.BCEWithLogitsLoss()`.

---

## 15. DO NOT BREAK THESE THINGS (CRITICAL RULES FOR CODEX)

> [!CAUTION]
> 1. **DO NOT DELETE OR OVERWRITE EXISTING TRAINED MODELS:** The files in `models/` (`lstm_detector.pt`, `autoencoder_detector.pt`, `rl_agent.zip`, `gan_generator.pt`, `gan_discriminator.pt`) are fully trained, verified artifacts. Do not delete them or overwrite them with dummy stubs.
> 2. **DO NOT CHANGE THE GYMNASIUM OBSERVATION DIMENSION:** The observation space in `strategic/rl_env.py` is strictly 24-dimensional. Modifying it will break compatibility with the pre-trained `models/rl_agent.zip`.
> 3. **DO NOT ALTER MIN-MAX SCALING FORMULAS:** The detection models depend on the exact min-max scaling dictionaries stored inside the checkpoint files.
> 4. **DO NOT REMOVE ATTRIBUTION TO ANDIKUMAR:** All progress logs in [`ASCENDPG_PROJECT_MASTER (Abin2) (2).md`](file:///c:/project/ASCENDPG_PROJECT_MASTER%20(Abin2)%20(2).md) for the training, XAI, and app tracks belong to Andikumar.
> 5. **PRESERVE STREAMLIT RELATIVE IMPORTS:** When running `streamlit run app/Home.py`, the working directory is typically `ascend-pg-webapp/`. Scripts must resolve project roots using `sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))`.

---

## 16. CODEX STARTING INSTRUCTIONS

You are taking over this project as the lead AI coding assistant.
1. **First Action:** Read this document (`CODEX_HANDOFF.md`) and the master log [`ASCENDPG_PROJECT_MASTER (Abin2) (2).md`](file:///c:/project/ASCENDPG_PROJECT_MASTER%20(Abin2)%20(2).md).
2. **Immediate Task:** Implement the 3 empty Streamlit pages in `c:\project\ascend-pg-webapp\app\pages\`:
   - `2_Run_Simulation.py`
   - `3_Live_Battle.py` (Must include the live timestamped Event Log Table)
   - `4_Report.py` (Must display the DVS gauge, SHAP, LIME, and RL rationales)
3. **Verification:** Run `streamlit run app/Home.py` and test the complete end-to-end user flow in the browser.

---

# TL;DR FOR CODEX

- **What this is:** ASCEND-PG is an adaptive cyber-physical security platform for power grid OT networks combining pandapower, real Modbus emulations, a 17-technique MITRE ATT&CK for ICS RL agent, a tabular GAN, a dual LSTM + Autoencoder detector, and an XAI/DVS assessment layer.
- **Current State:** All backend AI/ML models are trained, evaluated, and saved in `models/`. All XAI tools (`xai/`) and DVS metrics (`metrics/`) are functional. The Streamlit UI has `Home.py` and `1_Configure_Network.py` ready, but pages 2, 3, and 4 are empty placeholders.
- **Immediate Next Step:** Write `app/pages/2_Run_Simulation.py`, `app/pages/3_Live_Battle.py` (featuring the required event log table), and `app/pages/4_Report.py`, then test via `streamlit run app/Home.py`.

---

## 17. SESSION UPDATE (LATEST FIXES & FEATURES)

> **Note:** The following updates have been completed and pushed to the Abin branch to resolve UI/UX issues and seamlessly integrate the Mininet physical testbed results into the DVS Executive Report.

### 1. PyVis Topology Enhancements (app/pages/3_Live_Battle.py & testbed/visualize_topology.py)
- **Restored Vector Assets:** Reverted the UI to use the preferred crisp, custom-colored cyan 3D isometric vector SVGs instead of rasterized images. 
- **Fixed Layout & Artifacts:** Removed the solid blue background squares that bled through transparent icons by overriding shapeProperties background colors to gba(0,0,0,0). Adjusted PyVis physics (
ode_distance=130, spring_length=50) to create a clean, un-crammed layout.
- **Floating Legend:** Injected a sleek, semi-transparent absolute-positioned HTML legend directly into the PyVis canvas to explain the edge colors (Solid Orange = Power Line, Dashed Blue = IT/OT Comm) and node borders (Red Ring = Compromised, Green Ring = Detected).

### 2. Baseline Grid Configuration Bugfix (testbed/grid_env.py & app/pages/2_Run_Simulation.py)
- **Fixed Hardcoded Grid:** Previously, the uild_baseline() function hardcoded the pandapower grid to pn.case14(), completely ignoring the user's choice in 1_Configure_Network.py.
- **Dynamic Loading:** The simulation page now properly retrieves the pandapower_case variable from st.session_state and passes it to the backend. The IEEE-30 grid selection now functions correctly.

### 3. Mininet Testbed Executive Report Integration (xai/recommendation_templates.py)
- **Hardware-in-the-Loop Reporting:** Modified the DVS report generator to automatically check for data/cycle_report.json (the output of the live 14-step Mininet attack cycle).
- **Executive Validation Table:** If found, the final downloadable Markdown/PDF report now includes a "Hardware-in-the-Loop Testbed Validation" table showing exact physical success rates vs. Suricata IDS alert counts for every step.
- **Targeted Mitigations:** Implemented logic to automatically map any successfully compromised physical step to its corresponding MITRE ATT&CK ID, querying TECHNIQUE_MITIGATIONS to append a dedicated list of defense recommendations tailored precisely to the attacks that bypassed the IDS.

### 4. WSL Compatibility Fixes
- **CRLF Line Endings:** Fixed \r\n line endings (os error 2) in all bash scripts (start_testbed.sh, scripts/*.sh, scripts/*.py) to ensure flawless execution in WSL/Linux environments.
