# ASCEND-PG Evaluation Parameters

Complete reference of all evaluation metrics, KPIs, and parameters across the ASCEND-PG system.

---

## Table of Contents

1. [Attack Metrics (RL Agent)](#1-attack-metrics-rl-agent)
2. [Defense Metrics](#2-defense-metrics)
3. [Network Metrics](#3-network-metrics)
4. [Report Metrics](#4-report-metrics)
5. [Training Metrics](#5-training-metrics)
6. [DVS (Defense Vulnerability Score)](#6-dvs-defense-vulnerability-score)
7. [XAI Metrics](#7-xai-metrics)

---

## 1. Attack Metrics (RL Agent)

### 1.1 Evasion Metrics

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `evasion_rate` | float | [0, 1] | Percentage of steps that evaded detection | `rl_env.py` |
| `recent_evasion_rate` | float | [0, 1] | Sliding window (last 5 steps) evasion rate | `rl_env.py` |
| `detected` | bool | True/False | Whether current step was detected | `rl_env.py` |
| `detection_confidence` | float | [0.0, 1.0] | Detection confidence score per step | `rl_env.py` |
| `detection_method` | string | - | Detection mechanism used | `rl_env.py` |

**Detection Methods:**
- `suricata` - Suricata IDS signature match
- `ml_lstm` - LSTM anomaly detector
- `ml_autoencoder` - Autoencoder anomaly detector
- `hybrid` - Combined Suricata + ML
- `calibrated` - Mock/simulation mode

### 1.2 Campaign Metrics

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `campaign_complete` | bool | True/False | All 4 tactical stages completed | `rl_env.py` |
| `completed_stages` | set | {0,1,2,3} | Which stages were completed | `rl_env.py` |
| `chain` | list | - | List of technique IDs used in order | `rl_env.py` |
| `step_count` | int | 0-16 | Number of steps in current episode | `rl_env.py` |

### 1.3 Targeting Metrics

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `target_bus` | int | [0, num_buses) | Which bus was attacked | `rl_env.py` |
| `compromised_buses` | set | - | Set of all compromised bus indices | `rl_env.py` |
| `attack_depth` | float | [0, 1] | Min hop distance to nearest generator | `rl_env.py` |
| `frac_compromised` | float | [0, 1] | Fraction of total buses compromised | `rl_env.py` |

### 1.4 Action Parameters

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `register_address` | int | 40000-40049 | Modbus register address used | `rl_env.py` |
| `register_offset` | int | [0, 49] | Offset from base register | `rl_env.py` |
| `value_magnitude` | float | [0.9, 1.1] | Write value scale factor | `rl_env.py` |
| `value_level` | int | [0, 9] | Value magnitude index | `rl_env.py` |

**Register Base Addresses by Technique:**
| Technique | Base Address | Description |
|-----------|--------------|-------------|
| T0836 (FDI) | 40000 | Holding registers |
| T0835 (I/O Image) | 1 | Coils |
| T0816 (Restart) | 99 | Restart coil |
| T0801 (Monitor) | 30000 | Input registers (read) |
| T0802 (Collection) | 30000 | Input registers (read) |
| T0806 (Brute Force) | 40000 | All registers |

### 1.5 Detection Risk Multipliers

| Parameter | Formula | Range | Description |
|-----------|---------|-------|-------------|
| `register_risk` | `1.0 - (register_offset / 50) * 0.3` | 0.7 - 1.0 | Risk from register choice |
| `value_deviation` | `abs(value_magnitude - 1.0)` | 0.0 - 0.1 | Deviation from normal value |
| `value_risk` | `1.0 + value_deviation * 5.0` | 1.0 - 1.5 | Risk from value deviation |
| `target_risk` | 1.2 if generator, else 1.0 | 1.0 - 1.2 | Risk from target type |
| `risk_multiplier` | `register_risk * value_risk * target_risk` | 0.7 - 1.8 | Combined detection risk |
| `adjusted_p` | `base_p * risk_multiplier` | - | Adjusted detection probability |

### 1.6 Reward Function Components

| Component | Value | Trigger | Description |
|-----------|-------|---------|-------------|
| Step cost | -0.1 | Every step | Base cost for taking action |
| Evasion bonus | +1.5 * (1 - conf) | Not detected | Reward for evading detection |
| Detection penalty | -2.5 * conf | Detected | Penalty for being detected |
| Stage progression | +3.0 | Correct stage order | Reward for following attack chain |
| Redundant stage | -1.5 | Repeating completed stage | Penalty for redundancy |
| Out-of-order | -1.0 | Wrong stage order | Penalty for skipping stages |
| Generator targeting | +0.5 | Attacking generator bus | Bonus for high-impact targets |
| Lateral movement | +0.3 | Compromising new bus | Bonus for spreading |
| Clustering penalty | -0.5 | Attacking same area | Penalty for lack of diversity |
| Completion (evaded) | +8.0 | All 4 stages, no detection | Maximum success bonus |
| Completion (detected) | +4.0 | All 4 stages, some detected | Partial success bonus |
| Multi-bus bonus | +0.2 * count | Per compromised bus | Bonus for widespread compromise |

### 1.7 Observation Space (229 dimensions)

| Section | Dims | Indices | Description |
|---------|------|---------|-------------|
| Current stage | 1 | [0] | Normalized [0,1] |
| Recent evasion rate | 1 | [1] | Last 5 steps evasion |
| Last confidence | 1 | [2] | Previous step confidence |
| One-hot technique | 17 | [3-19] | Which technique was last used |
| Completed stages | 4 | [20-23] | Multi-hot completed stages |
| Last register | 1 | [24] | Normalized register offset |
| Last value | 1 | [25] | Normalized value magnitude |
| Last target | 1 | [26] | Normalized target bus |
| Bus voltages | 50 | [27-76] | Normalized by 1.1 |
| Bus degrees | 50 | [77-126] | Normalized by max degree |
| Bus types | 50 | [127-176] | Slack=1.0, PV=0.5, PQ=0.0 |
| Compromised | 50 | [177-226] | 1=compromised, 0=safe |
| Fraction compromised | 1 | [227] | Count / num_buses |
| Attack depth | 1 | [228] | Min hop to generators |

### 1.8 Step Info Dict

| Key | Type | Description |
|-----|------|-------------|
| `technique_id` | string | Selected MITRE technique ID |
| `technique_name` | string | Selected technique name |
| `stage` | int | Technique's tactical stage (0-3) |
| `detection_confidence` | float | Detection confidence score |
| `detected` | bool | Boolean detection result |
| `campaign_complete` | bool | All 4 stages completed |
| `chain` | list | List of all technique IDs used |
| `target_bus` | int | Targeted bus index |
| `compromised_buses` | list | List of compromised bus indices |
| `register_offset` | int | Register offset (0-49) |
| `register_address` | int | Actual Modbus register address |
| `value_magnitude` | float | Write value scale factor (0.9x-1.1x) |
| `value_level` | int | Value magnitude index (0-9) |

---

## 2. Defense Metrics

### 2.1 Hybrid Detector

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `suricata_detected` | bool | True/False | Suricata found matching alerts | `hybrid_detector.py` |
| `suricata_alert_count` | int | 0+ | Number of matching Suricata alerts | `hybrid_detector.py` |
| `suricata_signatures` | list | - | List of matched alert signatures | `hybrid_detector.py` |
| `ml_detected` | bool | True/False | ML fusion exceeded threshold | `hybrid_detector.py` |
| `ml_confidence` | float | [0, 1] | Fused ML confidence score | `hybrid_detector.py` |
| `ml_lstm_confidence` | float | [0, 1] | LSTM detector confidence | `hybrid_detector.py` |
| `ml_ae_score` | float | [0, 1] | Autoencoder anomaly score | `hybrid_detector.py` |
| `ml_available` | bool | True/False | ML models loaded and working | `hybrid_detector.py` |
| `ml_error` | string | - | Error message if ML inference failed | `hybrid_detector.py` |
| `combined_detected` | bool | True/False | Overall OR of suricata + ml | `hybrid_detector.py` |
| `detection_method` | string | - | One of: "both", "suricata", "ml", "undetected" | `hybrid_detector.py` |

### 2.2 ML Detector

| Parameter | Type | Range | Description | Source |
|-----------|------|-------|-------------|--------|
| `lstm_confidence` | float | [0, 1] | LSTM sigmoid output | `ml_detector.py` |
| `ae_anomaly_score` | float | [0, 1] | Normalized AE reconstruction error | `ml_detector.py` |
| `ae_max_reconstruction_error` | float | 0+ | Raw max MSE across window rows | `ml_detector.py` |
| `fused_confidence` | float | [0, 1] | Weighted average of LSTM + AE | `ml_detector.py` |
| `detected` | bool | True/False | `fused_confidence > 0.50` | `ml_detector.py` |

**Constants:**
| Constant | Value | Description |
|----------|-------|-------------|
| `ML_CONFIDENCE_THRESHOLD` | 0.50 | Detection threshold |
| `LSTM_WEIGHT` | 0.50 | LSTM contribution weight |
| `AE_WEIGHT` | 0.50 | Autoencoder contribution weight |

### 2.3 ML Training Metrics

| Metric | Formula | Description |
|--------|---------|-------------|
| `accuracy` | `(TP + TN) / Total` | Overall classification accuracy |
| `precision` | `TP / (TP + FP)` | Of flagged-as-attack, how many truly are |
| `recall` | `TP / (TP + FN)` | Of real attacks, how many were caught |
| `f1` | `2 * precision * recall / (precision + recall)` | Harmonic mean of precision and recall |
| `tp` | - | True Positives |
| `fp` | - | False Positives |
| `fn` | - | False Negatives |
| `tn` | - | True Negatives |
| `baseline_accuracy` | `1 - (y_test.sum() / len(y_test))` | Naive "always benign" baseline |
| `total_loss` | - | BCE loss per epoch |

### 2.4 Suricata IDS Rules

| SID | Rule Name | MITRE Technique | Description |
|-----|-----------|-----------------|-------------|
| 9000001 | FDI - Holding Register Write | T0836 | Detects false data injection |
| 9000002 | DoS - Modbus Request Flood | T0814 | Detects denial of service |
| 9000004 | Recon - Device ID Query | T0888 | Detects device enumeration |
| 9000005 | Recon - Read Exception Status | T0840 | Detects reconnaissance |
| 9000006 | Recon - Diagnostics FC08 | T0840 | Detects diagnostics scan |
| 9000007 | CmdInject - Coil Write | T0855 | Detects command injection |
| 9000008 | CmdInject - Diagnostics Restart | T0855 | Detects restart attempt |
| 9000009 | CmdInject - Clear Counters | T0855 | Detects counter tampering |
| 9000010 | DoS - Rapid TCP SYN | T0814 | Detects SYN flood |
| 9000020 | DoS - Sub-Threshold Read Flood | T0814 | Detects slow DoS |
| 9000022 | MITM - Non-Standard Port 503 | T0830 | Detects MITM attempt |
| 9000023 | BruteForce - Rapid Register Enum | T0806 | Detects brute force |
| 9000024 | DoV - Forged FC06 Write | T0815 | Detects denial of view |
| 9000025 | Recon - Coil Read | T0801 | Detects coil reconnaissance |

---

## 3. Network Metrics

### 3.1 Flow Logger Metrics

| Parameter | Type | Unit | Description | Source |
|-----------|------|------|-------------|--------|
| `duration_sec` | float | seconds | Flow duration | `flow_logger.py` |
| `total_packets` | int | packets | Total packets in flow | `flow_logger.py` |
| `total_bytes` | int | bytes | Total bytes in flow | `flow_logger.py` |
| `fwd_packets` | int | packets | Forward direction packet count | `flow_logger.py` |
| `bwd_packets` | int | packets | Backward direction packet count | `flow_logger.py` |
| `fwd_bytes` | int | bytes | Forward direction byte count | `flow_logger.py` |
| `bwd_bytes` | int | bytes | Backward direction byte count | `flow_logger.py` |
| `bytes_per_sec` | float | bytes/sec | Throughput | `flow_logger.py` |
| `packets_per_sec` | float | packets/sec | Packet rate | `flow_logger.py` |
| `min_packet_length` | int | bytes | Minimum packet length | `flow_logger.py` |
| `max_packet_length` | int | bytes | Maximum packet length | `flow_logger.py` |
| `avg_packet_length` | float | bytes | Average packet length | `flow_logger.py` |
| `syn_count` | int | count | SYN flag count | `flow_logger.py` |
| `ack_count` | int | count | ACK flag count | `flow_logger.py` |
| `psh_count` | int | count | PSH flag count | `flow_logger.py` |
| `rst_count` | int | count | RST flag count | `flow_logger.py` |
| `fin_count` | int | count | FIN flag count | `flow_logger.py` |
| `flow_timeout` | float | seconds | Flow timeout (default: 30.0) | `flow_logger.py` |

### 3.2 CIC-IDS-2017 Features (78 dimensions)

| Category | Features | Count |
|----------|----------|-------|
| Port & Duration | Destination Port, Flow Duration | 2 |
| Packet Counts | Total Fwd Packets, Total Backward Packets | 2 |
| Byte Lengths | Total Length of Fwd/Bwd Packets | 2 |
| Fwd Packet Length | Max, Min, Mean, Std | 4 |
| Bwd Packet Length | Max, Min, Mean, Std | 4 |
| Throughput | Flow Bytes/s, Flow Packets/s | 2 |
| IAT Mean/Std/Max/Min | Flow IAT Mean/Std/Max/Min | 4 |
| Fwd IAT | Total/Mean/Std/Max/Min | 5 |
| Bwd IAT | Total/Mean/Std/Max/Min | 5 |
| TCP Flags | Fwd/Bwd PSH, URG Flags | 4 |
| Flag Counts | FIN, SYN, RST, PSH, ACK, URG, CWE, ECE | 8 |
| Header Lengths | Fwd/Bwd Header Length | 2 |
| Packet Rates | Fwd/Bwd Packets/s | 2 |
| Packet Size | Min/Max Packet Length, Mean/Std/Variance | 5 |
| Ratios | Down/Up Ratio, Average Packet Size | 2 |
| Segment Sizes | Avg Fwd/Bwd Segment Size | 2 |
| Bulk Rates | Fwd/Bwd Avg Bytes/Packets/Bulk, Rate | 6 |
| Subflows | Subflow Fwd/Bwd Packets/Bytes | 4 |
| Window | Init_Win_bytes_forward/backward | 2 |
| Data | act_data_pkt_fwd, min_seg_size_forward | 2 |
| Active | Active Mean/Std/Max/Min | 4 |
| Idle | Idle Mean/Std/Max/Min | 4 |

### 3.3 Modbus Packet Logger

| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `timestamp` | string | ISO format UTC timestamp | `modbus_logger.py` |
| `src_ip` | string | Source IP address | `modbus_logger.py` |
| `dst_ip` | string | Destination IP address | `modbus_logger.py` |
| `src_port` | int | Source port | `modbus_logger.py` |
| `dst_port` | int | Destination port | `modbus_logger.py` |
| `protocol` | string | "Modbus/TCP" | `modbus_logger.py` |
| `direction` | string | "request" or "response" | `modbus_logger.py` |
| `mbap_trans_id` | int | MBAP transaction ID | `modbus_logger.py` |
| `mbap_unit_id` | int | Modbus unit ID | `modbus_logger.py` |
| `function_code` | int | Modbus function code (numeric) | `modbus_logger.py` |
| `function_name` | string | Human-readable function name | `modbus_logger.py` |
| `is_exception` | bool | Is exception response | `modbus_logger.py` |
| `exception_code` | string | Exception code (if applicable) | `modbus_logger.py` |
| `start_address` | int | Register start address | `modbus_logger.py` |
| `quantity` | int | Register count requested | `modbus_logger.py` |
| `values` | list | Register values | `modbus_logger.py` |
| `raw_hex` | string | Raw packet hex dump | `modbus_logger.py` |
| `packet_length` | int | Raw byte length | `modbus_logger.py` |

### 3.4 Topology Metrics

| Metric | Type | Description | Source |
|--------|------|-------------|--------|
| `num_buses` | int | Number of nodes (PLCs) | `topology.py` |
| `num_edges` | int | Number of network links | `topology.py` |
| `bus_types` | list | 3=slack, 1=PV, 2=PQ | `topology.py` |
| `voltages` | list | Per-bus voltage in p.u. | `topology.py` |
| `bus_degrees` | list | Per-bus connection count | `topology.py` |
| `max_degree` | int | Maximum bus degree | `topology.py` |
| `gen_buses` | list | Generator bus indices | `topology.py` |
| `ip_map` | dict | bus_id -> IP address mapping | `topology.py` |
| `depth_from_gens` | list | BFS hop distance to nearest generator | `topology.py` |

### 3.5 PLC Server Metrics

| Data | Type | Description | Source |
|------|------|-------------|--------|
| `vm_pu` | float | Voltage magnitude (per unit) | `plc_server.py` |
| `va_deg` | float | Voltage angle (degrees) | `plc_server.py` |
| `pg` | float | Real power generation (MW) | `plc_server.py` |
| `qg` | float | Reactive power generation (Mvar) | `plc_server.py` |
| `pl` | float | Real power load (MW) | `plc_server.py` |
| `ql` | float | Reactive power load (Mvar) | `plc_server.py` |
| Register map | - | 100 HR + coils + DI + IR per PLC | `plc_server.py` |

---

## 4. Report Metrics

### 4.1 Executive Summary

| Metric | Type | Description |
|--------|------|-------------|
| `total_steps` | int | Total attack steps executed |
| `detected_count` | int | Steps that were detected |
| `compromised_count` | int | Steps that evaded detection |
| `evasion_rate` | float | `compromised_count / total_steps` |
| `critical` | int | Critical severity findings |
| `high` | int | High severity findings |
| `medium` | int | Medium severity findings |
| `low` | int | Low severity findings |
| `info` | int | Informational findings |
| `overall_risk` | string | CRITICAL / HIGH / MEDIUM / LOW |

### 4.2 Per-Finding Metrics

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Finding ID (e.g., "ASCEND-PG-001") |
| `technique_id` | string | MITRE ATT&CK technique ID |
| `technique_name` | string | Technique name |
| `severity` | string | Critical / High / Medium / Low / Informational |
| `cvss` | float | Approximate CVSS score |
| `target` | string | Target host IP/name |
| `stage` | int | MITRE tactical stage (0-3) |
| `detected` | bool | Whether attack was detected |
| `detection_confidence` | float | Detection confidence [0-1] |
| `detection_method` | string | How it was detected |
| `attack_actual` | string | What the attack actually did |
| `defense_response` | string | How the defense responded |
| `impact` | string | Generic impact description |
| `remediation` | string | How to fix the vulnerability |

### 4.3 CVSS Scores

| Severity | CVSS Score |
|----------|------------|
| Critical | 9.5 |
| High | 7.5 |
| Medium | 5.0 |
| Low | 2.5 |
| Informational | 0.0 |

### 4.4 Severity Classification Logic

| Condition | Severity |
|-----------|----------|
| Stage 3 + confidence < 0.5 | Critical |
| Stage 3 + confidence < 0.8 | High |
| Stage 2 + confidence < 0.3 | High |
| Stage 2 + confidence < 0.6 | Medium |
| Stage 1 + confidence < 0.4 | Medium |
| Stage 1 (else) | Low |
| Stage 0 + confidence < 0.3 | Low |
| Default | Informational |

### 4.5 Overall Risk Rating

| Condition | Rating |
|-----------|--------|
| Any Critical finding | CRITICAL |
| Any High finding | HIGH |
| Any Medium finding | MEDIUM |
| Otherwise | LOW |

### 4.6 Evidence Per Finding

| Field | Description |
|-------|-------------|
| `timestamp` | Event timestamp |
| `step` | Step number in campaign |
| `detection_method` | How it was detected |
| `confidence` | Detection confidence |
| `mode` | Testbed mode (real, simulation, etc.) |
| `target` | Target host |
| `src_ip` | Source IP of attack |

---

## 5. Training Metrics

### 5.1 Training Callback Metrics

| Metric | Description | Frequency |
|--------|-------------|-----------|
| `step` | Training step number | Every 500 steps |
| `avg_reward` | Average reward over last 100 steps | Every 500 steps |
| `evasion_rate` | Average evasion rate over last 100 steps | Every 500 steps |
| `total_evasions` | Running total of evasion steps | Every 500 steps |
| `best_evasion` | Best evasion rate seen | Every 500 steps |
| `no_improve_count` | Steps without improvement | Every 500 steps |

### 5.2 PPO Hyperparameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `learning_rate` | 3e-4 | Learning rate |
| `gamma` | 0.99 | Discount factor |
| `clip_range` | 0.2 | PPO clip range |
| `ent_coef` | 0.01 | Entropy coefficient |
| `n_steps` | 2048 | Steps per update |
| `batch_size` | 64 | Mini-batch size |
| `n_epochs` | 10 | Epochs per update |
| `net_arch` | [256, 256, 128] | Network architecture |

### 5.3 Evaluation Metrics (Post-Training)

| Metric | Description |
|--------|-------------|
| `campaigns_completed` | Episodes that completed all 4 stages |
| `total_rewards` | Per-episode total rewards |
| `evasion_rates` | Per-episode evasion rates |
| `sample_chains` | Up to 3 sample attack chains |
| `campaign_completion_%` | `campaigns_completed / n_episodes * 100` |
| `avg_reward` | `sum(total_rewards) / n_episodes` |
| `avg_evasion` | `sum(evasion_rates) / n_episodes * 100` |
| `plateau_status` | "Saturated" or "Progressing" |

### 5.4 Training Performance

| Metric | Description |
|--------|-------------|
| `elapsed` | Training time in seconds |
| `timesteps/sec` | `total_timesteps / elapsed` |
| `total_timesteps` | Total training steps |

---

## 6. DVS (Defense Vulnerability Score)

### 6.1 Evaluation Results

| Metric | Description |
|--------|-------------|
| `num_episodes` | Number of evaluation episodes |
| `evasion_rates` | Per-episode evasion rates list |
| `avg_evasion_rate` | Mean evasion rate across episodes |
| `completion_count` | Episodes where campaign completed |
| `completion_rate` | `completion_count / num_episodes` |
| `max_stages_reached` | Per-episode max stage reached |
| `avg_max_stage` | Mean max stage across episodes |
| `plateau_detected` | Boolean from PlateauTracker |
| `episode_rewards` | Per-episode total rewards |
| `avg_reward` | Mean reward across episodes |
| `chains` | Per-episode attack chains |

### 6.2 DVS Composite Score

| Component | Weight | Formula | Range |
|-----------|--------|---------|-------|
| `evasion_score` | 30% | `avg_evasion_rate * 100` | 0-100 |
| `campaign_score` | 30% | `completion_rate * 100` | 0-100 |
| `stage_depth_score` | 25% | `(avg_max_stage / 3) * 100` | 0-100 |
| `plateau_score` | 15% | 100 if plateau, else 50 | 50 or 100 |
| **DVS Total** | 100% | Weighted sum, clipped [0, 100] | 0-100 |

### 6.3 DVS Rating Bands

| DVS Range | Rating | Color | Description |
|-----------|--------|-------|-------------|
| 0-25 | Robust | Green | Defense is effective |
| 26-50 | Moderate | Yellow | Some vulnerabilities exist |
| 51-75 | Vulnerable | Orange | Significant gaps in defense |
| 76-100 | Critical | Red | Defense is easily bypassed |

### 6.4 PlateauTracker Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `patience` | 5 | Steps without improvement before plateau |
| `min_evasion_gain` | 0.02 | Minimum gain to reset stagnation counter |
| `best_evasion_rate` | 0.0 | Best evasion rate seen |
| `stagnant_count` | 0 | Consecutive episodes without improvement |
| `history` | [] | List of all episode evasion rates |

---

## 7. XAI Metrics

### 7.1 SHAP Explainer

| Metric | Description |
|--------|-------------|
| `prediction` | LSTM detection confidence for the window |
| `base_value` | SHAP expected value |
| `shap_values` | 2D array (WINDOW_SIZE x feature_dim) |
| `feature_importance` | Mean |SHAP| per feature across timesteps |
| `top_features` | Top-k features by importance |

### 7.2 LIME Explainer

| Metric | Description |
|--------|-------------|
| `anomaly_probability` | `min(reconstruction_error / (2 * threshold), 1.0)` |
| `reconstruction_error` | MSE for the explained row |
| `threshold` | 95th percentile benign error |
| `is_anomaly` | `reconstruction_error > threshold` |
| `explanation_list` | LIME feature contribution weights for anomaly class |

### 7.3 RL Decision Explainer

| Metric | Description |
|--------|-------------|
| `chosen_probability` | PPO action probability for chosen technique |
| `action_probabilities` | Full probability distribution over 17 techniques |
| `value_estimate` | Critic network value estimate (expected future reward) |
| `evasion_rate` | From observation vector |
| `last_confidence` | From observation vector |
| `completed_stages` | From observation vector |
| `reward` | Step reward |
| `detected` | Step detection result |
| `detection_confidence` | Step confidence |
| `campaign_complete` | Whether all 4 stages completed |

---

## Appendix A: MITRE ATT&CK for ICS Techniques

| ID | Name | Stage | Mock Prob |
|----|------|-------|-----------|
| T0886 | Remote Services | 0 | 0.50 |
| T0846 | Remote System Discovery | 0 | 0.70 |
| T0888 | Remote System Info Discovery | 0 | 0.45 |
| T0842 | Network Sniffing | 0 | 0.25 |
| T0830 | Adversary-in-the-Middle | 1 | 0.55 |
| T0801 | Monitor Process State | 1 | 0.35 |
| T0802 | Automated Collection | 1 | 0.60 |
| T0869 | Standard App Layer Protocol | 1 | 0.40 |
| T0814 | Denial of Service | 2 | 0.85 |
| T0878 | Alarm Suppression | 2 | 0.60 |
| T0816 | Device Restart/Shutdown | 2 | 0.75 |
| T0881 | Service Stop | 2 | 0.70 |
| T0836 | Modify Parameter (FDI) | 2 | 0.65 |
| T0835 | Manipulate I/O Image | 2 | 0.65 |
| T0806 | Brute Force I/O | 2 | 0.80 |
| T0832 | Manipulation of View (Replay) | 3 | 0.40 |
| T0815 | Denial of View | 3 | 0.70 |

---

## Appendix B: File References

| File | Metrics Tracked |
|------|-----------------|
| `strategic/rl_env.py` | Reward function, observation space, step info dict |
| `strategic/train_rl.py` | Training callbacks, evaluation results |
| `defense/hybrid_detector.py` | Suricata + ML fusion metrics |
| `defense/ml_detector.py` | LSTM + AE metrics |
| `defense/flow_logger.py` | Network flow metrics |
| `defense/modbus_logger.py` | Modbus packet metrics |
| `testbed/topology.py` | Topology metrics |
| `testbed/plc_server.py` | PLC register data |
| `reports/pentest_report.py` | Report metrics, severity, CVSS |
| `metrics/dvs.py` | DVS composite score |
| `xai/shap_explain.py` | SHAP feature importance |
| `xai/lime_explain.py` | LIME anomaly detection |
| `xai/attack_decision_explain.py` | RL decision rationale |
| `app/pages/3_Live_Battle.py` | Dashboard metrics |
| `app/pages/4_Report.py` | Report display metrics |

---

*Last updated: 2026-09-10*
