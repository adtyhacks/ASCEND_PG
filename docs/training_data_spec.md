# ASCEND-PG Training Data Contract

This document defines the only acceptable data handoff from the testbed track
to the GAN/RL/detection training track. It prevents accidental training on
unlabeled, incompatible, or leakage-prone data.

## Current status

No training dataset is present in this repository yet. `data/episode_log.csv`
is empty. Do not describe a model as trained until the source files, split
manifest, training command, saved weights, and evaluation metrics exist.

## Data sources and roles

1. **ASCEND-PG Mininet/Modbus captures — required final evidence.** Capture
   normal SCADA polling and every implemented attack from the project's own
   isolated testbed. These captures are the only source used for final held-out
   evaluation and the panel demonstration.
2. **CICModbusDataset2023 — primary public supplement.** Use its benign PCAPs,
   attack PCAPs, and timestamped attack logs for pretraining/development. It
   covers reconnaissance, query flooding, false-data injection, and baseline
   replay in a simulated substation Modbus setting. Download only from the
   official CIC page and retain the required citation/license notice.
3. **WUSTL-IIoT-2021 — optional supplemental flow pretraining.** Use only for
   generic SCADA/IIoT flow behaviour (normal, DoS, reconnaissance, command
   injection). It is not a substitute for Modbus-specific final evaluation.

Never merge public and ASCEND-PG rows into the same test split. `source` must
remain a column throughout preprocessing.

## Required raw artefacts per testbed episode

Store raw artefacts outside git under `data/raw/` or `data/captured_pcaps/`:

- PCAP captured at the OVS mirror or monitoring interface.
- Attack/campaign log with UTC start/end timestamps, source/target, technique,
  parameters, random seed, and scenario identifier.
- SCADA/PLC telemetry log: timestamp, PLC/bus ID, register address, register
  value, voltage/process value where available.
- Suricata `eve.json` extract for the same interval.

At a minimum collect separate episodes for Normal, Recon, FDI, and DoS. Add
Replay and MITM only after their real attack scripts are working. For every
attack class, vary target and bounded attack parameters over multiple
independent episodes; do not create apparent diversity by duplicating rows.

## Canonical processed tables

### `data/processed/flow_features.csv`

One row per CICFlowMeter flow/window. Required metadata columns:

`timestamp_utc, source, scenario_id, episode_id, step_id, topology_id,
src_ip, dst_ip, src_port, dst_port, protocol, attack_type, mitre_technique,
label_binary, label_multiclass`

Then retain the numeric CICFlowMeter features without target leakage. Do not
train on identifiers or direct labels such as raw IP addresses, timestamps,
scenario IDs, file names, or log-derived attack names.

### `data/processed/telemetry.csv`

`timestamp_utc, source, scenario_id, episode_id, plc_id, bus_id,
register_address, register_value, voltage_pu, packet_count, byte_count,
attack_type, mitre_technique, label_binary`

Missing electrical values are allowed only when explicitly represented as
missing; never silently manufacture them. The preprocessing manifest must say
which telemetry fields are available for every source.

### `data/processed/campaign_trace.json`

One record per RL episode: observation summary, available actions, selected
MITRE technique, GAN parameter proposal and seed, detector/IDS results,
reward components, terminal reason, and timestamp. This is RL training/audit
data and report evidence, not a replacement for flow/telemetry features.

## Model-specific inputs

| Component | Inputs | Labels / target | Notes |
|---|---|---|---|
| GAN | Normalized numeric attack-flow/telemetry features plus attack class/technique condition | No detection label as a feature | Train only on attack rows. Validate generated distributions against held-out real attack rows. |
| PPO RL | Running `rl_env` observation from campaign state, IDS/model feedback, history, and safe action mask | Reward from evasion, impact, cost, repetition penalty, and safety rules | PPO is online RL: it does **not** train from a standalone CSV. Save its episode trace. |
| LSTM | Chronologically ordered, fixed-length windows of flow and available telemetry features | Binary/multiclass attack label or normal-prediction error | Build sequences inside each episode; never allow a sequence to cross episode boundaries. |
| Autoencoder | Normal-only training windows | Reconstruction error at validation/test time | Train on normal rows only; attack rows are evaluation data. |
| Fusion / XAI | Held-out LSTM + AE scores with feature names and provenance | Detection verdict | SHAP/LIME must use the actual preprocessed feature names, not anonymous column numbers. |

## Split and quality rules

- Split by **episode/scenario**, never randomly by individual row. This avoids
  nearly identical packets from one attack appearing in both train and test.
- Keep an ASCEND-PG-only held-out test set for final metrics. Public data may
  be used for pretraining but cannot be the final claimed result.
- Record exact split manifests, scaler fit on training data only, model seed,
  package versions, and metrics: precision, recall, F1, ROC-AUC where valid,
  false-negative rate, confusion matrix, and DVS inputs.
- Keep raw PCAPs and large processed data out of git. Commit only scripts,
  schema examples, aggregate metrics, and small non-sensitive samples.

## Handoff to Andikumar

Provide one archive or shared folder containing:

```text
data/
├── processed/
│   ├── flow_features.csv
│   ├── telemetry.csv
│   └── campaign_trace.json
├── splits/
│   ├── train_episodes.csv
│   ├── validation_episodes.csv
│   └── test_episodes.csv
├── manifests/
│   ├── feature_dictionary.md
│   ├── collection_manifest.json
│   └── preprocessing_versions.txt
└── README.md
```

The receiving README must state source, attack coverage, row/episode counts,
missing fields, preprocessing command, and the immutable held-out test set.
