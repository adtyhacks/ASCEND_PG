# ASCEND-PG — Project Master File
Single source of truth for this project. Read this whole file before doing anything else.

## ⚠️ INSTRUCTIONS — READ FIRST

**If you are an AI model being handed this file in a new chat:** This is the complete context for a college Major Project (cybersecurity, power grid attack simulation + defense). Read this entire file before responding to anything else the user says. The Progress Tracker (§9) is the most important section — it tells you exactly what's been decided, what's built, what's broken, and what's next. Don't assume anything about the project that contradicts what's written here; this file is more current than any general knowledge you have about the topic.

After every major change in the session — a decision made, something built, a bug hit/fixed, a module completed — update §9 (Progress Tracker) with a new dated entry and update §10 (Open Items) to check off/add items, the same way this file has been updated in past sessions. Do this before the session ends, not just when the user explicitly asks.

**Attribution requirement — mandatory:** Every entry added to §9 (Progress Tracker), and every completed-task update made to §2 (Users), must state **which user did the work**, by name (Abinraj, Andikumar, or Karthik — see §2). If the user in the chat doesn't say who did the work, ask before logging it — don't guess or leave it unattributed. This applies regardless of which AI model or chat session is doing the update.

**If you are the student using this file:** After every work session — whether you built something, hit a bug, changed a decision, or just planned something — add a new dated entry to §9 Progress Tracker before you close the chat, and say **who did the work** so it gets attributed correctly. Do this whether you're working with this AI model or a different one. This file only works as a continuity mechanism if it's kept current. When starting a new chat to continue work, paste/upload this whole file as your first message and say "continue this project."

## 1. Project Summary

**Title:** ASCEND-PG — An Automated CyberAttack Simulation and Defense Evaluation Framework for Power Grid Systems with Explainable Reporting

**Academic context:** B.Tech Computer Engineering Major Project, Pillai College of Engineering, University of Mumbai, AY 2025–26. Team of 4 (Abinraj V B Baburajan, Padmapriya Nair, Aaditya Anilkumar, Karthik Jayachandran), supervised by Dr. Mimi Cherian.

**What it does:** A Purple Team security assessment tool for smart power grids. An administrator selects a standard IEEE topology or uploads a validated custom topology; ASCEND-PG renders the electrical grid and its derived ICS/OT communication layer, then runs a controlled attack campaign in an emulated testbed. A GAN varies attack parameters and an RL attacker selects and sequences enabled MITRE ATT&CK for ICS strategies according to defense feedback. Trained LSTM/Autoencoder models evaluate the attacks, and the campaign ends only when the configured strategy space has been explored or a defined performance plateau/stalemate is reached. ASCEND-PG then produces an explainable report: what happened, what was detected or missed, why the attacker changed strategy, and prioritized defense improvements supported by SHAP/LIME evidence.

**Deliverable form:** A local Streamlit web application where a network administrator selects or uploads a topology, configures defenses and campaign limits, views the rendered electrical + ICS topology, starts a controlled adaptive simulation, watches the live Red/Blue sequence, and downloads an explainable final report.

## 2. Users

Three users work on this project. Abinraj is listed first as the primary/lead user.

| # | Name | Machine / Specs | Role in build |
|---|------|------------------|----------------|
| 1 | **Abinraj** | Ryzen 5 + Vega 11 (integrated graphics) | Testbed layer (Modules 1–5): WSL2, Mininet, MiniCPS, real Modbus PLC/SCADA, attack tools, traffic capture, CICFlowMeter — no GPU needed |
| 2 | **Andikumar** | Ryzen 5 5600H + RTX 3050 Laptop (4GB VRAM), 16GB RAM | Training layer (Modules 6–8): GAN, RL agent, LSTM/Autoencoder — WSL2 + CUDA + PyTorch |
| 3 | Karthik | Intel i5 + GTX 1650 | (tasks not yet assigned/logged) |

**Resolved:** The "RTX 3060 machine" referenced throughout earlier sections of this file was a misremembered spec — it is **Andikumar's Ryzen 5 + RTX 3050 (4GB VRAM)** machine, not a 3060 and not a teammate's separate machine. All references below have been corrected. Known constraint: 4GB VRAM is modest for GAN training specifically — architectures are kept lean (small MLP-based tabular GAN, not deep/wide) to stay within budget.

**Completed tasks so far:**
*Abinraj:*
- Session 1 — Initial report review & lightweight architecture (Prototype Build Guide)
- Session 2 — Hardware-tuned hybrid guide (Hybrid Build Guide)
- Session 3 — Web app decision + full Teacher Guide (WebApp Teacher Guide)
- Session 4 — Scoped-down MVP: testbed + attack + detection (MVP Guide), including the `ModuleNotFoundError` fix and the rule_based_attacker vs rule_based_attack_generator naming fix
- Session 5 — Demo rejected, pivot to v2 real-tools architecture (v2 RealTools Guide)
- Session 6 — Project master file created for cross-chat/cross-model continuity
- Session 7 — Two-machine work split confirmed; started testbed setup on Ryzen 5 + Vega 11: WSL2/Ubuntu 22.04 install, base Linux tools install, and the Mininet `pep8`→`pycodestyle` install-script fix (Mininet CLI install still unresolved/blocked as of this session)
- Session 8 — Added §2 (Users) and the mandatory attribution requirement
- Session 9 — Mininet install fully resolved (root cause: missing `python`→`python3` symlink), MiniCPS installed, Module 3 (Mininet topology + real Modbus PLC/SCADA scripts) built, debugged through several pymodbus 3.14.x API breaking changes, and confirmed working end-to-end (5 PLCs + SCADA client polling cleanly)
- Session 13 — Integrated the working mock testbed into the canonical `ascend-pg-webapp/` per §7 (fully distributed, no `mock/` subfolder): testbed PLC/SCADA scripts, real FDI/DoS/recon attack scripts, custom Suricata IDS rules, the cycle runner, and a Streamlit Live Battle view — folded in the verified mock cycle results and retired the temporary "mock submission" master as the source of truth
- Session 14 — Defined and recorded the canonical product workflow: topology selection/custom import → rendered electrical + ICS topology → controlled adaptive MITRE campaign → strategy-space/plateau stop → XAI-backed defense report
- Session 15 — Training-data contract and source hierarchy defined (docs/training_data_spec.md)
- Session 16 — Testbed capture and episode-aware flow labeling pipeline added (scripts/capture_testbed_session.sh, scripts/label_captured_flows.py)
- Session 17 (2026-09-04) — Local venv setup & app activation, stub pages created (2_Run_Simulation.py, 4_Report.py, main.py), real-time live telemetry instrumentation added across attack scripts, WSL2/Ubuntu 24.04 filesystem crash recovery, Mininet/OVS testbed deployment and verification (7-host topology up)

*Andikumar:*
- Session 10 — Machine spec corrected (RTX 3050, not 3060), formally assigned to Modules 6–8 (training track), Module 6 (GAN) architecture planned and code written (`generative/gan.py`, `generative/train_gan.py`)
- Session 11 — Beginner-level setup guide produced (`ASCENDPG_Andikumar_Setup_Guide.md`); native Windows setup decided (no WSL2 needed for pure training work); setup not yet performed, blocked on getting the placeholder dataset from Abinraj

Karthik has no logged tasks yet — add contributions to §9 as they come in, tagged with his name per the attribution requirement above.

## 3. Current Phase / Status (read this first, most important)

We are on: **Version 2 (v2) — Real Tools Rebuild.**

The first working version (rule-based attack injection + statistical detection, on synthetic pandapower/numpy data) was demoed to the panel and rejected for two reasons:
1. The testbed/attack layer wasn't built on a "real tool" (it was synthetic data manipulation, not real network traffic)
2. Detection and attack generation needed to be actually trained AI models, not rule-based fallbacks

We now have access to Andikumar's Ryzen 5 + RTX 3050 (4GB VRAM) machine for real training, and are rebuilding the testbed/attack layer using Mininet + MiniCPS (real ICS network emulation) with real open-source attack tooling: pymodbus FDI, a raw-socket Modbus DoS flood, Scapy replay, and arpspoof MITM, feeding genuinely trained GAN/RL/LSTM/Autoencoder models.

As of the last update to this file: the v2 architecture and full step-by-step build guide has been written (see §8, file `ASCEND-PG_v2_RealTools_Guide.md`). Work is split across two machines: the testbed layer (Modules 1–5) is being built on Abinraj's Ryzen 5 + Vega 11 machine; Andikumar's Ryzen 5 + RTX 3050 machine handles Modules 6–8 (GAN/RL/LSTM/Autoencoder training). Captured/labeled flow data gets transferred to Andikumar's machine when training starts.

**Testbed track (Abinraj) status:** Mininet install fully resolved and MiniCPS installed. **Module 3 is complete and confirmed working** — `mininet_topology.py`, `plc_server.py`, and `scada_client.py` ran a full test with 5 PLC hosts + 1 SCADA client polling simultaneously for 15+ cycles with zero failures — genuine Modbus TCP traffic on an emulated ICS network, directly addressing the panel's original rejection reason. As of Session 13 these files, plus a working **Module 4** (real attacks) and a real IDS detection checkpoint, now physically live in `ascend-pg-webapp/` per §7 (they had been developed/verified in a separate mock-submission folder; that work is now integrated and the mock master retired). **Module 4 is substantially working:** real FDI (`attacks/fdi_attack.py`, T0836), a raw-socket Modbus DoS flood (`attacks/dos_attack.py`, T0814 — replaces the originally-planned hping3, which can't drive an app-layer flood event), and recon (`attacks/recon_step.py`, nmap + Modbus device-ID, T0846/T0888) run end-to-end via `scripts/run_cycle.py`, with **Suricata** (`detection/suricata/modbus_rules.rules`) as the real-IDS detection layer producing per-step DETECTED/NOT-DETECTED verdicts. Verified mock run: recon DETECTED, FDI DETECTED, DoS-quiet NOT DETECTED (under threshold — intended negative control), DoS-loud DETECTED. **Still open on Module 4:** MITM (arpspoof, T0830) and Replay (Scapy, T0832) not yet attempted. Next: Module 5 (CICFlowMeter capture/labeling). **Flagged risk:** Abinraj's machine runs Python 3.14, not the 3.10–3.11 targeted in §6 — has already caused breakage (MiniCPS's Modbus wrapper was Python-2-only/incompatible, worked around by writing PLC/SCADA scripts directly against modern pymodbus instead) and may resurface with CICFlowMeter or other older tooling.

**Training track (Andikumar) status:** Machine spec corrected (RTX 3050, not 3060). Module 6 (GAN) architecture planned and code written, built against a placeholder CIC-IDS-2017 dataset in the `generative/` directory — no file conflicts with Abinraj's `testbed/`/`attacks/` work. A full beginner setup guide has been produced but **setup has not yet been performed** — blocked on getting the placeholder dataset file from Abinraj.

## 4. Key Decisions Made (and why)

| Decision | Reasoning |
|---|---|
| Web app, not website or desktop app | Streamlit = fastest to build with only Python, no separate frontend needed, still runs in a real browser |
| pandapower for electrical modeling | Real, legitimate, widely-used open-source power system library — kept in both v1 and v2, was never the part the panel objected to |
| v1 → rejected: numpy-synthetic network traffic + rule-based attacker/detector | Not a "real tool," models weren't actually trained |
| v2 → current: Mininet + MiniCPS for the testbed | Real, published, open-source Linux network emulator built specifically for ICS/CPS security research — addresses "need a real tool" directly |
| Real attack tooling: pymodbus (FDI), raw-socket Modbus flood (DoS), Scapy (Replay), arpspoof/dsniff (MITM) | Each technique must generate genuine network/protocol traffic in the isolated testbed. The raw Modbus flood replaces the earlier hping3 plan because the testbed detector needs application-layer Modbus traffic. |
| CICFlowMeter for feature extraction | Same tool used to build the CIC-IDS-2017 dataset already cited in our literature review — ties captured data to the same schema |
| GAN + RL + LSTM + Autoencoder must be actually trained and used in the final app, not just designed | This was the second panel objection — non-negotiable from here on |
| Training happens on Andikumar's RTX 3050 machine (via WSL2 + CUDA) | Only team machine with a dedicated GPU; WSL2 lets it run CUDA training. The testbed itself (Mininet/MiniCPS, Modules 1–5) needs no GPU, so it's built separately on Abinraj's Ryzen 5 + Vega 11 machine — captured/labeled data is transferred to Andikumar's machine only when it's time to train (Modules 6–8) |
| MITRE ATT&CK mapping stays a static hardcoded JSON lookup | This was never objected to — static lookup tables are the standard, correct approach here, not a shortcut |
| Rule-based components from v1 are kept as baseline comparisons in the final report, not deleted | "Baseline detector caught X%, trained detector caught Y%" is a stronger result than showing only one number |
| DoS is a raw-socket Modbus flood script (`attacks/dos_attack.py`), not hping3 (Session 13) | Suricata's `modbus.flooded` event needs unreplied *application-layer* Modbus requests; hping3 floods at the packet layer and never speaks Modbus, so it can't trigger the app-layer detector. A hand-built MBAP/PDU frame fired fire-and-forget does. §7's "DoS = hping3 CLI" note is superseded. |
| Suricata (custom Modbus rules) is the testbed's detection checkpoint (Session 13) | Gives a *real IDS* ground truth for recon/FDI/DoS now, ahead of the trained LSTM/Autoencoder detectors (which remain the final deliverable). Not a replacement for them — a verifiable milestone. Added to §6 (was not previously in the stack). |
| Topology input is preset selection plus validated custom import, not a free-form grid editor (Session 14) | Real grids have operator-specific, evolving electrical and communication topologies. IEEE benchmark cases give reproducible experiments; a schema-validated import gives configurability. A free-form editor would need electrical validity/power-flow enforcement and is out of scope. |
| The adaptive campaign has explicit terminal conditions (Session 14) | Stop when all enabled MITRE strategies/parameter ranges have been attempted, or when a defined consecutive-episode plateau shows no material attacker-utility improvement. This prevents an uncontrolled or arbitrary endless simulation and makes the final report reproducible. |

## 5. Architecture Overview — Canonical Product Flow

1. **Topology and defense configuration** → The administrator chooses a reproducible IEEE benchmark (IEEE-14 default, IEEE-30 scale test) or uploads a schema-validated custom grid description. They choose enabled defenses, enabled MITRE techniques, episode budget, detection thresholds, and plateau settings.
2. **Topology rendering and testbed mapping** → pandapower validates/solves the electrical case. ASCEND-PG renders buses, lines, generators, and loads, then deterministically maps each selected bus/substation to ICS assets (PMU + RTU/PLC) and connects them to the SCADA, HMI, historian, firewall, and Mininet communication topology. Electrical and ICS layers are displayed together but remain distinct models.
3. **Controlled attack campaign** → The Mininet + real Modbus testbed runs normal SCADA traffic first. The attacker operates only against this isolated local testbed. The MITRE catalog provides permitted strategies: reconnaissance (T0846/T0888), FDI (T0836), DoS (T0814), Replay (T0832), and MITM (T0830) as each implementation becomes available.
4. **Generative + strategic adaptation** → The GAN proposes bounded, realistic parameter variations for the chosen technique (for example target PLC/register, FDI value or duration, and DoS rate). The PPO RL policy observes prior attack parameters, detector confidence/verdicts, IDS evidence, and campaign history; it selects the next enabled technique/parameter set to maximize a documented reward balancing evasion, impact, cost, and repetition penalty. Every state summary, action, reward, seed, and parameter mutation is logged.
5. **Detection and defense feedback** → Suricata remains the real-IDS testbed checkpoint. Trained LSTM and Autoencoder models score captured traffic/telemetry; fusion produces the application detection confidence and verdict. The feedback becomes the next RL observation, while the IDS and model results are retained separately for honest comparison.
6. **Terminal condition** → The campaign stops when either (a) every enabled technique/parameter range has been attempted within the configured budget, or (b) a stalemate/plateau is reached: attacker utility fails to improve by the configured minimum across a fixed number of consecutive episodes. It can also stop at the explicit safety episode/time limit. No attack is run outside the isolated testbed.
7. **Metrics, XAI, and report** → DVS summarizes coverage, false-negative performance, and awareness. SHAP/LIME explain trained-detector decisions and identify influential flow/telemetry features. The report combines those explanations with the recorded GAN/RL decision trace to explain why the attacker changed strategy, what defenses succeeded or failed, mapped MITRE techniques, and prioritized, situation-specific defense recommendations.

**Layer ownership:** Testbed/attack capture (Abinraj); GAN/RL/LSTM/Autoencoder training (Andikumar); major Streamlit UX integration (Karthik); final cross-layer wiring is a shared Module 9 task.

## 6. Tools & Libraries (full current stack)

- **Network testbed:** Mininet, MiniCPS, Open vSwitch, WSL2 (Ubuntu 22.04)
- **ICS protocols:** pymodbus (Modbus TCP — real PLC/SCADA simulation)
- **Recon tools:** nmap (port-502 sweep, T0846), pymodbus Read Device Identification (T0888)
- **Attack tools:** pymodbus (FDI via register writes, T0836); raw-socket Modbus flood script (DoS, T0814 — supersedes hping3 for app-layer detection, see §9 Session 13); Scapy (packet replay, T0832 — planned); arpspoof/dsniff (MITM, T0830 — planned)
- **Intrusion detection (testbed checkpoint):** Suricata with custom Modbus rules (`detection/suricata/modbus_rules.rules`) — real IDS ground truth ahead of the trained LSTM/Autoencoder detectors
- **Traffic capture:** tcpdump, Wireshark/tshark
- **Feature extraction:** CICFlowMeter (Java, converts pcap → ML-ready flow CSV)
- **ML/AI:** PyTorch (CUDA build for RTX 3050, 4GB VRAM — lean/small architectures), scikit-learn, gymnasium, stable-baselines3 (PPO/DQN), SHAP, LIME
- **Power system modeling:** pandapower (IEEE-14 bus)
- **Web app:** Streamlit, Plotly, pyvis (network diagram visualization)
- **Reporting:** Jinja2, WeasyPrint (PDF generation)
- **Dataset:** ASCEND-PG self-captured labeled Modbus flows + telemetry (required final evaluation); CICModbusDataset2023 public PCAP + timestamped attack logs (primary Modbus/ICS supplement); WUSTL-IIoT-2021 (optional generic SCADA/IIoT flow pretraining); CIC-IDS-2017 only as a legacy/general baseline. Full schema, split, and handoff rules: `docs/training_data_spec.md`.
- **Dev tooling:** VS Code (+ Python & Jupyter extensions), Git/GitHub, Python 3.10–3.11, venv

## 7. Directory Structure (target — matches the v2 guide)

```
ascend-pg-webapp/
├── venv/
├── app/
│   ├── Home.py                     # Streamlit entry point + topology diagram
│   └── pages/                      # (Phase: split Home.py into multipage flow)
│       ├── 1_Configure_Network.py   # preset/custom topology, defenses, enabled MITRE catalog, episode/plateau limits
│       ├── 2_Run_Simulation.py      # validates config and starts the isolated adaptive campaign
│       ├── 3_Live_Battle.py         # rendered electrical + ICS topology, live Red/Blue event trace (Karthik to expand)
│       └── 4_Report.py              # DVS, detection/XAI evidence, GAN/RL decision trace, recommendations
├── testbed/
│   ├── grid_env.py                 # pandapower baseline
│   ├── network_topology.py         # maps buses → ICS/OT device graph
│   ├── visualize_topology.py       # pyvis diagram renderer
│   ├── mininet_topology.py         # Mininet network definition (v2)
│   ├── plc_server.py               # real Modbus PLC server (v2)
│   └── scada_client.py             # real Modbus SCADA poller (v2)
├── attacks/
│   ├── fdi_attack.py               # real Modbus write injection — T0836 (v2, working)
│   ├── dos_attack.py               # raw-socket Modbus flood — T0814 (v2, working; supersedes hping3, see §9 S13)
│   ├── recon_step.py               # nmap sweep + Modbus device-ID query — T0846/T0888 (v2, working)
│   └── replay_attack.py            # real Scapy packet replay — T0832 (planned)
│   # MITM = arpspoof CLI command (T0830, no script; Suricata can't alert on ARP — see detection/suricata/)
├── generative/
│   ├── rule_based_attack_generator.py  # v1 baseline (kept for comparison)
│   ├── gan.py
│   └── train_gan.py                # trains on real captured + CIC-IDS2017 data
├── strategic/
│   ├── rule_based_attacker.py      # v1 baseline (kept for comparison)
│   ├── rl_env.py                   # wraps real attack scripts + real detector feedback
│   └── train_rl.py
├── standardization/
│   └── mitre_mapper.py              # static MITRE catalog + strategy metadata/constraints
├── detection/
│   ├── rule_based_detector.py      # v1 baseline (kept for comparison)
│   ├── lstm_detector.py
│   ├── autoencoder_detector.py
│   ├── fusion.py
│   └── suricata/
│       └── modbus_rules.rules      # custom Suricata rules — testbed IDS checkpoint (v2, working)
├── metrics/
│   └── dvs.py
├── xai/
│   ├── shap_explain.py
│   ├── lime_explain.py
│   └── recommendation_templates.py
├── models/                          # saved trained weights (.pt files)
├── data/
│   ├── mitre_ics_map.json
│   ├── sample_topologies/
│   │   └── *.json                   # IEEE presets and validated custom-topology schema examples
│   ├── cic_ids2017_subset.csv
│   ├── captured_flows/              # real pcap-derived, labeled flow data (v2)
│   ├── log_store.json               # runtime: live attacker/SCADA events (written by run_cycle.py)
│   ├── cycle_report.json            # runtime: per-step DETECTED/NOT-DETECTED verdicts
│   └── campaign_trace.json          # runtime: RL state/action/reward + GAN parameter/seed trace for report
├── scripts/
│   ├── prepare_dataset.py           # Kaggle download + stratified sampling
│   ├── capture_testbed_session.sh   # bounded OVS-monitor PCAP + Suricata evidence capture (v2)
│   ├── label_captured_flows.py      # joins CICFlowMeter rows to campaign step windows (v2)
│   ├── run_cycle.py                 # v2: orchestrates recon→fdi→dos, correlates Suricata verdicts
│   └── setup_mirror.sh              # v2: OVS SPAN/mirror port for Suricata
├── docs/
│   ├── suricata_setup.md            # v2: Suricata + OVS mirror install/config
│   └── testbed_runbook.md           # v2: end-to-end run steps for the attack/detection cycle
├── requirements.txt
└── main.py
```

## 8. Reference Documents (the detailed how-to guides — this file is the index, not a replacement)

| File | Status | Covers |
|---|---|---|
| `ASCENDPG_Prototype_Build_Guide.md` | 🟡 Superseded (testbed/attack layer only) | Original lightweight architecture: pandapower, small GAN/RL/LSTM, no Docker. Still valid for the concept of each layer; testbed/attack implementation replaced by v2. |
| `ASCENDPG_Hybrid_Build_Guide.md` | 🟡 Superseded (was for a different hardware split) | Dataset/model sizing for 16GB-no-GPU + i5/GTX1060 split. Device-aware CUDA code pattern from here is directly reused in v2. |
| `ASCENDPG_WebApp_Teacher_Guide.md` | 🟢 Active | Full Streamlit app structure: config screen, multi-page flow, recommendation templates, XAI wiring, deployment. Still the reference for the app layer — just needs real model calls wired in per v2 §10. |
| `ASCEND-PG_MVP_Guide.md` | 🟡 Superseded (was the rejected demo) + 🟢 partially active | Testbed+attack+detection MVP with rule-based components. The rejected version. The visual network topology diagram (pyvis) concept from this file is still active — v2 reuses it, just needs to show real Mininet host IPs instead of synthetic bus IDs. |
| `ASCENDPG_v2_RealTools_Guide.md` | 🟢 Active — current build target | Mininet+MiniCPS testbed, real attack tools, CICFlowMeter, real GAN/RL/LSTM training on RTX 3060. This is what the team is currently building. |
| `ASCENDPG_PROJECT_MASTER.md` (this file) | 🟢 Active | Master index + progress tracker. Always the first thing to read/share when resuming. |

## 9. Progress Tracker

Format for new entries: `### [YYYY-MM-DD or session #] — Short title`, followed by bullet points of what happened. **Always state who did the work (Abinraj, Andikumar, or Karthik).** Always append to the bottom of this section (chronological order), never delete old entries — this is the project history.

### Session 1 — Initial report review & lightweight architecture — *Abinraj*
- Reviewed the uploaded Major Project-A report (ASCEND-PG concept, literature survey, proposed methodology)
- Scoped down the report's Docker/Kafka/OpenSearch research-stack architecture to a laptop-buildable version: pandapower for the testbed, small GAN/RL/LSTM
- Produced `ASCEND-PG_Prototype_Build_Guide.md` with full system requirements and step-by-step instructions
- Added detailed CIC-IDS-2017 dataset download + stratified sampling instructions (Kaggle API, `scripts/prepare_dataset.py`)

### Session 2 — Hardware-tuned hybrid guide — *Abinraj*
- User has 16GB RAM, no dedicated GPU; teammate has i5 + RTX 1060
- Produced `ASCEND-PG_Hybrid_Build_Guide.md`: same architecture, larger dataset/model sizes, device-aware CUDA code pattern so the same script runs on both machines
- Established work split: no-GPU machine does testbed/metrics/dashboard, GPU machine does GAN/LSTM training

### Session 3 — Web app decision + full Teacher Guide — *Abinraj*
- Decided: Streamlit web app (not website, not desktop app) — reasoning documented in §4
- Defined the actual product flow: admin configures network + defense → runs simulation → live Red/Blue battle view → explainable report — this maps directly onto the existing RL feedback loop
- Produced `ASCEND-PG_WebApp_Teacher_Guide.md`: full install instructions, repo structure, config screen, rule-based fallbacks for GAN/RL/LSTM (explicitly scoped as demo-safety-net only, not primary deliverable), recommendation-template XAI reporting, Streamlit multi-page wiring, deployment steps
- User clarified: real trained models are the actual deliverable, hardcoded versions are fallback only — this was added explicitly to the guide

### Session 4 — Scoped-down MVP (testbed + attack + detection only) — *Abinraj*
- User needed to demo just testbed → attack simulation → detection first, full system later
- Produced `ASCEND-PG_MVP_Guide.md` using legitimate baseline algorithms (rule-based semantic attack injection, Z-score statistical detection) as Phase 1, explicitly positioned as a future baseline comparison, not a throwaway stub
- Fixed a `ModuleNotFoundError: No module named 'testbed'` bug — root cause was `sys.path.append(os.path.abspath(".."))` being relative to cwd, not the script location; fixed to use `os.path.dirname(__file__)`
- Corrected a naming/placement confusion: `strategic/rule_based_attacker.py` (adaptive attack selector, Phase 2) vs `generative/rule_based_attack_generator.py` (attack data generator, built in MVP) are two different files with two different jobs
- Added a real visual network diagram (pyvis) mapping IEEE-14 buses to actual ICS/OT device types (Substation, PMU, RTU, SCADA Server, Historian, HMI, Firewall) with live red/green compromised/detected highlighting tied to the attack/detection buttons

### Session 5 — Demo rejected, pivot to v2 (real tools + real training) — *Abinraj*
- Panel rejected the demo: needed a "real tool" (open source) for the testbed, and genuinely trained models for attack/detection, not rule-based
- Gained access to a teammate's Ryzen 5 + RTX 3060 machine for real training
- Decided: Mininet + MiniCPS (Linux/WSL2) for the testbed, over Docker — more realistic network emulation, matches published ICS security research tooling
- Confirmed RTX 3060 machine is on Windows → recommended WSL2 Ubuntu as the single environment for both the testbed and CUDA training (GPU passthrough works in WSL2)
- Produced `ASCEND-PG_v2_RealTools_Guide.md`: WSL2/CUDA driver setup, Mininet+MiniCPS install (with a flagged WSL2/OVS compatibility risk and VirtualBox fallback), real Modbus PLC/SCADA scripts, real attack scripts (pymodbus FDI, hping3 DoS, Scapy replay, arpspoof MITM), tcpdump+CICFlowMeter capture/labeling pipeline, GAN/RL/LSTM training code targeting the RTX 3060, and an explicit "what to tell the panel this time" section
- Status at end of this session: guide written, execution not yet started.

### Session 6 — This master file created — *Abinraj*
- Created `ASCEND-PG_PROJECT_MASTER.md` (this file) to solve cross-chat/cross-model continuity — consolidates all decisions, current status, tool stack, directory structure, and a chronological progress log
- Going forward, this file must be updated after every work session (see instructions at top)

### Session 7 — Two-machine work split confirmed, starting testbed setup — *Abinraj*
- Realized Modules 1–5 (WSL2, Mininet, MiniCPS, real Modbus PLC/SCADA scripts, attack tools, traffic capture, CICFlowMeter) need no GPU at all
- Decision: build the entire testbed layer on the user's own Ryzen 5 + Vega 11 (integrated graphics) machine; reserve the RTX 3060 machine purely for Modules 6–8 (GAN/RL/LSTM/Autoencoder training)
- Captured/labeled flow data will be transferred to the RTX 3060 machine only when training starts
- Starting Module 2 (WSL2 + tool installation) on the Ryzen 5 + Vega 11 machine now — no NVIDIA driver step needed on this machine, skip §3.2 of the v2 guide, and skip installing the CUDA build of PyTorch here since no training happens on this machine
- Completed Module 2.1 (BIOS SVM/virtualization enabled), 2.2 (WSL2 + Ubuntu 22.04 installed), 2.3 (base Linux tools installed: python3, git, wireshark/tshark/tcpdump, openvswitch-switch, hping3, dsniff, etc. — all verified working)
- Module 2.4 (Mininet install) hit a real bug: Mininet's `util/install.sh` referenced the package `pep8`, which no longer exists in current Ubuntu repos (renamed to `pycodestyle` some time after the script was written). Fixed by editing line 177 of `util/install.sh` from `pep8=pep8` to `pep8=pycodestyle` (first attempt used a global sed find-and-replace which broke the line entirely — corrected with a line-targeted `sed -i '177s/.*/pep8=pycodestyle/'` instead)
- After the fix, `sudo util/install.sh -a` completed in ~30 seconds (suspiciously fast for a full build) and `sudo mn --test pingall` returned `mn: command not found` — meaning Mininet's actual CLI never got installed, likely because the install script exited early/skipped steps rather than genuinely completing. Not yet resolved — next step is re-running with full output captured to a log file to see exactly what happened, rather than trusting the fast exit.
- Open note for whoever continues this: if you hit the same `pep8` package error on a fresh install attempt elsewhere, the fix above applies directly — don't use a global sed replace, target the specific line number.

### Session 8 — Users section added — *Abinraj*
- Added §2 (Users) listing all three team members, their machine specs, and confirmed that all work completed to date (Sessions 1–7) was done by Abinraj
- Added a mandatory attribution requirement to the top instructions: every future Progress Tracker entry and completed-task update must name which user (Abinraj, Andikumar, or Karthik) did the work

### Session 9 — Mininet install fixed, MiniCPS installed, Module 3 (topology + PLC/SCADA scripts) built and debugged — *Abinraj*
- **Module 2.4 (Mininet install) resolved.** Root cause: Ubuntu 22.04 has no `python` binary by default (only `python3`), which caused the original `util/install.sh -a` run to silently no-op several python-dependent steps — explaining both the suspiciously fast ~30s completion and the later `mn: command not found` error. Fix chain: (1) installed `python-is-python3` for the `python` symlink, (2) manually ran `sudo python setup.py install` in `~/mininet` since the `mininet` package itself never got installed by the original script run, (3) compiled and installed the missing `mnexec` helper binary via `make mnexec` + copied to `/usr/local/bin`. Verified with `sudo mn --test pingall`: 0% dropped (2/2 received).
- **Module 2.5 (MiniCPS install) completed.** The `minicps` repo uses `pyproject.toml`, not `setup.py` — installed via `sudo python -m pip install . --break-system-packages` (also needed `--break-system-packages` on the plain `pip3 install -r requirements.txt` step, since Ubuntu 22.04+ blocks system-wide pip installs by default per PEP 668). Verified via `python3 -c "import minicps"`. Bundled example scenarios available in the repo: `toy`, `swat-s1` (published SWaT testbed — worth citing as prior art), `s3-2017`.
- **Important environment finding:** this machine is running **Python 3.14**, not the 3.10–3.11 targeted in §6. Flagged as an ongoing version-mismatch risk — has already caused real breakage (see below) and will likely resurface with CICFlowMeter or other older tooling.
- **Key architecture decision:** inspected MiniCPS's bundled example PLC scripts (`examples/toy/plc1.py`) and found they subclass `minicps.devices.PLC`, which for Modbus (`minicps/pymodbus/servers.py`) is Python-2-only code targeting a pymodbus API (`pymodbus.server.async`) that no longer exists in pymodbus 3.x. Decided to **skip MiniCPS's Modbus wrapper entirely** and write `plc_server.py`/`scada_client.py` directly against raw modern pymodbus (3.14.x) instead of `minicps.devices.PLC`. Kept `mininet.topo.Topo` for the network topology only (`mininet_topology.py`), independent of MiniCPS's device layer.
- Built three testbed files (Module 3): `mininet_topology.py` (5 PLC/RTU hosts + 1 SCADA + 1 attacker on a flat `/24`, matches §5 architecture), `plc_server.py` (Modbus TCP server), `scada_client.py` (Modbus TCP polling client).
- Debugged pymodbus 3.14.x API drift while getting these running — several breaking changes from what most tutorials/docs show for older 3.x versions: `slave=` kwarg renamed to `device_id=`, `ModbusSlaveContext` renamed to `ModbusDeviceContext`, `ModbusServerContext(slaves=...)` renamed to `ModbusServerContext(devices=...)`, and `ModbusDeviceIdentification` moved from `pymodbus.device` to the top-level `pymodbus` package.
- Also hit and fixed two environment issues unrelated to pymodbus: (1) `Controller.checkListening()` in Mininet shells out to `telnet`, which isn't installed by default — fixed with `sudo apt install telnet`; (2) `OVSController` looks for a binary named `ovs-controller`, but current OVS packages ship it as `ovs-testcontroller` — fixed by installing `openvswitch-testcontroller` and symlinking it to `/usr/local/bin/ovs-controller`.
- Also hit and fixed one more pymodbus 3.14.x API surprise beyond the import path: `ModbusSequentialDataBlock`'s internal validation now shifts the starting address down by 1 before checking it's in range, so passing `0` as the starting address (the value every online example uses) throws `TypeError: 0 <= address < 65535`. Fixed by starting the datastore at address `1` instead of `0`.
- **Status at end of session: Module 3 fully confirmed working.** Started all 5 PLC servers (`10.0.0.1`–`10.0.0.5`) plus the SCADA client polling all five simultaneously — ran cleanly for 15+ poll cycles with zero connection failures or dropped hosts. This is genuine Modbus TCP traffic across a 7-host emulated ICS network (5 PLC + 1 SCADA + 1 attacker, attacker not yet used) — real protocol traffic, not simulated/rule-based, directly addressing the panel's original rejection reason.

### Session 10 — Machine spec corrected, Andikumar assigned to training track, Module 6 started — *Andikumar*
- Confirmed the "RTX 3060 machine" referenced since Session 5 was a misremembered spec — it is Andikumar's own Ryzen 5 5600H + RTX 3050 Laptop GPU (4GB VRAM), 16GB RAM. Corrected all references in §2, §3, §4, §6.
- Andikumar formally assigned to Modules 6–8 (GAN, RL agent, LSTM/Autoencoder training) — §2 updated. Karthik's role still unassigned.
- Flagged known constraint: 4GB VRAM is modest for GAN training — keeping architectures lean (small MLP-based tabular GAN, not conv/deep) rather than assuming RTX 3060-class headroom.
- Planned architecture for all three training modules before touching the testbed's real data (which isn't ready yet):
  - **Module 6 (GAN):** MLP-based tabular GAN (not DCGAN-style) since flow features are tabular, not image data — generator/discriminator are 2–3 dense layers, batch size 64–128, mixed precision to fit 4GB VRAM, WGAN-GP as fallback if standard GAN loss is unstable.
  - **Module 7 (RL agent):** stable-baselines3 PPO with default small MLP policy — deliberately lightweight, GPU is not the bottleneck here; environment design (`rl_env.py` step/reward wiring to real attack scripts + detector feedback) is the actual work, buildable/testable now against a mock stub environment.
  - **Module 8 (LSTM + Autoencoder):** small LSTM (64–128 hidden units) + small bottleneck autoencoder (trained on normal traffic only), fused via a simple weighted/logistic layer.
- Started implementing Module 6 (`generative/gan.py`, `generative/train_gan.py`) using `data/cic_ids2017_subset.csv` as a placeholder data source, matching the schema expected from Abinraj's eventual captured/labeled flow output — code will only need repointing to real data later, not rewriting.
- **Conflict-avoidance note:** Andikumar's work stays entirely inside `generative/`, `strategic/`, `detection/`, and `models/` (per §7 directory structure) — no overlap with Abinraj's `testbed/` and `attacks/` files. No merge conflicts expected between the two tracks until Module 9 (final wiring), which happens after both tracks are independently done.

### Session 11 — Beginner setup guide created for Andikumar's machine — *Andikumar*
- Andikumar requested a from-scratch, beginner-level setup walkthrough (fresh laptop → running Module 6) since this is his first time doing this kind of project — treat all steps as unverified/not yet run by him.
- **Decision:** Andikumar's machine will be set up **natively on Windows**, not WSL2. Reasoning: WSL2 was only ever needed because the original v2 guide assumed training and testbed (Mininet/MiniCPS) shared one machine. Now that the testbed track lives on Abinraj's machine and Andikumar's machine does pure PyTorch training only, WSL2 adds unnecessary setup complexity with no benefit. Revisit only if this changes.
- Produced `ASCENDPG_Andikumar_Setup_Guide.md` (delivered to Andikumar, not yet in this repo bundle) covering: Python 3.11 + PATH setup, VS Code + Python/Jupyter extensions, Git, NVIDIA driver check (`nvidia-smi`), venv creation, PyTorch CUDA-build install (matched to detected CUDA version) with a GPU-detection verification command, supporting package installs (`pandas`, `numpy`, `scikit-learn`, `gymnasium`, `stable-baselines3`, `shap`, `lime`), and the folder structure below.
- **Folder structure confirmed for Andikumar's machine** (subset of full §7 structure — only what his track needs):
  ```
  ascend-pg-webapp/
  ├── generative/       (Module 6 — gan.py, train_gan.py placed here)
  ├── strategic/        (Module 7 — not yet started)
  ├── detection/         (Module 8 — not yet started)
  ├── data/             (placeholder cic_ids2017_subset.csv goes here)
  └── models/           (trained weights save here — gan_generator.pt, gan_discriminator.pt)
  ```
  `testbed/`, `attacks/`, `app/` intentionally excluded — those are Abinraj's track, kept out of Andikumar's local folder to avoid confusion/conflicts.
- **Status as of this session: setup not yet performed.** Andikumar has the guide and the Module 6 code (`gan.py`, `train_gan.py` from Session 10) but has not yet run through Steps 1–12 (Python/VS Code/Git/CUDA install, venv, package install, placeholder dataset, first training run). Nothing to report from an actual run yet — next update to this file should come once he confirms `train_gan.py` ran successfully (or reports an error to debug).
- **Blocked on:** Step 11 in the guide (getting `data/cic_ids2017_subset.csv`) — Andikumar needs to get this file from whoever ran `scripts/prepare_dataset.py` in an earlier session (likely Abinraj), or generate it fresh via Kaggle (steps not yet given, since teammate hand-off is faster).

### Session 12 — Abinraj's and Andikumar's independently-updated master files merged into one — *Andikumar*
- Abinraj had continued working in a separate chat session in parallel, producing his own updated copy of this file (through his Session 9 — Module 3 testbed work). Andikumar's copy had independently progressed through what was locally labeled "Session 9" and "Session 10" (GAN start + setup guide). Both branches shared an identical Session 1–8 history.
- Merged the two by chronological renumbering: Abinraj's testbed Session 9 kept as Session 9; Andikumar's GAN-start and setup-guide entries shifted to Session 10 and Session 11 to remove the numbering collision (no content changed, only the numbers/cross-references).
- §2 (Users) completed-tasks list updated to include Abinraj's Sessions 8–9 and Andikumar's Sessions 10–11 together.
- §3 (Current Phase) rewritten to summarize both tracks' live status side by side: testbed (Module 3 done, Module 4 next, Python 3.14 version-mismatch risk flagged) and training (setup guide produced, not yet run, blocked on dataset hand-off).
- §10 (Open Items) testbed section updated to match Abinraj's resolved Mininet/MiniCPS status and his actual next step (Module 4 — manual attack tool testing), replacing the stale "BLOCKED" language from the pre-merge version.
- **Going forward:** since work is now confirmed happening in parallel chats, whoever updates this file next should check the other person's most recent copy before assuming this one is current, to avoid this same collision happening again.

### Session 13 — Mock testbed integrated into the main webapp — *Abinraj*
- **Context:** the real testbed/attack/detection/visualization code had been built and verified in a separate temporary "mock submission" folder. Integrated it into the canonical `ascend-pg-webapp/` per §7 so the repo matches reality. The temporary "Ascend pg mock submission master file" is **retired as a source of truth** — its useful progress is folded into this entry + `docs/`; this master file remains the absolute authority.
- **Layout — fully distributed into §7 (no `mock/` subfolder).** File mapping:
  - `testbed/` ← `mininet_topology.py`, `plc_server.py`, `scada_client.py`
  - `attacks/` ← `fdi_attack.py` (was `modbus_fdi_attack.py`), `dos_attack.py` (was `modbus_dos_attack.py`), `recon_step.py`
  - `detection/suricata/` ← `modbus_rules.rules`
  - `scripts/` ← `run_cycle.py`, `setup_mirror.sh`
  - `docs/` ← `suricata_setup.md` + new `testbed_runbook.md`
  - `app/pages/3_Live_Battle.py` ← the mock's Streamlit live view (previously an empty stub)
- **Path rewiring for the distributed layout:** `run_cycle.py` now resolves step scripts + the shared log/report via `Path(__file__)` anchors (`attacks/*.py`, `data/log_store.json`, `data/cycle_report.json`) instead of bare filenames in a flat cwd, and launches steps with `sys.executable` so they inherit the same pymodbus-equipped interpreter. `recon_step.py`/`dos_attack.py`/`scada_client.py` default their `--log` to `<repo>/data/log_store.json`; the Live Battle page reads the two `data/` JSONs. All paths are `__file__`-anchored, so cwd no longer matters.
- **Reconciliations recorded against this master:** DoS is a raw-socket Modbus flood script, **not hping3** (§4/§6/§7 updated — hping3 floods at the packet layer and can't trigger Suricata's app-layer `modbus.flooded`); recon (`recon_step.py`, nmap + Modbus device-ID) added to the chain (§6/§7); **Suricata** added to the stack as the testbed detection checkpoint (§6 — was not previously listed); the MITM Suricata rule was dropped (Suricata can't alert on ARP) and Replay not attempted.
- **Live view decision:** used the mock's Streamlit view as `app/pages/3_Live_Battle.py` (best fit for the Streamlit deliverable + the empty page stub) as a small live window; **Karthik owns the major Live Battle UI**. The standalone `build_diagram.py`/`diagram.html` viewer was intentionally *not* brought in — redundant with the Streamlit page ("no unnecessary parts").
- **requirements.txt:** added `pymodbus==3.14.*`.
- **Verified mock cycle results (2026-08-12) folded in:** recon → DETECTED (sid 9000004), FDI → DETECTED (sid 9000001), DoS-quiet → NOT DETECTED (under Suricata's ~500-request flood threshold — intended negative control), DoS-loud → DETECTED (sid 9000002, via the flow-timeout re-scan in `run_cycle.py`). Full reproduction steps in `docs/testbed_runbook.md`.
- **Excluded as unnecessary:** stale runtime JSON artifacts (regenerated at run time), `__pycache__/`, a demo-only `add_test_traffic.py`, the mock's unrelated `.claude/settings.local.json`, and the temporary mock docs (`README_MOCK.md`, `DAY1_CHECKLIST.md`, `ASCENDPG_MOCK_SUBMISSION_MASTER.md` — content folded here / into the runbook). All 8 integrated Python files byte-compile cleanly (`py_compile`).
- **Not yet re-run in the new locations:** integration is on-disk in the Windows webapp copy; the scripts still need a re-verify run on the WSL2 testbed to confirm end-to-end from their new §7 paths.

### Session 14 — Canonical adaptive campaign workflow defined — *Abinraj*
- Recorded the definitive product flow in §1, §4, §5, §7, and §10: administrator selects IEEE benchmark topology or uploads a validated custom topology → ASCEND-PG renders electrical and derived ICS/OT topology → isolated Mininet campaign starts → GAN varies bounded technique parameters and PPO selects the next enabled MITRE ATT&CK for ICS strategy from defense feedback → trained detectors feed the next decision → campaign ends on strategy-space exhaustion, configured budget/safety limit, or an explicit performance plateau/stalemate → XAI-backed report is generated.
- Clarified the two topology layers: electrical topology (buses, lines, generators, loads) is distinct from the derived communication/ICS topology (PMU, RTU/PLC, SCADA, HMI, historian, firewall, and Mininet links). Benchmark IEEE topologies provide reproducibility; custom uploads must be schema-validated rather than drawn free-form.
- Defined report evidence requirements: per-episode MITRE technique, target, GAN parameters/seed, RL state summary/action/reward, Suricata and trained-detector verdicts, DVS, SHAP/LIME feature evidence, and ranked defenses. "Why did the AI change attack structure?" must be answered from the stored decision trace, not an invented natural-language explanation.
- Confirmed quality rule: GAN, PPO RL, LSTM, and Autoencoder are final deliverables and must be genuinely trained and invoked; v1 rule-based components remain comparison baselines only. No external framework replacement or reduced-scope fallback was approved.

### Session 15 — Training-data contract and source hierarchy defined — *Abinraj*
- Audited the canonical webapp copy before training: `data/episode_log.csv` is empty and no real captured-flow dataset is present; `generative/gan.py`, `generative/train_gan.py`, `strategic/rl_env.py`, `strategic/train_rl.py`, `detection/lstm_detector.py`, `detection/autoencoder_detector.py`, and `detection/fusion.py` are currently empty. Therefore no model may be claimed as trained yet.
- Added `ascend-pg-webapp/docs/training_data_spec.md`, defining raw artefacts, canonical processed flow/telemetry tables, mandatory provenance and episode labels, model-specific inputs, episode-level split/no-leakage rules, reproducibility artefacts, and the exact handoff package for Andikumar.
- Data-source hierarchy decided: ASCEND-PG's own isolated Mininet/Modbus PCAP + SCADA/PLC telemetry is required for final held-out evaluation; CICModbusDataset2023 is the primary public Modbus/ICS development/pretraining supplement; WUSTL-IIoT-2021 is optional generic SCADA/IIoT flow pretraining; CIC-IDS-2017 is not a substitute for Modbus evidence. PPO RL is recorded as online environment training, not CSV-only supervised training.

### Session 16 — Testbed capture and episode-aware flow labeling pipeline added — *Abinraj*
- Added `scripts/capture_testbed_session.sh`: a bounded, host-shell WSL capture utility that writes a monitor-interface PCAP, UTC session metadata, and Suricata `eve.json` snapshot without launching or altering attacks. It is run separately before the normal/campaign traffic, keeping collection evidence separate from attack execution.
- Added `scripts/label_captured_flows.py`: reads a CICFlowMeter CSV and the real `data/cycle_report.json`, assigns Normal/Recon/FDI/DoS labels from exact UTC step windows, adds source/scenario/episode/topology/MITRE provenance, and writes a per-session manifest with per-step assigned-flow counts. It deliberately fails on unparseable timestamps and warns on zero-row steps rather than silently producing unreliable labels.
- Updated `docs/testbed_runbook.md` with the capture command and post-CICFlowMeter labeling command. This is the first executable step toward the schema-compliant handoff required by Session 15; no capture has been run from this environment yet.

### Session 17 (2026-09-04) — WebApp launch, live attack telemetry instrumentation, and WSL2 testbed deployment — *Abinraj*
- **Windows WebApp Activation & Stubs Completed:**
  - Initialized Windows virtual environment (`venv/`) and installed full dependencies (`streamlit`, `pandapower`, `scikit-learn`, `gymnasium`, `stable-baselines3`, `shap`, `lime`, `matplotlib`, `plotly`, `jinja2`, `pyvis`, `pymodbus==3.14.*`).
  - Added missing `pyvis` dependency to `requirements.txt`.
  - Created `main.py` entrypoint and built functional stubs for `app/pages/2_Run_Simulation.py` (configuration summary, MITRE technique display, defense parameters) and `app/pages/4_Report.py` (reads real `cycle_report.json` or shows structured placeholders), eliminating navigation crashes. Verified Streamlit app running cleanly at `http://localhost:8501`.
- **Live Attack Telemetry Instrumentation:**
  - Identified that prior attack scripts only logged start/end markers to `data/log_store.json`, preventing live in-flight progress on `app/pages/3_Live_Battle.py`.
  - Upgraded attack scripts with granular real-time telemetry streaming:
    - `attacks/fdi_attack.py`: Added full `log_event()` instrumentation for each individual register write in single and sustained injection modes, plus error/done events.
    - `attacks/dos_attack.py`: Added `PROGRESS_INTERVAL = 50` so during the flood loop a `dos_progress` event is emitted every 50 packets.
    - `attacks/dos_conn_exhaust.py`: Added `CONNECT_PROGRESS_INTERVAL = 10` progress events and `HOLD_HEARTBEAT_SEC = 5` heartbeat events during connection hold.
    - `attacks/replay_attack.py`: Added per-frame live logging (`replay_frame`) during replay loops.
- **WSL2 Testbed Troubleshooting & Deployment:**
  - Encountered WSL2 ext4 filesystem read-only crash (`E_FAIL` error code 6, dpkg lock failures). Recovered via Windows host reboot and WSL instance restart.
  - Resolved Ubuntu 24.04 PEP 668 `externally-managed-environment` restriction by installing runtime dependencies (`pymodbus`, `numpy`, `pandas`) via `--break-system-packages`.
  - Resolved Mininet environment issues in Ubuntu 24.04: installed `net-tools` (providing `ifconfig`), `openvswitch-switch`, `openvswitch-testcontroller`, `telnet`, set up the `/usr/local/bin/ovs-controller` symlink, rebuilt and installed `mininet` via `setup.py install`.
  - Verified network sanity using `sudo mn --test pingall` (0% dropped).
  - Successfully brought up the real 7-host ICS testbed topology via `sudo python3 testbed/mininet_topology.py` (`attacker` 10.0.0.66, `scada` 10.0.0.10, and `plc1`-`plc5` on 10.0.0.1–10.0.0.5 connected to switch `s1`).

## 10. Open Items / Next Steps (update this section as things get resolved)

**On the Ryzen 5 + Vega 11 machine (testbed track — Abinraj):**
- Install WSL2 + Ubuntu 22.04/24.04 (no NVIDIA driver step needed — skip v2 guide §3.2) ✅
- Install base Linux tools (§3.3) ✅
- Install Mininet (§3.4) ✅ — resolved via python-is-python3 + manual `setup.py install` + manual mnexec build + net-tools/ifconfig fix (Session 9 & 17)
- Install MiniCPS (v2 guide §3.5) ✅ — installed via `pip install .` (repo uses pyproject.toml, not setup.py); Wireshark/tshark/tcpdump/hping3/dsniff already done
- **Module 3 (Mininet topology + Modbus PLC/SCADA scripts) ✅** — `mininet_topology.py`, `plc_server.py`, `scada_client.py` complete and verified live in WSL2 (Session 9 & 17). 7-host network up and ready.
- **Local Windows WebApp environment ✅ (Session 17):** Windows `venv/` created, all requirements installed, missing `pyvis` added, `main.py` created, pages 2 & 4 stubbed, app active on `localhost:8501`.
- **Live Battle real-time telemetry ✅ (Session 17):** `fdi_attack.py`, `dos_attack.py`, `dos_conn_exhaust.py`, and `replay_attack.py` instrumented to emit granular in-flight events to `data/log_store.json`.
- Install CICFlowMeter (v2 guide §3.7) — not yet done; watch for Python 3.14 version-mismatch issues (flagged in Session 9/§3)
- **Next up:** Module 4 — mostly ✅ (Session 13 & 17). FDI (`attacks/fdi_attack.py`), DoS (`attacks/dos_attack.py`, raw-socket flood — replaces hping3), and recon (`attacks/recon_step.py`) run end-to-end via `scripts/run_cycle.py` and are detected by Suricata per the verified mock run. **Remaining:** attempt MITM (arpspoof, T0830) and Replay (Scapy, T0832) — neither scripted/verified yet.
- **Suricata IDS detection checkpoint ✅ (Session 13)** — custom Modbus rules (`detection/suricata/modbus_rules.rules`) working end-to-end (recon/FDI/DoS verdicts). Setup in `docs/suricata_setup.md`, full run steps in `docs/testbed_runbook.md`. Real-IDS ground truth ahead of the trained detectors — not a replacement for Module 8.
- **Live Battle view ✅ integrated (Session 13 & 17), ⏳ to be wired into the app flow** — `app/pages/3_Live_Battle.py` polling `data/log_store.json` every 3s with live event telemetry, ready for Karthik to expand into the major Live Battle UI.
- **Canonical app flow (Session 14) — implement/wire in this order:** (1) preset IEEE-14/IEEE-30 selector plus validated custom-topology upload; (2) render electrical and derived ICS/OT topology before execution; (3) defense settings, enabled MITRE techniques, maximum episodes/time, and plateau threshold/window; (4) simulation start; (5) live campaign trace; (6) final report. Do not implement a free-form grid editor.
- **Campaign-control contract (Session 14) — required before PPO/RL wiring:** define the observation schema, allowed action catalogue, bounded GAN parameter ranges, reward components, repetition penalty, safety limit, and plateau rule. Persist every episode to `data/campaign_trace.json` so the report can prove the reason for each RL strategy change.
- **Re-verify the cycle from the new §7 paths on the WSL2 testbed** — integration is currently on-disk only; run `scripts/run_cycle.py` once to confirm end-to-end after the move.
- Capture a full labeled session and run it through CICFlowMeter (Module 5) — confirm the exact CLI invocation for whichever CICFlowMeter fork ends up being used
- **Data pipeline scripts ✅ (Session 16):** run `scripts/capture_testbed_session.sh` on WSL2 for every independent scenario, then CICFlowMeter, then `scripts/label_captured_flows.py`. Inspect each manifest before adding the session to the training package.
- Collect the Session 15 raw artefact bundle for each normal/Recon/FDI/DoS episode: PCAP, attack/campaign log, PLC/SCADA telemetry, and Suricata extract. Build `flow_features.csv`, `telemetry.csv`, split manifests, and collection manifest according to `docs/training_data_spec.md`; retain an ASCEND-PG-only held-out test set.
- Transfer `data/captured_flows/labeled_flows.csv` to Andikumar's RTX 3050 machine

**On Andikumar's Ryzen 5 + RTX 3050 machine (training track — Andikumar):**
- **Not yet done — next immediate action:** work through `ASCENDPG_Andikumar_Setup_Guide.md` (Python 3.11, VS Code, Git, NVIDIA driver check, venv, PyTorch CUDA build, supporting packages) — native Windows, no WSL2 needed (see Session 10 decision)
- **Blocked:** need `data/cic_ids2017_subset.csv` from Abinraj (or whoever ran `scripts/prepare_dataset.py`) before `train_gan.py` can actually be run — guide Step 11
- **Replace the old CIC-IDS-only handoff assumption (Session 15):** receive the schema-compliant data package defined in `docs/training_data_spec.md`. CICModbusDataset2023 may be used for development/pretraining after official download; final metrics must use the held-out ASCEND-PG capture set.
- Module 6 code written (`generative/gan.py`, `generative/train_gan.py`, from Session 10) but **not yet executed/verified** — MLP-based tabular GAN sized for 4GB VRAM, placeholder data source
- Module 7 — RL agent (`strategic/rl_env.py`, `strategic/train_rl.py`), stable-baselines3 PPO — not started, buildable against a mock environment stub pending real attack/detector feedback loop
- Module 8 — LSTM + Autoencoder detection (`detection/lstm_detector.py`, `detection/autoencoder_detector.py`, `detection/fusion.py`) — not started
- Train and validate the GAN/RL/LSTM/Autoencoder as actual project components; retain run logs, data splits, model weights, validation metrics, and reproducible seeds for the final evidence package. The model decision trace must support the Session 14 report requirements.
- Transfer/repoint all three modules from placeholder CIC-IDS-2017 data to Abinraj's real `data/captured_flows/labeled_flows.csv` once his testbed track produces it

**Either machine, once models are trained:**
- Rewire the Streamlit app to call the trained models instead of the rule-based fallbacks (Module 9)
- Implement the final campaign termination/report pipeline: strategy-space exhaustion or plateau/safety stop → DVS + SHAP/LIME + GAN/RL trace → ranked defense recommendations
- Re-demo to the panel

## 11. How to Resume Work in a New Chat

1. Start a new chat (with this or any other capable AI model)
2. Upload/paste this entire file as your first message
3. Say what you want to do next — e.g. "continue from where we left off" or "help me with Module 3" or "I hit this error: ..." — and **say who you are** (Abinraj, Andikumar, or Karthik) so work gets attributed correctly
4. The model should read §2 (Users), §3 (current phase), and §9 (progress tracker) first to understand exactly where things stand and who's doing what before responding
5. Before ending that session, add a new dated entry to §9 describing what got done, who did it, any decisions made, and any bugs/blockers hit — then re-save/re-download this file so it's ready for next time
