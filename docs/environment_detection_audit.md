# Environment and detection pipeline audit

The landing page uses `/api/sample-environment`, a static, labelled projection in
`data/sample_topologies/ics_sample.json`. It was exported once from the canonical
IEEE-14 model (14 PLCs, SCADA, attacker, IDS monitor, CORE hub). It never loads the
selected topology, executes a power flow, queries CORE, or reads a live campaign.
Sample rule rows are parsed from the bundled Suricata rule file. Sample scenarios
have **not evaluated** detection; they are not simulated positive detections.

## T0816 trace and root causes

The registry maps T0816 to `device_restart`, `attacks/device_restart.py`, stage 2,
and SID 9000007. The script writes coil 6 (the generator emergency-stop coil), not
a verified physical hardware restart. Runtime logs recorded
`ModbusClientMixin.write_coil() got an unexpected keyword argument 'slave'`.
The installed/project-pinned pymodbus 3.14 API uses `device_id`; the script now
uses that API. T0835 and T0801 had the same obsolete call and were corrected.
Historical logs also contain unreachable-target failures; those remain failures.

The executor obtained a positive ML verdict and method `ml`, then replaced
`detected` with false in its FAILED/TIMEOUT branches. The controller consequently
saved a failed finish without a detection event. Saved T0816 finish records still
contain method `ml` and confidence around 0.99945. Method `ml`, `suricata`, or
`both` was assigned only to positive verdicts by that executor. Reports can
therefore recover these historical positives from the saved method without
inventing a confidence threshold or rewriting append-only evidence. Explicit
new boolean results remain authoritative. Failed execution earns no evasion or
impact credit, even when detected.

The report additionally used the internal step as the official technique name,
and indexed a list of MITRE tactics with the four-stage RL index. Those are
different taxonomies. All event details/report labels now resolve through the
registry, independently of the execution stage.

## MITRE mapping audit

Names/tactics were checked against the official technique pages at
`https://attack.mitre.org/techniques/<ID>/` on 2026-10-08. Execution indices and
scripts remain stable for the trained model. Detection SIDs below indicate
project signature coverage, not guaranteed detections or verified impact.

| ID | Official name | Tactic | Internal step | SIDs |
|---|---|---|---|---|
| T0886 | Remote Services | Initial Access, Lateral Movement | remote_services | 9000026 |
| T0846 | Remote System Discovery | Discovery | recon_nmap_devid | 9000004 |
| T0888 | Remote System Information Discovery | Discovery | recon_nmap_devid | 9000004 |
| T0840 | Network Connection Enumeration | Discovery | recon_fc_scan | 9000005, 9000006 |
| T0830 | Adversary-in-the-Middle | Collection | mitm_proxy | 9000022 |
| T0801 | Monitor Process State | Collection | monitor_process_state | 9000023 |
| T0802 | Automated Collection | Collection | automated_collection | 9000027 |
| T0869 | Standard Application Layer Protocol | Command and Control | standard_protocol_c2 | 9000028 |
| T0814 | Denial of Service | Inhibit Response Function | dos_loud | 9000002, 9000023, 9000010 |
| T0878 | Alarm Suppression | Inhibit Response Function | alarm_suppression | 9000029 |
| T0816 | Device Restart/Shutdown | Inhibit Response Function | device_restart | 9000007 |
| T0881 | Service Stop | Inhibit Response Function | service_stop | 9000030 |
| T0836 | Modify Parameter | Impair Process Control | fdi_attack | 9000001 |
| T0835 | Manipulate I/O Image | Inhibit Response Function | manipulate_io_image | 9000007 |
| T0806 | Brute Force I/O | Impair Process Control | brute_force_io | 9000023 |
| T0855 | Unauthorized Command Message (historical) | Impair Process Control | cmd_inject_coil | 9000007, 9000001, 9000006, 9000008, 9000009 |
| T0832 | Manipulation of View | Impact | replay_attack | No signature; ML required |
| T0815 | Denial of View | Impact | denial_of_view | 9000001, 9000024 |

T0842 is officially Network Sniffing / Discovery. The model's historical action
index 3 maps to the implemented active FC scan, T0840; display lookup preserves
T0842's own metadata when reading historical events. FC scanning is a project
enumeration scenario, not passive sniffing. T0855 is now replaced by
[T1692.001](https://attack.mitre.org/techniques/T1692/001/). Its historical ID is
retained for checkpoint/event compatibility and the replacement is shown in
Technical Details. T0830 and T0835 tactics were corrected; FDI/Replay implementation
suffixes were removed from official names. All mapped SIDs and script paths are
validated against repository sources. Generic/shared signatures can match
benign traffic; SID coverage alone does not establish technique execution.

## DVS

Reports previously required `run_metadata.dvs_evaluation`, but GUI execution
never wrote it. Attack finishes lacked explicit nullable verdicts and episode
boundaries/rewards. These records alone cannot reconstruct all seven inputs:
`avg_evasion_rate`, `completion_rate`, `avg_max_stage`, `plateau_detected`,
`completion_count`, `num_episodes`, `avg_reward`.

The controller now assigns episode IDs, retains authoritative results/rewards,
and persists statistics on successful stage completion, bounded full-run
completion, execution stop, reset, or runtime stop. Duplicate acceptance does
not duplicate episodes. Pending/interrupted results and unavailable detection
are reported explicitly and cannot produce a score. Successful, evaluated
misses alone earn evasion/depth credit; failed executions do not. The existing
four-weight DVS formula is unchanged. The same PlateauTracker is shared with
offline evaluation. A score can describe one observed episode; episode count
remains visible and a larger evaluation is needed to assess convergence.
False positives/latency are not invented; neither is an input to this formula.

## Rules and topology

Canonical reporting previously replaced every topology field with
`Not established` and every rules list with `[]`, even when a saved topology
existed. Reports now read the selected run's `scenario.json` topology. CORE
startup records the actual bundled `-S` rules only after the IDS process is
verified in its namespace. This is an active-at-start snapshot, not a claim that
Suricata is still running. Older runs without that snapshot show an explicit
unavailable reason. Bundled rules are never substituted as live evidence.

Negative Suricata verdicts require EVE observations in the attack window; an old
file or missing feed is unavailable. Missing/failed ML inference is likewise
unavailable. Reports, event logs and campaign statistics share the three-state
interpretation. Detection rate uses evaluated events only, with unavailable
events counted separately.

## Verification and limits

Regression tests cover sample independence, mapped scripts/SIDs, installed
Modbus method signature, historical T0816 recovery, failed execution with a
positive ML verdict, three-state semantics, unchanged DVS arithmetic, stored
episode statistics, report HTTP generation/download, immutable evidence and
frontend disclosures/runtime guards. Runtime execution is replaced at the
test boundary; no new attack was dispatched against the user's current testbed.
Historical missing rewards/episode boundaries cannot be manufactured. Raw
stored events and the user's existing runtime files are preserved.

## Files changed

- Sample and mappings: `data/environment.py`, `data/sample_topologies/ics_sample.json`,
  `data/mitre_registry.py`, `data/mitre_ics_map.json`.
- Attack API calls: `attacks/device_restart.py`, `attacks/manipulate_io_image.py`,
  `attacks/monitor_process_state.py`.
- Detection/execution/storage: `defense/detection_result.py`,
  `defense/hybrid_detector.py`, `scripts/testbed_executor.py`,
  `scripts/ppo_step_watcher.py`, `scripts/core_session.py`, `testbed/run_store.py`.
- Campaign/evaluation: `gui/campaign.py`, `metrics/campaign_evaluation.py`,
  `metrics/dvs_score.py`, `strategic/rl_env.py`.
- GUI/reporting: `gui/server.py`, `gui/adapter.py`, `gui/reporting.py`,
  `gui/web/app.js`, `gui/web/index.html`, `reports/pentest_report.py`,
  `xai/recommendation_templates.py`.
- Tests: `scripts/test_environment_pipeline.py`, `scripts/test_dvs_reports.py`,
  `scripts/test_gui_frontend.js`, `scripts/test_gui_reports.py`,
  `scripts/test_report_normalization.py`, `scripts/test_report_run_summary.py`.
- Audit: `docs/environment_detection_audit.md`.

`core_topology.xml` and untracked runtime/handoff files were already modified
before this task; they were not edited as part of these fixes.
