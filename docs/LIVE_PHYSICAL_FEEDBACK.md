# Live PLC-state feedback into PPO

## Data path

The GUI campaign still creates `AttackStrategyEnv(topology=active_topology)` and uses
the existing PPO checkpoint, action selection, watcher, detection and reward flow.
The environment never loads another IEEE case. Its initial voltages are calculated
from the selected model, and every `_get_obs()` now reads the canonical runtime
voltage state rather than the array copied at construction.

For each owned watcher attack request, `testbed/physical_feedback.py` verifies the
run, generation, CORE session, topology revision and target bus/IP, then reads the
target PLC's **explicitly mapped writable registers** before execution. No legacy
register name automatically becomes an electrical control. The real Modbus client
uses the declared port/unit and client offset, with bounded two-second reads and no
retry loop. Baseline Pandapower parameters are synchronized from verified readbacks
and solved before the attack, then snapshotted.

After execution, the watcher reads the same registers again. Observed changes update
the declared `net[element].at[index, parameter]`, then the existing
`testbed.topology.run_power_flow()` invokes Pandapower's solver. This happens even if
the attack reports failure, since partial writes may have occurred. Subprocess
success, detection or evasion alone never implies a physical change. The runtime
identity is checked again before state publication.

## Supported mappings

Only these writable semantic/element/parameter combinations are implemented:

| Semantic | Pandapower target |
| --- | --- |
| generator_active_power | gen.p_mw |
| generator_voltage_setpoint | gen.vm_pu |
| slack_voltage_setpoint | ext_grid.vm_pu |
| load_active_power | load.p_mw |
| load_reactive_power | load.q_mvar |
| line_in_service | line.in_service |
| bus_nominal_voltage | bus.vn_kv |

Mappings require an existing validated table index. Numeric holding-register
readbacks decode as `raw / scale`, matching the PLC template encoding convention.
Boolean coil readbacks map directly to `in_service`. Unsupported semantics,
contradictory duplicate parameter mappings, absent indices and failed readbacks
produce explicit errors. Input-register result mappings are read-only and never
treated as physical actuators. No tables, generators, loads or line trips are invented.

The verified integration uses the actual PLC datastore built by `plc_server`:
holding-register **client offset 0**, `uint16`, scale **10000**, semantic
`generator_voltage_setpoint`, mapped to **Pandapower gen row 0, vm_pu** on the existing
IEEE-14 electrical model. A real FC6 datastore operation changes **10450 → 10250**
(1.045 → 1.025 p.u.); FC3 readback supplies the values to the feedback engine.
There are no hardcoded before/after bus-voltage results.

## Canonical state and observation compatibility

Solved state is attached to the selected canonical `Topology` via
`apply_physical_state()`. `Topology.voltages` exposes the current solved bus voltages.
The persisted topology definition and its revision remain unchanged: a physical
state update is not a topology replacement and must not invalidate CORE ownership,
campaign revision checks, watcher generations or service fingerprints.

The changing Pandapower network and last result persist atomically in the existing
run directory as `physical_state.json`, bound to scenario/run/generation/topology.
The next watcher step restores this network so physical changes accumulate.
The GUI campaign reloads this scoped state on completion and before the next
prediction; `_get_obs()` refreshes its voltage slots from the canonical state.
A focused handoff test captures the actual array passed to `model.predict()` and
checks it against the newly solved voltages.

The existing observation remains **230 float32 values**, including voltage slots
**28–77**, normalized by the existing **1.1** divisor. The action dimensions remain
**18 × 50 × 10 × 50**. Explicit register layouts within the existing 50-address
range now use the same selected logical offset directly as the Modbus client
address, without legacy 40000/30000 labels. Legacy undeclared layouts retain their
existing address behavior. Larger custom layouts remain PPO-incompatible.
The PPO algorithm, checkpoint architecture and reward formula are unchanged.

## Evidence, failure and display

Each completed feedback update appends a `physical_state_updated` event through the
existing run store and is included in the step result and retained attack evidence.
It records availability, power-flow success, before/after/delta voltages, minimum
voltages, affected buses, exact register/raw/decoded parameter changes, generator
and slack output, load values and line loading. GUI grid status exposes the same
scoped result as `physical_feedback` and uses solved model voltages when available.
These are simulated electrical results driven by real readbacks, not physical
voltage-sensor measurements.

On nonconvergence, invalid results, unreachable PLCs or unsupported mappings,
`power_flow_success=false`, current voltage results/deltas are empty and minimum
voltage after is null. Last-valid before evidence remains when it was captured.
The canonical state rejects further voltage observations, and campaign inference
stops instead of feeding stale, NaN or fabricated 1.0 values into PPO. Attack and
detection completion/evidence remain preserved. Restart the assessment after
correcting the error; the feedback engine does not silently reset the failed model.
The electrical source loader also now rejects power-flow failure instead of building
a unit-voltage fallback. Network-only topologies explicitly report
`physical_model_available=false` and are refused by the fixed electrical PPO projection.

## Verification and limitations

The deterministic real solver/datastore integration measured minimum voltage
**1.0100000000 → 1.0098253297 p.u.**, maximum absolute bus delta **0.0200000000 p.u.**,
and changes at ten buses. It verified canonical state, unchanged topology revision,
unchanged observation shape and the next PPO observation/prediction input.
Tests use temporary topology/run stores, actual Pandapower and real Pymodbus
datastore FC3/FC6 operations. No CORE session, listener, campaign or attack is launched.

The running CORE session/watcher is not restarted by this task. Restart the watcher
through the normal lifecycle when deploying the new code. The live socket-reader
path is implemented, but no attack against that running session was used for testing.
Only explicit mappings provide feedback; unannotated presets/registers are not
assigned guessed physical effects. Pre/post snapshots do not capture transient
changes restored before the post-readback. Result-register telemetry is not written
back into PLC input registers. Arbitrary vendor models, signed/float/multiword register
formats and changes outside the supported mapping list are not implemented.

## Files changed

- New: `testbed/physical_feedback.py`, `scripts/test_physical_feedback.py`,
  `docs/LIVE_PHYSICAL_FEEDBACK.md`.
- Updated: `testbed/topology.py`, `strategic/rl_env.py`, `scripts/ppo_step_watcher.py`,
  `gui/campaign.py`, `gui/grid_status.py`, `scripts/test_canonical_architecture.py`,
  `scripts/test_gui_campaign.py`, `scripts/test_grid_status.py`.

Focused verification commands:

```sh
.venv-wsl/bin/python -m unittest scripts.test_physical_feedback scripts.test_canonical_architecture scripts.test_external_mvp scripts.test_grid_status -v
.venv-wsl/bin/python -m scripts.test_gui_campaign
.venv-wsl/bin/python -m scripts.test_core_runtime_serialization
node scripts/test_grid_status_frontend.js
node scripts/test_gui_frontend.js
```

No commit, push, reset, clean, amendment or uncontrolled attack is performed.

Results: the combined physical/canonical/import/grid run passed all **51 tests**.
The final **9-test physical suite** passed, including new-run context clearing;
the deterministic integration was rerun successfully with a retained-network
restoration assertion. Campaign handoff/worker/cache regressions, CORE helper
serialization, grid frontend and main GUI frontend checks also passed.
`git diff --check` passed. Existing Pandapower/Pymodbus deprecation warnings remain.
