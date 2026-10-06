# Network & Grid Status

## Historical source audit

The last legacy screen was `19299dd:app/pages/2_Run_Simulation.py`
(also available as `a3b9e0c^:app/pages/2_Run_Simulation.py`). Lines 26–72
called `testbed.grid_env.build_baseline`, retained its results in Streamlit
session state, and displayed bus count, calculated voltage range/profile/table,
line count, maximum calculated line loading/profile/table, and a normal-traffic
preview. These were baseline calculations, not SCADA measurements. The charts
used Streamlit bar charts; the topology used PyVis.

`grid_env.py` loads a Pandapower case and runs AC power flow. Its traffic
timestamps, endpoints, packet sizes and voltages are seeded random samples.
No measured bandwidth calculation was found in the legacy app history searched.
CORE XML `bandwidth=0` is a link configuration, not observed traffic or capacity.
The synthetic traffic preview is intentionally not migrated as live monitoring.

## Native GUI and sources

Open **Network & Grid Status** (`#grid`). The read-only `/api/grid-status`
endpoint follows the existing selected `Topology` model for presets and custom
topologies. No power-flow reruns, PLC queries, collector, evidence writes or
Streamlit runtime are added. The page refreshes existing sources every five
seconds while visible.

| Metric | Existing source and interpretation |
| --- | --- |
| Electrical components, names, types, model voltage | `Topology.nodes`; calculated/configured baseline, not a live measurement |
| Model real/reactive generation/load | `pg`, `qg`, `pl`, `ql`; sums require every component's field. Current preset all-zero placeholders are unavailable; custom configuration/default values remain explicitly model data |
| Electrical / communication connections, total network devices | `Topology.edges` / `canonical_snapshot().links` with `core_link=True` / canonical nodes |
| Communication status / responding components | Retained `data/core-runtime/scada.jsonl`; successful read = Monitoring, latest failed read = Offline, absent/stale data = Not available. Offline does not confirm a powered-off PLC |
| Recent detection notices | Latest 100 security events from the active run; operational notices, not finding counts or severity/DVS |
| Observed flow traffic rate | Retained `data/core-runtime/suricata/eve.json` flow byte counters and start/end times |

Live sources require a matching active assessment, session, generation and
topology version. Observations must be timestamped after session/run creation,
within 120 seconds of the snapshot, and not in the future. PLC observations must
match the selected addresses. The existing reader bounds each background source
to its latest 100 rows and at most 2 MiB. No old log data is presented as current.
Background logs do not carry generation IDs themselves: this is temporal/address
scoping for operational presentation, not new forensic attribution or evidence.

For flow traffic, both endpoints must belong to the canonical network. Keep the
latest cumulative byte counters for each unique flow identity (including flow
start and endpoints), preventing repeated EVE snapshots from being summed twice:

`observed bit/s = 8 * sum(bytes_toserver + bytes_toclient) / (latest flow end - earliest flow start)`

Both byte counters and valid start/end times are required; flows must begin within
the current scope/freshness window. This is the average of retained observed
flows over that window, not link capacity or complete network utilization.
Missing/incomplete sources give **Not available**, never invented zero bandwidth.

Measured voltage/power, electrical Healthy/Warning/Critical classifications and
line loading remain unavailable. Current SCADA uses holding-register reads;
the PLC's voltage/power register maps are input registers. Holding-register
values cannot safely be interpreted as voltage or power. IP addresses and
observation timestamps remain in collapsed technical details.
