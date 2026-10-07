# One active canonical topology

`testbed.topology.get_topology()` is the sole active model accessor. The in-memory
object mirrors `data/topology_selection.json` (`ascend.canonical/v1`), whose
fingerprint invalidates the cached object when another process changes selection.
GUI selectors and imported Use This Topology call `activate_topology()` to atomically
replace the whole selection. No topology merge is performed. Imported candidates
in `data/imported_topology.json` are previews, not active state. The previous
`topology_source.json` is read only as a legacy initialization migration; new code
never writes or independently uses it as another active source. Existing files are
preserved. The next explicit selection persists the new canonical format.

All projections have the same content revision:

- PyVis and GUI network configuration derive from the active model/snapshot.
- Firewall context derives from the active model's network and policy metadata.
- Pandapower derives from the active custom electrical model, or the exact stored
  IEEE network (including transformers, generators and loads). It never reloads
  a preset solely because a case name looks like IEEE-14/30.
- CORE XML generation derives from the active model. It rejects unsupported graphs
  before writing XML; it never substitutes the default hub network for an imported
  graph. Existing owned-session/generation/service/watcher operations are retained.
- PPO environment construction receives the active object. It never loads a case
  or changes global selection. An incompatible object is rejected. Campaign
  revisions invalidate old in-memory sessions; retained evidence is not erased.

Selection remains blocked while an owned CORE session marker exists. Stop that
owned session before selecting/rebuilding. A topology-dependent owned testbed must
be rebuilt after changes, not reused against another graph. Older saved reports
keep their original context; old runtime revisions require rebuilding to continue.

## Capability reporting

GET `/api/topology/source` returns the active source, revision and physical model,
CORE projection and PPO compatibility, plus node/link counts. Network and Runtime
show these fields. CORE readiness requires a matching owned runtime revision;
model availability does not claim live electrical measurements. The CORE GUI
button and app API route are removed. The underlying CORE helper/package is retained.

Arbitrary GNS3/firewall/router graphs remain valid active topology data and are
visualized faithfully. They have no electrical model unless electrical data is
explicitly supplied. The current executor supports the existing hub, SCADA,
attacker, IDS and canonical PLC layout/IPs/interfaces only. Other graphs report
CORE Invalid and PPO Not compatible rather than inventing working services.
Imported ASCEND graphs matching the supported projection can generate that testbed.

## Custom capability schema

See `examples/custom_capabilities.json`. Legacy nodes/edges remain supported.
Each bus may include `voltage_pu` (alias of voltage), `voltage_min_pu`,
`voltage_max_pu`, `vn_kv`, slack/pv/pq type, pg/qg/pl/ql and parameterized lines.
Its optional `plc` object contains id, associated bus_id, IP, modbus_port, unit_id,
and a typed registers list. PLC identity/IP/bus references must agree.

Registers use actual client offsets 0–4095, not documentation labels such as
40000. Each definition has address, name, type, data_type, semantic, scale, unit,
attackable, optional initial_value and optional physical_mapping. Supported spaces
are holding_register/input_register (uint16), coil/discrete_input (bool).
Read-only spaces cannot declare direct-write attackability. Duplicate space/address
definitions and malformed scales/types/initial values are rejected. Declared spaces
initialize PLC data blocks; omitted spaces retain existing template defaults.
Runtime projection currently supports port 502 and the existing unit-ID behavior.

Physical mappings are validated references, **not an implemented feedback loop**.
Supported table/parameter references are bus.vn_kv, res_bus.vm_pu/va_degree,
ext_grid.vm_pu, gen.p_mw/vm_pu, load.p_mw/q_mvar, and line.in_service. Indices must
exist in the selected generated model. res_bus mappings are read-only. These
references do not cause Modbus writes to change Pandapower or update live voltage.

Attack declarations accept technique IDs or primary step names extracted from
the actual `TECHNIQUE_TO_STEP_NAME` implementation registry. Detection declarations
are modbus_reads, modbus_writes, coil_changes, network_flow_monitoring, suricata,
ml_flow_detection. These describe supported module/observation categories; they
do not assert a detector is running or that every declared attack succeeds, and
are not permission policies or policy-network action masks. Unsupported declarations
are rejected. Input-register false responses/replay remain network attacks, not
direct writes to read-only registers.

Explicit client-offset register layouts are CORE-capable when the network layout
is supported, but are **PPO Not compatible**: the existing trained action space
uses legacy register bases. An action adapter/retraining is future work. Ordinary
supported custom bus topologies retain the existing PPO observation/action shape.

Validation rejects duplicate IDs, dangling network/electrical/PLC references,
conflicting mappings, invalid bus limits, invalid register definitions and physical
indices. Invalid custom selections raise errors and never fall back to IEEE-14.

Tests: `python -m unittest scripts.test_canonical_architecture scripts.test_external_mvp`.
They construct environments, solve baseline models and generate temporary XML;
they do not execute PPO predictions, attacks, CORE, watchers or live services.
