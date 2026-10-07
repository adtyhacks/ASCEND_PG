# External topology, firewall model and remediation MVP

The active-state/projection architecture is now defined in
[CANONICAL_TOPOLOGY.md](CANONICAL_TOPOLOGY.md). `topology_selection.json` is the
only active selection; `topology_source.json` is legacy migration input only.

Import in the dedicated GUI's Network page. Choose ASCEND JSON or GNS3, upload,
then inspect validation and preview, and click **Use This Topology** to activate
the imported analysis source. Validation alone does not activate it. The sample can be downloaded
with the sample link. Results/Reports exposes structured recommendations.

## Exchange format

See `examples/ascend_exchange.json` for a complete SCADA → firewall → PLC example.
The schema discriminator is `ascend.exchange/v1`. IDs are nonempty strings.

| Field | Contents |
| --- | --- |
| power_grid.buses | id, optional voltage_pu and vn_kv |
| power_grid.lines | id, from_bus, to_bus; extra engineering metadata preserved |
| power_grid.generators / loads | id, bus; optional p_mw/q_mvar metadata preserved |
| network.devices | id, name, type, optional ip/zone, interfaces |
| device.interfaces | id, name, optional ip/zone |
| links | id, exactly two endpoints: device and interface |
| mapping | bus and device (PLC or RTU) |
| firewalls | id references firewall device; default_action; rules |

Types: switch, router, scada, hmi, plc, rtu, attacker, ids, ips, firewall, generic.
Duplicate IDs within each collection, unresolved endpoints, unknown device types,
invalid IPs, power references, and firewall selectors are rejected. Empty power
collections are valid for network-only GNS3 imports. Existing ASCEND custom
nodes/edges JSON is also accepted through a compatibility conversion.

Firewall rule fields: rule_id, priority, source, destination, protocol,
source_port, destination_port, action. Lower priority numbers match first; ties
use file order. Selectors accept device IDs, IP/CIDR, `any`, or `zone:<name>`.
Zone selectors must reference a zone declared on a firewall interface. Ports
accept an integer, null, or `any`; protocol is tcp/udp/icmp/any. No match uses
default_action (deny by default). Evaluations always return `enforced: false`.
Device identities/zones represent trusted design metadata, not authenticated
runtime identities. Device ID and IP selectors are distinct; supply the matching
representation. There is no routing or firewall-path simulation.

## API

- GET /api/topology/import-sample: sample exchange document.
- POST /api/topology/import: `{format: "ascend"|"gns3", document: {...}, save: true}`.
  `save:false` validates/renders without persistence. Limit: 2 MiB, 500 devices,
  2000 network links. Invalid imports preserve the last saved import.
- GET /api/topology/imported: last validated candidate, PyVis HTML, warnings.
- GET /api/topology/source: active source, revision, devices and policy context.
- POST /api/topology/use-imported: `{revision}` from the validated preview;
  persists the active canonical design in data/topology_selection.json. Requires no
  owned CORE session marker. IEEE/custom selection switches back to canonical.
- POST /api/firewall/evaluate: `{firewall_id, traffic: {source, destination,
  protocol, source_port, destination_port}}`.
- GET /api/report-summary retains existing fields and adds
  remediation_recommendations for the selected saved run.
- Existing POST /api/report/generate embeds structured recommendations in HTML.

The validated candidate is stored atomically in data/imported_topology.json, separate
from topology_selection.json and all runtime files. Existing run snapshots remain
authoritative; new canonical CORE runs do not inherit an inactive imported candidate. External
analysis mode cannot launch CORE; select a supported IEEE/custom topology first.
Old runs never acquire later imported
configuration. Matching to findings uses exact device ID/name/IP and requires
one unambiguous match. This is contextual advice, not proof the design was deployed.

## GNS3 scope

Reads topology.nodes and topology.links; preserves IDs, names, original type and
template ID. Explicit ports retain names and adapter/port identity; missing port
entries are reconstructed from link endpoints and marked inferred_from_link.
Only directly present node/port IP fields are imported. Known types and explicit
name hints classify devices; otherwise generic. Classification priority is explicit
device metadata, appliance/template metadata, node type, template name, then a
controlled name fallback. FW/FW-1/FW1, ASA, pfSense, OPNsense, FortiGate/Fortinet
are recognized at token boundaries. Original node/type metadata is preserved.
Firewall devices without imported policy appear with empty rules and an explicitly
modeled default deny; this does not import guest configuration. Source/destination
lists use active devices, excluding switches, firewalls and IDS/IPS, with a selection
placeholder instead of guessing Internet → Internet. Does not open referenced files,
parse guest/vendor configs, execute appliances, infer electrical buses, or invent
firewall rules. Use the exchange format to add those details.

## Boundaries

Only imported graphs matching the supported hub/Modbus projection can generate
CORE XML; arbitrary routed/firewall/GNS3 graphs remain analysis-only. The existing
ownership lifecycle remains unchanged. No firewall enforcement, rule application, automatic remedy, physical
feedback, voltage recovery, or controlled re-test/comparison is added. Proposed
rules require engineer review, correct order, verified identities, path placement,
and independent execution evidence. Existing isolate/restore is unaffected.
GUI recommendations use readable cards; raw JSON is collapsed under Technical
Details. Source changes reload firewall/device choices and clear old decisions.
Structured report integration targets the dedicated GUI HTML report; the existing
PDF export retains its existing generic remediation text.

Focused tests: `python -m unittest scripts.test_external_mvp`.
