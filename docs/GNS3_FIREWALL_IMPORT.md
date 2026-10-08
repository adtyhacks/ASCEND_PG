# GNS3 firewall configuration import

Identification, imported configuration, and enforcement are separate. A normalized
firewall device does not imply that guest configuration exists or that packets are
filtered. Nothing in this importer contacts GNS3, boots an appliance, reads a local
configuration path, mounts a disk image, or applies rules to CORE.

## Sources

The existing upload accepts a JSON `.gns3` project with `topology.nodes` and
`topology.links`. The sample `examples/scada_firewall_plc.gns3` supplies topology,
ports and appliance identity only: its firewall has `configuration_available:false`,
no rules and an unknown default policy.

Supported configuration payloads, in precedence order:

1. `node.firewall_configuration` (explicit ASCEND structured extension).
2. `node.properties.firewall_configuration` (same extension).
3. Embedded `node.appliance`, `node.properties.appliance`, `node.template`, or
   `node.properties.template` metadata containing `firewall_configuration`.
4. Nonempty inline `node.properties.startup_config_content`, then
   `node.properties.running_config_content`. A focused ASA extended ACL parser is
   selected only when both `access-list` and `access-group` syntax are present.

These structured extension fields are **not claims that standard GNS3 QEMU
projects export guest firewall rules**. GNS3 emulator configuration contents must
actually be supplied in the uploaded document. GNS3 exposes inline startup
configuration for supported emulator APIs; a saved project may instead contain a
filename or store the configuration in project files or an appliance disk.
Template UUIDs, filenames, image names and ports alone never supply policy rules.
No source candidates are merged: the highest-precedence supplied payload wins.

References: [GNS3 emulator configuration examples](https://github.com/GNS3/gns3-server/blob/master/docs/curl.rst),
[Cisco ASA extended ACL grammar](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/acl-extended.html).

## Structured extension example

Add this **only with configuration actually obtained from that firewall** to the
corresponding project node (IDs below must match the uploaded topology):

```json
{
  "firewall_configuration": {
    "hostname": "edge-fw",
    "interfaces": [{"id": "inside", "name": "inside", "ip": "10.0.0.1/24", "zone": "operations"}],
    "zones": [{"id": "operations", "interfaces": ["inside"]}],
    "address_objects": [{"id": "clients", "network": "10.0.0.0/24"}],
    "services": [{"id": "modbus", "protocol": "tcp", "destination_port": 502}],
    "default_policy": "DENY",
    "rules": [{
      "rule_id": "scada-modbus", "priority": 0,
      "source": "scada", "destination": "plc8", "protocol": "TCP",
      "source_port": "any", "destination_port": 502, "action": "ALLOW"
    }]
  }
}
```

An explicit `rules` array is required; empty means supplied configuration with zero
rules. Source, destination, protocol, action, and both ports must be explicit.
Ports support integers 0–65535, `any`, or null (the existing canonical wildcard).
Protocols support any/TCP/UDP/ICMP. Actions normalize ALLOW/DENY to lowercase.
Missing rule IDs/order priorities derive stable IDs/list positions; supplied IDs
and priorities remain intact. The array order and each original rule are retained.
Evaluation uses priority with original order as the tie breaker.

Hostname, interface IPs, zones, address objects and services remain associated with
the firewall ID in this topology. Configured guest interfaces remain separate from
GNS3 adapter/port IDs; there is no guessed mapping between them.
`object:<id>` source/destination references and rule `service` references are retained
and validated against declared objects/services. Their expansion is not implemented;
model evaluation is disabled for these policies. Unrecognized references fail validation.
Default action accepts `default_action` or `default_policy`; absent means unknown,
not a fabricated deny. Each collection contains objects with unique nonempty IDs.

## ASA subset and limitations

Inline ASA contents import hostname, static interface IPv4 addresses, `nameif`
zones, extended permit/deny ACLs, any/any4, host and IPv4/netmask selectors,
IP/TCP/UDP/ICMP protocols, numeric `eq` source/destination ports, source order,
explicit `line` priority and ACL/interface/direction bindings. Original lines and
the full source payload are retained. Remarks are not policy rules.

ASA object/group expansion, named services, ranges, IPv6, NAT, schedules, logging
modifiers and other advanced ACL syntax are unsupported. Recognized unsupported
statements mark the import incomplete and emit warnings. Successfully parsed rules
remain visible; omitted statements remain in original source metadata. ASA model
evaluation is always disabled: multiple ACLs and interface directions cannot safely
be flattened into the existing model. A single global default policy remains unknown.
`import_complete` refers to the focused subset, not to full appliance configuration.

pfSense, OPNsense and FortiGate/Fortinet are recognized as firewall identities.
Their XML/CLI vendor rule parsers are not implemented. Supplied unsupported inline
configuration is marked available but incomplete, retained verbatim, and cannot be
evaluated. Path-only or image-only exports are marked configuration unavailable.
Malformed structured payloads fail validation before replacing a saved candidate.

## Active topology and GUI

The canonical exchange carries all imported firewall data through existing
serialization and evidence snapshots. Validation creates a candidate; **Use This
Topology** activates it. Switching replaces the entire firewall context, selectors,
policy result and topology view. Configuration from another source is never merged.
Saved older GNS3 candidates can recover configuration from retained original nodes
in memory without rewriting evidence files.

The firewall selector includes only normalized firewall devices. Endpoint selectors
use actual active devices, excluding infrastructure switch/firewall/IDS/IPS devices.

## Custom topology policies use the same model

The custom topology builder stores optional `firewalls` beside its electrical
`nodes` and `edges`. Each entry contains the firewall device identity, interfaces,
zones, address objects, services, ordered rules and default action. Validation
promotes that definition into the same `ascend.exchange/v1` firewall collection
used by GNS3 imports; the GUI evaluator and CORE compiler therefore receive one
policy shape. Custom rules require explicit source and destination ports (`"any"`
is explicit), and no rules are generated when the collection is empty.
No endpoints are invented. The GUI shows name, Imported/Not Available, rule count,
configured interface count and known/unknown default. Partial imports show a warning.
Unavailable or unsupported policies disable evaluation, and the backend also rejects
it. Evaluation is model-only; known endpoint IPs are derived from active topology
metadata rather than trusted client address claims. Remediation retains the data but
skips unsupported policy evaluation.

## Focused tests

`python -m unittest scripts.test_gns3_firewall scripts.test_external_mvp scripts.test_canonical_architecture -v`

`node scripts/test_external_frontend.js`

Tests use temporary canonical stores and mocked UI/API calls. No services, packets,
campaigns, runtime firewall enforcement, commits or pushes are involved.
