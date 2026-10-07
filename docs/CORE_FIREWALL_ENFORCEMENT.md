# CORE firewall enforcement

## Deployment and scope

The active `Topology.exchange` is the source of the routed CORE projection. The
existing XML generator now selects this projection when canonical firewall devices
exist; it does not substitute an IEEE case or build a separate topology. XML carries
the canonical source, revision and deterministic runtime plan. Validation recomputes
the entire plan and XML, rejecting altered links, addresses, services or policies.

The supported initial projection has exactly one firewall, two or more disjoint
IPv4 subnets and acyclic switch segments. Each segment attaches to exactly one
firewall interface. Endpoints have one addressed interface. A segment cannot have a
second firewall attachment or bypass. CORE interface IDs/names/MACs derive
deterministically from canonical interfaces; configured addresses may fill an exact
matching interface ID, never a guessed appliance-port mapping. Conflicts are rejected.
Endpoint routes use the sole firewall address on their subnet. No control network,
external interface or guest disk image is attached.

Firewall, endpoint and switch nodes are compiled with the original canonical names.
Imported endpoint roles use plain isolated Linux nodes with routing configuration;
the projection does not emulate a vendor guest or automatically launch SCADA, PLC,
IDS or PPO applications. Existing legacy hub/Modbus services remain unchanged.
Imported PLC register-service declarations and unsupported IDS/IPS/router roles are
rejected rather than silently replaced. PPO eligibility is disabled for this routed
projection; attack selection itself is unchanged.

## Backend and policy semantics

The initial backend is **nftables**, available in this WSL installation. There is no
iptables fallback in this change: an unavailable/unsupported nft backend produces
an explicit failed status and leaves forwarding disabled. No package is installed.

Rules compile source/destination IPv4 or CIDR, uniquely addressed canonical device
IDs, any/TCP/UDP/ICMP, numeric source/destination ports, allow/deny, stable priority
ordering, and an explicit default action. Unknown defaults, ambiguous addresses,
unavailable/partial configurations, object/service references, scoped vendor ACLs,
IPv6, and port constraints on non-TCP/UDP rules are rejected before allocation.

Filtering applies to routed **forwarded IPv4 traffic**. Traffic within a shared L2
segment and traffic addressed to the firewall itself do not traverse this policy.
No implicit established/related accept, NAT, rule expansion or bidirectional permit
is inserted. Replies require explicit canonical rules. The `ip ascend_fw` table has
a forward filter hook, a drop guard policy, ordered canonical counter/verdict rules,
and a terminal counter/verdict for the canonical default. A default allow is honored
by that terminal rule. Rule counts exclude the terminal default rule.

[Netfilter's nftables documentation](https://netfilter.org/projects/nftables/manpage.html)
defines the hook, rule, counter, check and batch-loading semantics used here.

## Installation, ownership and evidence

All runtime installation, status inspection and packet probing go through
`core_request` → `scripts/core_session.py`, with the existing thread serialization,
process file lock, owned session token, endpoint and generation validation. There is
no second lifecycle. Namespace services initially disable IPv4 and IPv6 forwarding.
After the existing CORE start succeeds, the helper:

1. Confirms the firewall network namespace differs from the host namespace.
2. Leaves IPv4 forwarding disabled and requires a fresh namespace ruleset.
3. Validates the compiled batch with `nft -c -f -`, then loads with `nft -f -`.
4. Reads the actual JSON ruleset and checks tables, hook, policy, rule order,
   selectors, protocol, ports and verdicts against the canonical compilation.
5. Enables IPv4 forwarding only after successful readback, then verifies it.

Failures return `enforced:false` with the error, record failure and attempt to keep
forwarding disabled. A failed installation leaves the managed session available for
diagnosis with its ownership and generation intact. Restart after correction; no
automatic retry or policy replacement occurs. Host firewall tables are never flushed
or changed. Status checks verify the namespace, generation/revision, actual rule
semantics/fingerprint and forwarding. Counters can change without invalidating the
fingerprint. Unexpected changes mark enforcement failed and disable forwarding when
namespace identity is still confirmed. A cleanup failure is reported explicitly.

Generation-scoped append-only JSONL is retained under
`data/core-runtime/firewall-evidence/<generation>.jsonl`. GUI-created sessions also
append matching events through the existing run store with session/generation IDs:
`firewall_initialized`, `firewall_configuration_loaded`, `firewall_rules_installed`,
`firewall_installation_failed`, `firewall_enforcement_state`, and controlled
`packet_allowed`/`packet_denied`/`packet_verification_failed` events.

The GUI distinguishes the existing model decision from runtime enforcement. ACTIVE
requires an installation verified for the same active revision, session and generation;
failure shows the reason. A stale or unavailable refresh clears the ACTIVE display.
Installation status never implies that an observed packet was blocked.

## Controlled verification

Run inside the configured WSL application environment:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv-wsl/bin/python -m scripts.verify_core_firewall
```

The script refuses an occupied managed runtime **before changing topology or sending
packets**. It temporarily activates the canonical `examples/core_firewall_smoke.json`,
uses the existing compiler and owned start path, creates a run for evidence, and
issues one bounded ICMP request each from an allowed and denied client to a destination
across FW-1. It requires a successful reply plus the correct accept counter increase
for allowed traffic, and ping failure plus the specific drop counter increase for
denied traffic. A timeout alone is not blocking evidence. No PPO, watcher, exploit,
external destination or long-running listener is started. Generation checks protect
probe/cleanup requests from session replacement. The owned session is deleted and
the previous canonical topology restored after successful cleanup; startup cleanup
failures retain the matching topology for diagnosis.

The current session was occupied during development, so live packet verification is
pending. Offline tests exercise compilation, interface mapping, rule ordering/defaults,
actual-readback validation, installation failure, host namespace refusal, status drift,
counter changes, bounded probe evidence and GUI status. Installed CORE wrapper tests
also verify the generated node/link definitions. No packet success/drop is claimed
until the controlled live smoke completes.

Focused commands:

```sh
.venv-wsl/bin/python -m unittest scripts.test_firewall_core scripts.test_gns3_firewall scripts.test_external_mvp scripts.test_canonical_architecture -v
/opt/core/venv/bin/python -m unittest scripts.test_core_integration -v
.venv-wsl/bin/python -m scripts.test_core_runtime_serialization
node scripts/test_external_frontend.js
node scripts/test_gui_frontend.js
node scripts/test_gui_report_frontend.js
```

## Files changed for this task

- New: `firewall/compiler.py`, `firewall/runtime.py`, `firewall/smoke.py`,
  `testbed/firewall_topology.py`, `scripts/verify_core_firewall.py`,
  `scripts/test_firewall_core.py`, `examples/core_firewall_smoke.json`,
  `docs/CORE_FIREWALL_ENFORCEMENT.md`.
- Updated: `testbed/generate_core_topo.py`, `testbed/core_xml.py`,
  `testbed/topology.py`, `scripts/core_session.py`, `scripts/test_core_integration.py`,
  `gui/adapter.py`, `gui/campaign.py`, `gui/imports.py`, `gui/web/app.js`,
  `gui/web/external.js`, `scripts/test_external_frontend.js`.

Validation results: 60 application-environment Python tests passed; 23 installed-CORE
Python tests passed (11 firewall unit tests overlap); the CORE helper serialization
regression and all three mocked frontend suites passed. XML converted successfully
through the installed CORE wrapper classes. `git diff --check` passed. Existing
Pandapower/Pymodbus deprecation warnings remain. The live smoke entry point refused
the occupied runtime; session 1 remained RUNTIME with 18 nodes and its watcher IDLE.
No commits, pushes, resets or untracked-file cleanup were performed.
