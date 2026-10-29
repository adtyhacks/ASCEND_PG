# ASCEND-PG

ASCEND-PG is a local power-grid cybersecurity assessment platform. It combines a
Pandapower electrical-grid model, a CORE network testbed, a PPO attack campaign,
Suricata and learned detection, and reports built from saved assessment evidence.
Run the application and CORE on the same Ubuntu Linux machine or Ubuntu WSL2
distribution. The browser can run on Windows when the server runs inside WSL2.

The current network emulator is **CORE 9.2.1**. The managed workflow does not
require Mininet, Open vSwitch, Docker, EMANE, or OSPF/Quagga/FRR. Generated session
options disable OVS. Some older scripts and documentation retain Mininet/OVS
references; those are not instructions for this workflow.

## Contents

- [Project overview](#project-overview)
- [Features](#features)
- [Architecture](#architecture)
- [System requirements](#system-requirements)
- [Ubuntu installation](#ubuntu-installation)
- [CORE installation and configuration](#core-installation-and-configuration)
- [Configuration](#configuration)
- [Running ASCEND-PG](#running-ascend-pg)
- [Application workflow](#application-workflow)
- [Testing and validation](#testing-and-validation)
- [Troubleshooting](#troubleshooting)
- [Project structure](#project-structure)
- [Runtime data and Git hygiene](#runtime-data-and-git-hygiene)
- [Stopping services and cleanup](#stopping-services-and-cleanup)
- [Security and limitations](#security-and-limitations)

## Project overview

Select an IEEE-14, IEEE-30, or validated custom electrical topology. The application
projects that selection into a CORE communication network containing PLCs, SCADA,
an attacker, and an IDS monitor. A campaign selects attack steps with a trained PPO
policy and submits them to a watcher inside the managed attacker namespace.
The executor records execution outcomes separately from detector verdicts.
Reports use saved run-scoped evidence rather than treating background traffic as
attack findings.

The primary application is `python -m gui.server`, a local HTTP server serving
`gui/web/`. It is not a Flask/FastAPI service and requires no database. The older
`app/` Streamlit interface is not the supported launch path in this guide;
Streamlit is not listed in the current `requirements.txt`.

## Features

- IEEE-14 and IEEE-30 electrical-grid configuration and modeled power-flow status.
- Custom JSON topology validation, saving, selection, and CORE export.
- Managed CORE session creation, status, ownership-scoped shutdown, and optional
  attachment of CORE's desktop GUI.
- PPO assessment initialization, individual steps, bounded full campaigns, and
  PLC network-interface isolation/restoration controls.
- Suricata Modbus rules, LSTM and autoencoder detection, and hybrid verdicts.
- Separate views of run-scoped security events, network events, and background
  SCADA/Suricata observations, with technical evidence details.
- Reports for saved assessments with HTML generation, viewing, and download.

The GUI does not expose a PDF download. Lower-level report code includes PDF
rendering, but the current Reports page delivers HTML.

## Architecture

```text
Browser on localhost:8765
  -> gui.server / gui.adapter / gui.campaign
      -> testbed.topology -> Pandapower electrical model
      -> testbed.generate_core_topo -> core_topology.xml
      -> testbed.core_runtime -> scripts/core_session.py
          -> CORE gRPC daemon on localhost:50051
              -> Linux node namespaces and hub communication network
                  -> PLC Modbus servers + SCADA + Suricata IDS
                  -> attacker watcher -> scripts/testbed_executor.py
                      -> registered attack implementation
                      -> Suricata + LSTM/AE hybrid detection
                      -> pending/result handoff to campaign controller
      -> testbed.run_store -> saved JSON/JSONL evidence
      -> gui.reporting -> reports.pentest_report -> HTML report
```

The CORE helper validates the generated XML, registers fingerprinted application
service templates through CORE's API, converts the XML to gRPC session objects,
and calls `StartSession` for a known allocated session ID. Thus
`core_topology.xml` is consumed by the current managed execution path; it is not
just a drawing. Direct `core-cli xml` import is unnecessary for the GUI workflow.

The electrical grid's buses and lines differ from its OT communication topology.
Electrical edges remain in the Pandapower model. CORE uses a central hub by
default so the IDS can observe shared traffic. An optional generated switch does
not automatically mirror all unicast traffic. Editing a CORE drawing does not
update the application's electrical model.

## System requirements

| Component | Requirement or scope |
| --- | --- |
| Operating system | Ubuntu Linux or Ubuntu **WSL2**, with working Linux network namespaces and CORE's native utilities. Native Windows Python and WSL1 cannot run the managed testbed. |
| Reference environment | Ubuntu **22.04.5 LTS**, application Python **3.12**, CORE **9.2.1**, and Suricata **6.0.4** were found in the existing installation. Ubuntu 22.04 LTS is the reproduction baseline. |
| Other Ubuntu releases | Ubuntu 24.04 LTS provides distribution Python 3.12, but a fresh installation on it has not been validated for this checkout. Do not treat that as a tested environment. |
| Python environments | Python 3.12 for the application. The CORE helper needs CORE 9.2.1's Python package and `grpcio`; these are not installed by application requirements. CORE's own installer supports Python 3.9+, but use its matching installed interpreter for the helper. |
| CORE | Privileged `core-daemon`, Python gRPC client/wrappers, native `vnoded` and `vcmd`, and Linux networking utilities. Installing only a Python package is insufficient. |
| Suricata | Executable, readable YAML configuration, Modbus protocol support, and this repository's rule file. Managed startup checks that the executable/configuration exist. |
| Permissions | `sudo` for system packages, CORE installation, daemon startup and service changes. The browser server itself runs as the ordinary user. Node processes and packet capture execute through privileged CORE. |
| GPU | Not required. CPU PyTorch works; the requirements file also contains a CUDA 12.4 package index. |
| Desktop display | Required only for optional `core-gui`: Linux desktop, WSLg or a configured X server. Not required for the browser UI. |

There is no measured minimum RAM/CPU specification. Capacity depends on topology
size, model loading and traffic. Keep the daemon, GUI, helper and node service
paths on the same machine. The daemon must be able to read the checkout and the
application interpreter; node services use absolute paths generated at startup.

For WSL2, use an Ubuntu terminal for every Bash command below. If systemd is
unavailable, the foreground daemon option works without it. Enabling WSL systemd
is optional and follows [Microsoft's WSL instructions](https://learn.microsoft.com/windows/wsl/systemd);
that host-level change requires a planned WSL shutdown and should not interrupt an
active assessment. A Linux-filesystem clone is preferable for fresh installations;
the existing mounted checkout can be reused without moving it.

## Ubuntu installation

### Existing working WSL2 installation

Do not reinstall CORE, recreate `.venv-wsl`, or upgrade dependencies merely to
launch an already working installation. In the existing checkout, CORE and the
application are both installed in `.venv-wsl`; `/opt/core/venv` is not present.

```bash
# Existing checkout from this project; use your own checkout path elsewhere.
cd /mnt/c/project/ascend-pg-webapp
test -x .venv-wsl/bin/python
source .venv-wsl/bin/activate
python --version
python -c 'import pandapower, pymodbus, torch; import core.api.grpc.client; import grpc'
export ASCEND_APP_PYTHON="$PWD/.venv-wsl/bin/python"
export ASCEND_CORE_PYTHON="$PWD/.venv-wsl/bin/python"
export ASCEND_CORE_ADDRESS=localhost:50051
# Optional CORE desktop GUI, if installed in this same environment:
export ASCEND_CORE_GUI="$PWD/.venv-wsl/bin/core-gui"
```

Continue with [Running ASCEND-PG](#running-ascend-pg). If the environment path is
missing or broken, diagnose it before creating a replacement. Virtual environments
are not portable between Windows and Linux or after moving their base interpreter.

### Fresh installation

The steps below are source/configuration-checked instructions, not a claim that a
fresh machine was provisioned during documentation validation.

**Terminal 1 — install prerequisites (`sudo` required):**

```bash
sudo apt update
sudo apt install -y git curl ca-certificates build-essential autoconf automake \
  pkg-config libev-dev nftables iproute2 ethtool procps iputils-ping \
  python3 python3-pip python3-venv python3-tk tk suricata
```

CORE's versioned installer also installs its native build/runtime dependencies.
The managed hub topology does not need routing suites or OVS packages. Suricata's
distro service, if enabled by package installation, is separate from the per-node
Suricata instance CORE starts; ASCEND-PG does not require starting that host service.

For lower-level WeasyPrint PDF rendering, install these native libraries (`sudo`
required). They are not needed just to serve the browser or download HTML:

```bash
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
  libharfbuzz-subset0 fonts-dejavu-core
```

See the [WeasyPrint Ubuntu installation guidance](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#ubuntu-20-04)
if an installed version reports a missing native library.

**Clone branch `Abin`:**

```bash
mkdir -p ~/src
cd ~/src
git clone --branch Abin https://github.com/root-FURY127/ascend-pg-webapp.git
cd ascend-pg-webapp
```

For an existing clone, keep its current changes and use its own directory instead
of cloning over it. Do not reset or switch branches while unrelated work is present.

**Create the application environment once:** Ubuntu 22.04's default Python is not
3.12. One supported way to obtain a separate 3.12 interpreter is
[uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
curl -LsSf https://astral.sh/uv/install.sh -o /tmp/ascend-uv-install.sh
# Inspect the installer before running it.
less /tmp/ascend-uv-install.sh
sh /tmp/ascend-uv-install.sh
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.12
uv venv --seed --python 3.12 .venv-wsl
source .venv-wsl/bin/activate
python -m pip install --upgrade pip
```

On Ubuntu 24.04, `sudo apt install python3.12 python3.12-venv` followed by
`python3.12 -m venv .venv-wsl` is an alternative to uv. Do not run either creation
command over a working `.venv-wsl`.

**Install Python dependencies — select one path:**

```bash
# Standard requirements, including the extra CUDA 12.4 wheel index.
python -m pip install -r requirements.txt
```

For an explicitly CPU-only installation, keep `requirements.txt` unchanged and
use a temporary filtered copy to exclude its Torch/index lines:

```bash
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
ascend_cpu_requirements=$(mktemp)
sed '/^--extra-index-url[[:space:]]/d; /^torch[[:space:]]*$/d' \
  requirements.txt > "$ascend_cpu_requirements"
python -m pip install -r "$ascend_cpu_requirements"
rm -- "$ascend_cpu_requirements"
python -m pip check
```

The requirements cover Pandapower, PyVis, NumPy, pandas, scikit-learn, Torch,
Gymnasium, Stable-Baselines3, SHAP, LIME, Matplotlib, Plotly, Jinja2, WeasyPrint,
`pymodbus==3.14.*`, fpdf2, Markdown and Scapy. Most versions are not pinned;
a fresh resolution may differ from the existing installation. Retain a working
environment and its version inventory rather than assuming upgrades are compatible.

Install CORE separately next. Do not install an unrelated PyPI package named
`core` as a substitute for Common Open Research Emulator.

## CORE installation and configuration

### Fresh CORE installation only

Use CORE **9.2.1** to match the current gRPC/XML integration. These commands follow
the [versioned CORE README](https://github.com/coreemu/core/blob/release-9.2.1/README.md)
and [installer tasks](https://github.com/coreemu/core/blob/release-9.2.1/tasks.py).
The installer uses `sudo` internally; run it as the ordinary user. Do not run it
over an existing CORE installation.

**Terminal 1 — leave the application environment before installing CORE:**

```bash
deactivate
cd ~/src
git clone --branch release-9.2.1 --depth 1 https://github.com/coreemu/core.git
cd core
./setup.sh
source ~/.bashrc
inv install --no-ospf
```

Skipping OSPF is appropriate for ASCEND-PG's PLC/SCADA hub services. CORE installs
native utilities and its Python environment, configuration and systemd unit. The
standard source installer targets `/opt/core/venv`, but **verify that path** before
using it. This differs from the existing installation's `.venv-wsl` service.

```bash
command -v vnoded
command -v vcmd
command -v core-daemon
systemctl cat core-daemon
test -x /opt/core/venv/bin/python
/opt/core/venv/bin/python -c 'import importlib.metadata as m; import core.api.grpc.client; import grpc; print(m.version("core"))'
```

If your installer uses a different location, use that actual interpreter below.
If systemd is not enabled, omit `systemctl` and use foreground startup instead.

### Interpreter and endpoint configuration

Back in the **application checkout**, activate its environment and export paths
before launching the GUI. This is the separate-environment example after the
standard CORE source installation:

```bash
cd ~/src/ascend-pg-webapp
source .venv-wsl/bin/activate
export ASCEND_APP_PYTHON="$PWD/.venv-wsl/bin/python"
export ASCEND_CORE_PYTHON=/opt/core/venv/bin/python
export ASCEND_CORE_ADDRESS=localhost:50051
export ASCEND_CORE_GUI=/opt/core/venv/bin/core-gui
"$ASCEND_CORE_PYTHON" -c 'import core.api.grpc.client; import grpc'
```

For an existing shared environment, use the `.venv-wsl` exports in the reuse
section instead. The GUI's default CORE helper interpreter is
`<checkout>/.venv-wsl/bin/python`, **not** `/opt/core/venv/bin/python`.

CORE 9.2.1's default configuration location is `/opt/core/etc/core.conf`. Verify
the daemon's `--help` and service `ExecStart` when an installation differs. Its
local endpoint configuration is:

```ini
[core-daemon]
grpcaddress = localhost
grpcport = 50051
```

Keep gRPC on loopback: clients can request privileged node execution. Do not
publish port 50051 to a LAN or use a remote daemon with different filesystem paths.
Changing a running daemon's configuration takes effect only on a planned restart
after stopping its sessions; normal application launches need no daemon restart.

The service must have a real executable in `ExecStart`. If `systemctl cat
core-daemon` shows a literal placeholder such as `$DAEMON` with no valid override,
the unit needs repair. For a shared `.venv-wsl` installation, this is an example
override **only when needed**, from the checkout (`sudo` required):

```bash
test -x "$PWD/.venv-wsl/bin/core-daemon"
sudo mkdir -p /etc/systemd/system/core-daemon.service.d
sudo tee /etc/systemd/system/core-daemon.service.d/ascend.conf >/dev/null <<EOF
[Service]
ExecStart=
ExecStart=$PWD/.venv-wsl/bin/core-daemon
Environment=PYTHONDONTWRITEBYTECODE=1
EOF
sudo systemctl daemon-reload
```

Use a stable checkout path without spaces for this unit example. Preserve any
existing administrator overrides; do not overwrite a working service. Reloading
unit definitions is not restarting the daemon. If repairing an active service,
schedule shutdown first rather than changing it during an assessment.

### Suricata configuration

Set the existing YAML's `app-layer.protocols.modbus.enabled` to `yes`, ensure TCP
502 is recognized for Modbus, and keep EVE JSON output enabled with alert and flow
events. Edit the existing entries rather than adding duplicate YAML keys. Review
the installed Suricata version's schema before changing it.

The CORE IDS service passes the repository rules with `-S`; no manual copying of
rules into `/etc/suricata/rules` or OVS mirror port is needed. Validate before
starting a session (`sudo` required; this tests configuration without capturing
traffic):

```bash
ascend_suricata_check=$(mktemp -d)
sudo /usr/bin/suricata -T -c /etc/suricata/suricata.yaml \
  -S "$PWD/detection/suricata/modbus_rules.rules" -l "$ascend_suricata_check"
```

Use your configured executable/YAML paths if overridden. Inspect the exit status
and rule-loading errors. The temporary directory holds validation logs; this does
not overwrite campaign EVE evidence. The older [Suricata setup document](docs/suricata_setup.md)
describes a legacy Mininet/OVS workflow and is not the setup procedure for CORE.

## Configuration

Environment variables must be **exported in the shell before starting the GUI**.
There is no automatic `.env` loader. Both the GUI process and any manually invoked
CORE helper need the relevant exports.

| Variable | Current default | Purpose |
| --- | --- | --- |
| `ASCEND_CORE_PYTHON` | `<checkout>/.venv-wsl/bin/python` | Interpreter running `scripts/core_session.py`; must import CORE and gRPC. |
| `ASCEND_APP_PYTHON` | `<checkout>/.venv-wsl/bin/python` | Interpreter embedded in generated PLC/SCADA/watcher services. |
| `ASCEND_CORE_ADDRESS` | `localhost:50051` | CORE gRPC endpoint. |
| `ASCEND_CORE_GUI` | `/opt/core/venv/bin/core-gui` | Optional desktop GUI executable; override for shared `.venv-wsl` installations. |
| `ASCEND_SURICATA` | `/usr/bin/suricata` | IDS executable. |
| `ASCEND_SURICATA_CONFIG` | `/etc/suricata/suricata.yaml` | IDS YAML configuration. |
| `ASCEND_SURICATA_EVE` | `<checkout>/data/core-runtime/suricata/eve.json` | Hybrid detector's EVE reader path. This does not relocate the IDS writer. |
| `ASCEND_CAPTURE_IFACE` | Automatically discovered | ML capture interface. Usually leave unset; node capture uses `eth0`. |

`ASCEND_SESSION_ID` and `ASCEND_SESSION_GENERATION` are injected by the managed
watcher launcher. Do not manually set them to bypass session ownership checks.
If overriding the EVE reader path, ensure it points to the file the IDS actually
writes; the generated IDS service writes into `data/core-runtime/suricata/`.

Important configuration and evidence files:

- `data/sample_topologies/`: predefined references and saved custom definitions.
- `data/topology_selection.json`: persisted selected topology.
- `core_topology.xml`: generated communication topology and service templates;
  regenerated by GUI **Start CORE** for the selected topology.
- `testbed/ip_config.py`: canonical network addresses and PLC-count bounds.
- `data/mitre_registry.py`: attack catalogue, implementation and detector mappings.
- `detection/suricata/modbus_rules.rules`: application IDS signatures.
- `models/rl_agent.zip`: required PPO checkpoint for campaign initialization.
- `models/lstm_detector.pt`, `models/autoencoder_detector.pt`, and
  `models/autoencoder_threshold.json`: required learned-detector artifacts.
- `data/core-runtime/session.json`: owned session ID, endpoint and generation token.
- `data/runs/<scenario_id>/<run_id>/`: run metadata, topology snapshot, JSONL event
  streams, saved evaluation and generated `report.html` when available.

Custom JSON uses a `custom_` case name, ordered consecutive zero-based `bus_id`
values, bus types `slack`, `pv` or `pq`, exactly one slack bus, and valid connected
edges. Canonical PLC IPs are assigned by the application. Download the template
from Network Setup instead of guessing the complete schema. Stop the owned session
before changing topology; the UI rejects changes while it is active.

## Running ASCEND-PG

### Terminal 1 — check or start the daemon

Activate/export your paths using either the existing-installation or fresh-install
section, from the application checkout. Check the service first:

```bash
systemctl status core-daemon --no-pager
```

If it is inactive and correctly configured, start it (`sudo` required):

```bash
sudo systemctl start core-daemon
```

Leave an already healthy daemon running. Autostart is optional and requires
`sudo systemctl enable core-daemon`. Check actual gRPC readiness:

```bash
"$ASCEND_CORE_PYTHON" scripts/core_session.py health
```

Expect JSON with `ok: true` and `daemon_ready: true`. The helper checks gRPC, not
systemd alone. Its health command can create helper lock/directory metadata but
does not create a session or execute attacks.

**Without systemd**, keep a dedicated terminal open and launch the installed
daemon in the foreground (`sudo` required), only if another daemon is not running:

```bash
sudo "$ASCEND_CORE_PYTHON" "$(dirname "$ASCEND_CORE_PYTHON")/core-daemon" \
  --grpc-address localhost --grpc-port 50051
```

This explicit path works even when `sudo` does not inherit the activated venv PATH.
The daemon still needs native `vnoded`/`vcmd` available on its PATH.

### Terminal 2 — launch the browser server

Open another Ubuntu terminal, enter the same checkout, activate `.venv-wsl`, and
repeat the appropriate `ASCEND_*` exports. Exports from Terminal 1 are not inherited
by a separately opened terminal.

```bash
source .venv-wsl/bin/activate
python -m gui.server
```

Open **<http://127.0.0.1:8765>** in your browser. The server binds to loopback on
fixed port 8765; no port environment variable or command-line override is
implemented. In WSL2, try the Windows browser's localhost forwarding first. Keep
the terminal running and use its tracebacks when diagnosing API failures.

Starting the HTTP server does not create a CORE session or launch a campaign.
Use the managed GUI workflow below. Do not start a second GUI or managed session
against the same checkout's shared queue.

## Application workflow

1. **Landing:** enter the workspace or inspect the Sample Environment. Sample
   content is illustrative and does not start a real assessment.
2. **Network Setup:** select IEEE-14/IEEE-30 or download, edit, validate and save a
   custom JSON topology. Confirm the selection before proceeding.
3. **Network & Grid Status:** inspect the electrical baseline, modeled voltage and
   power, and available observations. Missing/stale PLC reads do not prove a
   physical shutdown.
4. **Start CORE / Run CORE:** select **Start CORE**. It generates XML for the current
   topology, creates a saved run, registers services and starts the owned session.
   Confirm `RUNTIME` and resolve startup errors before continuing.
5. **Start monitoring:** this launches the attacker-node PPO watcher. **It enables
   execution of pending campaign requests**, rather than merely opening a passive
   monitoring view. Check for an `IDLE` heartbeat in the current generation before
   starting an assessment. Do not start it if an old pending request has not been
   understood and resolved through the managed workflow.
6. **Assessment:** initialize the campaign, then use an individual step or a bounded
   full campaign only when ready to execute attacks inside the isolated testbed.
   Distinguish executed/failed/timed-out steps from detector verdicts and verified
   effects. Isolation/restoration changes the selected PLC's CORE `eth0` link state.
7. **Reports:** select the saved assessment and generate, open or download HTML.
   Report generation needs completed attack evidence, not just a running session.
   Reports reuse saved evaluation; they do not run a fresh campaign to calculate DVS.

CORE's optional **Open CORE GUI** attaches to the owned communication session. It
needs a working display and the correct `ASCEND_CORE_GUI` executable. The browser
workflow remains usable without it.

Only one owned session and one watcher are supported per checkout. Do not run
direct `core-cli` sessions alongside the managed GUI: SCADA, IDS and PPO handoff
files are shared. For low-level XML registration/import details see
[docs/core_wsl2.md](docs/core_wsl2.md), but note its older `/opt/core/venv` examples
and custom-export limitations do not describe every current installation; the
code and interpreter table above take precedence.

## Testing and validation

The following selected regression tests use mocks and temporary artifacts. They
do not contact a live daemon, launch a session, run live attacks or replace saved
run evidence. Run from the checkout with the existing application environment that
also imports CORE, or an application test environment containing CORE 9.2.1's
Python package. A separate CORE-only environment lacks application dependencies.

```bash
python -B -m unittest \
  scripts.test_core_integration \
  scripts.test_custom_topology.CustomTopology.test_custom_representation_roundtrip_and_addresses \
  scripts.test_custom_topology.CustomTopology.test_custom_core_xml_and_gui_session_projection \
  scripts.test_custom_topology.CustomTopology.test_predefined_selection_and_core_consistency \
  scripts.test_campaign_topology_targets \
  scripts.test_core_namespace_preflight \
  scripts.test_finding_evidence
# Keep this module in a fresh process: it asserts PPO has not been imported.
python -B -m scripts.test_dvs_reports
python -B -m scripts.test_core_runtime_serialization
```

These check XML/service contracts, mocked lifecycle cleanup, custom topology and
target validation, namespace evidence, DVS/report handling, finding evidence and
helper serialization. They are not end-to-end proof of live attack or IDS success.
The full `test_custom_topology` module includes an older session-marker test that
can invoke a real CORE status query and whose expected error wording no longer
matches the implementation. It is excluded from this safe selection. Combining
the DVS module with campaign tests in one process also invalidates its import
isolation assertion; run it separately as shown.
Do not run broad test discovery or all `verify_*` scripts against a live checkout
without inspecting them; older integration scripts can write reports/runtime
artifacts or perform live operations. `scripts/verify_core_live.py`, campaign
controls and `scripts/run_cycle.py` are not documentation smoke tests.

Safe inspection commands include:

```bash
python -c 'import sys; print(sys.executable); print(sys.version)'
"$ASCEND_CORE_PYTHON" -c 'import importlib.metadata as m; import core.api.grpc.client; print(m.version("core"))'
git diff --check
```

Installation instructions were checked against repository sources, CORE 9.2.1's
installer/CLI and the existing Ubuntu configuration. A clean installation, package
upgrades, a new session and attack traffic were not executed to validate this guide.

## Troubleshooting

| Symptom | Check and resolution |
| --- | --- |
| `ModuleNotFoundError` for application packages | Check `python`'s executable, activate `.venv-wsl`, and install requirements in that environment only when needed. Use `python -m pip` or `uv pip --python .venv-wsl/bin/python`; do not use Windows Python or `sudo pip`. |
| `No module named core` / `grpc` | Application requirements do not install CORE. Set `ASCEND_CORE_PYTHON` to the matching CORE interpreter and test its imports. The documented regression suite also needs CORE's package in its application test environment. |
| Missing `/opt/core/venv` | It is an installer-specific path, not a repository prerequisite. Check the service's actual `ExecStart`; the existing installation uses `.venv-wsl`. |
| Broken `.venv-wsl/bin/python` | Inspect `.venv-wsl/pyvenv.cfg` and the base interpreter. Restore the expected interpreter or build a separate replacement deliberately; moving a venv does not repair it. |
| CORE daemon unavailable / gRPC timeout | Check the exported address, service status and `journalctl -u core-daemon -n 50 --no-pager`. Verify listener with `ss -ltnp 'sport = :50051'`. Resolve the executable/configuration error before starting an inactive service. Avoid restarting a healthy daemon. |
| Service has `ExecStart=$DAEMON` | Inspect drop-ins with `systemctl cat core-daemon`; an override can supply the real executable. Follow the conditional unit repair above only if no valid override exists. |
| Owned session already exists | Use **Stop CORE Session** before replacing topology/session. Do not delete session state while the session runs. |
| Stale session, ownership mismatch or old generation | Inspect `data/core-runtime/session.json` and current helper status. The helper rejects another owner's session. Stop the owned session through the UI/helper; preserve state on cleanup failure and investigate the exact recorded ID. Never delete all CORE sessions or bypass ownership checks. |
| Watcher unavailable/stale | Confirm session is `RUNTIME`, heartbeat belongs to its ID/generation, and status is `IDLE`. Inspect attacker-node `ascend-watcher.log` and `data/watcher_heartbeat.json`. Do not run a watcher in the host namespace. |
| Namespace preflight failure | The watcher verifies isolated namespace, canonical addresses/routes and interface `eth0`. Do not disable this check, attach external interfaces or add external routes to make an attack run. |
| Topology validation failure | Use the downloadable template; check case name, ordered bus IDs, slack bus, connected valid edges, numeric fields, canonical addresses and supported PLC templates. Stop CORE before changing selection. |
| Suricata unavailable/no alerts | Check executable/YAML overrides, Modbus/EVE configuration, `-T` validation and `data/core-runtime/suricata/suricata.log`. Confirm the reader and writer use the same EVE file. A switch without mirroring may hide traffic; no alerts alone do not establish evasion. |
| Missing or incompatible models | Confirm the four campaign/detector files listed above. Inspect load errors and dependency versions; missing ML availability is not a negative detector verdict. Do not generate substitute experimental values. |
| CORE desktop GUI fails | Check display variables, WSLg/X availability and `ASCEND_CORE_GUI`; attach through the managed button instead of launching a second session from XML. |
| Port 8765 already in use | Inspect `ss -ltnp 'sport = :8765'`. Reuse the intended server or stop your duplicate process with Ctrl+C. The current server has no alternate-port option; do not kill unrelated processes. |
| Reports unavailable | Select a run with completed attack evidence. Resolve malformed/mismatched JSONL records without silently rewriting retained evidence. HTML download does not need a PDF renderer. |

Legacy error strings may mention Streamlit, Mininet-style interface names or older
paths. Diagnose the current managed CORE path rather than installing Mininet/OVS
to satisfy an obsolete message.

## Project structure

```text
gui/          Dedicated HTTP server, adapters, campaign/grid/report controllers
  web/        Browser HTML, JavaScript and styles
testbed/      Electrical topology, CORE XML/services, PLC/SCADA implementations
scripts/      CORE lifecycle helper, watcher, executor, diagnostics and tests
attacks/      Implementations selected by the attack registry
strategic/    PPO environment, training and evaluation code
defense/      Live capture/features, hybrid and ML detector integration
detection/    Learned models, training/fusion and Suricata rules
metrics/      Campaign evaluation, severity, verified finding evidence and DVS
reports/      Report normalization and HTML/PDF rendering support
data/         Topology definitions, runtime queues, telemetry and saved runs
models/       PPO, detector and other learned checkpoints
xai/          Attack-decision explanation helpers
generative/   Generative-model code; not a prerequisite service for the GUI
app/          Older Streamlit interface
docs/         Additional audits and setup notes, including legacy instructions
requirements.txt
core_topology.xml
README.md
```

## Runtime data and Git hygiene

Preserve evidence before cleanup. The existing `.gitignore` excludes
`.venv-wsl/`, `data/core-runtime/`, `data/runs/`, `data/raw/`, `data/log_store.json`
and `data/cycle_report.json`, among other artifacts. It does **not** exclude every
generated file, and ignore rules never untrack files already committed.

Review these before staging: `core_topology.xml`, `data/pending_step.json`,
`data/step_result.json`, `data/topology_selection.json`, watcher lock/heartbeat
files, campaign history, episode logs, generated topology visualizations,
Suricata/SCADA telemetry and reports. Some historical runtime snapshots are already
tracked; do not remove or commit them accidentally during documentation work.
Custom definitions intentionally shared as fixtures should be reviewed separately
from generated evidence.

```bash
git status --short
git diff -- README.md
git diff --check
# For a documentation-only commit, stage the intended documentation explicitly.
git add -- README.md
git diff --cached --stat
```

Avoid `git add .`, destructive `git clean`, and deleting `data/runs/` merely to get
a clean status. Keep local interpreter paths and secrets out of commits.

## Stopping services and cleanup

1. Allow an active step to finish when possible and preserve the required evidence
   and report. Stopping with a pending result can leave episode evaluation incomplete.
2. Use **Stop CORE Session** in the GUI. This delegates ownership-scoped deletion
   of the session, nodes and their processes; it does not stop the daemon service.
   The equivalent helper commands, from a shell with the correct exports, are:

   ```bash
   "$ASCEND_CORE_PYTHON" scripts/core_session.py status
   "$ASCEND_CORE_PYTHON" scripts/core_session.py stop
   "$ASCEND_CORE_PYTHON" scripts/core_session.py status
   ```

3. Stop the GUI server with **Ctrl+C** in its terminal. Closing the browser or
   stopping the HTTP server alone does not delete the CORE session.
4. Leave a shared daemon running if others use it. If it is dedicated to this
   installation and all its sessions have been dealt with, stop its service with
   `sudo systemctl stop core-daemon`, or Ctrl+C in the foreground daemon terminal.

Do not delete `data/core-runtime/session.json` or watcher locks while their session
is active. Ownership metadata prevents deleting unrelated sessions after daemon
restarts or ID reuse. Failed cleanup retains the allocated ID for investigation.
Archive selected evidence deliberately after shutdown; no blanket deletion command
is part of the normal workflow.

## Security and limitations

Use ASCEND-PG only for authorized, isolated simulation and testing. The watcher
checks namespace isolation before attack execution. Keep CORE gRPC and the browser
server local, avoid external network attachments, and do not run raw attack scripts
from the host namespace. The local GUI is not an authenticated multiuser deployment.

Model voltage/power, successful subprocess return codes, detector confidence,
campaign stage completion and DVS each describe different quantities. None alone
proves physical compromise or real-world grid impact. Background traffic is not
automatically attack-correlated evidence. Findings with unavailable verification
must remain unavailable rather than being inferred from attack severity.

The retained implementation does not supply a calibrated compromise probability.
Measured monitoring error requires labeled positive and negative outcomes; time to
compromise and early warning require verified correlated outcome timestamps.
The current retained runs do not establish these metrics. A short event span is
not necessarily a completed experiment horizon.

Dependencies are largely unpinned, one pending/result queue is shared per checkout,
and arbitrary distributed/routed/container CORE topologies are outside the managed
XML contract. Use the tested version family and inspect errors rather than assuming
every upstream release or older project entry point is compatible.
