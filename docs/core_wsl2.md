# CORE 9.2.1 / WSL2 operation

Run this checkout from WSL, not Windows Python. The dedicated GUI is served by
`gui.server` using Python's HTTP server; there is no Flask/FastAPI server or
database. CORE runs as a privileged daemon; the GUI itself does not need sudo.

## Environment

Keep the working CORE Python 3.12 installation intact. Use a separate Python
3.12 application environment (the Windows `venv/Scripts` directory cannot run
under WSL):

```bash
cd /mnt/d/1.STUDY_MATERIALS/Cyber_Major_project/Project/V2/ascend-pg-webapp
uv venv --python /opt/core/venv/bin/python .venv-wsl
uv pip install --python .venv-wsl/bin/python -r requirements.txt
```

The requirements file includes a CUDA package index. For a CPU-only machine,
install PyTorch from its CPU index before installing the other dependencies.
Suricata, its YAML configuration, and CORE networking utilities must be installed
in WSL. The repository's Modbus rules are explicitly passed to Suricata.

Optional exported environment variables (these are not automatically loaded from
an `.env` file):

| Variable | Default |
| --- | --- |
| `ASCEND_CORE_PYTHON` | `/opt/core/venv/bin/python` |
| `ASCEND_CORE_ADDRESS` | `localhost:50051` |
| `ASCEND_APP_PYTHON` | `<checkout>/.venv-wsl/bin/python` |
| `ASCEND_SURICATA` | `/usr/bin/suricata` |
| `ASCEND_SURICATA_CONFIG` | `/etc/suricata/suricata.yaml` |
| `ASCEND_SURICATA_EVE` | `<checkout>/data/core-runtime/suricata/eve.json` |

The configured daemon must run on the same WSL machine and see the same absolute
paths. Keep gRPC on loopback; CORE grants privileged node execution to its clients.
Systemd is optional: the application checks gRPC readiness, not systemd state.
If using the existing service, `systemctl status core-daemon` diagnoses it.

## Managed workflow

```bash
.venv-wsl/bin/python testbed/generate_core_topo.py --case 14
/opt/core/venv/bin/python scripts/core_session.py health
/opt/core/venv/bin/python scripts/core_session.py start core_topology.xml
/opt/core/venv/bin/python scripts/core_session.py status
# Start only when ready to accept attack requests from Live Battle:
/opt/core/venv/bin/python scripts/core_session.py watcher
# Stop the owned session, its nodes, and their processes:
/opt/core/venv/bin/python scripts/core_session.py stop
```

Launch the UI with `.venv-wsl/bin/python -m gui.server`, then open
`http://127.0.0.1:8765`. The Run / CORE page exposes these operations and
displays actual errors.
Launch `core-gui` without an XML positional argument to attach to a running
session or use its File > Open menu.

One managed session and one watcher are allowed per checkout because the existing
PPO pending/result queue is shared. Stop before regenerating/replacing a session.
State is stored in `data/core-runtime/session.json`; ownership metadata prevents
deleting unrelated sessions after daemon restarts or session ID reuse. Do not
delete that state while a session is running. Failed startup attempts are deleted
using the exact session ID allocated for the attempt. Cleanup failures retain the
ID and are reported, rather than hidden.

## Direct CLI / GUI XML import

```bash
.venv-wsl/bin/python testbed/generate_core_topo.py --case 30 --output data/core_topology_30.xml
/opt/core/venv/bin/python scripts/core_session.py register data/core_topology_30.xml
/opt/core/venv/bin/core-cli xml -f data/core_topology_30.xml
# Add -s to start immediately; delete the exact returned ID when finished:
/opt/core/venv/bin/core-cli session -i SESSION_ID delete
```

Registration is required after every daemon restart. It uses CORE's CreateService
API and does not modify CORE or require a daemon restart. Service names contain a
fingerprint of the full scripts, avoiding mutable definitions shared by sessions.
CORE 9.2.1's API-created CustomCoreService ignores per-node XML overrides when
rendering; therefore registration supplies the real templates for each definition.

Do not run direct CLI sessions alongside a managed session from the same checkout:
SCADA/IDS/PPO files are shared. Direct CLI sessions are not owned by the application
and must be cleaned up with their explicit ID. CORE's CLI may print a gRPC error
while returning exit code zero; inspect its response. Its OpenXml handler also
leaks a definition session for some non-IO errors. The managed workflow uses a
known session ID and StartSession instead.

## Diagnostics and tests

```bash
/opt/core/venv/bin/python scripts/test_core_integration.py
.venv-wsl/bin/python scripts/test_integration.py
.venv-wsl/bin/python scripts/test_sim_page.py
```

Node-local `ascend.log`, `ascend.pid`, and service scripts reside under the node's
CORE directory. The attacker watcher writes `ascend-watcher.log` there. Suricata
EVE is in `data/core-runtime/suricata/eve.json`. PLCs receive an explicit bus metadata
snapshot, avoiding an incorrect IEEE-14 default in an IEEE-30 session and avoiding
30 redundant Pandapower calculations during startup.

Supported generated CORE topologies are IEEE-14 and IEEE-30 using a central hub
(default) or switch. Electrical grid links remain in the existing grid model;
the hub represents the OT communication network. A switch does not mirror all
unicast traffic to IDS. User-uploaded custom topologies are not exported by this
generator; do not claim that an IEEE case export represents an uploaded topology.
