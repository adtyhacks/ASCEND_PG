"""CORE 9.2.1 service contract; registered through CreateService before import."""
import os
import json
import hashlib
from pathlib import Path
import shlex

SERVICE = "AscendApplicationV1"
FILES = ["ascend-start.sh", "ascend-validate.sh", "ascend-stop.sh"]
ROOT = Path(__file__).resolve().parents[1]


def service_name(scripts):
    digest = hashlib.sha256(json.dumps(scripts, sort_keys=True).encode()).hexdigest()[:20]
    return f"{SERVICE}_{digest}"


def app_python():
    return os.environ.get("ASCEND_APP_PYTHON", str(ROOT / ".venv-wsl/bin/python"))


def templates(command, *, probe=None):
    # CORE renders these as Mako templates; literal shell commands never contain
    # Mako expressions. Each node has its own working directory and PID file.
    command = shlex.join([str(x) for x in command])
    if "${" in command or "<%" in command:
        raise ValueError("Paths cannot contain Mako template delimiters")
    start = f"#!/bin/sh\nset -eu\n{command} > ascend.log 2>&1 &\necho $! > ascend.pid\n"
    validate = "#!/bin/sh\nset -eu\nsleep 2\nkill -0 \"$(cat ascend.pid)\"\n"
    if probe:
        validate += shlex.join([app_python(), "-c", probe]) + "\n"
    stop = '#!/bin/sh\nif [ -f ascend.pid ]; then kill "$(cat ascend.pid)" 2>/dev/null || true; rm -f ascend.pid; fi\n'
    return dict(zip(FILES, [start, validate, stop]))


def node_templates(role, case, ip=None, bus_id=None, node_data=None):
    python = app_python()
    if role == "plc":
        return templates([python, ROOT / "testbed/plc_server.py", "--ip", ip,
                          "--bus-id", bus_id, "--case", case,
                          "--node-json", json.dumps(node_data or {}, default=str)],
                         probe=f"import socket; socket.create_connection(({ip!r}, 502), 1).close()")
    if role == "scada":
        from testbed.ip_config import get_plc_ip
        return templates([python, ROOT / "testbed/scada_client.py", "--targets",
                          *[get_plc_ip(i) for i in range(case)], "--log", ROOT / "data/core-runtime/scada.jsonl"])
    if role == "ids":
        log_dir = ROOT / "data/core-runtime/suricata"
        return templates([os.environ.get("ASCEND_SURICATA", "/usr/bin/suricata"),
                          "-c", os.environ.get("ASCEND_SURICATA_CONFIG", "/etc/suricata/suricata.yaml"),
                          "-i", "eth0", "-l", log_dir,
                          "-S", ROOT / "detection/suricata/modbus_rules.rules",
                          "--set", "runmode=single"])
    raise ValueError(f"Unknown role: {role}")
