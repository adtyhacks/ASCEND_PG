"""Run with CORE's Python; bounded gRPC calls and ownership-scoped cleanup.

JSON stdin is used by Streamlit. CLI: register | health | start XML | status |
watcher | stop. Only one managed session per checkout because the existing PPO
queue and model telemetry are shared files.
"""
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grpc
from core.api.grpc import client, wrappers as w
from testbed.core_services import SERVICE, FILES, app_python
from testbed.core_xml import validate_xml, to_session

RUNTIME = ROOT / "data/core-runtime"
STATE = RUNTIME / "session.json"


class Deadlines:
    def __init__(self, stub):
        self.stub = stub

    def __getattr__(self, name):
        timeout = 150 if name == "StartSession" else 20
        return lambda request: getattr(self.stub, name)(request, timeout=timeout)


def register(c, root):
    # CORE 9.2.1 CustomCoreService renders defined_templates, ignoring XML
    # custom_templates. Register the actual scripts under immutable content IDs.
    known = {s.name for s in c.get_config().services}
    for config in root.findall("service_configurations/service"):
        name = config.get("name")
        if name in known:
            continue
        service = w.Service(group="ASCEND-PG", name=name, files=FILES,
                        startup=["sh ascend-start.sh"], validate=["sh ascend-validate.sh"],
                        shutdown=["sh ascend-stop.sh"],
                        validation_mode=w.ServiceValidationMode.NON_BLOCKING,
                        validation_timer=90, validation_period=1)
        scripts = {t.get("name"): t.text for t in config.findall("templates/template")}
        if not c.create_service(service, scripts):
            if name not in {s.name for s in c.get_config().services}:
                raise RuntimeError(f"CORE rejected service registration: {name}")
        known.add(name)


def owned_session(c):
    if not STATE.exists():
        return None
    state = json.loads(STATE.read_text())
    if state["endpoint"] != c.address:
        raise RuntimeError("Managed session belongs to a different CORE endpoint")
    if not c.check_session(state["id"]):
        STATE.unlink()
        return None
    session = c.get_session(state["id"])
    if session.metadata.get("ascend_owner") != state["token"]:
        raise RuntimeError("Session ownership mismatch; refusing to operate on another session")
    return session


def save_state(sid, token, endpoint):
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"id": sid, "token": token, "generation_id": token, "endpoint": endpoint, "created_at": time.time()}))
    temporary.replace(STATE)


def preflight():
    python = app_python()
    check = subprocess.run([python, "-c", "import pandapower, pymodbus; from pymodbus.datastore import ModbusDeviceContext"],
                           capture_output=True, text=True, timeout=120)
    if check.returncode:
        raise RuntimeError(f"Application interpreter dependencies failed: {check.stderr}")
    config = os.environ.get("ASCEND_SURICATA_CONFIG", "/etc/suricata/suricata.yaml")
    executable = os.environ.get("ASCEND_SURICATA", "/usr/bin/suricata")
    if not Path(config).is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("Suricata executable/config missing; set ASCEND_SURICATA and ASCEND_SURICATA_CONFIG")
    (RUNTIME / "suricata").mkdir(exist_ok=True)


def watcher_status(c, session):
    if not session or session.state != w.SessionState.RUNTIME:
        return "STOPPED"
    try:
        heartbeat = json.loads((ROOT / "data/watcher_heartbeat.json").read_text())
        state = json.loads(STATE.read_text())
        if (str(heartbeat.get("session_id")) == str(session.id)
                and heartbeat.get("generation_id") == state.get("generation_id", state["token"])
                and time.time() - heartbeat.get("timestamp", 0) < 10):
            return heartbeat.get("status", "UNKNOWN")
    except (OSError, ValueError):
        pass
    attacker = next(n for n in session.nodes.values() if n.name == "attacker")
    code, _ = c.node_command(session.id, attacker.id, 'test -f ascend-watcher.pid && kill -0 "$(cat ascend-watcher.pid)"', shell=True)
    return "UNVERIFIED" if code == 0 else "STOPPED"


def perform(c, request):
    action = request["action"]
    if action == "health":
        return {"endpoint": c.address, "sessions": len(c.get_sessions()), "daemon_ready": True}
    if action == "register":
        register(c, validate_xml(request.get("xml", ROOT / "core_topology.xml")))
        return {"service": SERVICE}
    session = owned_session(c)
    if action == "status":
        return {"session_id": session.id if session else None,
                "state": session.state.name if session else "STOPPED",
                "nodes": len(session.nodes) if session else 0,
                "watcher": watcher_status(c, session)}
    if action == "stop":
        if session and not c.delete_session(session.id):
            raise RuntimeError(f"CORE could not delete session {session.id}")
        STATE.unlink(missing_ok=True)
        return {"state": "STOPPED"}
    if action == "gui":
        if not session or session.state != w.SessionState.RUNTIME:
            raise RuntimeError("Start a managed CORE session before opening CORE GUI")
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            raise RuntimeError("CORE session is running, but no WSL GUI display is available. Enable WSLg or an X server, then retry Open CORE GUI.")
        executable = os.environ.get("ASCEND_CORE_GUI", "/opt/core/venv/bin/core-gui")
        if not os.access(executable, os.X_OK):
            raise RuntimeError(f"CORE GUI executable is unavailable: {executable}")
        # CORE's startup --session path joins on the Tk thread. The Sessions
        # dialog joins via ProgressTask, which cannot create canvas widgets on
        # the installed Tcl/Tk 9 runtime. Attach directly to the owned session.
        process = subprocess.Popen([executable, "--session", str(session.id)], cwd=ROOT, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        return {"session_id": session.id, "gui_pid": process.pid}
    if action == "start":
        if session:
            raise RuntimeError(f"Session {session.id} already exists ({session.state.name}); stop it before replacing")
        path = Path(request["xml"]).resolve()
        root = validate_xml(path)
        preflight()
        register(c, root)
        definition = to_session(root, None)
        token = uuid.uuid4().hex
        definition.metadata["ascend_owner"] = token
        definition.file = path
        created = c.create_session()
        definition.id = created.id
        save_state(created.id, token, c.address)
        try:
            result, exceptions = c.start_session(definition)
            if not result or exceptions:
                raise RuntimeError("CORE startup failed: " + "; ".join(exceptions))
            live = c.get_session(created.id)
            if live.state != w.SessionState.RUNTIME:
                raise RuntimeError(f"Unexpected CORE state: {live.state.name}")
            return {"session_id": live.id, "state": live.state.name, "nodes": len(live.nodes)}
        except Exception as exc:
            try:
                if not c.delete_session(created.id):
                    raise RuntimeError("DeleteSession returned false")
                STATE.unlink(missing_ok=True)
            except Exception as cleanup:
                raise RuntimeError(f"{exc}; cleanup failed for session {created.id}: {cleanup}") from exc
            raise
    if action == "watcher":
        if not session or session.state != w.SessionState.RUNTIME:
            raise RuntimeError("Start a managed CORE session before the PPO watcher")
        attacker = next(n for n in session.nodes.values() if n.name == "attacker")
        existing = watcher_status(c, session)
        if existing in ("IDLE", "BUSY", "STARTING"):
            return {"session_id": session.id, "watcher": existing}
        if existing == "UNVERIFIED":
            code, output = c.node_command(session.id, attacker.id,
                                          'if [ -f ascend-watcher.pid ]; then kill "$(cat ascend-watcher.pid)"; fi', shell=True)
            if code:
                raise RuntimeError(f"Could not replace unverified watcher: {output}")
            time.sleep(1)
        state = json.loads(STATE.read_text())
        command = shlex.join(["env", f"ASCEND_SESSION_ID={session.id}", f"ASCEND_SESSION_GENERATION={state.get('generation_id', state['token'])}", app_python(), "-u", str(ROOT / "scripts/ppo_step_watcher.py")])
        shell = f"{command} > ascend-watcher.log 2>&1 < /dev/null & echo $! > ascend-watcher.pid"
        code, output = c.node_command(session.id, attacker.id, shell, shell=True)
        if code:
            raise RuntimeError(f"Watcher launch failed: {output}")
        time.sleep(1)
        status = watcher_status(c, session)
        if status == "STOPPED":
            raise RuntimeError("Watcher exited; inspect attacker/ascend-watcher.log")
        return {"session_id": session.id, "watcher": status}
    if action == "defend":
        if not session or session.state != w.SessionState.RUNTIME:
            raise RuntimeError("Start a managed CORE session before applying a defense")
        target = str(request.get("target_node", ""))
        if not target.startswith("plc") or not target[3:].isdigit():
            raise ValueError("Defense target must be a canonical PLC node, such as plc1")
        node = next((n for n in session.nodes.values() if n.name == target), None)
        if node is None:
            raise ValueError(f"Target {target} is not present in the managed CORE session")
        defense = request.get("defense_action")
        commands = {"isolate": "ip link set dev eth0 down", "restore": "ip link set dev eth0 up"}
        if defense not in commands:
            raise ValueError("Supported defenses are isolate and restore")
        code, output = c.node_command(session.id, node.id, commands[defense], shell=True)
        if code:
            raise RuntimeError(f"CORE defense action failed for {target}: {output}")
        return {"session_id": session.id, "target_node": target, "defense_action": defense, "output": output}
    if action == "interface_state":
        if not session or session.state != w.SessionState.RUNTIME:
            raise RuntimeError("Start a managed CORE session before querying an interface")
        target = str(request.get("target_node", "")); interface = str(request.get("interface", "eth0"))
        if not target.startswith("plc") or not target[3:].isdigit() or interface != "eth0":
            raise ValueError("Query requires a canonical PLC target and eth0")
        node = next((n for n in session.nodes.values() if n.name == target), None)
        if node is None: raise ValueError(f"Target {target} is not present in the managed CORE session")
        code, output = c.node_command(session.id, node.id, "ip -o link show dev eth0", shell=True)
        if code: raise RuntimeError(f"Interface query failed for {target}: {output}")
        return {"session_id":session.id,"target_node":target,"interface":interface,"state":"DOWN" if " state DOWN " in output else "UP" if " state UP " in output else "UNKNOWN","raw":output}
    raise ValueError(f"Unknown action: {action}")


def main():
    request = ({"action": sys.argv[1], **({"xml": sys.argv[2]} if len(sys.argv) > 2 else {})}
               if len(sys.argv) > 1 else json.load(sys.stdin))
    RUNTIME.mkdir(parents=True, exist_ok=True)
    with (RUNTIME / "session.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another CORE operation is in progress")
        endpoint = os.environ.get("ASCEND_CORE_ADDRESS", "localhost:50051")
        c = client.CoreGrpcClient(endpoint)
        with c.context_connect():
            try:
                grpc.channel_ready_future(c.channel).result(timeout=5)
            except grpc.FutureTimeoutError as exc:
                raise RuntimeError(f"CORE daemon unavailable at {endpoint}; start core-daemon in WSL") from exc
            c.stub = Deadlines(c.stub)
            result = perform(c, request)
            print(json.dumps({"ok": True, **result}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(1)
