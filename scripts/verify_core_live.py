"""Read-only Modbus/IDS checks against the currently owned CORE session.

Run using CORE's Python. Does not start attacks or delete the session.
"""
import json
from pathlib import Path
import shlex
import sys
import time
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.core_session import owned_session, Deadlines, ROOT, STATE
from testbed.core_services import app_python
from core.api.grpc.client import CoreGrpcClient
import os


def main():
    c = CoreGrpcClient(os.environ.get("ASCEND_CORE_ADDRESS", "localhost:50051"))
    with c.context_connect():
        c.stub = Deadlines(c.stub)
        session = owned_session(c)
        assert session and session.state.name == "RUNTIME", "No owned runtime session"
        plc_count = sum(n.name.startswith("plc") for n in session.nodes.values())
        created = json.loads(STATE.read_text()).get("created_at", 0)
        command = "\n".join([
            "from pymodbus.client import ModbusTcpClient",
            f"for i in range(1, {plc_count + 1}):",
            "    c = ModbusTcpClient(f'10.0.0.{i}', port=502, timeout=2)",
            "    assert c.connect(), f'PLC {i} unreachable'",
            "    r = c.read_holding_registers(address=0, count=6, device_id=1)",
            "    c.close()",
            "    assert not r.isError(), f'PLC {i}: {r}'",
            "    assert len(r.registers) == 6",
            f"print('PASS {plc_count} real Modbus PLC reads from SCADA')",
        ])
        code, output = c.node_command(session.id, 2, shlex.join([app_python(), "-c", command]))
        assert code == 0, output
        print(output.strip())
        for node in session.nodes.values():
            if node.name.startswith("plc") or node.name in ("scada", "ids_monitor"):
                code, output = c.node_command(session.id, node.id, "sh ascend-validate.sh")
                assert code == 0, f"{node.name}: {output}"
        print("PASS all node service validations")
        eve = ROOT / "data/core-runtime/suricata/eve.json"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if eve.exists():
                for line in eve.read_text().splitlines()[-2000:]:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    event_time = datetime.fromisoformat(event["timestamp"]).timestamp()
                    if event_time < created:
                        continue
                    if event.get("event_type") == "modbus" or event.get("app_proto") == "modbus":
                        print("PASS IDS EVE contains decoded Modbus traffic")
                        return
            time.sleep(1)
        raise AssertionError("IDS did not report decoded Modbus traffic in EVE")


if __name__ == "__main__":
    main()
