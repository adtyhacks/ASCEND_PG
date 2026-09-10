"""
ASCEND-PG testbed/scada_client.py

Real Modbus TCP SCADA polling client, built directly on pymodbus
(3.14.x API). Polls one or more PLC hosts' holding registers on a
fixed interval and prints/logs the readings.

Each successful poll is written to the shared log store as a
"normal_traffic" event, so the Live Battle page (app/pages/3_Live_Battle.py)
can render ongoing legitimate SCADA<->PLC traffic distinctly from
attack/recon events -- steady links vs. the red/green attack-highlight edge.

Run this on the Mininet-emulated SCADA host, e.g.:
    scada.cmd('python3 testbed/scada_client.py --targets 10.0.0.1 10.0.0.2 &')
"""

import argparse
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scada_client")

# Shared event log store lives in the repo's data/ dir (see §7 of the master
# file). Anchored to this file's location (testbed/ -> repo root) so it resolves
# the same regardless of the cwd the SCADA host launches the script from.
LOG_STORE = Path(__file__).resolve().parent.parent / "data" / "log_store.json"


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    events = []
    if LOG_STORE.exists():
        try:
            events = json.loads(LOG_STORE.read_text())
        except json.JSONDecodeError:
            events = []
    events.append(event)
    LOG_STORE.parent.mkdir(parents=True, exist_ok=True)
    LOG_STORE.write_text(json.dumps(events, indent=2))


def poll_plc(ip, port, count, device_id=1, address=0):
    """
    Connects to one PLC, reads its holding registers once, and
    returns the register list (or None on failure).

    NOTE: pymodbus 3.12+ renamed the `slave=` kwarg to `device_id=`.
    """
    if address == 0:
        log.warning("Reading from address 0 - ensure this matches PLC template (Siemens uses 40000+, AB uses 0)")
    
    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.warning("Could not connect to PLC at %s:%d", ip, port)
        return None
    try:
        result = client.read_holding_registers(
            address=address, count=count, device_id=device_id
        )
        if result.isError():
            log.warning("Modbus error reading %s:%d -> %s", ip, port, result)
            return None
        return result.registers
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG SCADA polling client")
    parser.add_argument("--targets", nargs="+", required=True,
                        help="PLC IP addresses to poll, e.g. 10.0.0.1 10.0.0.2")
    parser.add_argument("-p", "--port", type=int, default=502)
    parser.add_argument("-n", "--num-registers", type=int, default=10,
                        help="how many holding registers to read per poll")
    parser.add_argument("-a", "--address", type=int, default=0,
                        help="starting register address (default: 0, use 40000 for Siemens HR)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between poll cycles")
    parser.add_argument("--log", default=None,
                        help="override the shared event log store path "
                             "(defaults to <repo>/data/log_store.json)")
    args = parser.parse_args()

    global LOG_STORE
    if args.log:
        LOG_STORE = Path(args.log)

    log.info("SCADA polling started -- targets: %s", args.targets)

    try:
        while True:
            for ip in args.targets:
                registers = poll_plc(ip, args.port, args.num_registers, address=args.address)
                if registers is not None:
                    log.info("%s -> %s", ip, registers)
                    log_event({
                        "stage": "normal_traffic", "technique": "N/A",
                        "action": f"poll_{ip}", "target": ip,
                    })
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("SCADA polling stopped")


if __name__ == "__main__":
    main()

