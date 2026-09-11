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
import socket
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("scada_client")

LOG_STORE = Path(__file__).resolve().parent.parent / "data" / "log_store.json"


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    LOG_STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_STORE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def check_port(ip, port, timeout=1):
    """Quick TCP connectivity check (no pymodbus overhead)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def poll_plc(ip, port, count, device_id=1, address=0, timeout=2):
    client = ModbusTcpClient(ip, port=port, timeout=timeout)
    if not client.connect():
        return None
    try:
        result = client.read_holding_registers(
            address=address, count=count, device_id=device_id
        )
        if result.isError():
            return None
        return result.registers
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG SCADA polling client")
    parser.add_argument("--targets", nargs="+", required=True,
                        help="PLC IP addresses to poll")
    parser.add_argument("-p", "--port", type=int, default=502)
    parser.add_argument("-n", "--num-registers", type=int, default=10)
    parser.add_argument("-a", "--address", type=int, default=0)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    global LOG_STORE
    if args.log:
        LOG_STORE = Path(args.log)

    log.info("SCADA polling started -- targets: %s (%d PLCs)", args.targets, len(args.targets))

    reachable = []
    unreachable = []
    for ip in args.targets:
        if check_port(ip, args.port, timeout=1):
            reachable.append(ip)
            log.info("  [OK]   %s:502 reachable", ip)
        else:
            unreachable.append(ip)
            log.warning("  [FAIL] %s:502 unreachable", ip)

    log.info("Connectivity: %d/%d PLCs reachable", len(reachable), len(args.targets))
    if unreachable:
        log.warning("Unreachable PLCs: %s", unreachable)

    cycle = 0
    try:
        while True:
            cycle += 1
            polls_ok = 0
            polls_fail = 0
            for ip in args.targets:
                registers = poll_plc(ip, args.port, args.num_registers,
                                     address=args.address, timeout=2)
                if registers is not None:
                    polls_ok += 1
                    log_event({
                        "stage": "normal_traffic", "technique": "N/A",
                        "action": f"poll_{ip}", "target": ip,
                    })
                else:
                    polls_fail += 1
            log.info("Cycle %d: %d ok, %d fail", cycle, polls_ok, polls_fail)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("SCADA polling stopped")


if __name__ == "__main__":
    main()
