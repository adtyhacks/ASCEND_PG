"""
ASCEND-PG testbed/scada_client.py

Real Modbus TCP SCADA polling client, built directly on pymodbus
(3.14.x API). Polls one or more PLC hosts' holding registers on a
fixed interval and prints/logs the readings -- this is the "normal
operation" traffic your detection layer (LSTM/Autoencoder) will
learn a baseline from, and that your attack scripts will disrupt.

Run this on the Mininet-emulated SCADA host, e.g.:
    scada.cmd('python3 scada_client.py --targets 10.0.0.1 10.0.0.2 &')
"""

import argparse
import time
import logging

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scada_client")


def poll_plc(ip, port, count, device_id=1):
    """
    Connects to one PLC, reads its holding registers once, and
    returns the register list (or None on failure).

    NOTE: pymodbus 3.12+ renamed the `slave=` kwarg to `device_id=`.
    If you're following an older tutorial online, it will use
    `slave=` -- that will raise a runtime error on this version.
    """
    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.warning("Could not connect to PLC at %s:%d", ip, port)
        return None

    try:
        result = client.read_holding_registers(
            address=0, count=count, device_id=device_id
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
    parser.add_argument("--interval", type=float, default=1.0,
                         help="seconds between poll cycles")
    args = parser.parse_args()

    log.info("SCADA polling started -- targets: %s", args.targets)

    try:
        while True:
            for ip in args.targets:
                registers = poll_plc(ip, args.port, args.num_registers)
                if registers is not None:
                    log.info("%s -> %s", ip, registers)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("SCADA polling stopped")


if __name__ == "__main__":
    main()
