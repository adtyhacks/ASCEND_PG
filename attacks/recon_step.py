#!/usr/bin/env python3
"""
ASCEND-PG attacks/recon_step.py

Discovery-phase script for the attacker host. Implements MITRE ATT&CK for
ICS techniques T0846 (Remote System Discovery) and T0888 (Remote System
Information Discovery), run BEFORE the actual attack — mirrors a real
attacker's flow.

Run this ON THE ATTACKER HOST inside the Mininet topology, e.g. from the
Mininet CLI:
    mininet> attacker python3 attacks/recon_step.py --subnet 10.0.0.0/24

Both steps below are real network traffic — nothing simulated:
  1. An nmap TCP sweep of the segment, looking for open Modbus port 502 —
     how a real attacker finds PLCs on an unfamiliar network.
  2. For every host found listening on 502, a real Modbus "Read Device
     Identification" request (function code 0x2B, sub-function 0x0E) —
     pulls vendor name / product info straight off the PLC over the wire.

Every probe sent and every response received is appended to the shared JSON
log store, timestamped, so it shows up in the Live Battle page's diagram/log
table (app/pages/3_Live_Battle.py) exactly like the attack step does.

VERSION NOTE (matches the master file's pymodbus version-mismatch flag): this
targets pymodbus 3.14.x's API. `read_device_information` is the 3.14.x-era
method name for the device-ID request — if your installed pymodbus version
differs, check
`python3 -c "from pymodbus.client import ModbusTcpClient; help(ModbusTcpClient)"`
and adjust the call in read_device_identification() below.
"""

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pymodbus.client import ModbusTcpClient

MODBUS_PORT = 502

# Shared event log store — repo data/ dir, anchored to this file (attacks/ ->
# repo root) so a standalone run resolves the same path the cycle runner uses.
DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "log_store.json"


def _json_safe(obj):
    """Fallback encoder for json.dumps: decodes bytes so pymodbus's
    device-ID info dict (which returns raw bytes for vendor/product
    fields) can be logged without crashing."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    return str(obj)


def log_event(log_path: Path, event: dict):
    """Append one event to the shared JSON log store (JSONL format)."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, default=_json_safe) + "\n")


def nmap_sweep(subnet: str, log_path: Path) -> list:
    """Real nmap TCP sweep for port 502 across the given subnet.
    Returns list of IPs found with Modbus port open.

    Preserve the requested subnet/range so all current CORE PLCs can be
    discovered, including IEEE-14 and IEEE-30 nodes above .7.
    """
    print(f"[recon] nmap sweep of {subnet} for open Modbus port {MODBUS_PORT} ...")
    log_event(log_path, {
        "stage": "recon", "technique": "T0846",
        "action": "nmap_sweep_start", "subnet": subnet,
    })

    scan_target = subnet

    result = subprocess.run(
        [
            "nmap",
            "-p", str(MODBUS_PORT),
            "--open",           # only report open ports
            "-T4",              # aggressive timing (faster in virtual nets)
            "--host-timeout", "10s",   # give up on any host after 10 s
            "--max-retries", "1",      # 1 retry per probe (default is 6)
            "-oG", "-",         # greppable output on stdout
            scan_target,
        ],
        capture_output=True, text=True, timeout=120,
    )

    found = []
    for line in result.stdout.splitlines():
        if "Ports:" in line and f"{MODBUS_PORT}/open" in line:
            ip = line.split()[1]
            found.append(ip)

    log_event(log_path, {
        "stage": "recon", "technique": "T0846",
        "action": "nmap_sweep_result", "hosts_found": found,
    })
    print(f"[recon] found {len(found)} host(s) with Modbus open: {found}")
    return found



def read_device_identification(ip: str, log_path: Path):
    """Real Modbus Read Device Identification request (FC 0x2B/0x0E)
    against one target. Returns whatever pymodbus gives back, or None."""
    print(f"[recon] querying device identification on {ip} ...")
    log_event(log_path, {
        "stage": "recon", "technique": "T0888",
        "action": "device_id_query_start", "target": ip,
    })

    client = ModbusTcpClient(ip, port=MODBUS_PORT, timeout=3)
    info = None
    try:
        if client.connect():
            resp = client.read_device_information(device_id=1)  # see VERSION NOTE above
            if not resp.isError():
                info = resp.information  # dict of object_id -> value
    except Exception as exc:
        # a failed probe is itself a real, loggable event — keep recon
        # resilient rather than letting one bad target crash the whole run
        info = None
        log_event(log_path, {
            "stage": "recon", "technique": "T0888",
            "action": "device_id_query_error", "target": ip, "error": str(exc),
        })
    finally:
        client.close()

    log_event(log_path, {
        "stage": "recon", "technique": "T0888",
        "action": "device_id_query_result", "target": ip, "info": info,
    })
    print(f"[recon] {ip} -> {info}")
    return info


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG recon step")
    parser.add_argument("--subnet", default="10.0.0.0/24",
                         help="Testbed subnet to sweep (matches the 5-PLC + "
                              "SCADA + attacker /24 from the master file)")
    parser.add_argument("--log", default=str(DEFAULT_LOG),
                         help="Path to the shared event log store "
                              "(defaults to <repo>/data/log_store.json)")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    targets = nmap_sweep(args.subnet, log_path)
    results = {}
    for ip in targets:
        results[ip] = read_device_identification(ip, log_path)
        time.sleep(0.5)  # keeps recon traffic visually/temporally distinct
                          # from the attack step that follows

    print("[recon] done.")
    return targets, results


if __name__ == "__main__":
    main()
