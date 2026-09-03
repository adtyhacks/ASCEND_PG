# ASCEND-PG testbed — attack/detection cycle runbook

End-to-end steps to reproduce the real recon → FDI → DoS cycle against the
emulated ICS network and see per-step Suricata verdicts. Everything below runs
on the WSL2/Ubuntu machine that hosts the testbed (Abinraj's track). Paths are
relative to the repo root (`ascend-pg-webapp/`).

**Prereqs (one-time):** pymodbus (`pip install -r requirements.txt`), Mininet +
MiniCPS + Open vSwitch, `nmap`, and Suricata (see `docs/suricata_setup.md`).

## 1. Bring up the network

    sudo python3 testbed/mininet_topology.py

Leaves you at the `mininet>` CLI with plc1–5, scada, attacker on 10.0.0.0/24.

## 2. Start the PLC servers (one per PLC host)

From the mininet CLI, background a Modbus server on each PLC (repeat for
plc2–plc5 on 10.0.0.2–10.0.0.5):

    mininet> plc1 python3 testbed/plc_server.py -i 10.0.0.1 &

## 3. (Optional) Start the SCADA poller — generates "normal" traffic

    mininet> scada python3 testbed/scada_client.py --targets 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 &

## 4. Mirror traffic to the monitor port + start Suricata

In a second terminal (host shell, not the mininet CLI):

    sudo bash scripts/setup_mirror.sh
    sudo suricata -c /etc/suricata/suricata.yaml -i <monitor-iface> -v

(see `docs/suricata_setup.md` for the yaml config + interface name)

## 5. Run the attack cycle from the attacker host

For a training-data capture, start this first in a separate host-shell terminal
(choose the actual monitor interface and a new scenario ID):

    sudo bash scripts/capture_testbed_session.sh --interface <monitor-iface> --scenario cycle_001 --duration 900

    mininet> attacker python3 scripts/run_cycle.py

Runs recon → fdi_attack → dos_quiet → dos_loud, waits for Suricata's flow-timeout
alerts, prints a DETECTED/NOT-DETECTED report, and writes `data/log_store.json`
+ `data/cycle_report.json`.

## 6. Watch it live

On the machine with the repo (can be the same box):

    streamlit run app/Home.py      # then pick "Live Battle" in the sidebar
    # or, standalone:  streamlit run app/pages/3_Live_Battle.py

The page polls `data/log_store.json` + `data/cycle_report.json` every 3s.

## Verified reference run (mock testbed, 2026-08-12)

| Step       | Technique      | Expected      | Result       | Signature |
|------------|----------------|---------------|--------------|-----------|
| recon      | T0846 / T0888  | DETECTED      | DETECTED     | sid 9000004 |
| fdi_attack | T0836          | DETECTED      | DETECTED     | sid 9000001 |
| dos_quiet  | T0814          | NOT DETECTED  | NOT DETECTED | (under threshold) |
| dos_loud   | T0814          | DETECTED      | DETECTED     | sid 9000002 (flow-timeout) |

`dos_quiet` staying under Suricata's ~500-request flood threshold is the
intended negative control — it shows the detector isn't just alerting on any
DoS-shaped traffic. See `attacks/dos_attack.py`'s docstring for the threshold
mechanics and the raw-socket rationale.

## 7. Convert and label captures for model training

Run your selected CICFlowMeter fork against the captured PCAP. Then label the
result with the exact campaign windows; replace the flow-file path with the
CICFlowMeter output and keep every scenario in its own file:

    python3 scripts/label_captured_flows.py \
      --flows data/cicflow_output/cycle_001.csv \
      --scenario-id cycle_001 \
      --output data/processed/cycle_001_labeled_flows.csv

The command also writes a manifest showing how many flows fell in each attack
window. A zero count is a capture clock/time-zone problem to resolve before
training. See `docs/training_data_spec.md` for the full handoff and split
rules; never randomly split individual rows from the same episode.
