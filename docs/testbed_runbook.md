# ASCEND-PG testbed — attack/detection cycle runbook

End-to-end steps to reproduce the full recon → injection → command injection →
DoS → replay cycle against the emulated ICS network and see per-step Suricata
verdicts. Everything below runs on the WSL2/Ubuntu machine that hosts the testbed
(Abinraj's track). Paths are relative to the repo root (`ascend-pg-webapp/`).

**Prereqs (one-time):** pymodbus (`pip install -r requirements.txt`), Mininet +
MiniCPS + Open vSwitch, `nmap`, Suricata (see `docs/suricata_setup.md`), and
CICFlowMeter (see §7 below — `sudo bash scripts/install_cicflowmeter.sh`).

## 1. Bring up the network

    sudo python3 testbed/mininet_topology.py

Leaves you at the `mininet>` CLI with plc1–5, scada, attacker on 10.0.0.0/24.

## 2. Start the PLC servers (one per PLC host)

From the mininet CLI, background a Modbus server on each PLC:

    mininet> plc1 python3 testbed/plc_server.py -i 10.0.0.1 &
    mininet> plc2 python3 testbed/plc_server.py -i 10.0.0.2 &
    mininet> plc3 python3 testbed/plc_server.py -i 10.0.0.3 &
    mininet> plc4 python3 testbed/plc_server.py -i 10.0.0.4 &
    mininet> plc5 python3 testbed/plc_server.py -i 10.0.0.5 &

## 3. (Optional) Start the SCADA poller — generates "normal" traffic

    mininet> scada python3 testbed/scada_client.py --targets 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 &

## 4. Mirror traffic + start Suricata

In a **second terminal** (host shell, not the mininet CLI).
`setup_mirror.sh` now creates a dedicated tap interface `s1-mon` that receives
a copy of ALL switch traffic — visible at WSL2 host level for tshark/Scapy.

    sudo bash scripts/setup_mirror.sh
    # Verify: ip link show s1-mon   (should show state UP)
    # Quick test: sudo tshark -i s1-mon -c 5 -f "tcp port 502"

    sudo suricata -c /etc/suricata/suricata.yaml -i s1-mon -v

(see `docs/suricata_setup.md` for the yaml config)

## 5. Run the attack cycle

For a training-data capture, start capture FIRST in a **third host-shell terminal**:

    sudo bash scripts/capture_testbed_session.sh \
        --interface s1-mon --scenario cycle_001 --duration 900

Then launch the attack cycle from the attacker host inside Mininet:

    mininet> attacker sudo python3 scripts/run_cycle.py

The cycle runs 12 steps (recon_nmap_devid → recon_fc_scan → fdi_attack →
naive_response_injection → complex_response_injection → cmd_inject_coil →
cmd_inject_register → malicious_fc → dos_quiet → dos_loud → dos_conn_exhaust →
replay_attack), waits for Suricata flow-timeout alerts, prints a
DETECTED/NOT-DETECTED report, and writes `data/log_store.json` +
`data/cycle_report.json`.

**Note on replay_attack:** requires `s1-mon` to be up (setup_mirror.sh done)
and SCADA to be polling (step 3). If no frames are captured it logs
`replay_abort` and moves on — not a crash.

## 6. Watch it live

    streamlit run app/Home.py      # pick "Live Battle" in the sidebar

The page polls `data/log_store.json` + `data/cycle_report.json` every 3s.

## 7. Convert PCAP to flows (CICFlowMeter — Module 5)

### One-time install (run once on the WSL2 machine):

    sudo bash scripts/install_cicflowmeter.sh

This creates `~/cicflow-env/` with Python 3.11 + cicflowmeter. Bypasses
Python 3.14 compatibility issues — the venv is completely separate from pymodbus.

### Convert PCAP → CSV:

    bash scripts/run_cicflowmeter.sh \
        data/captures/cycle_001/capture.pcap \
        data/cicflow_output/ \
        cycle_001

Output: `data/cicflow_output/cycle_001.csv` — one row per bidirectional flow,
~80 features (duration, packet lengths, IAT statistics, flags, etc.).

### Verify the output looks right:

    head -2 data/cicflow_output/cycle_001.csv   # check column headers
    wc -l data/cicflow_output/cycle_001.csv     # check row count (>0)

## 8. Label flows for model training

    python3 scripts/label_captured_flows.py \
        --flows data/cicflow_output/cycle_001.csv \
        --scenario-id cycle_001 \
        --output data/processed/cycle_001_labeled_flows.csv

The script reads `data/cycle_report.json` for the exact UTC attack windows,
assigns labels (Normal / Recon / FDI / DoS / CmdInject / Replay / MITM),
adds provenance columns (scenario_id, episode_id, technique, MITRE ID), and
writes a per-step manifest showing flow counts per label.

**If manifest shows 0 rows for any attack step:** the PCAP clock and the
cycle_report timestamps don't agree — check that the capture was running
before the cycle started and that system time is UTC (`timedatectl`).

## Verified reference run (mock testbed, 2026-08-12)

| Step       | Technique      | Expected      | Result       | Signature |
|------------|----------------|---------------|--------------|-----------| 
| recon      | T0846 / T0888  | DETECTED      | DETECTED     | sid 9000004 |
| fdi_attack | T0836          | DETECTED      | DETECTED     | sid 9000001 |
| dos_quiet  | T0814          | NOT DETECTED  | NOT DETECTED | (under threshold) |
| dos_loud   | T0814          | DETECTED      | DETECTED     | sid 9000002 (flow-timeout) |

`dos_quiet` staying under Suricata's ~500-request flood threshold is the
intended negative control. See `attacks/dos_attack.py` for threshold mechanics.

## Full pipeline summary (per scenario)

```
1. sudo python3 testbed/mininet_topology.py
2. [Mininet] start plc_server × 5, scada_client
3. [Host] sudo bash scripts/setup_mirror.sh
4. [Host] sudo suricata -c /etc/suricata/suricata.yaml -i s1-mon -v
5. [Host] sudo bash scripts/capture_testbed_session.sh --interface s1-mon --scenario <id> --duration 900
6. [Mininet] attacker sudo python3 scripts/run_cycle.py
7. [Host] bash scripts/run_cicflowmeter.sh data/captures/<id>/capture.pcap data/cicflow_output/ <id>
8. [Host] python3 scripts/label_captured_flows.py --flows data/cicflow_output/<id>.csv --scenario-id <id> --output data/processed/<id>_labeled_flows.csv
```
