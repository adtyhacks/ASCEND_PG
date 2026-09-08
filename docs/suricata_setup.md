# Suricata + OVS Mirror Port setup (ASCEND-PG testbed IDS)

Run these on the same WSL2/Ubuntu machine as your Mininet testbed. Do steps 1–4
BEFORE touching Mininet — validate Suricata's config standalone first, don't
debug Suricata and Mininet/OVS integration at the same time.

Suricata is the real-IDS detection layer for the testbed checkpoint. The custom
rules live in `detection/suricata/modbus_rules.rules`; the trained
LSTM/Autoencoder detectors (`detection/lstm_detector.py`,
`autoencoder_detector.py`, `fusion.py`) remain the final deliverable — Suricata
gives a working, real-IDS ground truth now.

## 1. Install Suricata

    sudo apt update
    sudo apt install -y suricata

Verify:

    suricata --build-info | head -20

## 2. Enable Modbus detection in suricata.yaml

Open `/etc/suricata/suricata.yaml`, find the `app-layer: protocols:` block,
and add/edit the `modbus` section under it:

    modbus:
      enabled: yes
      detection-ports:
        dp: 502
      stream-depth: 0

If a `modbus:` section already exists but is commented out or `enabled: no`,
just flip it — don't duplicate the block. Without `enabled: yes` + the
`detection-ports`, Suricata will still start but Modbus rules silently won't
match anything — this is the single most likely "why isn't it detecting
anything" trap, so double check it.

## 3. Point Suricata at the custom rules

In the same `suricata.yaml`, find `rule-files:` and add:

    rule-files:
      - modbus_rules.rules   # this project's custom rules (detection/suricata/)
      - modbus-events.rules  # ships with Suricata — flood/invalid-value events, reused for DoS

Copy `detection/suricata/modbus_rules.rules` (from this repo) into Suricata's
rules directory (usually `/etc/suricata/rules/` — check `default-rule-path:`
near the top of suricata.yaml) or point `rule-files:` at its absolute path
directly.

## 4. Validate config before touching Mininet

    sudo suricata -T -c /etc/suricata/suricata.yaml -v

Fix anything it complains about here first.

## 5. Set up the OVS mirror port (do this AFTER your Mininet topology is up)

The repo ships `scripts/setup_mirror.sh`, which mirrors the 5 PLC ports + the
attacker + SCADA ports on bridge `s1` to the monitor port (`s1-eth6`). Run it
once the topology from `testbed/mininet_topology.py` is up:

    sudo bash scripts/setup_mirror.sh

Or do it by hand if your port numbering differs:

    # Find your bridge name (usually s1 for a single-switch topology)
    sudo ovs-vsctl show

    # Mirror ALL traffic on the bridge to a chosen monitor port.
    # Replace <bridge> with your actual switch name, and <monitor-port>
    # with the OVS port your monitor host is attached to (the SCADA host is
    # fine to double as the monitor — no need for a 7th host).
    sudo ovs-vsctl -- set Bridge <bridge> mirrors=@m \
      -- --id=@p get Port <monitor-port> \
      -- --id=@m create Mirror name=ascendpg-mirror select-all=true output-port=@p

Verify it's attached:

    sudo ovs-vsctl list Mirror

## 6. Run Suricata against the attacker switch port

In WSL2, the OVS mirror port (`s1-mon`) doesn't work due to kernel limitations
(`NO-CARRIER, state DOWN`). Instead, run Suricata directly on the attacker's
switch port (`s1-eth7`), which sees all attack traffic:

    sudo suricata -c /etc/suricata/suricata.yaml -i s1-eth7 -D

Watch `/var/log/suricata/eve.json` for alerts as you generate test traffic
(this is the same eve.json `scripts/run_cycle.py` correlates against for its
per-step DETECTED/NOT DETECTED verdicts). Before running the real recon/attack
scripts, do one manual sanity check: from any host, do a plain pymodbus
read/write against a PLC and confirm Suricata logs *something* — proves the
pipeline is alive before you add recon/attack complexity on top.

**Interface mapping:**

| Switch Port | Host | IP |
|---|---|---|
| s1-eth1 | plc1 | 10.0.0.1 |
| s1-eth2 | plc2 | 10.0.0.2 |
| s1-eth3 | plc3 | 10.0.0.3 |
| s1-eth4 | plc4 | 10.0.0.4 |
| s1-eth5 | plc5 | 10.0.0.5 |
| s1-eth6 | scada | 10.0.0.10 |
| s1-eth7 | attacker | 10.0.0.66 |

## Known risk (WSL2 + OVS)

The OVS mirror port (`s1-mon`) does not work in WSL2 — the interface shows
`NO-CARRIER, state DOWN` and captures zero packets. This is a WSL2 kernel
limitation. The fallback (and current working solution) is running Suricata
directly on the attacker's switch port (`s1-eth7`). This sees all attack
traffic but not SCADA-to-PLC polling responses. For full visibility, consider
running on a native Linux host or using `tcpdump` captures for offline analysis.
