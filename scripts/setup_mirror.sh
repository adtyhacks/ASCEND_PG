#!/bin/bash
# setup_mirror.sh — ASCEND-PG OVS traffic mirror setup
#
# Creates a dedicated Linux tap interface (s1-mon) that receives a copy
# of ALL traffic between PLCs (s1-eth1..5), the attacker (s1-eth7), and
# SCADA (s1-eth6). The tap is visible at the WSL2 host level so Scapy
# (replay_attack.py) and tshark/tcpdump can sniff it without needing to
# operate inside a Mininet host namespace.
#
# Run AFTER the Mininet topology is up:
#   sudo bash scripts/setup_mirror.sh
#
# After this, capture/sniff with:
#   sudo tshark -i s1-mon -f "tcp port 502"
#   python3 attacks/replay_attack.py --target 10.0.0.1 --iface s1-mon

# Remove any stale mirror from a previous run
EXISTING=$(sudo ovs-vsctl list-br | head -1)
if sudo ovs-vsctl get bridge s1 mirrors 2>/dev/null | grep -q '[0-9a-f]'; then
    echo "[setup_mirror] Removing stale mirror from bridge s1 ..."
    sudo ovs-vsctl clear bridge s1 mirrors
fi

# Remove stale tap if it exists
if ip link show s1-mon &>/dev/null; then
    echo "[setup_mirror] Removing stale s1-mon tap interface ..."
    sudo ip link delete s1-mon
fi

# Create a new tap interface for sniffing
echo "[setup_mirror] Creating tap interface s1-mon ..."
sudo ip tuntap add s1-mon mode tap
sudo ip link set s1-mon up

# Add the tap as a port on the bridge, then mirror everything to it
echo "[setup_mirror] Adding s1-mon to bridge s1 ..."
sudo ovs-vsctl add-port s1 s1-mon

echo "[setup_mirror] Creating mirror (all ports -> s1-mon) ..."
MIRROR_ID=$(sudo ovs-vsctl \
  -- --id=@p1 get port s1-eth1 \
  -- --id=@p2 get port s1-eth2 \
  -- --id=@p3 get port s1-eth3 \
  -- --id=@p4 get port s1-eth4 \
  -- --id=@p5 get port s1-eth5 \
  -- --id=@p6 get port s1-eth6 \
  -- --id=@p7 get port s1-eth7 \
  -- --id=@mon get port s1-mon \
  -- --id=@m create mirror name=modbus-mirror \
     select-src-port=@p1,@p2,@p3,@p4,@p5,@p6,@p7 \
     select-dst-port=@p1,@p2,@p3,@p4,@p5,@p6,@p7 \
     output-port=@mon \
  -- set bridge s1 mirrors=@m)

echo "[setup_mirror] Mirror created: $MIRROR_ID"
echo "[setup_mirror] Done — sniff on interface: s1-mon"
echo "[setup_mirror] Test: sudo tshark -i s1-mon -c 5 -f 'tcp port 502'"
