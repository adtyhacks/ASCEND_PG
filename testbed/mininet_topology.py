"""
ASCEND-PG testbed/mininet_topology.py

Defines the emulated ICS network per the project architecture (§5):
5 PLC/RTU hosts, 1 SCADA polling client, 1 attacker host, all on one
switch (flat network -- matches how the real attack tools such as
arpspoof expect to operate on a shared L2 segment).

Follows the same Topo-subclass pattern MiniCPS's own examples use
(examples/toy/topo.py), but written independently -- this file has
no dependency on minicps.devices, only on mininet.topo.

Usage:
    sudo python3 mininet_topology.py
or import IcsTopo into a run.py orchestrator (recommended long-term,
mirrors examples/toy/run.py + examples/swat-s1/run.py).
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel


# --- addressing -------------------------------------------------------
# Flat /24 -- matches the addressing style used in MiniCPS's own
# examples (utils.py PLC1_ADDR = '10.0.0.1' + NETMASK = '/24').
NETMASK = "/24"

PLC_IPS = [
    "10.0.0.1",  # plc1
    "10.0.0.2",  # plc2
    "10.0.0.3",  # plc3
    "10.0.0.4",  # plc4
    "10.0.0.5",  # plc5
]
SCADA_IP = "10.0.0.10"
ATTACKER_IP = "10.0.0.66"

class IcsTopo(Topo):
    def build(self):
        switch = self.addSwitch("s1")

        # 5 emulated PLC/RTU hosts
        for i, ip in enumerate(PLC_IPS, start=1):
            host = self.addHost(f"plc{i}", ip=ip + NETMASK)
            self.addLink(host, switch)

        # 1 SCADA polling client
        scada = self.addHost("scada", ip=SCADA_IP + NETMASK)
        self.addLink(scada, switch)

        # 1 attacker host (runs pymodbus FDI / hping3 / Scapy / arpspoof)
        attacker = self.addHost("attacker", ip=ATTACKER_IP + NETMASK)
        self.addLink(attacker, switch)

def run():
    setLogLevel("info")
    topo = IcsTopo()
    # OVSController: local, no external SDN controller needed for this
    # flat-network use case -- matches what your earlier `mn --test
    # pingall` run already used ("Falling back to OVS Bridge").
    net = Mininet(topo=topo, controller=OVSController)
    net.start()
    print("*** ASCEND-PG testbed up.")
    print("*** PLC hosts:", [f"plc{i} ({ip})" for i, ip in enumerate(PLC_IPS, 1)])
    print(f"*** SCADA host: scada ({SCADA_IP})")
    print(f"*** Attacker host: attacker ({ATTACKER_IP})")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run()
