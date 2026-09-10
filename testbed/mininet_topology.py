"""
ASCEND-PG testbed/mininet_topology.py

Defines the emulated ICS network topology:
PLC/RTU hosts (one per bus), 1 SCADA polling client, 1 attacker host,
all on one switch (flat network).

Topology is loaded from CSV files (nodes.csv, edges.csv) or defaults to
IEEE-14 bus system.
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel


# --- addressing -------------------------------------------------------
NETMASK = "/24"
SCADA_IP = "10.0.0.20"
ATTACKER_IP = "10.0.0.66"

# Topology loaded dynamically
_topology = None


def _load_topology():
    """Load topology from CSV or use IEEE-14 defaults."""
    global _topology
    from testbed.topology import get_topology, load_topology
    import os
    csv_dir = os.environ.get("ASCEND_TOPOLOGY_DIR", "")
    if csv_dir and os.path.isdir(csv_dir):
        _topology = load_topology(csv_dir)
    else:
        _topology = get_topology()
    if _topology is None:
        from testbed.topology import Topology
        _topology = Topology()
    return _topology


def _get_plc_ips():
    """Get PLC IP addresses from topology."""
    topo = _load_topology()
    return [topo.get_ip(i) for i in range(topo.num_buses)]


def _get_bus_names():
    """Get bus names from topology."""
    topo = _load_topology()
    return {i: topo.name_map.get(i, f"Bus{i+1}") for i in range(topo.num_buses)}


def _get_bus_types():
    """Get bus types from topology."""
    topo = _load_topology()
    return {i: topo.bus_types[i] for i in range(topo.num_buses)}


class IcsTopo(Topo):
    def build(self):
        topo = _load_topology()
        switch = self.addSwitch("s1")

        # PLC/RTU hosts (one per bus)
        for i in range(topo.num_buses):
            ip = topo.get_ip(i)
            host = self.addHost(f"plc{i+1}", ip=ip + NETMASK)
            self.addLink(host, switch)

        # SCADA polling client
        scada = self.addHost("scada", ip=SCADA_IP + NETMASK)
        self.addLink(scada, switch)

        # Attacker host
        attacker = self.addHost("attacker", ip=ATTACKER_IP + NETMASK)
        self.addLink(attacker, switch)


def run():
    setLogLevel("info")
    topo_obj = IcsTopo()
    net = Mininet(topo=topo_obj, controller=OVSController)
    net.start()
    topo = _load_topology()
    plc_ips = [topo.get_ip(i) for i in range(topo.num_buses)]
    print(f"*** ASCEND-PG testbed up ({topo.num_buses} PLCs).")
    print("*** PLC hosts:", [f"plc{i+1} ({ip})" for i, ip in enumerate(plc_ips)])
    print(f"*** SCADA host: scada ({SCADA_IP})")
    print(f"*** Attacker host: attacker ({ATTACKER_IP})")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    run()
