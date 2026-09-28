"""
ASCEND-PG — Centralized Network IP Configuration & Allocation Registry

Provides deterministic IP address assignments for all testbed nodes
(PLCs, SCADA, Attacker, IDS Monitor) across IEEE-14, IEEE-30, and custom cases.
Guarantees zero IP collisions.
"""

from typing import Dict, Any

# Infrastructure IPs
SCADA_IP: str = "10.0.0.100"
ATTACKER_IP: str = "10.0.0.66"
MONITOR_IP: str = "10.0.0.99"
SUBNET_CIDR: str = "10.0.0.0/24"
NETMASK_BITS: int = 24

# Dedicated PLC range: 10.0.0.1 to 10.0.0.50 (bus_id 0 to 49)
PLC_IP_START: int = 1
MAX_PLC_COUNT: int = 50

def get_plc_ip(bus_id: int) -> str:
    """Return deterministic IP for a bus index (0-indexed)."""
    if bus_id < 0 or bus_id >= MAX_PLC_COUNT:
        raise ValueError(f"bus_id {bus_id} out of range [0, {MAX_PLC_COUNT - 1}]")
    return f"10.0.0.{bus_id + PLC_IP_START}"

def get_bus_id_from_ip(ip: str) -> int:
    """Return bus index from IP address, or -1 if not a PLC IP."""
    if not ip.startswith("10.0.0."):
        return -1
    try:
        last_octet = int(ip.split(".")[3])
        bus_id = last_octet - PLC_IP_START
        if 0 <= bus_id < MAX_PLC_COUNT:
            return bus_id
    except (ValueError, IndexError):
        pass
    return -1

def get_node_ip_map(num_buses: int) -> Dict[str, str]:
    """Return full node -> IP mapping for a given bus count."""
    ip_map = {
        "scada": SCADA_IP,
        "attacker": ATTACKER_IP,
        "ids_monitor": MONITOR_IP,
    }
    for b in range(num_buses):
        ip_map[f"plc{b + 1}"] = get_plc_ip(b)
    return ip_map

def audit_ip_uniqueness(num_buses: int) -> bool:
    """Verify that there are no duplicate IPs across infrastructure and PLCs."""
    mapping = get_node_ip_map(num_buses)
    ips = list(mapping.values())
    if len(ips) != len(set(ips)):
        duplicates = [ip for ip in ips if ips.count(ip) > 1]
        raise ValueError(f"IP address collision detected: {set(duplicates)}")
    return True
