#!/usr/bin/env python3
"""Test PLC templates and register maps."""
import sys
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from testbed.plc_templates import (
    PLC_TEMPLATES, build_register_map, build_device_id, get_plc_template, list_templates
)
from testbed.topology import Topology, load_topology

print("=== Available PLC Templates ===")
for name in list_templates():
    t = get_plc_template(name)
    print(f"  {name}: {t.vendor} {t.model} (FW: {t.firmware})"
          f"{' [CVE: ' + t.cve_id + ']' if t.has_firmware_vuln else ''}")

# Test register maps for each bus type
print("\n=== Register Maps ===")
for role in ["generator", "load", "substation"]:
    rmap = build_register_map(role, 0)
    print(f"\n  {role.upper()}:")
    print(f"    Discrete Inputs: {len(rmap.discrete_inputs)}")
    print(f"    Coils: {len(rmap.coils)}")
    print(f"    Input Registers: {len(rmap.input_registers)}")
    print(f"    Holding Registers: {len(rmap.holding_registers)}")
    for addr, name, val, *rest in rmap.input_registers[:3]:
        unit = rest[0] if rest else ""
        print(f"      IR {addr}: {name} = {val} {unit}")

# Test with IEEE-14 topology
print("\n=== IEEE-14 Topology with PLC Types ===")
topo = Topology()
for i in range(min(5, topo.num_buses)):
    node = topo.nodes[i]
    print(f"  Bus {i}: {node.get('plc_type', 'N/A')} ({node.get('bus_role', node.get('type', 'N/A'))})")

# Test device identification
print("\n=== Device Identification (FC43) ===")
for tpl_name in ["siemens_s7_1200", "allen_bradley_compactlogix", "schneider_modicon_m340"]:
    tpl = get_plc_template(tpl_name)
    dev_id = build_device_id(tpl, 0)
    print(f"  {tpl_name}:")
    for k, v in dev_id["objects"].items():
        print(f"    0x{k:02X}: {v}")

print("\n=== ALL PLC TEMPLATE TESTS PASSED ===")
