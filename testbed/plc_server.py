"""
ASCEND-PG testbed/plc_server.py

Real Modbus TCP PLC server with IEEE-14 bus data seeded into registers.

Each PLC represents one IEEE-14 bus. Holding registers store:
  - Reg 0-9:   Bus voltage (pU), angle, real/reactive power
  - Reg 10-19: Load data (MW, Mvar)
  - Reg 20-29: Generator data (MW, Mvar setpoints)
  - Reg 30-99: Detailed telemetry (line flows, transformer taps)

Coils represent breaker states (open/closed) for that bus's lines.

Run on Mininet host:
    plc1.cmd('python3 plc_server.py -i 10.0.0.1 --bus-id 0 &')
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusServerContext,
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
)
from pymodbus import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("plc_server")

# IEEE-14 bus data from pandapower case14 power flow solution
# Format: (voltage_pu, voltage_angle_deg, P_MW, Q_Mvar, load_MW, load_Mvar)
IEEE14_BUS_DATA = {
    0:  {"name": "Bus 1 (Slack)",    "vm_pu": 1.060, "va_deg": 0.00,    "pg": 232.4, "qg": -16.9, "pl": 0.0,   "ql": 0.0},
    1:  {"name": "Bus 2 (PV)",       "vm_pu": 1.045, "va_deg": -4.98,   "pg": 40.0,  "qg": 42.4,  "pl": 21.7,  "ql": 12.7},
    2:  {"name": "Bus 3 (PV)",       "vm_pu": 1.010, "va_deg": -12.72,  "pg": 0.0,   "qg": 23.4,  "pl": 94.2,  "ql": 19.0},
    3:  {"name": "Bus 6 (PV)",       "vm_pu": 1.070, "va_deg": -14.22,  "pg": 0.0,   "qg": -6.3,  "pl": 11.2,  "ql": 7.5},
    4:  {"name": "Bus 8 (PV)",       "vm_pu": 1.080, "va_deg": -14.22,  "pg": 0.0,   "qg": 17.4,  "pl": 0.0,   "ql": 0.0},
    5:  {"name": "Bus 4 (PQ)",       "vm_pu": 1.019, "va_deg": -10.33,  "pg": 0.0,   "qg": 0.0,   "pl": 47.8,  "ql": -3.9},
    6:  {"name": "Bus 5 (PQ)",       "vm_pu": 1.020, "va_deg": -8.78,   "pg": 0.0,   "qg": 0.0,   "pl": 7.6,   "ql": 1.6},
    7:  {"name": "Bus 7 (PQ)",       "vm_pu": 1.062, "va_deg": -13.37,  "pg": 0.0,   "qg": 0.0,   "pl": 0.0,   "ql": 0.0},
    8:  {"name": "Bus 9 (PQ)",       "vm_pu": 1.056, "va_deg": -14.94,  "pg": 0.0,   "qg": 0.0,   "pl": 29.5,  "ql": 16.6},
    9:  {"name": "Bus 10 (PQ)",      "vm_pu": 1.051, "va_deg": -15.10,  "pg": 0.0,   "qg": 0.0,   "pl": 9.0,   "ql": 5.8},
    10: {"name": "Bus 11 (PQ)",      "vm_pu": 1.057, "va_deg": -14.79,  "pg": 0.0,   "qg": 0.0,   "pl": 3.5,   "ql": 1.8},
    11: {"name": "Bus 12 (PQ)",      "vm_pu": 1.055, "va_deg": -15.07,  "pg": 0.0,   "qg": 0.0,   "pl": 6.1,   "ql": 1.6},
    12: {"name": "Bus 13 (PQ)",      "vm_pu": 1.050, "va_deg": -15.56,  "pg": 0.0,   "qg": 0.0,   "pl": 13.5,  "ql": 5.8},
    13: {"name": "Bus 14 (PQ)",      "vm_pu": 1.036, "va_deg": -16.21,  "pg": 0.0,   "qg": 0.0,   "pl": 14.9,  "ql": 5.0},
}

# Bus types: 3=slack(gen), 1=PV(gen), 2=PQ(load)
IEEE14_BUS_TYPES = [3, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2]

# IEEE-14 line connectivity (from_bus, to_bus) — 23 lines
IEEE14_LINES = [
    (0, 1), (0, 2), (0, 4),   # Bus 1 connects to 2, 3, 5
    (1, 2), (1, 3), (1, 4),   # Bus 2 connects to 3, 4, 5
    (2, 3),                     # Bus 3 connects to 4
    (3, 6),                     # Bus 4 connects to 7
    (4, 5), (4, 6), (4, 7),   # Bus 5 connects to 6, 7, 9
    (5, 8),                     # Bus 6 connects to 10
    (6, 9),                     # Bus 7 connects to 11
    (7, 8), (7, 9), (7, 10),  # Bus 8 connects to 9, 10, 11
    (8, 9),                     # Bus 9 connects to 10
    (8, 11), (8, 12),          # Bus 9 connects to 12, 13
    (9, 10),                    # Bus 10 connects to 11
    (10, 11),                   # Bus 11 connects to 12
    (11, 12),                   # Bus 12 connects to 13
    (11, 13),                   # Bus 12 connects to 14
]


def build_context(bus_id: int, num_registers: int = 100):
    """Build Modbus data blocks with realistic register maps from topology."""
    from testbed.topology import get_topology
    from testbed.plc_templates import (
        build_register_map, build_device_id, get_plc_template, PLC_TEMPLATES
    )

    topo = get_topology()
    node = topo.nodes[bus_id] if topo and bus_id < len(topo.nodes) else {}

    # Get PLC template and bus role
    plc_type = node.get("plc_type", "generic_modbus")
    bus_role = node.get("bus_role", node.get("type", "pq"))
    template = get_plc_template(plc_type)

    # Get power flow values
    vm_pu = float(node.get("voltage", 1.0))
    pg = float(node.get("pg", 0.0))
    qg = float(node.get("qg", 0.0))
    pl = float(node.get("pl", 0.0))
    ql = float(node.get("ql", 0.0))

    # Build realistic register map
    reg_map = build_register_map(bus_role, bus_id, vm_pu, pg, qg, pl, ql)

    # Build register blocks from template address ranges
    def _build_block(start_addr, count, defaults=None):
        values = [0] * count
        if defaults:
            for addr, name, val, *rest in defaults:
                idx = addr - start_addr
                if 0 <= idx < count:
                    values[idx] = max(0, min(65535, int(val)))
        # pymodbus 3.15+ requires address >= 1; normalize to address 1
        # so SCADA client can read all PLCs from a single address
        effective_addr = 1
        return ModbusSequentialDataBlock(effective_addr, values)

    # Coils (digital outputs)
    co_block = _build_block(template.co_start, template.co_count,
                            [(a, n, v) for a, n, v in reg_map.coils])

    # Discrete inputs (digital status)
    di_block = _build_block(template.di_start, template.di_count,
                            [(a, n, v) for a, n, v in reg_map.discrete_inputs])

    # Input registers (read-only analog)
    ir_block = _build_block(template.ir_start, template.ir_count,
                            [(a, n, v, *r) for a, n, v, *r in reg_map.input_registers])

    # Holding registers (read/write analog)
    hr_block = _build_block(template.hr_start, template.hr_count,
                            [(a, n, v, *r) for a, n, v, *r in reg_map.holding_registers])

    # Store device ID for FC43 responses
    device_id = build_device_id(template, bus_id)
    if not hasattr(build_context, "_device_ids"):
        build_context._device_ids = {}
    build_context._device_ids[bus_id] = {"template": template, "device_id": device_id, "reg_map": reg_map}

    device = ModbusDeviceContext(
        di=di_block, co=co_block, ir=ir_block, hr=hr_block,
    )
    return ModbusServerContext(devices=device, single=True)



def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG Modbus PLC server (IEEE-14)")
    parser.add_argument("-i", "--ip", type=str, required=True,
                         help="IP to bind (Mininet host IP, e.g. 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=502,
                         help="Modbus TCP port (default 502)")
    parser.add_argument("--bus-id", type=int, required=True,
                         help="IEEE-14 bus ID (0-13)")
    parser.add_argument("-n", "--num-registers", type=int, default=100,
                         help="number of holding registers")
    args = parser.parse_args()

    bus_name = IEEE14_BUS_DATA.get(args.bus_id, {}).get("name", f"Bus {args.bus_id}")

    identity = ModbusDeviceIdentification()
    identity.VendorName = "ASCEND-PG"
    identity.ProductCode = f"PLC-B{args.bus_id}"
    identity.ProductName = f"ASCEND-PG PLC ({bus_name})"
    identity.ModelName = "ASCEND-PG PLC v2"
    identity.MajorMinorRevision = "2.0"

    context = build_context(args.bus_id, args.num_registers)

    log.info("Starting PLC for %s on %s:%d", bus_name, args.ip, args.port)
    StartTcpServer(context=context, identity=identity, address=(args.ip, args.port))


if __name__ == "__main__":
    main()
