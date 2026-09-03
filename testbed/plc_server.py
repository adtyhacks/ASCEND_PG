"""
ASCEND-PG testbed/plc_server.py

Real Modbus TCP PLC server, built directly on pymodbus (3.14.x API),
NOT on minicps.devices.PLC -- MiniCPS's bundled Modbus wrapper is
Python-2-only and targets a pymodbus API that no longer exists in 3.x.

Run this on a Mininet-emulated PLC host, e.g.:
    plc1.cmd('python3 plc_server.py -i 10.0.0.1 &')

Holding registers here represent sensor/actuator values that the
SCADA client polls and that your FDI attack script will later write
to directly (that write IS the False Data Injection attack).
Coils represent binary control outputs (e.g., breaker trip/close commands)
that command injection attacks will toggle directly.
"""

import argparse
import logging

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusServerContext,
    ModbusSequentialDataBlock,
    ModbusDeviceContext,   # renamed from ModbusSlaveContext in 3.12+
)
from pymodbus import ModbusDeviceIdentification

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("plc_server")


def build_context(num_registers=100):
    """
    All holding registers, coils, discrete inputs, and input registers
    start at address 1 initialized to 0 in their own dedicated data blocks.
    In your real topology, seed these with realistic starting values per
    PLC (voltage, current, breaker state, etc.) based on your IEEE-14 bus mapping.
    """
    di_block = ModbusSequentialDataBlock(1, [0] * num_registers)
    co_block = ModbusSequentialDataBlock(1, [0] * num_registers)
    ir_block = ModbusSequentialDataBlock(1, [0] * num_registers)
    hr_block = ModbusSequentialDataBlock(1, [0] * num_registers)

    device = ModbusDeviceContext(
        di=di_block,   # discrete inputs
        co=co_block,   # coils -- what command injection attacks will toggle
        ir=ir_block,   # input registers
        hr=hr_block,   # holding registers -- this is what FDI attacks target
    )
    # single=True means one logical device behind this server (device_id 1)
    return ModbusServerContext(devices=device, single=True)


def main():
    parser = argparse.ArgumentParser(description="ASCEND-PG Modbus PLC server")
    parser.add_argument("-i", "--ip", type=str, required=True,
                         help="IP to bind (the Mininet host's own IP, e.g. 10.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=502,
                         help="Modbus TCP port (default 502 -- requires root/sudo)")
    parser.add_argument("-n", "--num-registers", type=int, default=100,
                         help="number of holding registers to expose")
    args = parser.parse_args()

    identity = ModbusDeviceIdentification()
    identity.VendorName = "ASCEND-PG"
    identity.ProductCode = "PLC"
    identity.ProductName = "ASCEND-PG Simulated PLC"
    identity.ModelName = "ASCEND-PG PLC v1"
    identity.MajorMinorRevision = "1.0"

    context = build_context(args.num_registers)

    log.info("Starting Modbus TCP PLC server on %s:%d", args.ip, args.port)
    StartTcpServer(context=context, identity=identity, address=(args.ip, args.port))


if __name__ == "__main__":
    main()
