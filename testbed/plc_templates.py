"""
ASCEND-PG — PLC Templates & Realistic ICS Register Maps

Defines predefined PLC types (Siemens, Allen Bradley, Schneider) with:
- Vendor-specific register addressing and protocol quirks
- Realistic register maps for generator, load, and substation buses
- Modbus function code support per device type
- Firmware version and model identification

Each PLC type has:
- Device identification registers (FC43)
- Input registers (analog inputs: voltage, current, power)
- Holding registers (setpoints, control parameters)
- Discrete inputs (digital status: breaker positions, alarms)
- Coils (digital outputs: relay controls, breaker commands)
"""

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# =============================================================================
# PLC Device Templates
# =============================================================================

@dataclass
class PLCTemplate:
    """Defines a PLC device type with vendor-specific behavior."""
    vendor: str
    model: str
    firmware: str
    unit_id: int = 1

    # Supported Modbus function codes
    supported_fc: List[int] = field(default_factory=lambda: [1, 2, 3, 4, 5, 6, 15, 16, 43])

    # Register address ranges
    di_start: int = 1000      # Discrete inputs start
    di_count: int = 64
    co_start: int = 0         # Coils start
    co_count: int = 64
    ir_start: int = 3000      # Input registers start
    ir_count: int = 100
    hr_start: int = 4000      # Holding registers start
    hr_count: int = 100

    # Vendor-specific quirks
    max_read_registers: int = 125
    max_write_registers: int = 123
    supports_broadcast: bool = False
    has_firmware_vuln: bool = False  # Known CVE
    cve_id: Optional[str] = None


# Predefined PLC templates
PLC_TEMPLATES = {
    "siemens_s7_1200": PLCTemplate(
        vendor="Siemens",
        model="S7-1200",
        firmware="4.5.2",
        supported_fc=[1, 2, 3, 4, 5, 6, 15, 16, 43],
        hr_start=40000,
        ir_start=30000,
        di_start=10000,
        co_start=0,
        has_firmware_vuln=True,
        cve_id="CVE-2019-13945",
    ),
    "siemens_s7_1500": PLCTemplate(
        vendor="Siemens",
        model="S7-1500",
        firmware="2.8.1",
        supported_fc=[1, 2, 3, 4, 5, 6, 15, 16, 43],
        hr_start=40000,
        ir_start=30000,
        di_start=10000,
        co_start=0,
        has_firmware_vuln=False,
    ),
    "allen_bradley_compactlogix": PLCTemplate(
        vendor="Allen Bradley",
        model="CompactLogix 5370",
        firmware="33.011",
        supported_fc=[1, 2, 3, 4, 6, 16, 43],
        hr_start=0,
        ir_start=3,
        di_start=10,
        co_start=0,
        max_read_registers=80,
        has_firmware_vuln=True,
        cve_id="CVE-2022-1159",
    ),
    "allen_bradley_controllogix": PLCTemplate(
        vendor="Allen Bradley",
        model="ControlLogix 5580",
        firmware="35.011",
        supported_fc=[1, 2, 3, 4, 6, 16, 43],
        hr_start=0,
        ir_start=3,
        di_start=10,
        co_start=0,
        max_read_registers=80,
    ),
    "schneider_modicon_m340": PLCTemplate(
        vendor="Schneider Electric",
        model="Modicon M340",
        firmware="3.20",
        supported_fc=[1, 2, 3, 4, 5, 6, 15, 16, 43],
        hr_start=0,
        ir_start=30000,
        di_start=10000,
        co_start=0,
        supports_broadcast=True,
        has_firmware_vuln=True,
        cve_id="CVE-2019-6856",
    ),
    "schneider_modicon_m580": PLCTemplate(
        vendor="Schneider Electric",
        model="Modicon M580",
        firmware="3.10",
        supported_fc=[1, 2, 3, 4, 5, 6, 15, 16, 43],
        hr_start=0,
        ir_start=30000,
        di_start=10000,
        co_start=0,
        supports_broadcast=True,
    ),
    "generic_modbus": PLCTemplate(
        vendor="Generic",
        model="Modbus TCP Device",
        firmware="1.0.0",
        supported_fc=[1, 2, 3, 4, 5, 6, 15, 16, 43],
        hr_start=0,
        ir_start=0,
        di_start=0,
        co_start=0,
    ),
}


# =============================================================================
# Realistic Register Maps (per bus type)
# =============================================================================

@dataclass
class RegisterMap:
    """Realistic ICS register layout for a bus."""
    bus_type: str  # "generator", "load", "substation"

    # Discrete Inputs (read-only digital status)
    # Each: (address, name, default_value)
    discrete_inputs: List[tuple] = field(default_factory=list)

    # Coils (read/write digital outputs)
    coils: List[tuple] = field(default_factory=list)

    # Input Registers (read-only analog values)
    # Each: (address, name, value, unit, scale_factor)
    input_registers: List[tuple] = field(default_factory=list)

    # Holding Registers (read/write analog values)
    holding_registers: List[tuple] = field(default_factory=list)


def build_generator_register_map(bus_id: int, vm_pu: float = 1.05,
                                  pg: float = 100.0, qg: float = 50.0) -> RegisterMap:
    """Build realistic register map for a generator bus."""
    return RegisterMap(
        bus_type="generator",
        discrete_inputs=[
            (10000, "Breaker_Status_1", 1),        # CB closed
            (10001, "Breaker_Status_2", 1),
            (10002, "Exciter_Alarm", 0),            # Normal
            (10003, "Overexcited", 0),
            (10004, "Underexcited", 0),
            (10005, "Overtemp_Alarm", 0),
            (10006, "Low_Oil_Level", 0),
            (10007, "Vibration_High", 0),
            (10008, "Gen_Ready", 1),
            (10009, "Grid_Sync", 1),
            (10010, "AVR_Active", 1),
            (10011, "GOV_Active", 1),
        ],
        coils=[
            (0, "Trip_Breaker_1", 0),               # Open breaker
            (1, "Trip_Breaker_2", 0),
            (2, "Raise_Excitation", 0),
            (3, "Lower_Excitation", 0),
            (4, "Raise_Speed", 0),
            (5, "Lower_Speed", 0),
            (6, "Emergency_Stop", 0),
            (7, "Reset_Alarms", 0),
        ],
        input_registers=[
            (30000, "Voltage_PU", int(vm_pu * 10000), "p.u.", 10000),
            (30001, "Voltage_Angle_Deg", int(abs(random.uniform(0, 15)) * 100), "deg", 100),
            (30002, "Current_Amps", int(random.uniform(200, 800) * 10), "A", 10),
            (30003, "Real_Power_MW", int(pg * 10), "MW", 10),
            (30004, "Reactive_Power_Mvar", int(abs(qg) * 10), "Mvar", 10),
            (30005, "Frequency_mHz", int(random.uniform(59.9, 60.1) * 1000), "mHz", 1000),
            (30006, "Power_Factor", int(random.uniform(0.85, 0.98) * 1000), "", 1000),
            (30007, "Gen_Speed_RPM", int(random.uniform(3580, 3620)), "RPM", 1),
            (30008, "Stator_Temp_C", int(random.uniform(60, 90) * 10), "C", 10),
            (30009, "Rotor_Temp_C", int(random.uniform(70, 110) * 10), "C", 10),
            (30010, "Oil_Pressure_PSI", int(random.uniform(25, 45) * 10), "PSI", 10),
            (30011, "Coolant_Temp_C", int(random.uniform(30, 50) * 10), "C", 10),
        ],
        holding_registers=[
            (40000, "Voltage_Setpoint_PU", int(vm_pu * 10000), "p.u.", 10000),
            (40001, "MW_Setpoint", int(pg * 10), "MW", 10),
            (40002, "Mvar_Setpoint", int(abs(qg) * 10), "Mvar", 10),
            (40003, "Freq_Setpoint_mHz", 60000, "mHz", 1000),
            (40004, "Voltage_Droop_Pct", 400, "%", 100),
            (40005, "Freq_Droop_Pct", 500, "%", 100),
            (40006, "Max_MW_Limit", int(pg * 12), "MW", 10),
            (40007, "Min_MW_Limit", 0, "MW", 10),
            (40008, "Max_Mvar_Limit", int(abs(qg) * 15), "Mvar", 10),
            (40009, "Min_Mvar_Limit", int(-abs(qg) * 10), "Mvar", 10),
            (40010, "AVR_Gain", 200, "", 100),
            (40011, "GOV_Gain", 150, "", 100),
        ],
    )


def build_load_register_map(bus_id: int, pl: float = 50.0,
                             ql: float = 20.0, vm_pu: float = 1.02) -> RegisterMap:
    """Build realistic register map for a load bus."""
    return RegisterMap(
        bus_type="load",
        discrete_inputs=[
            (10000, "Breaker_Status", 1),
            (10001, "Load_Shed_Active", 0),
            (10002, "Under_Voltage", 0),
            (10003, "Over_Voltage", 0),
            (10004, "Overcurrent", 0),
            (10005, "Fault_Detected", 0),
            (10006, "UPS_Active", 0),
            (10007, "Load_Online", 1),
        ],
        coils=[
            (0, "Trip_Breaker", 0),
            (1, "Load_Shed", 0),
            (2, "Close_Breaker", 0),
            (3, "Reset_Fault", 0),
        ],
        input_registers=[
            (30000, "Voltage_PU", int(vm_pu * 10000), "p.u.", 10000),
            (30001, "Voltage_Angle_Deg", int(abs(random.uniform(5, 15)) * 100), "deg", 100),
            (30002, "Load_Current_A", int(random.uniform(100, 500) * 10), "A", 10),
            (30003, "Real_Load_MW", int(pl * 10), "MW", 10),
            (30004, "Reactive_Load_Mvar", int(abs(ql) * 10), "Mvar", 10),
            (30005, "Power_Factor", int(random.uniform(0.80, 0.95) * 1000), "", 1000),
            (30006, "Total_Wh", int(random.uniform(100000, 999999)), "Wh", 1),
            (30007, "Demand_kW", int(pl * 1.2 * 10), "kW", 10),
        ],
        holding_registers=[
            (40000, "Load_Shed_Pct", 0, "%", 100),
            (40001, "UVT_Setpoint_PU", 9000, "p.u.", 10000),
            (40002, "OVT_Setpoint_PU", 11000, "p.u.", 10000),
            (40003, "OCD_Setpoint_A", 6000, "A", 10),
            (40004, "Load_Priority", 1, "", 1),
            (40005, "Ramp_Rate_kW_per_min", 500, "kW/min", 10),
        ],
    )


def build_substation_register_map(bus_id: int, vm_pu: float = 1.02) -> RegisterMap:
    """Build realistic register map for a substation/transmission bus."""
    return RegisterMap(
        bus_type="substation",
        discrete_inputs=[
            (10000, "Bus_Breaker_1", 1),
            (10001, "Bus_Breaker_2", 1),
            (10002, "Bus_Breaker_3", 1),
            (10003, "Transformer_Alarm", 0),
            (10004, "Buchholz_Gas", 0),
            (10005, "Winding_Temp_High", 0),
            (10006, "Oil_Temp_High", 0),
            (10007, "SF6_Low_Pressure", 0),
            (10008, "DC_System_Fault", 0),
            (10009, "AC_System_Fault", 0),
        ],
        coils=[
            (0, "Trip_Breaker_1", 0),
            (1, "Trip_Breaker_2", 0),
            (2, "Trip_Breaker_3", 0),
            (3, "Close_Breaker_1", 0),
            (4, "Close_Breaker_2", 0),
            (5, "Close_Breaker_3", 0),
            (6, "Block_Auto_Close", 0),
            (7, "Transfer_Bus", 0),
        ],
        input_registers=[
            (30000, "Bus_Voltage_PU", int(vm_pu * 10000), "p.u.", 10000),
            (30001, "Bus_Angle_Deg", int(abs(random.uniform(5, 15)) * 100), "deg", 100),
            (30002, "Line_1_Current_A", int(random.uniform(100, 600) * 10), "A", 10),
            (30003, "Line_2_Current_A", int(random.uniform(100, 600) * 10), "A", 10),
            (30004, "Line_3_Current_A", int(random.uniform(100, 600) * 10), "A", 10),
            (30005, "Transformer_Tap", int(random.uniform(0.95, 1.05) * 10000), "p.u.", 10000),
            (30006, "Winding_Temp_C", int(random.uniform(50, 85) * 10), "C", 10),
            (30007, "Oil_Temp_C", int(random.uniform(40, 70) * 10), "C", 10),
            (30008, "SF6_Pressure_PSI", int(random.uniform(70, 80) * 10), "PSI", 10),
        ],
        holding_registers=[
            (40000, "Tap_Setpoint", int(vm_pu * 10000), "p.u.", 10000),
            (40001, "Tap_Lower_Limit", 9500, "p.u.", 10000),
            (40002, "Tap_Upper_Limit", 10500, "p.u.", 10000),
            (40003, "Overcurrent_Setpoint_A", 8000, "A", 10),
            (40004, "Distance_Z1_Setpoint", 800, "ohms", 1000),
            (40005, "Distance_Z2_Setpoint", 1200, "ohms", 1000),
            (40006, "Auto_Close_Delay_s", 50, "s", 10),
        ],
    )


# =============================================================================
# Device Identification Response (FC43 / MEI)
# =============================================================================

def build_device_id(template: PLCTemplate, bus_id: int) -> dict:
    """Build Modbus device identification response (FC43, MEI Type 0x0E)."""
    return {
        "unit_id": template.unit_id,
        "mei_type": 0x0E,
        "conformity_level": 0x01,  # Basic identification
        "objects": {
            0x00: template.vendor,         # VendorName
            0x01: template.model,          # ProductCode
            0x02: template.firmware,       # FirmwareRevision
            0x03: f"ASCEND-PG-Bus{bus_id}",  # VendorUrl
            0x04: f"SN-{template.vendor[:3].upper()}-{bus_id:04d}",  # ProductName
            0x05: "MODBUS TCP",            # ApplicationName
        },
        "not_supported_objects": [],
    }


# =============================================================================
# Register Map Builder
# =============================================================================

def build_register_map(bus_type: str, bus_id: int, vm_pu: float = 1.02,
                       pg: float = 100.0, qg: float = 50.0,
                       pl: float = 50.0, ql: float = 20.0) -> RegisterMap:
    """Build a register map based on bus type."""
    if bus_type in ("slack", "pv", "gen", "generator"):
        return build_generator_register_map(bus_id, vm_pu, pg, qg)
    elif bus_type in ("pq", "load"):
        return build_load_register_map(bus_id, pl, ql, vm_pu)
    elif bus_type in ("sub", "substation", "bus"):
        return build_substation_register_map(bus_id, vm_pu)
    else:
        return build_load_register_map(bus_id, pl, ql, vm_pu)


def get_plc_template(template_name: str = "generic_modbus") -> PLCTemplate:
    """Get a PLC template by name."""
    return PLC_TEMPLATES.get(template_name, PLC_TEMPLATES["generic_modbus"])


def list_templates() -> List[str]:
    """List available PLC template names."""
    return list(PLC_TEMPLATES.keys())
