"""
ASCEND-PG — CORE 9.2.1 XML Scenario Generator

Generates structurally valid CORE 9.2.1 XML topology files (core_topology.xml)
from Pandapower IEEE-14 or IEEE-30 topologies.

Key Features:
  - Generates valid XML for CORE 9.2.1 (replaces legacy .imn)
  - Connects all nodes to a central HUB node (type="HUB"), disabling MAC learning
    on the virtual bridge so Suricata IDS on ids_monitor receives 100% of attack traffic
  - Uses centralized, non-colliding IP addresses from testbed.ip_config
  - Supports CLI argument parsing (--case 14 / --case 30, --output, --check-health)
"""

import argparse
import math
import os
import tempfile
import sys
import xml.dom.minidom
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from testbed.ip_config import (
    SCADA_IP,
    ATTACKER_IP,
    MONITOR_IP,
    NETMASK_BITS,
    get_plc_ip,
    audit_ip_uniqueness,
)
from testbed.topology import Topology, load_case
from testbed.core_services import SERVICE, node_templates, service_name
from testbed.core_xml import validate_xml


def add_application(parent, node_id, role, case, **kwargs):
    scripts = node_templates(role, case, **kwargs)
    name = service_name(scripts)
    service = ET.SubElement(parent, "service", name=name, node=str(node_id))
    templates = ET.SubElement(service, "templates")
    for filename, text in scripts.items():
        ET.SubElement(templates, "template", name=filename).text = text
    return name


def check_core_environment() -> Dict[str, Any]:
    """Probe the daemon, not just executable names on PATH."""
    from testbed.core_runtime import core_request
    try:
        return core_request("health")
    except RuntimeError as exc:
        return {"daemon_ready": False, "error": str(exc)}

def generate_core_xml(case: int = 14, output_path: str = "core_topology.xml", use_hub: bool = True,
                      topology: Topology = None) -> str:
    """
    Generate a valid CORE 9.2.1 XML scenario for IEEE-14 or IEEE-30.

    Args:
        case: 14 or 30
        output_path: Path to write the .xml file
        use_hub: If True, uses type="HUB" for node 1 so Suricata sees all unicast traffic.

    Returns:
        Absolute path to the generated XML file.
    """
    if topology is None and case not in (14, 30):
        raise ValueError(f"Invalid case {case}. Only IEEE-14 and IEEE-30 are supported.")

    if os.name != "posix":
        raise RuntimeError("Generate CORE scenarios inside WSL2 so service paths are Linux paths.")
    topo = topology if topology is not None else load_case(case)
    if topology is not None:
        if not isinstance(topology, Topology):
            raise ValueError("CORE generation requires the canonical Topology model.")
        # Apply the same CORE constraints to JSON, CSV and directly constructed models.
        Topology.from_custom_dict({**topology.to_dict(), "case_name": "custom_validation"})
    case = topo.num_buses
    audit_ip_uniqueness(case)

    scenario = ET.Element("scenario")

    # 1. Networks: Central Hub / Switch
    networks_el = ET.SubElement(scenario, "networks")
    net_type = "HUB" if use_hub else "SWITCH"
    s1_net = ET.SubElement(
        networks_el, "network",
        id="1", name="s1", icon="", canvas="1", type=net_type
    )
    ET.SubElement(s1_net, "position", x="600.0", y="450.0", lat="47.5768", lon="-122.1289", alt="2.0")

    devices_el = ET.SubElement(scenario, "devices")
    links_el = ET.SubElement(scenario, "links")
    service_configs_el = ET.SubElement(scenario, "service_configurations")

    # 2. Add SCADA (node 2)
    scada_dev = ET.SubElement(devices_el, "device", id="2", name="scada", icon="", canvas="1", type="PC", image="")
    ET.SubElement(scada_dev, "position", x="250.0", y="250.0", lat="47.5780", lon="-122.1320", alt="2.0")
    scada_services = ET.SubElement(scada_dev, "services")
    ET.SubElement(scada_services, "service", name="DefaultRoute")
    ET.SubElement(scada_services, "service", name=SERVICE)

    # SCADA link
    scada_link = ET.SubElement(links_el, "link", node1="2", node2="1")
    ET.SubElement(
        scada_link, "iface1",
        id="0", name="eth0", mac="00:00:00:aa:00:02",
        ip4=SCADA_IP, ip4_mask=str(NETMASK_BITS)
    )
    ET.SubElement(scada_link, "options", delay="0", bandwidth="0", loss="0.0", dup="0", jitter="0", unidirectional="0", buffer="0")

    # SCADA service config
    scada_services[-1].set("name", add_application(service_configs_el, 2, "scada", case))

    # 3. Add Attacker (node 3)
    att_dev = ET.SubElement(devices_el, "device", id="3", name="attacker", icon="", canvas="1", type="PC", image="")
    ET.SubElement(att_dev, "position", x="250.0", y="650.0", lat="47.5750", lon="-122.1320", alt="2.0")
    att_services = ET.SubElement(att_dev, "services")
    ET.SubElement(att_services, "service", name="DefaultRoute")

    att_link = ET.SubElement(links_el, "link", node1="3", node2="1")
    ET.SubElement(
        att_link, "iface1",
        id="0", name="eth0", mac="00:00:00:aa:00:03",
        ip4=ATTACKER_IP, ip4_mask=str(NETMASK_BITS)
    )
    ET.SubElement(att_link, "options", delay="0", bandwidth="0", loss="0.0", dup="0", jitter="0", unidirectional="0", buffer="0")

    # 4. Add IDS Monitor (node 4) — runs Suricata on eth0
    ids_dev = ET.SubElement(devices_el, "device", id="4", name="ids_monitor", icon="", canvas="1", type="PC", image="")
    ET.SubElement(ids_dev, "position", x="950.0", y="250.0", lat="47.5780", lon="-122.1250", alt="2.0")
    ids_services = ET.SubElement(ids_dev, "services")
    ET.SubElement(ids_services, "service", name="DefaultRoute")
    ET.SubElement(ids_services, "service", name=SERVICE)

    ids_link = ET.SubElement(links_el, "link", node1="4", node2="1")
    ET.SubElement(
        ids_link, "iface1",
        id="0", name="eth0", mac="00:00:00:aa:00:04",
        ip4=MONITOR_IP, ip4_mask=str(NETMASK_BITS)
    )
    ET.SubElement(ids_link, "options", delay="0", bandwidth="0", loss="0.0", dup="0", jitter="0", unidirectional="0", buffer="0")

    ids_services[-1].set("name", add_application(service_configs_el, 4, "ids", case))

    # 5. Add PLCs arranged in a geometric circle around the hub
    num_buses = topo.num_buses
    radius = 380.0
    center_x, center_y = 600.0, 450.0
    node_id_start = 5

    for b in range(num_buses):
        nid = node_id_start + b
        name = f"plc{b + 1}"
        ip = topo.get_ip(b) if topology is not None else get_plc_ip(b)

        angle = (2.0 * math.pi * b) / num_buses
        x = center_x + radius * math.cos(angle)
        y = center_y + radius * math.sin(angle)

        plc_dev = ET.SubElement(devices_el, "device", id=str(nid), name=name, icon="", canvas="1", type="host", image="")
        ET.SubElement(plc_dev, "position", x=f"{x:.1f}", y=f"{y:.1f}", lat=f"{47.5768 + (y-450)*0.00001:.5f}", lon=f"{-122.1289 + (x-600)*0.00001:.5f}", alt="2.0")
        plc_services = ET.SubElement(plc_dev, "services")
        ET.SubElement(plc_services, "service", name="DefaultRoute")
        ET.SubElement(plc_services, "service", name=SERVICE)

        plc_link = ET.SubElement(links_el, "link", node1=str(nid), node2="1")
        mac_suffix = f"{nid:04x}"
        ET.SubElement(
            plc_link, "iface1",
            id="0", name="eth0", mac=f"00:00:00:aa:{mac_suffix[:2]}:{mac_suffix[2:]}",
            ip4=ip, ip4_mask=str(NETMASK_BITS)
        )
        ET.SubElement(plc_link, "options", delay="0", bandwidth="0", loss="0.0", dup="0", jitter="0", unidirectional="0", buffer="0")

        plc_services[-1].set("name", add_application(service_configs_el, nid, "plc", case, ip=ip, bus_id=b, node_data=topo.nodes[b]))

    # 6. Global metadata & session options
    ET.SubElement(scenario, "session_origin", lat="47.579166412353516", lon="-122.13232421875", alt="2.0", scale="150.0")

    sess_opts = ET.SubElement(scenario, "session_options")
    ET.SubElement(sess_opts, "configuration", name="controlnet", value="")
    ET.SubElement(sess_opts, "configuration", name="enablerj45", value="1")
    ET.SubElement(sess_opts, "configuration", name="preservedir", value="0")
    ET.SubElement(sess_opts, "configuration", name="enablesdt", value="0")
    ET.SubElement(sess_opts, "configuration", name="ovs", value="0")

    sess_meta = ET.SubElement(scenario, "session_metadata")
    ET.SubElement(sess_meta, "configuration", name="shapes", value="[]")
    ET.SubElement(sess_meta, "configuration", name="hidden", value="[]")
    canvas_json = '{"gridlines": true, "dimensions": [1200, 900], "canvases": [{"id": 1, "wallpaper": null, "wallpaper_style": 1, "fit_image": false}]}'
    ET.SubElement(sess_meta, "configuration", name="canvas", value=canvas_json)
    ET.SubElement(sess_meta, "configuration", name="edges", value="[]")

    def_services = ET.SubElement(scenario, "default_services")
    pc_node = ET.SubElement(def_services, "node", type="PC")
    ET.SubElement(pc_node, "service", name="DefaultRoute")
    host_node = ET.SubElement(def_services, "node", type="host")
    ET.SubElement(host_node, "service", name="DefaultRoute")

    # Pretty print XML
    raw_xml = ET.tostring(scenario, encoding="utf-8")
    dom = xml.dom.minidom.parseString(raw_xml)
    pretty_xml = dom.toprettyxml(indent="  ")

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=out_file.parent,
                                     suffix=".xml", delete=False) as temporary:
        temporary.write(pretty_xml)
        temporary_path = Path(temporary.name)
    try:
        validate_xml(temporary_path)
        temporary_path.replace(out_file)
    finally:
        temporary_path.unlink(missing_ok=True)

    return str(out_file)


def main():
    parser = argparse.ArgumentParser(description="Generate CORE 9.2.1 XML Scenario for ASCEND-PG")
    parser.add_argument("--case", type=int, choices=[14, 30], default=14,
                        help="Power grid case: 14 for IEEE-14 (default) or 30 for IEEE-30")
    parser.add_argument("-o", "--output", type=str, default="core_topology.xml",
                        help="Output path for the generated CORE XML scenario file")
    parser.add_argument("--switch", action="store_true",
                        help="Use standard SWITCH instead of HUB (HUB is recommended for IDS visibility)")
    parser.add_argument("--check-health", action="store_true",
                        help="Check CORE 9.2.1 tools in system and WSL")

    args = parser.parse_args()

    if args.check_health:
        health = check_core_environment()
        print("CORE 9.2.1 Environment Health Check:")
        for k, v in health.items():
            print(f"  {k:20}: {v}")
        return

    out_path = generate_core_xml(case=args.case, output_path=args.output, use_hub=not args.switch)
    print(f"[*] CORE 9.2.1 XML scenario generated successfully: {out_path}")
    print(f"[*] Grid case: IEEE-{args.case} ({args.case} PLCs + SCADA + Attacker + IDS Monitor)")
    print(f"[*] Central switch mode: {'HUB (Full IDS tap visibility)' if not args.switch else 'SWITCH'}")
    print(f"[*] Register services first: /opt/core/venv/bin/python scripts/core_session.py register {out_path}")
    print("[*] To open visually: launch core-gui, then File > Open the generated XML")
    print(f"[*] To start via CLI: core-cli xml -f {Path(out_path).name} -s")


if __name__ == "__main__":
    main()
