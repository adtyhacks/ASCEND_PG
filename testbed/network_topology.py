"""
Maps the IEEE-14 bus electrical topology onto a realistic ICS/OT
communication architecture: every bus becomes a substation with a PMU
and RTU, all substations report up through a Firewall to a central
Control Center (SCADA Server, Historian, Engineering HMI).
"""

def build_ot_topology(net):
    nodes = []
    edges = []

    # --- Central Control Center (one logical location) ---
    nodes.append({"id": "scada_server", "label": "SCADA Server", "type": "scada_server"})
    nodes.append({"id": "historian", "label": "Historian", "type": "historian"})
    nodes.append({"id": "hmi", "label": "Engineering HMI", "type": "hmi"})
    nodes.append({"id": "firewall", "label": "Firewall (IT/OT Boundary)", "type": "firewall"})

    edges.append({"from": "scada_server", "to": "firewall", "type": "comm"})
    edges.append({"from": "historian", "to": "firewall", "type": "comm"})
    edges.append({"from": "hmi", "to": "scada_server", "type": "comm"})

    gen_buses = set(net.gen["bus"]) | set(net.ext_grid["bus"])

    # --- Field devices, one set per bus ---
    for bus_id in net.bus.index:
        is_gen = bus_id in gen_buses
        sub_type = "generation_substation" if is_gen else "distribution_substation"
        sub_label = f"{'Generation' if is_gen else 'Distribution'} Substation (Bus {bus_id})"

        substation_id = f"substation_{bus_id}"
        pmu_id = f"pmu_{bus_id}"
        rtu_id = f"rtu_{bus_id}"

        nodes.append({"id": substation_id, "label": sub_label, "type": sub_type})
        nodes.append({"id": pmu_id, "label": f"PMU (Bus {bus_id})", "type": "pmu"})
        nodes.append({"id": rtu_id, "label": f"RTU (Bus {bus_id})", "type": "rtu"})

        edges.append({"from": substation_id, "to": pmu_id, "type": "local"})
        edges.append({"from": substation_id, "to": rtu_id, "type": "local"})
        # Field-to-control-center comm link — this is the actual attack surface
        edges.append({"from": rtu_id, "to": "firewall", "type": "comm", "protocol": "DNP3"})

    # --- Physical power lines, electrical layer ---
    for _, line in net.line.iterrows():
        edges.append({
            "from": f"substation_{int(line['from_bus'])}",
            "to": f"substation_{int(line['to_bus'])}",
            "type": "power_line",
        })

    return nodes, edges