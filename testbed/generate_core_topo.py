import os
import sys
import math

# Ensure local imports work
sys.path.insert(0, os.path.abspath("."))

def generate_imn(filename="core_topology.imn"):
    from testbed.topology import get_topology, load_topology, Topology
    
    csv_dir = os.environ.get("ASCEND_TOPOLOGY_DIR", "")
    if csv_dir and os.path.isdir(csv_dir):
        topo = load_topology(csv_dir)
    else:
        topo = get_topology()
        
    if topo is None:
        topo = Topology()
    
    SCADA_IP = "10.0.0.20"
    ATTACKER_IP = "10.0.0.66"
    MONITOR_IP = "10.0.0.99"
    
    imn_lines = []
    
    # 1. Add Central Switch (node 1)
    imn_lines.append(f"""node n1 {{
    type lanswitch
    network-config {{
        hostname s1
        !
    }}
    canvas c1
    iconcoords {{500.0 400.0}}
    labelcoords {{500.0 430.0}}
}}""")

    node_id = 2
    links = []
    
    # 2. Add SCADA (node 2)
    imn_lines.append(f"""node n{node_id} {{
    type router
    model PC
    network-config {{
        hostname scada
        !
        interface eth0
         ip address {SCADA_IP}/24
        !
    }}
    canvas c1
    iconcoords {{200.0 200.0}}
    labelcoords {{200.0 230.0}}
    custom-config {{
        custom-config-id service:UserDefined
        custom-command UserDefined
        config {{
        ('UserDefined', 'startup')
        python3 testbed/scada_client.py &
        }}
    }}
    services {{DefaultRoute UserDefined}}
}}""")
    links.append(f"link l{len(links)+1} {{\n    nodes {{n{node_id} n1}}\n}}")
    node_id += 1

    # 3. Add Attacker (node 3)
    imn_lines.append(f"""node n{node_id} {{
    type router
    model PC
    network-config {{
        hostname attacker
        !
        interface eth0
         ip address {ATTACKER_IP}/24
        !
    }}
    canvas c1
    iconcoords {{200.0 600.0}}
    labelcoords {{200.0 630.0}}
}}""")
    links.append(f"link l{len(links)+1} {{\n    nodes {{n{node_id} n1}}\n}}")
    node_id += 1
    
    # 3b. Add Monitor/IDS (node 4) - Automatically runs Suricata
    imn_lines.append(f"""node n{node_id} {{
    type router
    model PC
    network-config {{
        hostname ids_monitor
        !
        interface eth0
         ip address {MONITOR_IP}/24
        !
    }}
    canvas c1
    iconcoords {{800.0 200.0}}
    labelcoords {{800.0 230.0}}
    custom-config {{
        custom-config-id service:UserDefined
        custom-command UserDefined
        config {{
        ('UserDefined', 'startup')
        suricata -c /etc/suricata/suricata.yaml -i eth0 --pidfile /var/run/suricata.pid -D
        }}
    }}
    services {{DefaultRoute UserDefined}}
}}""")
    links.append(f"link l{len(links)+1} {{\n    nodes {{n{node_id} n1}}\n}}")
    node_id += 1

    # 4. Add PLCs / RTUs arranged in a large circle for easy viewing
    num_buses = topo.num_buses
    radius = 350
    center_x, center_y = 500, 400
    
    for i in range(num_buses):
        ip = topo.get_ip(i)
        name = topo.name_map.get(i, f"plc{i+1}")
        
        angle = (2 * math.pi * i) / num_buses
        x = center_x + radius * math.cos(angle)
        y = center_y + radius * math.sin(angle)
        
        imn_lines.append(f"""node n{node_id} {{
    type router
    model host
    network-config {{
        hostname {name}
        !
        interface eth0
         ip address {ip}/24
        !
    }}
    canvas c1
    iconcoords {{{x:.1f} {y:.1f}}}
    labelcoords {{{x:.1f} {y+30:.1f}}}
    custom-config {{
        custom-config-id service:UserDefined
        custom-command UserDefined
        config {{
        ('UserDefined', 'startup')
        python3 testbed/plc_server.py -i {ip} &
        }}
    }}
    services {{DefaultRoute UserDefined}}
}}""")
        links.append(f"link l{len(links)+1} {{\n    nodes {{n{node_id} n1}}\n}}")
        node_id += 1
        
    imn_lines.extend(links)
    
    with open(filename, "w") as f:
        f.write("\n".join(imn_lines))
        
    print(f"[*] CORE topology generated successfully: {filename}")
    print("[*] To view and edit in the GUI, run: core-gui " + filename)

if __name__ == "__main__":
    generate_imn()
