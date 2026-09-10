import streamlit as st
import json
import glob
import os
import sys
import tempfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from testbed.topology import Topology, load_topology, set_topology, get_topology, save_topology_csv
from testbed.import_pkt import import_topology

st.set_page_config(page_title="Configure Network", layout="wide")
st.title("Network Configuration")

# --- Step 1: pick topology ---
st.header("1. Network Topology")
st.caption("Choose a preset or upload a custom topology for the testbed.")

col_preset, col_custom = st.columns(2)

with col_preset:
    st.subheader("Preset Topology")
    topology_files = glob.glob("data/sample_topologies/*.json")
    topology_options = {}
    for f in topology_files:
        with open(f) as fh:
            t = json.load(fh)
            topology_options[t["name"]] = t

    if topology_options:
        choice = st.selectbox("Choose a preset grid topology", list(topology_options.keys()))
        st.caption(topology_options[choice].get("description", ""))
    else:
        st.info("No preset topologies found in data/sample_topologies/")
        choice = None

with col_custom:
    st.subheader("Custom Topology")
    st.markdown("""
    Upload a custom topology using one of these formats:

    **CSV Format** (two files):
    - `nodes.csv`: `bus_id, name, type, voltage, ip, plc_type, bus_role`
    - `edges.csv`: `from_bus, to_bus`

    **XML Format** (Packet Tracer compatible):
    - Single `.xml` file with devices and connections
    """)

    upload_type = st.radio("Upload format", ["CSV (two files)", "XML (single file)"],
                           horizontal=True, key="upload_type")

    if upload_type == "CSV (two files)":
        col_nodes, col_edges = st.columns(2)
        with col_nodes:
            nodes_file = st.file_uploader("nodes.csv", type=["csv"], key="nodes_csv")
        with col_edges:
            edges_file = st.file_uploader("edges.csv", type=["csv"], key="edges_csv")

        if nodes_file and edges_file:
            with tempfile.TemporaryDirectory() as tmpdir:
                nodes_path = os.path.join(tmpdir, "nodes.csv")
                edges_path = os.path.join(tmpdir, "edges.csv")
                with open(nodes_path, "wb") as f:
                    f.write(nodes_file.read())
                with open(edges_path, "wb") as f:
                    f.write(edges_file.read())
                try:
                    topo = load_topology(tmpdir)
                    set_topology(topo)
                    st.success(f"Loaded: {topo.num_buses} buses, {len(topo.edges)} edges, "
                               f"{len(topo.gen_buses)} generators")
                    st.session_state["custom_topology"] = topo
                    save_topology_csv(topo, str(os.path.join(PROJECT_ROOT, "data", "topology")))
                except Exception as e:
                    st.error(f"Error loading topology: {e}")
    else:
        xml_file = st.file_uploader("Upload topology XML", type=["xml"], key="xml_topology_import")
        if xml_file:
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
                tmp.write(xml_file.read())
                tmp_path = tmp.name
            try:
                imported_nodes, imported_edges = import_topology(tmp_path)
                st.success(f"Imported: {len(imported_nodes)} nodes, {len(imported_edges)} edges")
                st.session_state["topo_nodes"] = imported_nodes
                st.session_state["topo_edges"] = imported_edges
            except Exception as e:
                st.error(f"Import failed: {e}")
            finally:
                os.unlink(tmp_path)

# --- Step 2: current topology summary ---
st.header("2. Current Topology")
topo = get_topology()
col_a, col_b, col_c, col_d = st.columns(4)
col_a.metric("Buses", topo.num_buses)
col_b.metric("Edges", len(topo.edges))
col_c.metric("Generators", len(topo.gen_buses))
col_d.metric("Max Degree", topo.max_degree)

# --- Step 3: export options ---
st.header("3. Export Options")
exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    st.markdown("**Download CSV Templates:**")
    template_nodes = "bus_id,name,type,voltage,ip,plc_type,bus_role,pg,qg,pl,ql\n0,Bus1,slack,1.060,10.0.0.1,siemens_s7_1200,generator,232.4,-16.9,0.0,0.0\n1,Bus2,pv,1.045,10.0.0.2,allen_bradley_compactlogix,generator,40.0,42.4,21.7,12.7\n2,Bus3,pq,1.010,10.0.0.3,generic_modbus,load,0.0,0.0,94.2,19.0\n"
    template_edges = "from_bus,to_bus\n0,1\n0,2\n1,2\n"
    st.download_button("Template nodes.csv", template_nodes, "nodes_template.csv", "text/csv")
    st.download_button("Template edges.csv", template_edges, "edges_template.csv", "text/csv")

with exp_col2:
    st.markdown("**Export Current Topology:**")
    if st.button("Export as CSV"):
        export_dir = os.path.join(PROJECT_ROOT, "data", "topology_export")
        save_topology_csv(topo, export_dir)
        st.success("Exported to data/topology_export/")
        nodes_path = os.path.join(export_dir, "nodes.csv")
        edges_path = os.path.join(export_dir, "edges.csv")
        if os.path.exists(nodes_path):
            with open(nodes_path, "r") as f:
                st.download_button("Download nodes.csv", f.read(), "nodes.csv", "text/csv")
        if os.path.exists(edges_path):
            with open(edges_path, "r") as f:
                st.download_button("Download edges.csv", f.read(), "edges.csv", "text/csv")

# --- Step 4: save config to session state ---
st.header("4. Save Configuration")
if st.button("Save Configuration and Continue →"):
    st.session_state["config"] = {
        "topology": topology_options.get(choice, {}) if choice else {},
    }
    st.success("Configuration saved. Go to 'Live Battle' in the sidebar.")
