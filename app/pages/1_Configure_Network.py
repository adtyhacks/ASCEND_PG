import streamlit as st
import json
import glob

st.set_page_config(page_title="Configure Network", layout="wide")
st.title("Network Configuration")

# --- Step 1: pick topology ---
st.header("1. Network Topology")
topology_files = glob.glob("data/sample_topologies/*.json")
topology_options = {}
for f in topology_files:
    with open(f) as fh:
        t = json.load(fh)
        topology_options[t["name"]] = t

choice = st.selectbox("Choose a preset grid topology", list(topology_options.keys()))
st.caption(topology_options[choice]["description"])

uploaded = st.file_uploader("Or upload your own topology (CSV) — optional", type=["csv"])
if uploaded is not None:
    st.warning("Custom topology upload is experimental — if it fails to parse, "
               "the simulation will automatically fall back to the preset selected above.")

# --- Step 2: save config to session state so other pages can use it ---
if st.button("Save Configuration and Continue →"):
    st.session_state["config"] = {
        "topology": topology_options[choice],
    }
    st.success("Configuration saved. Go to 'Live Battle' in the sidebar.")