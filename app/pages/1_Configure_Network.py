import streamlit as st
import json
import glob

st.set_page_config(page_title="Configure Network", layout="wide")
st.title("Network & Defense Configuration")

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

# --- Step 2: defense mechanisms ---
st.header("2. Defense Mechanisms")
col1, col2 = st.columns(2)

with col1:
    use_lstm = st.checkbox("Enable LSTM Detector (catches slow, staged attacks)", value=True)
    use_autoencoder = st.checkbox("Enable Autoencoder Detector (catches sudden anomalies)", value=True)
    segmentation = st.checkbox("Enable Network Segmentation (limits lateral movement)", value=False)

with col2:
    tau_high = st.slider("High-confidence detection threshold (τ_high)", 0.5, 0.99, 0.8)
    tau_low = st.slider("Low-confidence detection threshold (τ_low)", 0.1, 0.5, 0.3)
    n_episodes = st.slider("Number of attack episodes to simulate", 10, 200, 50)

# --- Step 3: save config to session state so other pages can use it ---
if st.button("Save Configuration and Continue →"):
    st.session_state["config"] = {
        "topology": topology_options[choice],
        "use_lstm": use_lstm,
        "use_autoencoder": use_autoencoder,
        "segmentation": segmentation,
        "tau_high": tau_high,
        "tau_low": tau_low,
        "n_episodes": n_episodes,
    }
    st.success("Configuration saved. Go to '2 Run Simulation' in the sidebar.")