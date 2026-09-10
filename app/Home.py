import streamlit as st

st.set_page_config(page_title="ASCEND-PG", layout="wide")
st.title("ASCEND-PG — Adaptive Security Co-Simulation for Power Grids")

st.markdown("""
### What is ASCEND-PG?

An automated penetration testing platform for ICS/SCADA networks that uses
reinforcement learning to discover optimal attack paths across power grid topologies.

### How It Works

1. **Upload a topology** (CSV with buses, connections, PLC types)
2. **PPO agent attacks** the network using MITRE ATT&CK for ICS techniques
3. **Hybrid detection** catches attacks via Suricata IDS + ML anomaly detection
4. **Generate report** — professional pentest report with findings and remediation

### Pages

| Page | Description |
|------|-------------|
| **Configure Network** | Select or upload topology |
| **Live Battle** | Run PPO attack campaigns, view real-time detection |
| **Report** | Generate pentest report from campaign results |
""")

st.info("Start by uploading a topology in **Configure Network**, then run attacks in **Live Battle**.")
