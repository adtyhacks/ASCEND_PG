import streamlit as st
import streamlit.components.v1 as components
import sys, os

# IMPORTANT: this must be based on this file's own location, not the current
# working directory — os.path.abspath("..") breaks if you launch streamlit
# from the repo root (cwd = repo root, not app/), which is exactly what the
# terminal instructions below have you do. This version works regardless of
# where you run the `streamlit run` command from.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testbed.grid_env import build_baseline
from testbed.network_topology import build_ot_topology
from testbed.visualize_topology import render_topology
from generative.rule_based_attack_generator import ATTACK_FUNCTIONS
from detection.rule_based_detector import RuleBasedDetector

st.set_page_config(page_title="ASCEND-PG MVP", layout="wide")
st.title("ASCEND-PG — MVP: Testbed → Attack → Detection")

st.write(
    "This is Phase 1 of the project: a working, honest baseline pipeline. "
    "Rule-based attack injection + statistical anomaly detection. "
    "GAN/RL-based attack generation and LSTM/Autoencoder detection are added in Phase 2."
)

# --- Step 1: load testbed ---
if st.button("1. Load Testbed (IEEE-14 Bus)"):
    net_obj, grid_df, traffic_df = build_baseline()
    st.session_state["net_obj"] = net_obj
    st.session_state["grid_df"] = grid_df
    st.session_state["traffic_df"] = traffic_df
    topo_nodes, topo_edges = build_ot_topology(net_obj)
    st.session_state["topo_nodes"] = topo_nodes
    st.session_state["topo_edges"] = topo_edges
    st.success(f"Testbed loaded: {len(grid_df)} buses, {len(traffic_df)} baseline packets.")

if "traffic_df" in st.session_state:
    st.subheader("Input: Baseline Traffic (normal, pre-attack)")
    st.dataframe(st.session_state["traffic_df"].head(20))

    # --- Network topology diagram: real ICS/OT components ---
    st.subheader("🗺️ Network Topology (Electrical + Communication Layers)")
    st.caption("Orange lines = physical power lines · Blue dashed lines = DNP3 communication links · "
               "Red border = compromised · Green border = attack detected")

    compromised, detected = set(), set()

    if "attacked_df" in st.session_state:
        attacked_buses = st.session_state["attacked_df"].loc[
            st.session_state["attacked_df"]["is_attacked"] == True, "dst_bus"
        ].unique()
        for b in attacked_buses:
            compromised.update({f"pmu_{b}", f"rtu_{b}"})

    if "result_df" in st.session_state:
        result_df_for_map = st.session_state["result_df"]
        caught = result_df_for_map.loc[
            (result_df_for_map["is_attacked"] == True) &
            (result_df_for_map["detection_verdict"] != "Missed"), "dst_bus"
        ].unique()
        for b in caught:
            detected.update({f"pmu_{b}", f"rtu_{b}"})
            compromised.discard(f"pmu_{b}")
            compromised.discard(f"rtu_{b}")

    topology_html = render_topology(
        st.session_state["topo_nodes"], st.session_state["topo_edges"],
        compromised_ids=compromised, detected_ids=detected,
    )
    components.html(topology_html, height=680, scrolling=True)

    # --- Step 2: choose and inject attack ---
    st.subheader("2. Simulate an Attack")
    attack_choice = st.selectbox("Attack type", list(ATTACK_FUNCTIONS.keys()))

    if st.button("Inject Attack"):
        attacked_df = ATTACK_FUNCTIONS[attack_choice](st.session_state["traffic_df"])
        st.session_state["attacked_df"] = attacked_df
        st.session_state["attack_choice"] = attack_choice
        st.rerun()  # refreshes the page so the topology diagram above picks up the new compromised set

    if "attacked_df" in st.session_state:
        st.subheader(f"Input: Traffic After {st.session_state['attack_choice']} Attack")
        st.dataframe(st.session_state["attacked_df"].head(20))
        n_injected = st.session_state["attacked_df"]["is_attacked"].sum()
        st.caption(f"{n_injected} packets were manipulated by this attack.")

        # --- Step 3: run detector ---
        st.subheader("3. Run Detection")
        if st.button("Run Blue Team Detector"):
            detector = RuleBasedDetector().fit(st.session_state["traffic_df"])
            result_df = detector.score(st.session_state["attacked_df"])
            st.session_state["result_df"] = result_df
            st.rerun()  # refreshes so the topology diagram flips compromised nodes to detected (green)

        if "result_df" in st.session_state:
            result_df = st.session_state["result_df"]
            st.subheader("Output: Detection Results")
            st.dataframe(
                result_df[["timestamp", "src_bus", "dst_bus", "voltage_pu",
                           "is_attacked", "detection_confidence", "detection_verdict"]].head(30)
            )

            col1, col2, col3 = st.columns(3)
            col1.metric("Total packets", len(result_df))
            col2.metric("Flagged as attacked", int((result_df["detection_verdict"] != "Missed").sum()))

            # How many of the truly attacked packets did we actually catch?
            truly_attacked = result_df[result_df["is_attacked"] == True]
            if len(truly_attacked) > 0:
                caught = (truly_attacked["detection_verdict"] != "Missed").sum()
                recall_pct = 100 * caught / len(truly_attacked)
                col3.metric("Attack packets caught", f"{recall_pct:.1f}%")

            st.bar_chart(result_df["detection_verdict"].value_counts())