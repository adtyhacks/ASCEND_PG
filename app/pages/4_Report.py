"""Executive DVS and explainability report for completed dashboard battles."""

import os
import sys

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from metrics.dvs import compute_dvs
from xai.recommendation_templates import format_report


st.set_page_config(page_title="Executive Report | ASCEND-PG", layout="wide")
st.title("Executive Defense Vulnerability Report")
st.caption("This report is calculated from the PPO campaigns recorded in the Live Battle page.")


def _evaluation_from_campaigns(campaigns: list, plateau_detected: bool) -> dict:
    """Adapt stored UI battle summaries to the existing, unchanged DVS interface."""
    return {
        "num_episodes": len(campaigns),
        "evasion_rates": [campaign["evasion_rate"] for campaign in campaigns],
        "avg_evasion_rate": float(np.mean([campaign["evasion_rate"] for campaign in campaigns])),
        "completion_count": sum(campaign["campaign_complete"] for campaign in campaigns),
        "completion_rate": float(np.mean([campaign["campaign_complete"] for campaign in campaigns])),
        "max_stages_reached": [campaign.get("max_stage", 0) for campaign in campaigns],
        "avg_max_stage": float(np.mean([campaign.get("max_stage", 0) for campaign in campaigns])),
        "plateau_detected": plateau_detected,
        "episode_rewards": [campaign.get("reward", 0.0) for campaign in campaigns],
        "avg_reward": float(np.mean([campaign.get("reward", 0.0) for campaign in campaigns])),
        "chains": [campaign.get("chain", []) for campaign in campaigns],
    }


battle_results = st.session_state.get("battle_results", {})
campaigns = battle_results.get("campaigns", [])
if not campaigns:
    st.warning("No completed PPO campaign is available yet. Run a Live Battle campaign before generating the report.")
    if st.button("Go to Live Battle"):
        st.switch_page("pages/3_Live_Battle.py")
    st.stop()

eval_results = _evaluation_from_campaigns(campaigns, battle_results.get("plateau_detected", False))
dvs_result = compute_dvs(eval_results)
st.session_state["dvs_result"] = dvs_result
chain_techniques = [
    tech.get("technique_id", "") if isinstance(tech, dict) else str(tech)
    for campaign in campaigns 
    for tech in campaign.get("chain", [])
]

gauge_color = {"Robust": "#34c759", "Moderate": "#f8e71c", "Vulnerable": "#f5a623", "Critical": "#ff3b30"}[dvs_result["rating"]]
gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=dvs_result["score"],
    title={"text": f"Defense Vulnerability Score — {dvs_result['rating']}"},
    gauge={"axis": {"range": [0, 100]}, "bar": {"color": gauge_color},
           "steps": [{"range": [0, 25], "color": "#e8f5e9"}, {"range": [25, 50], "color": "#fffde7"},
                     {"range": [50, 75], "color": "#fff3e0"}, {"range": [75, 100], "color": "#ffebee"}]},
))

left, right = st.columns([1, 1.2])
with left:
    st.plotly_chart(gauge, use_container_width=True)
with right:
    st.subheader(f"{dvs_result['color']} {dvs_result['rating']}")
    st.write(dvs_result["description"])
    st.caption(f"Based on {len(campaigns)} completed dashboard campaign(s).")
    for label, component in dvs_result["breakdown"].items():
        st.write(f"**{label.replace('_', ' ').title()}:** {component['score']:.1f}/100 — {component['detail']}")
        st.progress(int(round(component["score"])))

st.subheader("Observed MITRE attack path")
path_df = pd.DataFrame([
    {"Step": index + 1, "MITRE ID": event["MITRE ID"], "Technique": event["Technique Name"],
     "Stage": event["Stage"], "Detection confidence": event["Detector Confidence"], "Outcome": event["Status"]}
    for index, event in enumerate(campaigns[-1].get("events", []))
])
st.dataframe(path_df.astype(str), width="stretch", hide_index=True)

with st.expander("PPO decision rationales", expanded=False):
    for explanation in st.session_state.get("battle_explanations", []):
        chosen = explanation.get("chosen_technique", {})
        st.markdown(f"**Step {explanation.get('step', '?')} — {chosen.get('id', '?')} ({chosen.get('name', '?')})**")
        st.write(explanation.get("rationale", ""))
        alternatives = pd.DataFrame(explanation.get("top_alternatives", []))
        if not alternatives.empty:
            st.dataframe(alternatives[["id", "name", "stage_name", "probability"]].astype(str), hide_index=True,
                         width="stretch")

st.subheader("On-demand detector explanations")
st.caption("SHAP and LIME use the existing saved detector scaling and the CIC-IDS dataset until real captured flows are supplied.")
explain_col1, explain_col2 = st.columns(2)
with explain_col1:
    if st.button("Generate SHAP LSTM explanation"):
        with st.spinner("Computing SHAP values for one 10-flow detection window..."):
            from xai.shap_explain import _load_lstm, _scale, explain_detection, load_shap_explainer
            from detection.lstm_detector import WINDOW_SIZE
            import torch

            flow_df = pd.read_csv(os.path.join(PROJECT_ROOT, "data", "cic_ids2017_subset.csv"))
            label_col = next(column for column in flow_df.columns if column.strip().lower() == "label")
            model, scaling = _load_lstm()
            feature_df = flow_df.drop(columns=[label_col])
            benign_mask = flow_df[label_col].astype(str).str.strip().str.upper() == "BENIGN"
            benign = feature_df[benign_mask].reset_index(drop=True)
            explainer, names, feature_dim = load_shap_explainer(model, scaling, benign)
            result = explain_detection(explainer, feature_df.iloc[:WINDOW_SIZE], scaling, names, feature_dim)
            values = _scale(feature_df.iloc[:WINDOW_SIZE][names].select_dtypes(include=["number"]).fillna(0.0).values, scaling)
            with torch.no_grad():
                result["prediction"] = model(torch.tensor(values, dtype=torch.float32).unsqueeze(0).to(model.lstm.weight_ih_l0.device)).item()
            st.session_state["shap_result"] = result
with explain_col2:
    if st.button("Generate LIME anomaly explanation"):
        with st.spinner("Computing local autoencoder feature contributions..."):
            from xai.lime_explain import (_load_autoencoder, _make_anomaly_predict_fn, explain_anomaly,
                                          load_lime_explainer)

            flow_df = pd.read_csv(os.path.join(PROJECT_ROOT, "data", "cic_ids2017_subset.csv"))
            label_col = next(column for column in flow_df.columns if column.strip().lower() == "label")
            model, scaling, threshold = _load_autoencoder()
            features = flow_df[scaling["feature_cols"]].select_dtypes(include=["number"]).fillna(0.0)
            attack_index = flow_df.index[flow_df[label_col].astype(str).str.strip().str.upper() != "BENIGN"][0]
            lime = load_lime_explainer(scaling, features.values, scaling["feature_cols"])
            predict_fn = _make_anomaly_predict_fn(model, scaling, threshold)
            st.session_state["lime_result"] = explain_anomaly(
                lime, features.loc[attack_index].values, predict_fn, model, scaling, threshold
            )

if "shap_result" in st.session_state:
    shap_result = st.session_state["shap_result"]
    st.markdown(f"**LSTM detection confidence:** {shap_result['prediction']:.3f}")
    shap_df = pd.DataFrame(shap_result["top_features"], columns=["Feature", "Mean |SHAP|"])
    st.bar_chart(shap_df.set_index("Feature"))
if "lime_result" in st.session_state:
    lime_result = st.session_state["lime_result"]
    st.markdown(f"**Autoencoder reconstruction error:** {lime_result['reconstruction_error']:.6f} "
                f"(threshold {lime_result['threshold']:.6f})")
    lime_df = pd.DataFrame(lime_result["explanation_list"], columns=["Feature contribution", "Weight"])
    st.dataframe(lime_df, use_container_width=True, hide_index=True)

import json
from pathlib import Path

testbed_data = None
cycle_report_path = Path(PROJECT_ROOT) / "data" / "cycle_report.json"
if cycle_report_path.exists():
    try:
        with open(cycle_report_path, "r", encoding="utf-8") as f:
            testbed_data = json.load(f)
    except Exception:
        pass

report_markdown = format_report(dvs_result, chain_techniques, testbed_report=testbed_data)

dl_col1, dl_col2, _ = st.columns([1, 1, 2])
with dl_col1:
    st.download_button("Download Executive Report (Markdown)", report_markdown,
                       file_name="ascend_pg_defense_report.md", mime="text/markdown")
with dl_col2:
    try:
        import markdown
        from fpdf import FPDF
        
        # FPDF default fonts only support Latin-1. We safely encode to ASCII to strip emojis.
        safe_md = report_markdown.encode('ascii', 'ignore').decode('ascii')
        html = markdown.markdown(safe_md, extensions=['tables'])
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=10)
        pdf.write_html(html)
        pdf_bytes = pdf.output()
        
        st.download_button(
            label="Download Executive Report (PDF)",
            data=bytes(pdf_bytes),
            file_name="ascend_pg_defense_report.pdf",
            mime="application/pdf",
        )
    except Exception as e:
        st.warning("PDF generation unavailable. Install fpdf2 and markdown.")
