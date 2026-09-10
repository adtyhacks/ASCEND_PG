#!/usr/bin/env python3
"""Generate PDF version of evaluation parameters documentation."""
import sys
sys.path.insert(0, "/home/adty17/ascend-pg-webapp")

from fpdf import FPDF

class EvalParamsPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "ASCEND-PG | Evaluation Parameters", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(26, 35, 126)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(26, 35, 126)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(26, 35, 126)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(57, 73, 171)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def table_header(self, cols, widths):
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(26, 35, 126)
        self.set_text_color(255, 255, 255)
        for i, col in enumerate(cols):
            self.cell(widths[i], 6, col, border=1, fill=True, new_x="END")
        self.ln()

    def table_row(self, vals, widths, fill=False):
        self.set_font("Helvetica", "", 7)
        self.set_text_color(51, 51, 51)
        if fill:
            self.set_fill_color(240, 242, 255)
        else:
            self.set_fill_color(255, 255, 255)
        max_h = 6
        for i, val in enumerate(vals):
            self.cell(widths[i], 6, str(val)[:60], border=1, fill=True, new_x="END")
        self.ln()


pdf = EvalParamsPDF()
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=20)
pdf.add_page()

# Title
pdf.set_font("Helvetica", "B", 22)
pdf.set_text_color(26, 35, 126)
pdf.cell(0, 15, "ASCEND-PG", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "B", 16)
pdf.set_text_color(57, 73, 171)
pdf.cell(0, 10, "Evaluation Parameters Reference", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(100, 100, 100)
pdf.cell(0, 8, "Complete list of all metrics, KPIs, and parameters across the system", new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

# Table of Contents
pdf.set_font("Helvetica", "B", 12)
pdf.set_text_color(26, 35, 126)
pdf.cell(0, 8, "Table of Contents", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(51, 51, 51)
toc = [
    "1. Attack Metrics (RL Agent)",
    "2. Defense Metrics",
    "3. Network Metrics",
    "4. Report Metrics",
    "5. Training Metrics",
    "6. DVS (Defense Vulnerability Score)",
    "7. XAI Metrics",
]
for item in toc:
    pdf.cell(0, 6, item, new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)

# =============================================================================
# SECTION 1: Attack Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("1. Attack Metrics (RL Agent)")

pdf.sub_title("1.1 Evasion Metrics")
w = [40, 15, 20, 55, 30]
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w)
rows = [
    ["evasion_rate", "float", "[0, 1]", "Percentage of steps that evaded detection", "rl_env.py"],
    ["recent_evasion_rate", "float", "[0, 1]", "Sliding window (last 5 steps) evasion", "rl_env.py"],
    ["detected", "bool", "T/F", "Whether current step was detected", "rl_env.py"],
    ["detection_confidence", "float", "[0.0, 1.0]", "Detection confidence score per step", "rl_env.py"],
    ["detection_method", "string", "-", "Detection mechanism used", "rl_env.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("1.2 Campaign Metrics")
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w)
rows = [
    ["campaign_complete", "bool", "T/F", "All 4 tactical stages completed", "rl_env.py"],
    ["completed_stages", "set", "{0,1,2,3}", "Which stages were completed", "rl_env.py"],
    ["chain", "list", "-", "List of technique IDs used", "rl_env.py"],
    ["step_count", "int", "0-16", "Steps in current episode", "rl_env.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("1.3 Targeting Metrics")
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w)
rows = [
    ["target_bus", "int", "[0, N)", "Which bus was attacked", "rl_env.py"],
    ["compromised_buses", "set", "-", "Set of compromised bus indices", "rl_env.py"],
    ["attack_depth", "float", "[0, 1]", "Min hop distance to generators", "rl_env.py"],
    ["frac_compromised", "float", "[0, 1]", "Fraction of buses compromised", "rl_env.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("1.4 Action Parameters")
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w)
rows = [
    ["register_address", "int", "40000-40049", "Modbus register address", "rl_env.py"],
    ["register_offset", "int", "[0, 49]", "Offset from base register", "rl_env.py"],
    ["value_magnitude", "float", "[0.9, 1.1]", "Write value scale factor", "rl_env.py"],
    ["value_level", "int", "[0, 9]", "Value magnitude index", "rl_env.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("1.5 Detection Risk Multipliers")
pdf.table_header(["Parameter", "Formula", "Range", "Description", "Source"], w)
rows = [
    ["register_risk", "1-(off/50)*0.3", "0.7-1.0", "Risk from register choice", "rl_env.py"],
    ["value_deviation", "abs(val-1.0)", "0.0-0.1", "Deviation from normal", "rl_env.py"],
    ["value_risk", "1+dev*5.0", "1.0-1.5", "Risk from value deviation", "rl_env.py"],
    ["target_risk", "1.2 if gen", "1.0-1.2", "Risk from target type", "rl_env.py"],
    ["risk_multiplier", "reg*val*tgt", "0.7-1.8", "Combined detection risk", "rl_env.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("1.6 Reward Function Components")
w2 = [45, 15, 45, 55]
pdf.table_header(["Component", "Value", "Trigger", "Description"], w2)
rows = [
    ["Step cost", "-0.1", "Every step", "Base cost for taking action"],
    ["Evasion bonus", "+1.5*(1-c)", "Not detected", "Reward for evading detection"],
    ["Detection penalty", "-2.5*conf", "Detected", "Penalty for being detected"],
    ["Stage progression", "+3.0", "Correct stage", "Reward for following chain"],
    ["Redundant stage", "-1.5", "Repeat stage", "Penalty for redundancy"],
    ["Out-of-order", "-1.0", "Wrong stage", "Penalty for skipping stages"],
    ["Generator targeting", "+0.5", "Gen bus", "Bonus for high-impact targets"],
    ["Lateral movement", "+0.3", "New bus", "Bonus for spreading"],
    ["Clustering penalty", "-0.5", "Same area", "Penalty for lack of diversity"],
    ["Completion (evaded)", "+8.0", "All 4 stages", "Maximum success bonus"],
    ["Completion (detected)", "+4.0", "All 4 stages", "Partial success bonus"],
    ["Multi-bus bonus", "+0.2*count", "Per bus", "Bonus for widespread compromise"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w2, fill=(i % 2 == 0))

# =============================================================================
# SECTION 2: Defense Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("2. Defense Metrics")

pdf.sub_title("2.1 Hybrid Detector")
w3 = [40, 15, 20, 60, 30]
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w3)
rows = [
    ["suricata_detected", "bool", "T/F", "Suricata found matching alerts", "hybrid_detector"],
    ["suricata_alert_count", "int", "0+", "Number of matching alerts", "hybrid_detector"],
    ["suricata_signatures", "list", "-", "List of matched alert signatures", "hybrid_detector"],
    ["ml_detected", "bool", "T/F", "ML fusion exceeded threshold", "hybrid_detector"],
    ["ml_confidence", "float", "[0, 1]", "Fused ML confidence score", "hybrid_detector"],
    ["ml_lstm_confidence", "float", "[0, 1]", "LSTM detector confidence", "hybrid_detector"],
    ["ml_ae_score", "float", "[0, 1]", "Autoencoder anomaly score", "hybrid_detector"],
    ["ml_available", "bool", "T/F", "ML models loaded and working", "hybrid_detector"],
    ["combined_detected", "bool", "T/F", "Overall OR of suricata + ml", "hybrid_detector"],
    ["detection_method", "string", "-", "both/suricata/ml/undetected", "hybrid_detector"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w3, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("2.2 ML Detector")
pdf.table_header(["Parameter", "Type", "Range", "Description", "Source"], w3)
rows = [
    ["lstm_confidence", "float", "[0, 1]", "LSTM sigmoid output", "ml_detector"],
    ["ae_anomaly_score", "float", "[0, 1]", "Normalized AE reconstruction error", "ml_detector"],
    ["ae_max_recon_error", "float", "0+", "Raw max MSE across window", "ml_detector"],
    ["fused_confidence", "float", "[0, 1]", "Weighted avg of LSTM + AE", "ml_detector"],
    ["detected", "bool", "T/F", "fused_confidence > 0.50", "ml_detector"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w3, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("2.3 ML Training Metrics")
w4 = [35, 40, 75]
pdf.table_header(["Metric", "Formula", "Description"], w4)
rows = [
    ["accuracy", "(TP+TN)/Total", "Overall classification accuracy"],
    ["precision", "TP/(TP+FP)", "Of flagged-as-attack, how many truly are"],
    ["recall", "TP/(TP+FN)", "Of real attacks, how many were caught"],
    ["f1", "2*P*R/(P+R)", "Harmonic mean of precision and recall"],
    ["tp", "-", "True Positives"],
    ["fp", "-", "False Positives"],
    ["fn", "-", "False Negatives"],
    ["tn", "-", "True Negatives"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w4, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("2.4 Suricata IDS Rules")
w5 = [15, 55, 30, 50]
pdf.table_header(["SID", "Rule Name", "Technique", "Description"], w5)
rows = [
    ["9000001", "FDI - Holding Register Write", "T0836", "False data injection"],
    ["9000002", "DoS - Modbus Request Flood", "T0814", "Denial of service"],
    ["9000004", "Recon - Device ID Query", "T0888", "Device enumeration"],
    ["9000005", "Recon - Read Exception Status", "T0840", "Reconnaissance"],
    ["9000006", "Recon - Diagnostics FC08", "T0840", "Diagnostics scan"],
    ["9000007", "CmdInject - Coil Write", "T0855", "Command injection"],
    ["9000008", "CmdInject - Diagnostics Restart", "T0855", "Restart attempt"],
    ["9000009", "CmdInject - Clear Counters", "T0855", "Counter tampering"],
    ["9000010", "DoS - Rapid TCP SYN", "T0814", "SYN flood"],
    ["9000020", "DoS - Sub-Threshold Read Flood", "T0814", "Slow DoS"],
    ["9000022", "MITM - Non-Standard Port 503", "T0830", "MITM attempt"],
    ["9000023", "BruteForce - Rapid Register Enum", "T0806", "Brute force"],
    ["9000024", "DoV - Forged FC06 Write", "T0815", "Denial of view"],
    ["9000025", "Recon - Coil Read", "T0801", "Coil reconnaissance"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w5, fill=(i % 2 == 0))

# =============================================================================
# SECTION 3: Network Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("3. Network Metrics")

pdf.sub_title("3.1 Flow Logger Metrics")
w6 = [40, 15, 20, 55, 30]
pdf.table_header(["Parameter", "Type", "Unit", "Description", "Source"], w6)
rows = [
    ["duration_sec", "float", "seconds", "Flow duration", "flow_logger"],
    ["total_packets", "int", "packets", "Total packets in flow", "flow_logger"],
    ["total_bytes", "int", "bytes", "Total bytes in flow", "flow_logger"],
    ["fwd_packets", "int", "packets", "Forward direction count", "flow_logger"],
    ["bwd_packets", "int", "packets", "Backward direction count", "flow_logger"],
    ["fwd_bytes", "int", "bytes", "Forward direction bytes", "flow_logger"],
    ["bwd_bytes", "int", "bytes", "Backward direction bytes", "flow_logger"],
    ["bytes_per_sec", "float", "B/s", "Throughput", "flow_logger"],
    ["packets_per_sec", "float", "pkt/s", "Packet rate", "flow_logger"],
    ["syn_count", "int", "count", "SYN flag count", "flow_logger"],
    ["ack_count", "int", "count", "ACK flag count", "flow_logger"],
    ["rst_count", "int", "count", "RST flag count", "flow_logger"],
    ["fin_count", "int", "count", "FIN flag count", "flow_logger"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w6, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("3.2 CIC-IDS-2017 Features (78 dimensions)")
w7 = [50, 20, 70]
pdf.table_header(["Category", "Count", "Features"], w7)
rows = [
    ["Port & Duration", "2", "Destination Port, Flow Duration"],
    ["Packet Counts", "2", "Total Fwd/Bwd Packets"],
    ["Byte Lengths", "2", "Total Length of Fwd/Bwd Packets"],
    ["Fwd Packet Length", "4", "Max, Min, Mean, Std"],
    ["Bwd Packet Length", "4", "Max, Min, Mean, Std"],
    ["Throughput", "2", "Flow Bytes/s, Flow Packets/s"],
    ["Flow IAT", "4", "Mean/Std/Max/Min"],
    ["Fwd IAT", "5", "Total/Mean/Std/Max/Min"],
    ["Bwd IAT", "5", "Total/Mean/Std/Max/Min"],
    ["TCP Flags", "4", "Fwd/Bwd PSH, URG Flags"],
    ["Flag Counts", "8", "FIN, SYN, RST, PSH, ACK, URG, CWE, ECE"],
    ["Header Lengths", "2", "Fwd/Bwd Header Length"],
    ["Packet Rates", "2", "Fwd/Bwd Packets/s"],
    ["Packet Size", "5", "Min/Max, Mean/Std/Variance"],
    ["Ratios", "2", "Down/Up Ratio, Average Packet Size"],
    ["Bulk Rates", "6", "Fwd/Bwd Avg Bytes/Packets/Bulk, Rate"],
    ["Subflows", "4", "Subflow Fwd/Bwd Packets/Bytes"],
    ["Window", "2", "Init_Win_bytes_forward/backward"],
    ["Active", "4", "Mean/Std/Max/Min"],
    ["Idle", "4", "Mean/Std/Max/Min"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w7, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("3.3 Modbus Packet Logger")
w8 = [40, 15, 65, 40]
pdf.table_header(["Field", "Type", "Description", "Source"], w8)
rows = [
    ["timestamp", "string", "ISO format UTC timestamp", "modbus_logger"],
    ["src_ip / dst_ip", "string", "Source/destination IP", "modbus_logger"],
    ["src_port / dst_port", "int", "Source/destination port", "modbus_logger"],
    ["direction", "string", "request or response", "modbus_logger"],
    ["function_code", "int", "Modbus function code (numeric)", "modbus_logger"],
    ["function_name", "string", "Human-readable function name", "modbus_logger"],
    ["start_address", "int", "Register start address", "modbus_logger"],
    ["values", "list", "Register values", "modbus_logger"],
    ["exception_code", "string", "Exception code if applicable", "modbus_logger"],
    ["packet_length", "int", "Raw byte length", "modbus_logger"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w8, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("3.4 Topology Metrics")
pdf.table_header(["Metric", "Type", "Description", "Source"], w8)
rows = [
    ["num_buses", "int", "Number of nodes (PLCs)", "topology.py"],
    ["num_edges", "int", "Number of network links", "topology.py"],
    ["bus_types", "list", "3=slack, 1=PV, 2=PQ", "topology.py"],
    ["voltages", "list", "Per-bus voltage in p.u.", "topology.py"],
    ["bus_degrees", "list", "Per-bus connection count", "topology.py"],
    ["max_degree", "int", "Maximum bus degree", "topology.py"],
    ["gen_buses", "list", "Generator bus indices", "topology.py"],
    ["ip_map", "dict", "bus_id -> IP mapping", "topology.py"],
    ["depth_from_gens", "list", "BFS hop distance to generators", "topology.py"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w8, fill=(i % 2 == 0))

# =============================================================================
# SECTION 4: Report Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("4. Report Metrics")

pdf.sub_title("4.1 Executive Summary")
w9 = [40, 15, 95]
pdf.table_header(["Metric", "Type", "Description"], w9)
rows = [
    ["total_steps", "int", "Total attack steps executed"],
    ["detected_count", "int", "Steps that were detected"],
    ["compromised_count", "int", "Steps that evaded detection"],
    ["evasion_rate", "float", "compromised_count / total_steps"],
    ["critical", "int", "Critical severity findings"],
    ["high", "int", "High severity findings"],
    ["medium", "int", "Medium severity findings"],
    ["low", "int", "Low severity findings"],
    ["info", "int", "Informational findings"],
    ["overall_risk", "string", "CRITICAL / HIGH / MEDIUM / LOW"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w9, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("4.2 CVSS Scores")
w10 = [50, 40]
pdf.table_header(["Severity", "CVSS Score"], w10)
rows = [
    ["Critical", "9.5"],
    ["High", "7.5"],
    ["Medium", "5.0"],
    ["Low", "2.5"],
    ["Informational", "0.0"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w10, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("4.3 Severity Classification")
w11 = [80, 50]
pdf.table_header(["Condition", "Severity"], w11)
rows = [
    ["Stage 3 + confidence < 0.5", "Critical"],
    ["Stage 3 + confidence < 0.8", "High"],
    ["Stage 2 + confidence < 0.3", "High"],
    ["Stage 2 + confidence < 0.6", "Medium"],
    ["Stage 1 + confidence < 0.4", "Medium"],
    ["Stage 1 (else)", "Low"],
    ["Stage 0 + confidence < 0.3", "Low"],
    ["Default", "Informational"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w11, fill=(i % 2 == 0))

# =============================================================================
# SECTION 5: Training Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("5. Training Metrics")

pdf.sub_title("5.1 PPO Hyperparameters")
w12 = [50, 40, 60]
pdf.table_header(["Parameter", "Value", "Description"], w12)
rows = [
    ["learning_rate", "3e-4", "Learning rate"],
    ["gamma", "0.99", "Discount factor"],
    ["clip_range", "0.2", "PPO clip range"],
    ["ent_coef", "0.01", "Entropy coefficient"],
    ["n_steps", "2048", "Steps per update"],
    ["batch_size", "64", "Mini-batch size"],
    ["n_epochs", "10", "Epochs per update"],
    ["net_arch", "[256,256,128]", "Network architecture"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w12, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("5.2 Evaluation Metrics")
pdf.table_header(["Metric", "Type", "Description"], w9)
rows = [
    ["campaigns_completed", "int", "Episodes that completed all 4 stages"],
    ["total_rewards", "list", "Per-episode total rewards"],
    ["evasion_rates", "list", "Per-episode evasion rates"],
    ["campaign_completion_%", "float", "completion / n_episodes * 100"],
    ["avg_reward", "float", "Mean reward across episodes"],
    ["avg_evasion", "float", "Mean evasion across episodes"],
    ["plateau_status", "string", "Saturated or Progressing"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w9, fill=(i % 2 == 0))

# =============================================================================
# SECTION 6: DVS
# =============================================================================
pdf.add_page()
pdf.section_title("6. DVS (Defense Vulnerability Score)")

pdf.sub_title("6.1 DVS Composite Score")
w13 = [40, 15, 55, 30]
pdf.table_header(["Component", "Weight", "Formula", "Range"], w13)
rows = [
    ["evasion_score", "30%", "avg_evasion_rate * 100", "0-100"],
    ["campaign_score", "30%", "completion_rate * 100", "0-100"],
    ["stage_depth_score", "25%", "(avg_max_stage / 3) * 100", "0-100"],
    ["plateau_score", "15%", "100 if plateau, else 50", "50 or 100"],
    ["DVS Total", "100%", "Weighted sum, clipped [0,100]", "0-100"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w13, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("6.2 DVS Rating Bands")
w14 = [30, 30, 30, 60]
pdf.table_header(["Range", "Rating", "Color", "Description"], w14)
rows = [
    ["0-25", "Robust", "Green", "Defense is effective"],
    ["26-50", "Moderate", "Yellow", "Some vulnerabilities exist"],
    ["51-75", "Vulnerable", "Orange", "Significant gaps in defense"],
    ["76-100", "Critical", "Red", "Defense is easily bypassed"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w14, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("6.3 PlateauTracker")
pdf.table_header(["Parameter", "Default", "Description"], w9)
rows = [
    ["patience", "5", "Steps without improvement before plateau"],
    ["min_evasion_gain", "0.02", "Min gain to reset stagnation"],
    ["best_evasion_rate", "0.0", "Best evasion rate seen"],
    ["stagnant_count", "0", "Consecutive episodes without improvement"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w9, fill=(i % 2 == 0))

# =============================================================================
# SECTION 7: XAI Metrics
# =============================================================================
pdf.add_page()
pdf.section_title("7. XAI Metrics")

pdf.sub_title("7.1 SHAP Explainer")
w15 = [45, 95]
pdf.table_header(["Metric", "Description"], w15)
rows = [
    ["prediction", "LSTM detection confidence for the window"],
    ["base_value", "SHAP expected value"],
    ["shap_values", "2D array (WINDOW_SIZE x feature_dim)"],
    ["feature_importance", "Mean |SHAP| per feature across timesteps"],
    ["top_features", "Top-k features by importance"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w15, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("7.2 LIME Explainer")
pdf.table_header(["Metric", "Description"], w15)
rows = [
    ["anomaly_probability", "min(reconstruction_error / (2*threshold), 1.0)"],
    ["reconstruction_error", "MSE for the explained row"],
    ["threshold", "95th percentile benign error"],
    ["is_anomaly", "reconstruction_error > threshold"],
    ["explanation_list", "LIME feature contribution weights"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w15, fill=(i % 2 == 0))

pdf.ln(3)
pdf.sub_title("7.3 RL Decision Explainer")
pdf.table_header(["Metric", "Description"], w15)
rows = [
    ["chosen_probability", "PPO action probability for chosen technique"],
    ["action_probabilities", "Full distribution over 17 techniques"],
    ["value_estimate", "Critic network value estimate"],
    ["evasion_rate", "From observation vector"],
    ["last_confidence", "From observation vector"],
    ["completed_stages", "From observation vector"],
    ["reward", "Step reward"],
    ["detected", "Step detection result"],
    ["detection_confidence", "Step confidence"],
    ["campaign_complete", "All 4 stages completed"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w15, fill=(i % 2 == 0))

# =============================================================================
# Appendix: MITRE Techniques
# =============================================================================
pdf.add_page()
pdf.section_title("Appendix: MITRE ATT&CK for ICS Techniques")
w16 = [20, 55, 15, 20]
pdf.table_header(["ID", "Name", "Stage", "Mock Prob"], w16)
rows = [
    ["T0886", "Remote Services", "0", "0.50"],
    ["T0846", "Remote System Discovery", "0", "0.70"],
    ["T0888", "Remote System Info Discovery", "0", "0.45"],
    ["T0842", "Network Sniffing", "0", "0.25"],
    ["T0830", "Adversary-in-the-Middle", "1", "0.55"],
    ["T0801", "Monitor Process State", "1", "0.35"],
    ["T0802", "Automated Collection", "1", "0.60"],
    ["T0869", "Standard App Layer Protocol", "1", "0.40"],
    ["T0814", "Denial of Service", "2", "0.85"],
    ["T0878", "Alarm Suppression", "2", "0.60"],
    ["T0816", "Device Restart/Shutdown", "2", "0.75"],
    ["T0881", "Service Stop", "2", "0.70"],
    ["T0836", "Modify Parameter (FDI)", "2", "0.65"],
    ["T0835", "Manipulate I/O Image", "2", "0.65"],
    ["T0806", "Brute Force I/O", "2", "0.80"],
    ["T0832", "Manipulation of View (Replay)", "3", "0.40"],
    ["T0815", "Denial of View", "3", "0.70"],
]
for i, r in enumerate(rows):
    pdf.table_row(r, w16, fill=(i % 2 == 0))

# Save
output_path = "/home/adty17/ascend-pg-webapp/docs/EVALUATION_PARAMETERS.pdf"
pdf.output(output_path)
print(f"PDF saved to {output_path}")
