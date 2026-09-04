"""
XAI — Admin Hardening Recommendation Templates.

Maps DVS breakdown scores and detected attack techniques to actionable
security recommendations specific to ICS/SCADA environments. Each
recommendation includes:
  - Priority level (Critical / High / Medium / Low)
  - Category (Network, Process Control, Monitoring, Access Control, etc.)
  - Concise title and description
  - Relevant MITRE ATT&CK for ICS mitigation IDs

Owner: Andikumar (training track)
"""

import json
import os
import sys

# Ensure UTF-8 stdout on Windows console
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# MITRE ATT&CK for ICS technique-specific mitigations
# Each technique maps to recommended countermeasures
TECHNIQUE_MITIGATIONS = {
    "T0886": {
        "technique_name": "Remote Services",
        "mitigations": [
            {"id": "M0935", "name": "Limit Access to Resource Over Network",
             "action": "Restrict Modbus TCP port 502 access to authorized SCADA/HMI IP addresses only via firewall ACLs."},
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Place PLCs on a dedicated OT VLAN with strict inter-zone firewall rules."},
            {"id": "M0932", "name": "Multi-factor Authentication",
             "action": "Require MFA for remote access to engineering workstations and jump hosts."},
        ],
    },
    "T0846": {
        "technique_name": "Remote System Discovery",
        "mitigations": [
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Segment OT networks so host discovery scans from IT zones are blocked at the boundary firewall."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Deploy IDS/IPS rules to detect and alert on Nmap-style SYN scans targeting Modbus ports."},
        ],
    },
    "T0888": {
        "technique_name": "Remote System Information Discovery",
        "mitigations": [
            {"id": "M0941", "name": "Encrypt Sensitive Information",
             "action": "Disable or restrict Modbus Device Identification (FC 0x2B) on production PLCs."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Alert on unexpected Modbus FC 0x2B requests from non-engineering workstations."},
        ],
    },
    "T0842": {
        "technique_name": "Network Sniffing",
        "mitigations": [
            {"id": "M0941", "name": "Encrypt Sensitive Information",
             "action": "Use TLS-wrapped Modbus (Modbus/TCP Security) where supported by PLCs."},
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Use managed switches with port security to prevent unauthorized passive tapping."},
        ],
    },
    "T0830": {
        "technique_name": "Adversary-in-the-Middle",
        "mitigations": [
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Enable Dynamic ARP Inspection (DAI) on OT switches to prevent ARP cache poisoning."},
            {"id": "M0941", "name": "Encrypt Sensitive Information",
             "action": "Implement authenticated Modbus sessions or OPC UA Secure Channel for SCADA-PLC communication."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Monitor for duplicate MAC addresses and ARP table anomalies on OT network segments."},
        ],
    },
    "T0801": {
        "technique_name": "Monitor Process State",
        "mitigations": [
            {"id": "M0935", "name": "Limit Access to Resource Over Network",
             "action": "Rate-limit Modbus read requests per source IP to detect unusual polling patterns."},
            {"id": "M0813", "name": "Software Process and Device Authentication",
             "action": "Authenticate SCADA polling sessions so rogue clients cannot read process state."},
        ],
    },
    "T0802": {
        "technique_name": "Automated Collection",
        "mitigations": [
            {"id": "M0935", "name": "Limit Access to Resource Over Network",
             "action": "Whitelist specific Modbus register ranges per client IP to prevent full-sweep collection."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Alert on sequential register reads spanning the full address range from a single source."},
        ],
    },
    "T0869": {
        "technique_name": "Standard Application Layer Protocol",
        "mitigations": [
            {"id": "M0937", "name": "Filter Network Traffic",
             "action": "Deploy deep packet inspection (DPI) for Modbus TCP to validate function codes and payload sizes."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Baseline normal Modbus traffic patterns and alert on statistical deviations."},
        ],
    },
    "T0814": {
        "technique_name": "Denial of Service",
        "mitigations": [
            {"id": "M0937", "name": "Filter Network Traffic",
             "action": "Configure SYN flood protection and connection rate limiting on OT boundary firewalls."},
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Isolate critical PLC communication on dedicated VLANs with strict QoS guarantees."},
            {"id": "M0810", "name": "Out-of-Band Communications Channel",
             "action": "Maintain out-of-band serial connections to critical PLCs as a DoS-resilient fallback."},
        ],
    },
    "T0878": {
        "technique_name": "Alarm Suppression",
        "mitigations": [
            {"id": "M0816", "name": "Mitigation Limited or Not Effective",
             "action": "Implement alarm-change audit logging — any modification to alarm setpoints must be logged and reviewed."},
            {"id": "M0947", "name": "Audit",
             "action": "Generate immediate SOC alerts when alarm threshold registers are written outside scheduled maintenance windows."},
        ],
    },
    "T0816": {
        "technique_name": "Device Restart/Shutdown",
        "mitigations": [
            {"id": "M0800", "name": "Authorization Enforcement",
             "action": "Require physical key switch or authenticated dual-operator approval for PLC restart commands."},
            {"id": "M0947", "name": "Audit",
             "action": "Log all restart/reset coil writes with source IP, timestamp, and operator identity."},
        ],
    },
    "T0881": {
        "technique_name": "Service Stop",
        "mitigations": [
            {"id": "M0937", "name": "Filter Network Traffic",
             "action": "Block malformed Modbus frames at DPI-capable firewalls before they reach PLC servers."},
            {"id": "M0810", "name": "Out-of-Band Communications Channel",
             "action": "Deploy watchdog timers on PLC firmware to auto-recover from process hangs."},
        ],
    },
    "T0836": {
        "technique_name": "Modify Parameter (FDI)",
        "mitigations": [
            {"id": "M0800", "name": "Authorization Enforcement",
             "action": "Enforce write-protection on critical setpoint registers — only authenticated engineering workstations can modify."},
            {"id": "M0816", "name": "Mitigation Limited or Not Effective",
             "action": "Implement independent safety instrumented systems (SIS) that cross-check setpoint values against physics models."},
            {"id": "M0947", "name": "Audit",
             "action": "Log every register write with before/after values and compare against expected operational ranges."},
        ],
    },
    "T0835": {
        "technique_name": "Manipulate I/O Image",
        "mitigations": [
            {"id": "M0800", "name": "Authorization Enforcement",
             "action": "Use PLC firmware that supports I/O image write protection for non-safety-critical overrides."},
            {"id": "M0947", "name": "Audit",
             "action": "Monitor I/O image changes and alert when holding register writes bypass ladder logic."},
        ],
    },
    "T0806": {
        "technique_name": "Brute Force I/O",
        "mitigations": [
            {"id": "M0935", "name": "Limit Access to Resource Over Network",
             "action": "Rate-limit Modbus write operations per source and per register address range."},
            {"id": "M0918", "name": "Network Intrusion Prevention",
             "action": "Detect rapid sequential writes across the full I/O address range as a brute-force indicator."},
        ],
    },
    "T0832": {
        "technique_name": "Manipulation of View (Replay)",
        "mitigations": [
            {"id": "M0941", "name": "Encrypt Sensitive Information",
             "action": "Use session-authenticated Modbus with nonces or timestamps to prevent replay attacks."},
            {"id": "M0816", "name": "Mitigation Limited or Not Effective",
             "action": "Deploy independent telemetry validation sensors that cross-check SCADA readings against direct measurements."},
        ],
    },
    "T0815": {
        "technique_name": "Denial of View",
        "mitigations": [
            {"id": "M0810", "name": "Out-of-Band Communications Channel",
             "action": "Maintain redundant HMI polling paths (e.g., serial backup) so blocked TCP doesn't blind operators."},
            {"id": "M0930", "name": "Network Segmentation",
             "action": "Place HMI-to-PLC traffic on a dedicated segment with priority QoS to resist blocking attacks."},
        ],
    },
}


def get_technique_recommendations(technique_id: str) -> dict:
    """
    Returns technique-specific mitigation advice for a given MITRE ATT&CK for ICS technique.

    Args:
        technique_id: MITRE technique ID (e.g., "T0836")

    Returns:
        dict with technique_name and list of mitigations, or empty dict if unknown
    """
    return TECHNIQUE_MITIGATIONS.get(technique_id, {})


def get_dvs_recommendations(dvs_result: dict) -> list:
    """
    Generates prioritized hardening recommendations based on DVS sub-scores.

    Args:
        dvs_result: dict from metrics/dvs.py compute_dvs()

    Returns:
        List of recommendation dicts sorted by priority
    """
    recommendations = []
    breakdown = dvs_result.get("breakdown", {})

    # Evasion-based recommendations
    evasion_score = breakdown.get("evasion", {}).get("score", 0)
    if evasion_score > 70:
        recommendations.append({
            "priority": "Critical",
            "category": "Detection",
            "title": "Detection Layer Overhaul Required",
            "description": (
                f"Evasion rate is {evasion_score:.0f}% — the majority of attack techniques bypass "
                f"the LSTM + Autoencoder detection layer. Consider: (1) retraining detectors on "
                f"adversarial samples from the GAN, (2) adding signature-based rules for known "
                f"MITRE techniques, (3) deploying a third detection modality (e.g., rule-based Modbus DPI)."
            ),
        })
    elif evasion_score > 40:
        recommendations.append({
            "priority": "High",
            "category": "Detection",
            "title": "Targeted Detection Improvements Needed",
            "description": (
                f"Evasion rate is {evasion_score:.0f}% — some attack patterns consistently evade detection. "
                f"Review which techniques have the lowest detection confidence and add targeted training data."
            ),
        })

    # Campaign completion recommendations
    campaign_score = breakdown.get("campaign", {}).get("score", 0)
    if campaign_score > 50:
        recommendations.append({
            "priority": "Critical",
            "category": "Defense-in-Depth",
            "title": "Multi-Stage Attack Chains Succeeding",
            "description": (
                f"Campaign completion rate is {campaign_score:.0f}% — attackers can chain techniques "
                f"through all 4 tactical stages (Recon → Access → Tamper → Impact). "
                f"Implement stage-gate controls: block lateral movement at network boundaries, "
                f"require authentication for process control commands."
            ),
        })

    # Stage depth recommendations
    stage_score = breakdown.get("stage_depth", {}).get("score", 0)
    if stage_score > 60:
        recommendations.append({
            "priority": "High",
            "category": "Access Control",
            "title": "Deep Penetration Depth Detected",
            "description": (
                f"Attacks consistently reach deep tactical stages (score: {stage_score:.0f}/100). "
                f"Strengthen boundary controls between ICS zones. Implement strict allowlisting "
                f"for Modbus write operations on safety-critical registers."
            ),
        })

    # Plateau recommendations
    plateau_score = breakdown.get("plateau", {}).get("score", 0)
    if plateau_score >= 100:
        recommendations.append({
            "priority": "High",
            "category": "Monitoring",
            "title": "Defense Saturation Detected",
            "description": (
                "Evasion plateau detected — defenses have stopped improving against adversarial "
                "adaptation. Rotate defense strategies: retrain models on new data, deploy "
                "deception-based honeypot PLCs, or add behavioral analysis rules."
            ),
        })

    # General recommendation always included
    recommendations.append({
        "priority": "Medium",
        "category": "Process",
        "title": "Regular Red Team Re-evaluation",
        "description": (
            "Schedule periodic DVS re-evaluations (monthly or after infrastructure changes) "
            "to track defense posture trends and validate that mitigations are effective."
        ),
    })

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r["priority"], 4))

    return recommendations


def format_report(dvs_result: dict, chain_techniques: list = None) -> str:
    """
    Renders a markdown-formatted executive summary report.

    Args:
        dvs_result: Full DVS result dict
        chain_techniques: Optional list of technique IDs from a sample attack chain

    Returns:
        Markdown string
    """
    lines = []
    lines.append("# Defense Vulnerability Assessment Report")
    lines.append("")
    lines.append(f"## Overall Score: {dvs_result['color']} {dvs_result['score']:.1f} / 100 — {dvs_result['rating']}")
    lines.append("")
    lines.append(f"> {dvs_result['description']}")
    lines.append("")

    # Breakdown table
    lines.append("## Score Breakdown")
    lines.append("")
    lines.append("| Component | Sub-Score | Weight | Weighted | Detail |")
    lines.append("|-----------|-----------|--------|----------|--------|")
    for name, comp in dvs_result["breakdown"].items():
        lines.append(
            f"| {name.replace('_', ' ').title()} | {comp['score']:.1f} | {comp['weight']:.2f} | "
            f"{comp['weighted']:.1f} | {comp['detail']} |"
        )
    lines.append("")

    # Recommendations
    recommendations = get_dvs_recommendations(dvs_result)
    lines.append("## Prioritized Recommendations")
    lines.append("")
    for i, rec in enumerate(recommendations, 1):
        priority_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(rec["priority"], "⚪")
        lines.append(f"### {i}. {priority_emoji} [{rec['priority']}] {rec['title']}")
        lines.append(f"**Category:** {rec['category']}")
        lines.append("")
        lines.append(rec["description"])
        lines.append("")

    # Technique-specific mitigations from the attack chain
    if chain_techniques:
        lines.append("## Technique-Specific Mitigations")
        lines.append("")
        seen = set()
        for tech_id in chain_techniques:
            if tech_id in seen:
                continue
            seen.add(tech_id)
            mitigation_info = get_technique_recommendations(tech_id)
            if mitigation_info:
                lines.append(f"### {tech_id} — {mitigation_info['technique_name']}")
                for m in mitigation_info["mitigations"]:
                    lines.append(f"- **{m['id']} ({m['name']}):** {m['action']}")
                lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo: generate a sample report from a mock DVS result
    print("=" * 60)
    print("Recommendation Templates — Demo Report")
    print("=" * 60)

    # Simulate a DVS result for demo purposes
    mock_dvs = {
        "score": 72.5,
        "rating": "Vulnerable",
        "color": "🟠",
        "description": "Majority of campaigns complete successfully; significant defense gaps.",
        "breakdown": {
            "evasion": {"score": 75.0, "weight": 0.30, "weighted": 22.5, "detail": "Average evasion rate: 75.0%"},
            "campaign": {"score": 100.0, "weight": 0.30, "weighted": 30.0, "detail": "Campaign completion: 20/20"},
            "stage_depth": {"score": 100.0, "weight": 0.25, "weighted": 25.0, "detail": "Avg max stage reached: 3.0/3"},
            "plateau": {"score": 100.0, "weight": 0.15, "weighted": 15.0, "detail": "Plateau detected"},
        },
    }

    sample_chain = ["T0842", "T0801", "T0836", "T0832"]

    report = format_report(mock_dvs, sample_chain)
    print(report)

    print("\n[OK] Recommendation templates working correctly.")
