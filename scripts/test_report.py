#!/usr/bin/env python3
"""Test the pentest report generator."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from reports.pentest_report import generate_report, render_html, render_pdf
print("Import OK")

events = [
    {"MITRE ID": "T0846", "Technique Name": "Remote System Discovery", "Stage": 0, "Detected": False, "Detector Confidence": "0.1", "Detection Method": "suricata", "Target Host": "10.0.0.1", "Mode": "PPO + Real Testbed", "Timestamp": "2026-09-10T10:00:00", "Step": 1},
    {"MITRE ID": "T0830", "Technique Name": "Adversary-in-the-Middle", "Stage": 1, "Detected": False, "Detector Confidence": "0.15", "Detection Method": "none", "Target Host": "10.0.0.3", "Mode": "PPO + Real Testbed", "Timestamp": "2026-09-10T10:05:00", "Step": 2},
    {"MITRE ID": "T0836", "Technique Name": "Modify Parameter (FDI)", "Stage": 2, "Detected": True, "Detector Confidence": "0.85", "Detection Method": "both", "Target Host": "10.0.0.5", "Mode": "PPO + Real Testbed", "Timestamp": "2026-09-10T10:10:00", "Step": 3},
    {"MITRE ID": "T0815", "Technique Name": "Denial of View", "Stage": 3, "Detected": True, "Detector Confidence": "0.72", "Detection Method": "ml", "Target Host": "10.0.0.10", "Mode": "PPO + Real Testbed", "Timestamp": "2026-09-10T10:15:00", "Step": 4},
]

report = generate_report(events)
print(f"Report: {report['metadata']['overall_risk']} risk, {len(report['findings'])} findings")

html = render_html(report)
print(f"HTML: {len(html)} chars")

pdf = render_pdf(report)
print(f"PDF: {len(pdf)} bytes")

print("ALL OK")
