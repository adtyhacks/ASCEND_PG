#!/usr/bin/env python3
"""Deterministic presentation aliases; no services or persisted data."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gui.identity_presentation import aliases_for
from reports.pentest_report import generate_report, render_html


runs = [
    {"run_id": "run-first", "scenario_id": "scenario-a", "started_at": "2026-01-01T00:00:00Z",
     "core_session_id": "1916653781286537846", "generation_id": "generation-first"},
    {"run_id": "run-second", "scenario_id": "scenario-b", "started_at": "2026-01-02T00:00:00Z",
     "core_session_id": "1916653781286537847", "generation_id": "generation-second"},
]
events = [
    {"run_id": "run-first", "timestamp": "2026-01-01T00:02:00Z", "ppo_step": 2,
     "correlation_id": "step-2-595cb3b70f6e", "target_node": "plc14", "mitre_technique": "T0815"},
    {"run_id": "run-first", "timestamp": "2026-01-01T00:01:00Z", "ppo_step": 1,
     "correlation_id": "step-1-d2294dea07c1", "target_node": "plc1", "mitre_technique": "T0835"},
]

aliases = aliases_for(reversed(runs), reversed(events))
assert aliases.assessment("run-first") == "Assessment 1"
assert aliases.assessment("run-first") == "Assessment 1"
assert aliases.assessment("run-second") == "Assessment 2"
assert aliases.core_session("1916653781286537846") == "CORE Session 1"
assert aliases.core_session("1916653781286537846") == "CORE Session 1"
assert aliases.core_session("1916653781286537847") == "CORE Session 2"
assert aliases.runtime_generation("generation-first") == "Runtime Generation 1"
assert aliases.attack_event("step-1-d2294dea07c1", "run-first") == "Attack Event 1"
assert aliases.attack_event("step-1-d2294dea07c1", "run-first") == "Attack Event 1"
assert aliases.attack_event("step-2-595cb3b70f6e", "run-first") == "Attack Event 2"

presented = aliases.decorate_event(events[0])
assert presented["target_node"] == "plc14"
assert presented["mitre_technique"] == "T0815"
assert presented["correlation_id"] == events[0]["correlation_id"]
assert presented["display_identity"] == {"attack_step": "Attack Step 2", "attack_event": "Attack Event 2"}
assert "display_identity" not in events[0]

normalized = [{
    "Timestamp": "2026-01-01T00:01:10Z", "MITRE ID": "T0835", "Technique Name": "Manipulate I/O Image",
    "Stage": 2, "Target Host": "plc1", "Detected": False, "Detector Confidence": None,
    "Detection Method": "none", "Status": "failed", "Severity": "HIGH", "Attack Severity": "HIGH",
    "Correlation ID": "step-1-d2294dea07c1", "Canonical": True,
    "Evidence": {"attack": {"run_id": "run-first", "scenario_id": "scenario-a",
        "generation_id": "generation-first", "correlation_id": "step-1-d2294dea07c1",
        "timestamp": "2026-01-01T00:01:10Z", "evidence": {"return_status": "FAILED"}},
        "start": {"timestamp": "2026-01-01T00:01:00Z", "severity": "HIGH"}, "detection": None},
}]
report = generate_report(normalized, {"run_id": "run-first", "scenario_id": "scenario-a",
    "run_metadata": runs[0], "display_identity": aliases.run_identity(runs[0]),
    "security_events": [aliases.decorate_event(events[1])]})
html = render_html(report)
primary, technical = html.split("<details><summary>Technical details</summary>", 1)
assert "Assessment 1" in primary and "CORE Session 1" in primary and "Runtime Generation 1" in primary
assert "Attack Step 1" in html and "Attack Event 1" in html
assert "run-first" not in primary and "1916653781286537846" not in primary and "generation-first" not in primary
assert "run-first" in technical and "1916653781286537846" in technical and "generation-first" in technical
assert "step-1-d2294dea07c1" in technical
assert "plc1" in html and "T0835" in html

print("Identifier presentation: PASS (stable aliases, shared report names, traceable raw IDs, preserved domain IDs)")
