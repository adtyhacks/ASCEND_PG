"""Report-only access to saved canonical runs; no runtime or campaign actions."""
import os
import tempfile
from pathlib import Path
from urllib.parse import urlencode

from testbed import run_store
from reports.pentest_report import generate_report, render_html
from gui.identity_presentation import aliases_for, saved_run_metadata


def saved_runs():
    return saved_run_metadata()


def select_run(scenario_id=None, run_id=None):
    runs = saved_runs()
    if scenario_id or run_id:
        if not scenario_id or not run_id:
            raise ValueError("Both scenario_id and run_id are required.")
        run_store._path(scenario_id, run_id)
        runs = [r for r in runs if r["scenario_id"] == scenario_id and r["run_id"] == run_id]
    if not runs:
        raise FileNotFoundError("No saved run is available.")
    return runs[0]


def report_path(scenario_id, run_id):
    if not scenario_id or not run_id:
        raise ValueError("Both scenario_id and run_id are required.")
    run = select_run(scenario_id, run_id)
    return run_store._path(run["scenario_id"], run["run_id"]) / "report.html"


def summary(scenario_id=None, run_id=None):
    runs = saved_runs()
    if not runs:
        return {"available": False, "reason": "No saved run", "normalized_records": 0, "runs": [],
                "finding_summary": {"total_findings": 0, "detected": 0, "failed": 0, "timeout": 0, "techniques": 0, "targets": 0}}
    run = select_run(scenario_id, run_id)
    security = run_store.read_events(run["scenario_id"], run["run_id"], "security")
    registry = aliases_for(runs, security)
    records = run_store.report_events(security)
    # Reuse the report's finding construction over ALL normalized records.
    # This builds a model in memory only: no HTML generation or evidence writes.
    report = generate_report(records, {"run_metadata": run, "display_identity": registry.run_identity(run)})
    findings = report["findings"]
    finding_summary = {
        "total_findings": report["risk_summary"]["total"],
        "detected": sum(finding["detected"] is True for finding in findings),
        "failed": sum(str(finding["execution_result"]).strip().upper() == "FAILED" for finding in findings),
        "timeout": sum(str(finding["execution_result"]).strip().upper() == "TIMEOUT" for finding in findings),
        "techniques": len({finding["technique_id"] for finding in findings if finding["technique_id"] not in (None, "", "N/A")}),
        "targets": len({finding["target"] for finding in findings if finding["target"] not in (None, "", "N/A")}),
    }
    risk = report["risk_summary"]
    total = finding_summary["total_findings"]
    assessed_finding_dvs = sum(finding.get("finding_dvs") is not None for finding in findings)
    assessment_overview = {
        "severity_distribution": {
            label: risk.get(label.lower(), 0)
            for label in ("Critical", "High", "Medium", "Low", "Informational")
        },
        "attacks": [{
            "finding_id": finding["id"],
            "attack_step": finding.get("attack_step_name"),
            "attack_event": finding.get("attack_event_name"),
            "title": finding["title"],
            "description": finding["description"],
            "technique_id": finding["technique_id"],
            "target": finding["target"],
            "result": finding["execution_result"],
            "detected": finding["detected"],
            "detection_method": finding["detection_method"],
            "severity": finding["severity"],
            "finding_dvs": finding["finding_dvs"],
        } for finding in findings],
        "defense": {
            "detected": finding_summary["detected"],
            "total": total,
            "detection_rate": (finding_summary["detected"] / total) if total else None,
            "methods": risk.get("detection_methods", {}),
        },
        "dvs": {
            "finding_available": assessed_finding_dvs > 0,
            "finding_assessed": assessed_finding_dvs,
            "finding_total": total,
            "campaign_available": report["dvs"].get("score") is not None,
            "campaign_score": report["dvs"].get("score"),
            "campaign_rating": report["dvs"].get("rating"),
        },
    }
    path = report_path(run["scenario_id"], run["run_id"])
    url = "/api/report-file?" + urlencode({"scenario_id": run["scenario_id"], "run_id": run["run_id"]})
    return {"available": path.is_file(), "path": str(path) if path.is_file() else None,
            "url": url if path.is_file() else None, "run_id": run["run_id"], "scenario_id": run["scenario_id"],
            "display_identity": registry.run_identity(run),
            "normalized_records": len(records), "normalized_events": records[:100], "finding_summary": finding_summary,
            "assessment_overview": assessment_overview,
            "runs": [{"scenario_id": r["scenario_id"], "run_id": r["run_id"],
                      "display_name": registry.assessment(r["run_id"]),
                      "campaign_state": r.get("campaign_request", {}).get("state", "UNKNOWN")} for r in runs]}


def create_report(scenario_id, run_id):
    if not scenario_id or not run_id:
        raise ValueError("Both scenario_id and run_id are required.")
    run = select_run(scenario_id, run_id)
    security = run_store.read_events(scenario_id, run_id, "security")
    registry = aliases_for(saved_runs(), security)
    records = [registry.decorate_event(record) for record in run_store.report_events(security)]
    if not records:
        raise ValueError("This run has no completed attack evidence; no report was generated.")
    network = run_store.read_events(scenario_id, run_id, "network")
    for event in security + network:
        if event.get("scenario_id") != scenario_id or event.get("run_id") != run_id:
            raise ValueError("Evidence identity does not match the selected run.")
    report = generate_report(records, {"scenario_id": scenario_id, "run_id": run_id,
        "run_metadata": run, "display_identity": registry.run_identity(run),
        "security_events": [registry.decorate_event(event) for event in security], "network_events": network,
        "network_evidence_note": "Run-scoped observations; only matching correlation IDs establish step association. Background telemetry is excluded."})
    html = render_html(report)
    path = report_path(scenario_id, run_id)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            output.write(html)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return summary(scenario_id, run_id)
