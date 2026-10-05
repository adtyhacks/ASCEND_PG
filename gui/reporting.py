"""Report-only access to saved canonical runs; no runtime or campaign actions."""
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlencode

from testbed import run_store
from reports.pentest_report import generate_report, render_html


def saved_runs():
    runs = []
    for path in run_store.RUNS.glob("*/*/run.json"):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
            if run["scenario_id"] != path.parent.parent.name or run["run_id"] != path.parent.name:
                continue
            run_store._path(run["scenario_id"], run["run_id"])
            runs.append(run)
        except (OSError, ValueError, KeyError):
            continue
    return sorted(runs, key=lambda r: r.get("started_at", ""), reverse=True)


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
        return {"available": False, "reason": "No saved run", "normalized_records": 0, "runs": []}
    run = select_run(scenario_id, run_id)
    records = run_store.report_events(run_store.read_events(run["scenario_id"], run["run_id"], "security"))
    path = report_path(run["scenario_id"], run["run_id"])
    url = "/api/report-file?" + urlencode({"scenario_id": run["scenario_id"], "run_id": run["run_id"]})
    return {"available": path.is_file(), "path": str(path) if path.is_file() else None,
            "url": url if path.is_file() else None, "run_id": run["run_id"], "scenario_id": run["scenario_id"],
            "normalized_records": len(records), "normalized_events": records[:100],
            "runs": [{"scenario_id": r["scenario_id"], "run_id": r["run_id"], "campaign_state": r.get("campaign_request", {}).get("state", "UNKNOWN")} for r in runs]}


def create_report(scenario_id, run_id):
    if not scenario_id or not run_id:
        raise ValueError("Both scenario_id and run_id are required.")
    run = select_run(scenario_id, run_id)
    security = run_store.read_events(scenario_id, run_id, "security")
    records = run_store.report_events(security)
    if not records:
        raise ValueError("This run has no completed attack evidence; no report was generated.")
    network = run_store.read_events(scenario_id, run_id, "network")
    for event in security + network:
        if event.get("scenario_id") != scenario_id or event.get("run_id") != run_id:
            raise ValueError("Evidence identity does not match the selected run.")
    report = generate_report(records, {"scenario_id": scenario_id, "run_id": run_id,
        "run_metadata": run, "security_events": security, "network_events": network,
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
