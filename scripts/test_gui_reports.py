"""Deterministic report HTTP integration; never dispatches campaign/runtime actions."""
import hashlib
import json
import tempfile
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer
from gui import reporting
from gui.server import GuiHandler
from testbed import run_store
from reports.pentest_report import generate_report, render_pdf


def exercise(scenario, run):
    root = run_store._path(scenario, run)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.suffix in {".json", ".jsonl"}}
    server = ThreadingHTTPServer(("127.0.0.1", 0), GuiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        body = json.dumps({"scenario_id": scenario, "run_id": run}).encode()
        with urlopen(Request(base + "/api/report/generate", body, {"Content-Type": "application/json"})) as response:
            result = json.load(response)
        assert result["ok"] and result["available"] and result["normalized_records"] > 0
        file = Path(result["path"])
        with urlopen(base + result["url"]) as response:
            rendered = response.read()
            assert response.headers["Content-Type"].startswith("text/html")
            assert "sandbox" in response.headers["Content-Security-Policy"]
        assert rendered == file.read_bytes()
        html = rendered.decode("utf-8")
        assert "<!DOCTYPE html>" in html and "</html>" in html and run in html
        assert "Recorded evidence" in html and "correlation_id" in html
        assert "Defense command succeeded" not in html and "successfully bypassing" not in html
        records = run_store.report_events(run_store.read_events(scenario, run, "security"))
        pdf = bytes(render_pdf(generate_report(records, {"scenario_id": scenario, "run_id": run})))
        assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
        with urlopen(base + result["url"] + "&download=1") as response:
            assert response.headers["Content-Disposition"].startswith("attachment")
            assert response.read() == rendered
        with urlopen(base + "/api/report-summary?scenario_id=" + scenario + "&run_id=" + run) as response:
            assert json.load(response)["available"]
        try:
            urlopen(Request(base + "/api/report/generate", b'{"scenario_id":"../bad","run_id":"run-missing"}', {"Content-Type": "application/json"}))
            raise AssertionError("Traversal accepted")
        except HTTPError as error:
            assert error.code == 400 and not json.load(error)["ok"]
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.suffix in {".json", ".jsonl"}}
        assert before == after, "Canonical evidence changed"
        print(json.dumps({"report": str(file), "bytes": len(rendered), "records": result["normalized_records"], "http_open_download": "PASS", "evidence_unchanged": True}))
    finally:
        server.shutdown(); server.server_close(); thread.join()


def main():
    import sys
    if len(sys.argv) == 3:
        exercise(*sys.argv[1:])
        return
    original = run_store.RUNS
    try:
        with tempfile.TemporaryDirectory() as temporary:
            run_store.RUNS = Path(temporary)
            run = run_store.create_run({})
            s, r = run["scenario_id"], run["run_id"]
            try:
                reporting.create_report(s, r)
                raise AssertionError("Empty evidence accepted")
            except ValueError:
                pass
            run_store.append_event(s, r, category="security", event_type="attack_finished", correlation_id="test-c", result="failed", evidence={"step_name": "<script>alert(1)</script>"}, mitre_technique="T0836")
            run_store.append_event(s, r, category="security", event_type="detection", correlation_id="test-c", severity="HIGH", detection_method="ml", evidence={"ml_confidence": .91})
            run_store.append_event(s, r, category="network", event_type="network_flow", correlation_id="test-c", evidence={"packet_count": 2})
            exercise(s, r)
            html = reporting.report_path(s, r).read_text()
            assert "<script>" not in html and "&lt;script&gt;" in html and "packet_count" in html
            records = run_store.report_events(run_store.read_events(s, r, "security"))
            assert records[0]["Severity"] is None and records[0]["Detector Confidence"] == .91
            print("GUI report integration: PASS")
    finally:
        run_store.RUNS = original


if __name__ == "__main__": main()
