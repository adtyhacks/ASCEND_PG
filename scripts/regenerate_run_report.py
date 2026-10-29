import sys
from pathlib import Path
from testbed.run_store import read_events, metrics, report_events
from reports.pentest_report import generate_report, render_html
def main():
    scenario, run = sys.argv[1:3]; events = read_events(scenario, run, 'security')
    root = Path(__file__).resolve().parents[1] / 'data' / 'runs' / scenario / run
    report = generate_report(report_events(events), {'scenario_id':scenario, 'run_id':run, 'metrics':metrics(scenario, run)})
    (root/'report.html').write_text(render_html(report), encoding='utf-8')
    normalized = report_events(events)
    print(f"normalized_records={len(normalized)} detected={sum(bool(e['Detected']) for e in normalized)}")
if __name__ == '__main__': main()
