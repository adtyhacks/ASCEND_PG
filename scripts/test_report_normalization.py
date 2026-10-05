from testbed.run_store import report_events
def main():
    events=[{"event_type":"attack_finished","timestamp":"2026-01-01T00:00:01+00:00","correlation_id":"c1","mitre_technique":"T0836","attack_stage":2,"target_node":"plc1","evidence":{"step_name":"fdi_attack","ml_confidence":.9,"detection_method":"both"}}, {"event_type":"detection","timestamp":"2026-01-01T00:00:02+00:00","correlation_id":"c1"}]
    records=report_events(events); assert len(records)==1 and records[0]["Detected"] is True and records[0]["MITRE ID"]=="T0836"
    attack = {**events[0], "run_id": "run-one", "result": "failed"}
    foreign = {**events[1], "run_id": "run-two"}
    assert not report_events([attack, foreign])[0]["Detected"]
    assert not report_events([{**attack, "correlation_id": None}, {**events[1], "correlation_id": None}])[0]["Detected"]
    assert report_events([{**attack, "result": "detected"}])[0]["Detected"]
    print("report normalization regression: PASS")
if __name__ == '__main__': main()
