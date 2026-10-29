"""Synthetic corroborated facts for pure scorer tests, never production telemetry."""
from metrics.finding_evidence import bind_evidence

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:01:00+00:00"
IDENTITY = dict(scenario_id="s", run_id="r", generation_id="g", correlation_id="c")


def fixture_bundle(dimensions):
    rows = []
    def add(kind, second, **fields):
        rows.append(dict(kind=kind, timestamp=f"2026-01-01T00:00:{second:02d}+00:00",
                         target="10.0.0.1", **fields))
    if any(d != "confidentiality" for d in dimensions):
        add("write_ack", 20, source="attack_log", actor="attacker", space="holding", address=0, value=0)
    if "integrity" in dimensions:
        for second, values in ((10, [1]), (30, [0])):
            add("state_read", second, source="passive_scada", available=True, space="holding", address=0, count=1, values=values)
    if "availability" in dimensions:
        add("disruption_attempt", 20, source="attack_log", actor="attacker", packets_sent=10)
        for second, available in ((10, True), (30, False), (40, False)):
            add("state_read", second, source="passive_scada", available=available, space="holding", address=10, count=1, values=[1] if available else None)
        rows.append(dict(kind="state_read", timestamp="2026-01-01T00:00:35+00:00", target="10.0.0.2",
                         source="passive_scada", available=True, space="holding", address=10, count=1, values=[1]))
    if "confidentiality" in dimensions:
        add("collection_read", 30, source="executor_output", actor="attacker", values=[7], count=1)
    for dimension, sensor in (("operational_impact", "process_sensor"), ("physical_impact", "physical_sensor"), ("safety_impact", "safety_sensor")):
        if dimension in dimensions:
            add(dimension, 30, source="independent_instrument", instrument_kind=sensor,
                observed_before=1, observed_after=0, safe_min=.5, safe_max=1.5, units="fixture_units",
                instrument_reference=f"fixture:{dimension}", attribution_method="controlled_intervention")
    bundle = bind_evidence({"records": rows}, IDENTITY, START, END)
    ack = next((r["reference"] for r in bundle["records"] if r["kind"] == "write_ack"), None)
    for row in rows:
        if row["source"] == "independent_instrument":
            row["action_reference"] = ack
    return bind_evidence({"records": rows}, IDENTITY, START, END)
