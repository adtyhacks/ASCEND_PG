"""Deterministic active-run recovery coverage; does not contact CORE."""
import json
import tempfile
from pathlib import Path

from testbed import run_store


def write_run(root: Path, scenario: str, run: str, **values):
    path = root / scenario / run / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"scenario_id": scenario, "run_id": run, "status": "RUNNING", "lifecycle_status": "RUNNING", **values}), encoding="utf-8")


def main():
    runtime = {"id": 3, "generation_id": "c6f2c4a9cb8f4c41aba19789dcadf6c3"}
    original_runs = run_store.RUNS
    with tempfile.TemporaryDirectory() as temp:
        run_store.RUNS = Path(temp)
        try:
            # Session state already has this value in the page; the store
            # recovery contract returns the same canonical metadata.
            write_run(run_store.RUNS, "scenario-a", "run-a", core_session_id=3, generation_id=runtime["generation_id"])
            recovered = run_store.recover_active_run(runtime)
            assert recovered and recovered["run_id"] == "run-a" and recovered["scenario_id"] == "scenario-a"

            # A different generation, stopped run, or unmatched session cannot
            # be revived merely because it shares a historic numeric ID.
            write_run(run_store.RUNS, "scenario-b", "run-b", core_session_id=3, generation_id="generation-old")
            write_run(run_store.RUNS, "scenario-c", "run-c", core_session_id=4, generation_id=runtime["generation_id"])
            assert run_store.recover_active_run(runtime)["run_id"] == "run-a"
            assert run_store.recover_active_run({"id": 9, "generation_id": runtime["generation_id"]}) is None
            assert run_store.recover_active_run(None) is None

            # Ambiguity is rejected rather than choosing a run or creating one.
            write_run(run_store.RUNS, "scenario-d", "run-d", core_session_id=3, generation_id=runtime["generation_id"])
            assert run_store.recover_active_run(runtime) is None
        finally:
            run_store.RUNS = original_runs

    # A malformed aggregate event stream remains raw diagnostic evidence, but
    # cannot become Live Battle's displayable active run.
    with tempfile.TemporaryDirectory() as temp:
        run_store.RUNS = Path(temp)
        try:
            write_run(run_store.RUNS, "scenario-diagnostic", "run-diagnostic", core_session_id=3, generation_id=runtime["generation_id"])
            broken = run_store.RUNS / "scenario-diagnostic" / "run-diagnostic" / "events.jsonl"
            broken.write_text('{"event_type":', encoding="utf-8")
            selected, diagnostic = run_store.recover_displayable_active_run(runtime)
            assert selected is None
            assert diagnostic and diagnostic.line_number == 1

            # A valid aggregate stream remains eligible for normal recovery.
            broken.write_text('{"event_type": "attack_started"}\n', encoding="utf-8")
            selected, diagnostic = run_store.recover_displayable_active_run(runtime)
            assert diagnostic is None and selected and selected["run_id"] == "run-diagnostic"

            # Recovery only supplies an active run.  It does not manufacture
            # watcher handoff files; normal campaign stepping owns that work.
            session_state = {"active_run": selected}
            assert session_state["active_run"]["run_id"] == "run-diagnostic"
            assert not (Path(temp) / "pending_step.json").exists()

            # Internally inconsistent metadata cannot be selected even when
            # the session and generation otherwise match.
            write_run(run_store.RUNS, "scenario-diagnostic", "run-diagnostic",
                      status="STOPPED", core_session_id=3, generation_id=runtime["generation_id"])
            write_run(run_store.RUNS, "scenario-inconsistent", "run-inconsistent",
                      core_session_id=3, generation_id=runtime["generation_id"], scenario_id="wrong-scenario")
            assert run_store.recover_displayable_active_run(runtime)[0] is None
        finally:
            run_store.RUNS = original_runs
    print("active run recovery regression: PASS")


if __name__ == "__main__":
    main()
