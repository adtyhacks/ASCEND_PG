"""Deterministic JSONL event-store regression coverage; does not contact CORE."""
from __future__ import annotations

import json
import multiprocessing
import tempfile
import time
from pathlib import Path

from testbed import run_store


TOPOLOGY = {"topology_version": "test", "nodes": [], "links": []}


def _append(run: dict, event_type: str, **metadata: object) -> dict:
    return run_store.append_event(
        run["scenario_id"], run["run_id"], category="security", event_type=event_type,
        source_node="attacker", target_node="plc1", correlation_id="test-correlation",
        evidence={"step_name": "fdi_attack"}, **metadata,
    )


def _append_in_child(runs_root: str, scenario_id: str, run_id: str, prefix: str) -> None:
    run_store.RUNS = Path(runs_root)
    for index in range(20):
        run_store.append_event(
            scenario_id, run_id, category="security", event_type=f"{prefix}-{index}",
            source_node="attacker", target_node="plc1", correlation_id=f"{prefix}-{index}",
            evidence={"step_name": "fdi_attack"},
        )


def _read_in_child(runs_root: str, scenario_id: str, run_id: str, queue: multiprocessing.Queue) -> None:
    run_store.RUNS = Path(runs_root)
    queue.put(run_store.read_events(scenario_id, run_id))


def main() -> None:
    original_runs = run_store.RUNS
    with tempfile.TemporaryDirectory() as temporary:
        run_store.RUNS = Path(temporary)
        try:
            first = run_store.create_run(TOPOLOGY, scenario_id="scenario-jsonl-test")
            second = run_store.create_run(TOPOLOGY, scenario_id="scenario-jsonl-other")

            # Normal read, one append, sequential appends, schema retention,
            # and a separate run never appearing in this run's event stream.
            assert run_store.read_events(first["scenario_id"], first["run_id"]) == []
            one = _append(first, "attack_started")
            _append(first, "attack_finished", result="detected")
            _append(first, "detection", result="detected")
            _append(second, "attack_started")
            events = run_store.read_events(first["scenario_id"], first["run_id"], "security")
            assert [event["event_type"] for event in events] == ["attack_started", "attack_finished", "detection"]
            assert events[0]["event_id"] == one["event_id"] and events[0]["evidence"]["step_name"] == "fdi_attack"
            assert all(event["run_id"] == first["run_id"] for event in events)
            assert len(run_store.read_events(first["scenario_id"], first["run_id"])) == 3

            # Two independent processes represent Streamlit and watcher
            # writers.  All events remain complete, one-per-line JSON values.
            context = multiprocessing.get_context("spawn")
            writers = [context.Process(target=_append_in_child,
                                       args=(str(run_store.RUNS), first["scenario_id"], first["run_id"], prefix))
                       for prefix in ("streamlit", "watcher")]
            for writer in writers:
                writer.start()
            for writer in writers:
                writer.join(timeout=10)
                assert writer.exitcode == 0
            events = run_store.read_events(first["scenario_id"], first["run_id"])
            assert len(events) == 43
            events_path = Path(first["path"]) / "events.jsonl"
            assert len([json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line]) == 43

            # A reader waits while a cooperative writer owns the per-run lock,
            # then sees the completed final line.  This is the former refresh
            # race and proves it cannot expose transient partial JSON anymore.
            root = Path(first["path"])
            completed = context.Queue()
            with run_store._event_lock(root, run_store.fcntl.LOCK_EX):
                reader = context.Process(target=_read_in_child,
                                         args=(str(run_store.RUNS), first["scenario_id"], first["run_id"], completed))
                reader.start()
                time.sleep(0.05)
                assert reader.is_alive(), "reader did not wait for the active event write"
                with (root / "events.jsonl").open("ab", buffering=0) as out:
                    out.write((json.dumps({"event_type": "writer_completed", "run_id": first["run_id"]}) + "\n").encode())
            # Consume before joining: the child may otherwise block flushing
            # a normal-sized result through multiprocessing's pipe.
            completed_events = completed.get(timeout=5)
            reader.join(timeout=2)
            assert not reader.is_alive() and reader.exitcode == 0
            assert completed_events[-1]["event_type"] == "writer_completed"

            # Existing damaged evidence is never silently skipped: a final
            # unterminated fragment reports its exact location and preserves
            # the preceding parsed records in the diagnostic object.
            with (root / "events.jsonl").open("ab", buffering=0) as out:
                out.write(b'{"event_type":')
            try:
                run_store.read_events(first["scenario_id"], first["run_id"])
            except run_store.EventStoreReadError as exc:
                assert exc.kind == "incomplete trailing event data"
                assert exc.line_number == 45 and len(exc.valid_events) == 44
                assert exc.raw_line == '{"event_type":'
            else:
                raise AssertionError("incomplete trailing evidence was silently accepted")
        finally:
            run_store.RUNS = original_runs
    print("event store JSONL regression: PASS")


if __name__ == "__main__":
    main()
