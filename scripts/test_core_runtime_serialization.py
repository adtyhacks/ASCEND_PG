"""Deterministic GUI CORE-helper serialization checks; never starts CORE."""
from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gui import adapter, campaign
from testbed import core_runtime


def _successful_result(action: str) -> SimpleNamespace:
    return SimpleNamespace(
        stdout=json.dumps({"ok": True, "state": "RUNTIME", "session_id": 3, "action": action}),
        stderr="",
        returncode=0,
    )


def _concurrent_gui_paths_are_serialized() -> None:
    entered_first = threading.Event()
    entered_second = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    active = 0
    max_active = 0
    call_count = 0
    state_lock = threading.Lock()
    errors: list[BaseException] = []

    def fake_run(_command, *, input, **_kwargs):
        nonlocal active, max_active, call_count
        action = json.loads(input)["action"]
        with state_lock:
            call_count += 1
            call_number = call_count
            active += 1
            max_active = max(max_active, active)
        if call_number == 1:
            entered_first.set()
            if not release_first.wait(2):
                raise AssertionError("test did not release the first helper call")
        else:
            entered_second.set()
        with state_lock:
            active -= 1
        return _successful_result(action)

    def capture(function) -> None:
        try:
            function()
        except BaseException as exc:  # surfaced in the main test thread
            errors.append(exc)

    original_heartbeat = campaign.HEARTBEAT
    try:
        with tempfile.TemporaryDirectory() as temporary:
            heartbeat = Path(temporary) / "watcher_heartbeat.json"
            heartbeat.write_text(json.dumps({
                "status": "IDLE", "session_id": "3", "generation_id": "g" * 32,
                "timestamp": time.time(), "steps_executed": 0,
            }), encoding="utf-8")
            campaign.HEARTBEAT = heartbeat
            runtime = {"id": 3, "generation_id": "g" * 32}
            diagnostics = threading.Thread(target=capture, args=(adapter.get_system_status,))

            def validate_controller() -> None:
                second_started.set()
                campaign.CampaignController()._core_and_watcher(runtime, require_idle=True)

            validation = threading.Thread(target=capture, args=(validate_controller,))
            with patch.object(core_runtime.os, "name", "posix"), \
                    patch.object(core_runtime.subprocess, "run", side_effect=fake_run):
                diagnostics.start()
                assert entered_first.wait(1), "runtime diagnostics did not invoke core_request"
                validation.start()
                assert second_started.wait(1), "controller validation did not start"
                assert not entered_second.wait(0.1), "controller helper overlapped runtime diagnostics"
                release_first.set()
                diagnostics.join(2)
                validation.join(2)
            assert not diagnostics.is_alive() and not validation.is_alive()
            assert not errors, errors
            assert entered_second.is_set() and call_count == 2
            assert max_active == 1, f"CORE helper subprocesses overlapped: max_active={max_active}"
    finally:
        campaign.HEARTBEAT = original_heartbeat


def _single_call_and_timeout_behave_as_expected() -> None:
    with patch.object(core_runtime.os, "name", "posix"), \
            patch.object(core_runtime.subprocess, "run", return_value=_successful_result("status")) as run:
        result = core_runtime.core_request("status")
    assert result["ok"] is True and result["action"] == "status"
    assert run.call_count == 1

    original_timeout = core_runtime.CORE_REQUEST_LOCK_TIMEOUT_SECONDS
    core_runtime.CORE_REQUEST_LOCK_TIMEOUT_SECONDS = 0.01
    core_runtime._CORE_REQUEST_LOCK.acquire()
    try:
        with patch.object(core_runtime.os, "name", "posix"), \
                patch.object(core_runtime.subprocess, "run") as run:
            try:
                core_runtime.core_request("status")
            except RuntimeError as exc:
                assert str(exc) == "Timed out waiting for another GUI CORE helper operation."
            else:
                raise AssertionError("contended helper call should fail after its bounded wait")
            run.assert_not_called()
    finally:
        core_runtime._CORE_REQUEST_LOCK.release()
        core_runtime.CORE_REQUEST_LOCK_TIMEOUT_SECONDS = original_timeout


def _helper_flock_remains_nonblocking() -> None:
    helper_source = (Path(__file__).with_name("core_session.py")).read_text(encoding="utf-8")
    assert "fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)" in helper_source
    assert 'raise RuntimeError("Another CORE operation is in progress")' in helper_source


def _campaign_next_has_no_automatic_retry() -> None:
    root = Path(__file__).resolve().parents[1]
    server_source = (root / "gui" / "server.py").read_text(encoding="utf-8")
    frontend_source = (root / "gui" / "web" / "app.js").read_text(encoding="utf-8")
    assert server_source.count("CAMPAIGNS.next_step()") == 1
    assert frontend_source.count("runControl('/api/campaign/next'") == 1


def main() -> None:
    _concurrent_gui_paths_are_serialized()
    _single_call_and_timeout_behave_as_expected()
    _helper_flock_remains_nonblocking()
    _campaign_next_has_no_automatic_retry()
    print("CORE helper serialization regression: PASS")


if __name__ == "__main__":
    main()
