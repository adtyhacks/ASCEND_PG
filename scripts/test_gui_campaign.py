"""Deterministic Phase 3B handoff tests; never starts CORE or an attack."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gui import campaign
from testbed import run_store


class FakeTopology:
    revision = "test"
    physical_state = None
    case_name = "case14"
    num_buses = 1
    def get_ip(self, bus: int) -> str: return "10.0.0.1"
    def canonical_snapshot(self) -> dict:
        return {"nodes": [{"id": "plc1"}], "links": [], "topology_version": "test"}


class FakeEnvironment:
    _num_buses = 1

    def __init__(self):
        self._history = []
        self._step_count = 0
        self._chain = []
        self._compromised_buses = set()
        self.reward_calls = []
        self.observation_calls = 0

    def calculate_step_reward(self, **result):
        self.reward_calls.append(result)
        return -2.5 if result["detected"] else 1.0

    def _get_obs(self):
        self.observation_calls += 1
        return [self._step_count, len(self._history), self._last_confidence]

    def step(self, action):
        raise AssertionError("Post-result advancement must never call env.step()")


class CacheEnvironment:
    _num_buses = 1

    def __init__(self, number: int):
        self.number = number
        self.reset_calls = 0

    def reset(self):
        self.reset_calls += 1
        return [self.number, self.reset_calls], {}


class FakeModel:
    def __init__(self, number: int): self.number = number


def _cache_regression() -> None:
    """Exercise process-local model reuse without importing PPO or starting CORE."""
    original = campaign.DATA, campaign.PENDING_STEP, campaign.STEP_RESULT, campaign.HEARTBEAT, run_store.RUNS
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign.DATA = root / "data"
            campaign.PENDING_STEP = campaign.DATA / "pending_step.json"
            campaign.STEP_RESULT = campaign.DATA / "step_result.json"
            campaign.HEARTBEAT = campaign.DATA / "watcher_heartbeat.json"
            run_store.RUNS = campaign.DATA / "runs"
            runtime_path = campaign.DATA / "core-runtime" / "session.json"
            runtime_path.parent.mkdir(parents=True)
            model_path = root / "model.zip"; model_path.write_bytes(b"checkpoint-a")
            runtime = {"id": 3, "generation_id": "a" * 32}

            def write_runtime(*, watcher="IDLE"):
                runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
                campaign.HEARTBEAT.write_text(json.dumps({"status": watcher, "session_id": str(runtime["id"]),
                    "generation_id": runtime["generation_id"], "timestamp": time.time(), "steps_executed": 0}), encoding="utf-8")

            def request(action, **_):
                if action == "status":
                    return {"state": "RUNTIME", "session_id": runtime["id"], "watcher": "IDLE"}
                return {"session_id": runtime["id"]}

            environments: list[CacheEnvironment] = []
            load_calls: list[int] = []

            def configure(controller, *, fail_first=False, pause=False):
                def create_environment(_topology):
                    environment = CacheEnvironment(len(environments) + 1)
                    environments.append(environment)
                    return environment

                attempts = {"count": 0}
                def load_model(_checkpoint):
                    attempts["count"] += 1; load_calls.append(attempts["count"])
                    if pause: time.sleep(0.05)
                    if fail_first and attempts["count"] == 1: raise RuntimeError("simulated PPO load failure")
                    return FakeModel(attempts["count"]), 0.0, 0.0

                controller._create_environment = create_environment
                controller._load_model = load_model
                return attempts

            def create_owned_run(name):
                run = run_store.create_run(FakeTopology().canonical_snapshot(), scenario_id=name)
                return run_store.update_run(run["scenario_id"], run["run_id"], core_session_id=runtime["id"],
                    generation_id=runtime["generation_id"], lifecycle_status="RUNNING")

            write_runtime(); run_a = create_owned_run("scenario-cache-a")
            controller = campaign.CampaignController(request=request, topology=lambda: FakeTopology(), model_path=model_path)
            attempts = configure(controller)
            first = controller.start()
            assert first["initialization_timings"]["model_cache_hit"] is False and attempts["count"] == 1
            first_env, first_model = controller._sessions[run_a["run_id"]]["env"], controller._sessions[run_a["run_id"]]["model"]
            second = controller.start()
            second_env = controller._sessions[run_a["run_id"]]["env"]
            assert second["initialization_timings"]["model_cache_hit"] is True and attempts["count"] == 1
            assert second_env is not first_env and second_env.reset_calls == 1
            assert controller._sessions[run_a["run_id"]]["model"] is first_model

            # A new owned generation/run gets a new environment but never inherits run state.
            runtime.update({"id": 4, "generation_id": "b" * 32}); write_runtime(); run_b = create_owned_run("scenario-cache-b")
            third = controller.start()
            assert third["run_id"] == run_b["run_id"] and third["generation_id"] == runtime["generation_id"]
            assert attempts["count"] == 1 and set(controller._sessions) == {run_b["run_id"]}
            assert controller._sessions[run_b["run_id"]]["env"] is not second_env

            # Validation failures must happen before any cache/model work.
            runtime.update({"id": 99, "generation_id": "z" * 32}); write_runtime()
            before = attempts["count"]
            try: controller.start()
            except campaign.CampaignError as exc: assert exc.code == "no_active_run"
            else: raise AssertionError("missing active run must fail before model loading")
            assert attempts["count"] == before
            runtime.update({"id": 5, "generation_id": "c" * 32}); write_runtime(watcher="BUSY"); run_c = create_owned_run("scenario-cache-c")
            try: controller.start()
            except campaign.CampaignError as exc: assert exc.code == "watcher_unavailable"
            else: raise AssertionError("watcher validation must fail before model loading")
            assert attempts["count"] == before

            # A failed load cannot poison the cache, and retry succeeds.
            write_runtime(); failing = campaign.CampaignController(request=request, topology=lambda: FakeTopology(), model_path=model_path)
            failed_attempts = configure(failing, fail_first=True)
            try: failing.start()
            except RuntimeError as exc: assert "simulated PPO" in str(exc)
            else: raise AssertionError("simulated model load should fail")
            assert failing._cached_model is None and not campaign.PENDING_STEP.exists()
            retry = failing.start()
            assert failed_attempts["count"] == 2 and retry["initialization_timings"]["model_cache_hit"] is False

            # Checkpoint identity replacement forces a fresh model load.
            model_path.write_bytes(b"checkpoint-b-larger")
            os.utime(model_path, ns=(time.time_ns(), time.time_ns()))
            reloaded = failing.start()
            assert failed_attempts["count"] == 3 and reloaded["initialization_timings"]["model_cache_hit"] is False

            # Concurrent starts serialize cache population and keep a single active session.
            concurrent = campaign.CampaignController(request=request, topology=lambda: FakeTopology(), model_path=model_path)
            concurrent_attempts = configure(concurrent, pause=True)
            barrier = threading.Barrier(3); errors = []
            def start_worker():
                try: barrier.wait(); concurrent.start()
                except Exception as exc: errors.append(exc)
            workers = [threading.Thread(target=start_worker) for _ in range(2)]
            for worker in workers: worker.start()
            barrier.wait()
            for worker in workers: worker.join()
            assert not errors and concurrent_attempts["count"] == 1

            # Status and a step request serialize against the same mutable session.
            concurrent._select_step = lambda session: {"technique_id": "T0836", "step_name": "fdi_attack", "target_bus": 0,
                "register_address": 40000, "value_magnitude": 1.0, "attack_stage": 2, "_action": [0, 0, 5, 0]}
            barrier = threading.Barrier(3); errors = []
            def next_worker():
                try: barrier.wait(); concurrent.next_step()
                except Exception as exc: errors.append(exc)
            def status_worker():
                try: barrier.wait(); concurrent.status()
                except Exception as exc: errors.append(exc)
            workers = [threading.Thread(target=next_worker), threading.Thread(target=status_worker)]
            for worker in workers: worker.start()
            barrier.wait()
            for worker in workers: worker.join()
            assert not errors and campaign.PENDING_STEP.exists()
            pending = json.loads(campaign.PENDING_STEP.read_text(encoding="utf-8"))
            assert pending["run_id"] == run_c["run_id"] and pending["generation_id"] == runtime["generation_id"]
    finally:
        campaign.DATA, campaign.PENDING_STEP, campaign.STEP_RESULT, campaign.HEARTBEAT, run_store.RUNS = original


def _bounded_worker_regression() -> None:
    """Run the actual worker thread against in-memory authoritative results."""
    real_thread = threading.Thread
    for outcomes, expected_count in (([False], 1), ([True, False], 2), ([True, True, True], 3)):
        controller = campaign.CampaignController()
        run = {"run_id": "run-worker-test"}
        controller._campaign = lambda: ({"id": 3}, run, {"state": "READY"})
        controller._core_and_watcher = lambda *args, **kwargs: {}
        dispatches = []
        state = {"state": "READY"}
        threads = []

        def dispatch():
            number = len(dispatches) + 1
            dispatches.append(number)
            success = outcomes[min(number - 1, len(outcomes) - 1)]
            state.update({"state": "COMPLETED", "current_step": number, "error": None,
                          "latest_step_result": {"status": "DETECTED" if success else "FAILED",
                                                 "success": success, "detected": success,
                                                 "evaded": False, "correlation_id": f"step-{number}"}})

        def create_thread(**kwargs):
            thread = real_thread(**kwargs)
            threads.append(thread)
            return thread

        controller.next_step = dispatch
        controller.status = lambda: state
        with patch("gui.campaign.threading.Thread", side_effect=create_thread):
            response = controller.run_full(max_steps=3)
            assert response["max_steps"] == 3
            assert len(threads) == 1
            threads[0].join(timeout=5)
            assert not threads[0].is_alive(), "bounded worker did not terminate"
        assert len(dispatches) == expected_count, (outcomes, dispatches)
        assert dispatches == list(range(1, expected_count + 1))
        assert not controller._full_runs
        assert state["current_step"] == expected_count
        assert state["latest_step_result"]["success"] is outcomes[expected_count - 1]
        assert state["latest_step_result"]["status"] == ("DETECTED" if outcomes[expected_count - 1] else "FAILED")
        if not outcomes[expected_count - 1]:
            assert controller.status()["latest_step_result"]["success"] is False
            assert controller.status()["latest_step_result"]["status"] == "FAILED"
    print("Bounded worker: failed-first dispatch_count=1; failed-second=2; successful limit=3: PASS")


class MemoryMarker:
    def __init__(self, name, store):
        self.name, self.store = name, store

    def exists(self): return self.name in self.store
    def unlink(self, missing_ok=False): self.store.pop(self.name, None)


class MemoryEnvironment(FakeEnvironment):
    def __init__(self):
        super().__init__()
        self.step_calls = 0
        self._last_action = None
        self._last_confidence = 0.0

    def reset(self): return [0, 0, 0.0], {}

    def calculate_step_reward(self, **result):
        self.reward_calls.append(result)
        return -2.6 if result["status"] == "FAILED" else -2.5

    def step(self, action):
        self.step_calls += 1
        raise AssertionError("The controller must never call env.step()")


class MemoryCampaign:
    """Real controller methods over memory-only handoff/store dependencies."""
    def __init__(self, outcomes, *, automatic=False):
        self.outcomes, self.automatic = outcomes, automatic
        self.store, self.dispatches, self.progression = {}, [], []
        self.records = {"security": [], "network": [], "aggregate": []}
        self.environments, self.models, self.threads = [], [], []
        self.waiting_polls, self.retained_polls = 0, 0
        self.runtime = {"id": 3, "generation_id": "memory-generation"}
        self.run = {"run_id": "run-memory", "scenario_id": "scenario-memory",
                    "core_session_id": 3, "generation_id": "memory-generation"}
        self.heartbeat = {"status": "IDLE", "session_id": "3", "generation_id": "memory-generation",
                          "timestamp": time.time(), "steps_executed": 0}
        self.pending = MemoryMarker("pending_step.json", self.store)
        self.result = MemoryMarker("step_result.json", self.store)
        self.heartbeat_path = MemoryMarker("watcher_heartbeat.json", self.store)
        self.real_thread = threading.Thread
        self.controller = campaign.CampaignController(request=self.request, topology=lambda: FakeTopology())
        self.controller._active_run = self.active_run
        self.controller._model_identity = lambda: ("memory-checkpoint", 1, 1)
        self.controller._create_environment = self.create_environment
        self.controller._load_model = self.load_model

    def request(self, action, **kwargs):
        assert action == "status", "No runtime controls may execute"
        return {"state": "RUNTIME", "session_id": 3, "watcher": "IDLE"}

    def active_run(self, runtime, *, displayable=True):
        assert runtime["id"] == self.run["core_session_id"]
        assert runtime["generation_id"] == self.run["generation_id"]
        return deepcopy(self.run)

    def create_environment(self, topology):
        environment = MemoryEnvironment()
        self.environments.append(environment)
        return environment

    def load_model(self, checkpoint):
        class Model:
            def __init__(self): self.inputs = []
            def predict(self, observation, deterministic):
                assert deterministic is False
                self.inputs.append(deepcopy(observation))
                return [0, 3, 0, 0], None
            def learn(self, *args, **kwargs): raise AssertionError("Inference only")
        model = Model()
        self.models.append(model)
        return model, 0.0, 0.0

    def result_for(self, request, success=True):
        return {**{key: request[key] for key in ("run_id", "scenario_id", "campaign_id", "generation_id", "correlation_id")},
                "status": "SUCCESS" if success else "FAILED", "success": success,
                "detected": success, "evaded": False, "return_code": 0 if success else 1,
                "error": None if success else "mock authoritative failure", "ml_detected": True,
                "ml_confidence": 0.92 if success else 0.99, "alert_count": 1,
                "detection_method": "both" if success else "failed", "end_time": request["timestamp"]}

    def deliver(self):
        request = self.store.pop(self.pending.name)
        self.store[self.result.name] = self.result_for(request, self.outcomes[len(self.dispatches) - 1])
        self.heartbeat["steps_executed"] += 1
        self.append_event(self.run["scenario_id"], self.run["run_id"], category="security", event_type="attack_started",
                          **{key: request[key] for key in ("campaign_id", "generation_id", "correlation_id")})

    def read_json(self, path):
        if path is self.result:
            if self.automatic and self.pending.exists():
                self.waiting_polls += 1
                if self.waiting_polls >= 3:
                    self.deliver()
                elif self.result.exists():
                    self.retained_polls += 1
            return deepcopy(self.store.get(self.result.name))
        if path is self.heartbeat_path: return deepcopy(self.heartbeat)
        assert path.name == "session.json"
        return deepcopy(self.runtime)

    def atomic_json(self, path, request):
        assert path is self.pending
        self.store[path.name] = deepcopy(request)
        self.dispatches.append(deepcopy(request))
        self.waiting_polls = 0

    def update_run(self, scenario_id, run_id, **changes):
        assert (scenario_id, run_id) == (self.run["scenario_id"], self.run["run_id"])
        self.run.update(deepcopy(changes))
        state = changes.get("campaign_request")
        if state: self.progression.append((state["state"], state["current_step"]))
        return deepcopy(self.run)

    def read_events(self, scenario_id, run_id, category=None):
        assert (scenario_id, run_id) == (self.run["scenario_id"], self.run["run_id"])
        return deepcopy(self.records[category or "aggregate"])

    def append_event(self, scenario_id, run_id, *, category, event_type, **fields):
        assert category == "security"
        event = {"scenario_id": scenario_id, "run_id": run_id, "category": category,
                 "event_type": event_type, **deepcopy(fields)}
        self.records[category].append(event)
        self.records["aggregate"].append(deepcopy(event))
        return event

    def thread(self, **kwargs):
        thread = self.real_thread(**kwargs)
        self.threads.append(thread)
        return thread

    def __enter__(self):
        self.guards = ExitStack()
        for target in ("subprocess.Popen", "subprocess.run", "os.system", "socket.socket", "socket.create_connection"):
            self.guards.enter_context(patch(target, side_effect=AssertionError(f"Forbidden external operation: {target}")))
        for target, value in (("PENDING_STEP", self.pending), ("STEP_RESULT", self.result), ("HEARTBEAT", self.heartbeat_path)):
            self.guards.enter_context(patch.object(campaign, target, value))
        self.guards.enter_context(patch.object(campaign, "_read_json", side_effect=self.read_json))
        self.guards.enter_context(patch.object(campaign, "_atomic_json", side_effect=self.atomic_json))
        for name in ("update_run", "read_events", "append_event"):
            self.guards.enter_context(patch.object(run_store, name, side_effect=getattr(self, name)))
        modules = {"strategic.rl_env": SimpleNamespace(MITRE_TECHNIQUES=[{"id": "T0836", "stage": 2}],
                    REGISTER_BASES={"T0836": 40000}, VALUE_MAGNITUDES=[1.0]),
                   "scripts.testbed_executor": SimpleNamespace(TECHNIQUE_TO_STEP_NAME={"T0836": "fdi_attack"})}
        self.guards.enter_context(patch.dict("sys.modules", modules))
        self.guards.enter_context(patch("gui.campaign.threading.Thread", side_effect=self.thread))
        self.guards.enter_context(patch("gui.campaign.time.sleep", lambda seconds: None))
        self.completions = self.guards.enter_context(patch.object(self.controller, "_complete", wraps=self.controller._complete))
        return self

    def __exit__(self, *exception):
        try:
            for thread in self.threads: thread.join(timeout=3)
        finally:
            self.guards.close()


def _accepted_result_handoff_regression():
    with MemoryCampaign([True, True]) as fixture:
        controller = fixture.controller
        controller.start()
        first = controller.next_step()
        requested_session = controller._sessions[fixture.run["run_id"]]
        requested_state = _restart_state(fixture)
        assert not controller._full_runs
        try:
            controller.start()
        except campaign.CampaignError as exc:
            assert exc.code == "campaign_already_running"
        else:
            raise AssertionError("An outstanding REQUESTED step must reject restart")
        assert controller._sessions[fixture.run["run_id"]] is requested_session
        assert _restart_state(fixture) == requested_state
        fixture.deliver()
        completed = controller.status()
        assert completed["current_step"] == 1
        previous = deepcopy(fixture.store[fixture.result.name])
        session = controller._sessions[fixture.run["run_id"]]
        environment = session["env"]
        second = controller.next_step()
        assert first["correlation_id"] != second["correlation_id"]
        for _ in range(3):
            waiting = controller.status()
            assert waiting["state"] == "REQUESTED" and waiting["current_step"] == 1
            assert waiting["error"] is None, waiting["error"]
        # Only the exact accepted payload may be treated as consumed.
        for field in ("generation_id", "campaign_id", "correlation_id"):
            invalid = fixture.result_for(second)
            invalid[field] = "unexpected"
            fixture.store[fixture.result.name] = invalid
            assert controller.status()["error"]["code"] == "stale_result"
            assert session["current_step"] == 1 and environment._history == [1]
            assert fixture.completions.call_count == 1
        changed_previous = {**previous, "ml_confidence": 0.1}
        fixture.store[fixture.result.name] = changed_previous
        assert controller.status()["error"]["code"] == "stale_result"
        fixture.store[fixture.result.name] = previous
        assert controller.status()["error"] is None
        # Mutation of a returned response must not mutate the consumed marker.
        completed["latest_step_result"]["ml_confidence"] = 0.0
        assert controller.status()["error"] is None
        fixture.deliver()
        assert controller.status()["current_step"] == 2
        before = deepcopy(fixture.records)
        for _ in range(10): assert controller.status()["current_step"] == 2
        assert fixture.records == before and fixture.completions.call_count == 2
        assert session["env"] is environment and environment.step_calls == 0
        assert session["model"].inputs == [[0, 0, 0.0], [1, 1, 0.92]]
        restarted = controller.start()
        fresh = controller._sessions[fixture.run["run_id"]]
        assert restarted["current_step"] == 0 and fresh["env"] is not environment
        assert fresh["observation"] == [0, 0, 0.0] and fresh["env"]._history == []
        assert fresh["env"]._last_action is None and fresh.get("reward", 0.0) == 0.0
        assert "last_completed_result" not in fresh and len(fixture.models) == 1
    print("Accepted-result handoff: retained result waits; unexpected identities reject; duplicates/fresh environment: PASS")


def _integrated_bounded_worker_regression():
    for outcomes, expected in (([True, True, True], 3), ([False, True, True], 1),
                               ([True, False, True], 2), ([True, True, False], 3)):
        with MemoryCampaign(outcomes, automatic=True) as fixture:
            controller = fixture.controller
            controller.start()
            controller.run_full(max_steps=3)
            fixture.threads[0].join(timeout=3)
            assert not fixture.threads[0].is_alive() and not controller._full_runs
            status = controller.status()
            assert status["error"] is None, status["error"]
            assert status["state"] == "COMPLETED" and status["current_step"] == expected
            assert len(fixture.dispatches) == fixture.completions.call_count == expected
            assert status["latest_step_result"]["success"] is outcomes[expected - 1]
            assert not fixture.pending.exists()
            assert len({request["correlation_id"] for request in fixture.dispatches}) == expected
            session = controller._sessions[fixture.run["run_id"]]
            environment, model = session["env"], session["model"]
            assert len(fixture.environments) == len(fixture.models) == 1
            assert session["current_step"] == environment._step_count == expected
            assert model.inputs == [[0, 0, 0.0]] + [[step, step, 0.92] for step in range(1, expected)]
            assert environment._history == [int(value) for value in outcomes[:expected]]
            assert environment.step_calls == 0
            expected_reward = -2.5 * expected if outcomes[expected - 1] else -2.5 * (expected - 1) - 2.6
            assert session["reward"] == expected_reward
            assert fixture.retained_polls == 2 * (expected - 1)
            assert fixture.progression == [("READY", 0)] + [state for step in range(expected) for state in (("REQUESTED", step), ("COMPLETED", step + 1))]
            assert fixture.records["network"] == []
            pairs = [(record["correlation_id"], record["event_type"]) for record in fixture.records["security"]]
            assert len(pairs) == len(set(pairs))
            assert len(pairs) == 3 * expected - (0 if outcomes[expected - 1] else 1)
            for record in fixture.records["security"]:
                assert record["run_id"] == fixture.run["run_id"] and record["scenario_id"] == fixture.run["scenario_id"]
                assert record["campaign_id"] == fixture.run["run_id"] and record["generation_id"] == fixture.runtime["generation_id"]
            if not outcomes[expected - 1]:
                failure = status["latest_step_result"]
                assert failure["status"] == "FAILED" and failure["detected"] is False and failure["evaded"] is False
                assert failure["ml_detected"] is True and failure["alert_count"] > 0
                assert not any(record["event_type"] == "detection" and record["correlation_id"] == failure["correlation_id"] for record in fixture.records["security"])
            before = deepcopy(fixture.records)
            for _ in range(10): assert controller.status()["current_step"] == expected
            assert fixture.records == before and len(fixture.dispatches) == fixture.completions.call_count == expected
        print(f"Integrated bounded worker: outcomes={outcomes}, dispatches={expected}, completed={expected}, no extra dispatch: PASS")


def _restart_state(fixture):
    controller = fixture.controller
    session = controller._sessions[fixture.run["run_id"]]
    return deepcopy({"current_step": session["current_step"], "observation": session["observation"],
        "history": session["env"]._history, "reward": session.get("reward", 0.0),
        "consumed_result": session.get("last_completed_result"), "pending_action": session.get("pending_action"),
        "run": fixture.run, "handoff": fixture.store, "events": fixture.records,
        "timings": controller._initialization_timings, "registered": sorted(controller._full_runs)})


class StopMemoryWorker(RuntimeError):
    """Stop a paused test worker through its normal finally on test failure."""


def _active_worker_restart_regression():
    with MemoryCampaign([True, True, True], automatic=True) as fixture:
        controller = fixture.controller
        controller.start()
        original_next = controller.next_step
        dispatched, resume, cancel = threading.Event(), threading.Event(), threading.Event()
        worker_errors = []

        def paused_next():
            request = original_next()
            if len(fixture.dispatches) == 1:
                dispatched.set()
                assert resume.wait(timeout=4)
                if cancel.is_set(): raise StopMemoryWorker("focused restart regression failed")
            return request

        controller.next_step = paused_next
        with patch("threading.excepthook", side_effect=lambda args: worker_errors.append(args.exc_value)):
            controller.run_full(max_steps=3)
            try:
                assert dispatched.wait(timeout=4)
                fixture.deliver()
                assert controller.status()["current_step"] == 1
                session = controller._sessions[fixture.run["run_id"]]
                environment, model = session["env"], session["model"]
                before = _restart_state(fixture)
                assert fixture.run["run_id"] in controller._full_runs
                assert session["last_completed_result"] == fixture.store[fixture.result.name]
                try: controller.start()
                except campaign.CampaignError as exc: assert exc.code == "campaign_already_running"
                else: raise AssertionError("Registered bounded worker was restarted after step 1")
                assert controller._sessions[fixture.run["run_id"]] is session
                assert session["env"] is environment and session["model"] is model
                assert _restart_state(fixture) == before
                assert len(fixture.environments) == len(fixture.models) == 1
                resume.set()
                fixture.threads[0].join(timeout=4)
                assert not fixture.threads[0].is_alive() and not controller._full_runs
                assert controller.status()["current_step"] == 3 and len(fixture.dispatches) == 3
                assert environment.step_calls == 0 and fixture.completions.call_count == 3
                restarted = controller.start()
                fresh = controller._sessions[fixture.run["run_id"]]
                assert restarted["state"] == "READY" and restarted["current_step"] == 0
                assert fresh["env"] is not environment and fresh["model"] is model
                assert fresh["observation"] == [0, 0, 0.0] and fresh["env"]._history == []
                assert fresh.get("reward", 0.0) == 0.0 and fresh["env"]._last_action is None
                assert "last_completed_result" not in fresh and len(fixture.models) == 1
            finally:
                if not resume.is_set(): cancel.set()
                resume.set()
                fixture.threads[0].join(timeout=4)
            assert not fixture.threads[0].is_alive() and not worker_errors and not controller._full_runs
    print("Active worker restart: COMPLETED(1) rejects without state replacement; normal cleanup permits fresh restart: PASS")


def _restart_registration_race_regression():
    # Registration wins: a restart waits for the actual state lock, then sees
    # the registration before the worker has dispatched its first request.
    with MemoryCampaign([False], automatic=True) as fixture:
        controller = fixture.controller
        controller.start()
        session = controller._sessions[fixture.run["run_id"]]
        core_entered, permit_registration = threading.Event(), threading.Event()
        restart_attempted, worker_paused, permit_worker = threading.Event(), threading.Event(), threading.Event()
        original_core, original_next = controller._core_and_watcher, controller.next_step
        errors, restart_errors = [], []

        def gated_core(runtime, *, require_idle):
            result = original_core(runtime, require_idle=require_idle)
            if threading.current_thread().name == "register-client":
                core_entered.set()
                assert permit_registration.wait(timeout=4)
            return result

        def paused_next():
            worker_paused.set()
            assert permit_worker.wait(timeout=4)
            return original_next()

        def register_client():
            try: controller.run_full(max_steps=3)
            except BaseException as exc: errors.append(exc)

        def restart_client():
            restart_attempted.set()
            try: controller.start()
            except campaign.CampaignError as exc: restart_errors.append(exc.code)
            except BaseException as exc: errors.append(exc)

        controller._core_and_watcher, controller.next_step = gated_core, paused_next
        register = fixture.real_thread(target=register_client, name="register-client")
        restart = fixture.real_thread(target=restart_client)
        register.start()
        try:
            assert core_entered.wait(timeout=4)
            restart.start()
            assert restart_attempted.wait(timeout=4)
            acquired = controller._state_lock.acquire(blocking=False)
            if acquired: controller._state_lock.release()
            assert not acquired  # The real registration path owns the lock.
            permit_registration.set()
            register.join(timeout=4); restart.join(timeout=4)
            assert not register.is_alive() and not restart.is_alive() and not errors
            assert worker_paused.wait(timeout=4)
            assert restart_errors == ["campaign_already_running"]
            assert controller._sessions[fixture.run["run_id"]] is session
            assert fixture.run["run_id"] in controller._full_runs
            assert len(fixture.environments) == 1 and session["current_step"] == 0
        finally:
            permit_registration.set(); permit_worker.set()
            register.join(timeout=4)
            if restart.ident is not None: restart.join(timeout=4)
            for thread in fixture.threads: thread.join(timeout=4)
        assert not controller._full_runs and len(fixture.dispatches) == 1
        assert controller.status()["latest_step_result"]["success"] is False

    # Start wins: model/environment construction retains the state lock, so
    # registration cannot slip between the restart guard and publication.
    with MemoryCampaign([False], automatic=True) as fixture:
        controller = fixture.controller
        controller.start()
        original_create, original_update = controller._create_environment, fixture.update_run
        constructing, permit_start, registration_attempted = threading.Event(), threading.Event(), threading.Event()
        errors, responses, ready_registrations = [], [], []

        def held_create(topology):
            constructing.set()
            assert permit_start.wait(timeout=4)
            return original_create(topology)

        def checked_update(scenario_id, run_id, **changes):
            if changes.get("campaign_request", {}).get("state") == "READY":
                ready_registrations.append(run_id in controller._full_runs)
            return original_update(scenario_id, run_id, **changes)

        def start_client():
            try: responses.append(controller.start())
            except BaseException as exc: errors.append(exc)

        def register_client():
            registration_attempted.set()
            try: controller.run_full(max_steps=3)
            except BaseException as exc: errors.append(exc)

        controller._create_environment = held_create
        starter = fixture.real_thread(target=start_client)
        register = fixture.real_thread(target=register_client)
        with patch("testbed.run_store.update_run", side_effect=checked_update):
            starter.start()
            try:
                assert constructing.wait(timeout=4)
                register.start()
                assert registration_attempted.wait(timeout=4)
                acquired = controller._state_lock.acquire(blocking=False)
                if acquired: controller._state_lock.release()
                assert not acquired and not controller._full_runs
            finally:
                permit_start.set()
                starter.join(timeout=4)
                if register.ident is not None: register.join(timeout=4)
                for thread in fixture.threads: thread.join(timeout=4)
        assert not starter.is_alive() and not register.is_alive() and not errors
        assert responses[0]["state"] == "READY" and ready_registrations == [False]
        assert not controller._full_runs and len(fixture.dispatches) == 1
        assert len(fixture.environments) == 2 and len(fixture.models) == 1
    print("Restart/registration races: registration wins -> reject; start wins -> publish before registration: PASS")


def _unrelated_worker_restart_regression():
    with MemoryCampaign([True]) as fixture:
        controller = fixture.controller
        controller.start()
        old_environment = controller._sessions[fixture.run["run_id"]]["env"]
        controller._full_runs.add("run-unrelated")
        restarted = controller.start()
        assert restarted["state"] == "READY" and restarted["current_step"] == 0
        assert controller._full_runs == {"run-unrelated"}
        assert controller._sessions[fixture.run["run_id"]]["env"] is not old_environment
        assert len(fixture.models) == 1
    print("Restart guard uses the current run ID; unrelated registration does not block: PASS")


def main() -> None:
    original = campaign.DATA, campaign.PENDING_STEP, campaign.STEP_RESULT, campaign.HEARTBEAT, run_store.RUNS
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); campaign.DATA = root / "data"; campaign.PENDING_STEP = campaign.DATA / "pending_step.json"; campaign.STEP_RESULT = campaign.DATA / "step_result.json"; campaign.HEARTBEAT = campaign.DATA / "watcher_heartbeat.json"; run_store.RUNS = campaign.DATA / "runs"
            generation = "a" * 32
            (campaign.DATA / "core-runtime").mkdir(parents=True)
            (campaign.DATA / "core-runtime" / "session.json").write_text(json.dumps({"id": 3, "generation_id": generation}), encoding="utf-8")
            heartbeat = {"status": "IDLE", "session_id": "3", "generation_id": generation, "timestamp": time.time(), "steps_executed": 0}
            campaign.HEARTBEAT.write_text(json.dumps(heartbeat), encoding="utf-8")
            controller = campaign.CampaignController(request=lambda action, **_: {"state": "RUNTIME", "session_id": 3, "watcher": "IDLE"} if action == "status" else {"session_id": 3}, topology=lambda: FakeTopology(), model_path=root / "unused.zip")
            try: controller.start()
            except campaign.CampaignError as exc: assert exc.code == "no_active_run"
            else: raise AssertionError("campaign start must require an owned run")
            run = run_store.create_run(FakeTopology().canonical_snapshot(), scenario_id="scenario-guicampaign")
            run_store.update_run(run["scenario_id"], run["run_id"], core_session_id=3, generation_id=generation, lifecycle_status="RUNNING")
            class PredictModel:
                def __init__(self): self.inputs = []
                def predict(self, observation, **_):
                    self.inputs.append(list(observation))
                    return [0, 3, 0, 0], None
            model = PredictModel()
            controller._new_session = lambda active: {"env": FakeEnvironment(), "model": model,
                "observation": [0], "current_step": 0, "topology_revision": "test"}
            # Exercise the real selection method without importing PPO/grid dependencies.
            modules = {"strategic.rl_env": SimpleNamespace(MITRE_TECHNIQUES=[{"id": "T0836", "stage": 2}],
                REGISTER_BASES={"T0836": 40000}, VALUE_MAGNITUDES=[1.0]),
                "scripts.testbed_executor": SimpleNamespace(TECHNIQUE_TO_STEP_NAME={"T0836": "fdi_attack"})}
            select = controller._select_step
            def select_step(session):
                with patch.dict("sys.modules", modules): return select(session)
            controller._select_step = select_step
            started = controller.start(); assert started["state"] == "READY" and campaign.PENDING_STEP.exists() is False
            request = controller.next_step(); assert request["state"] == "REQUESTED" and campaign.PENDING_STEP.exists()
            assert request["current_step"] == controller.status()["current_step"] == 0
            session = controller._sessions[run["run_id"]]; env = session["env"]
            assert "_action" not in request and model.inputs == [[0]]
            for key in ("scenario_id", "run_id", "campaign_id", "correlation_id", "generation_id", "technique_id", "step_name", "target_ip", "target_node", "register_address", "value_magnitude"):
                assert request.get(key) is not None
            try: controller.next_step()
            except campaign.CampaignError as exc: assert exc.code == "pending_step_exists"
            else: raise AssertionError("a second pending request must be rejected")
            for field in ("generation_id", "campaign_id", "correlation_id"):
                stale = {key: request[key] for key in ("generation_id", "campaign_id", "correlation_id")}
                stale[field] = "stale"
                campaign.STEP_RESULT.write_text(json.dumps(stale), encoding="utf-8")
                assert controller.status()["error"]["code"] == "stale_result"
                assert session["current_step"] == 0 and session["observation"] == [0]
                assert env._history == [] and env.observation_calls == 0 and env.reward_calls == []
            campaign.PENDING_STEP.unlink()
            result = {"generation_id": generation, "campaign_id": request["campaign_id"], "correlation_id": request["correlation_id"], "detected": True, "evaded": False, "status": "SUCCESS", "detection_method": "hybrid", "ml_confidence": 0.92, "end_time": "2026-01-01T00:00:00+00:00"}
            campaign.STEP_RESULT.write_text(json.dumps(result), encoding="utf-8")
            status = controller.status(); assert status["state"] == "COMPLETED" and status["latest_step_result"]["correlation_id"] == request["correlation_id"]
            assert session["env"] is env and session["current_step"] == env._step_count == 1
            assert env._history == [1] and env._chain == ["T0836"] and env._last_action == [0, 3, 0, 0]
            assert env._last_register == 3 and env._last_value_mag == 1.0 and env._current_target_bus == 0
            assert env._last_confidence == 0.92 and not env._compromised_buses
            assert session["observation"] == [1, 1, 0.92] and session["reward"] == -2.5
            assert env.reward_calls == [{"status": "SUCCESS", "detected": True,
                "detection_conf": 0.92, "tech_stage": 2, "target_bus": 0}]
            assert controller.status()["current_step"] == 1 and env.observation_calls == 1
            controller._complete(run, request, result)
            assert session["current_step"] == 1 and env.observation_calls == 1 and len(env.reward_calls) == 1
            security = run_store.read_events(run["scenario_id"], run["run_id"], "security")
            assert {event["event_type"] for event in security} == {"attack_finished", "detection"}
            assert run_store.read_events(run["scenario_id"], run["run_id"], "network") == []
            second = controller.next_step()
            assert second["current_step"] == controller.status()["current_step"] == 1
            assert session["current_step"] == 1
            assert model.inputs == [[0], [1, 1, 0.92]] and session["env"] is env
            assert second["correlation_id"] != request["correlation_id"]
            for key in ("run_id", "generation_id", "campaign_id"):
                assert second[key] == request[key]
            assert controller.status()["error"] is None  # previously accepted result is still present
            assert session["current_step"] == 1 and session["observation"] == [1, 1, 0.92]
            campaign.PENDING_STEP.unlink()
            result2 = {**result, "correlation_id": second["correlation_id"], "detected": False,
                "evaded": True, "status": "UNDETECTED", "ml_confidence": 0.0}
            campaign.STEP_RESULT.write_text(json.dumps(result2), encoding="utf-8")
            assert controller.status()["current_step"] == 2
            assert session["observation"] == [2, 2, 0.0] and env._history == [1, 0]
            assert env._compromised_buses == {0} and session["reward"] == -1.5
            assert controller.status()["current_step"] == 2 and len(env.reward_calls) == 2
            security = run_store.read_events(run["scenario_id"], run["run_id"], "security")
            assert len(security) == 3  # two finishes, one detection; polling adds nothing
            third = controller.next_step()
            assert third["state"] == "REQUESTED" and third["current_step"] == 2
            assert session["current_step"] == env._step_count == 2
            pending = json.loads(campaign.PENDING_STEP.read_text(encoding="utf-8"))
            persisted = run_store.recover_active_run({"id": 3, "generation_id": generation})
            assert pending["current_step"] == persisted["campaign_request"]["current_step"] == 2
            assert controller.status()["current_step"] == 2
            assert model.inputs[-1] == [2, 2, 0.0]
            campaign.PENDING_STEP.unlink()
            result3 = {**result, "correlation_id": third["correlation_id"]}
            campaign.STEP_RESULT.write_text(json.dumps(result3), encoding="utf-8")
            assert controller.status()["current_step"] == 3
            assert session["current_step"] == env._step_count == 3
            assert controller.status()["current_step"] == 3
            assert len(run_store.read_events(run["scenario_id"], run["run_id"], "security")) == 5
            print("Completed counter: 0 -> 1 -> REQUESTED(1) -> 2 -> REQUESTED(2) -> 3: PASS")
            restarted = controller.start()
            new_session = controller._sessions[run["run_id"]]
            assert restarted["current_step"] == 0 and new_session["env"] is not env
            assert new_session["observation"] == [0] and new_session["env"]._history == []
            campaign.HEARTBEAT.write_text(json.dumps({**heartbeat, "generation_id": "wrong"}), encoding="utf-8")
            try: controller.next_step()
            except campaign.CampaignError as exc: assert exc.code == "watcher_unavailable"
            else: raise AssertionError("generation-mismatched watcher must be rejected")
    finally:
        campaign.DATA, campaign.PENDING_STEP, campaign.STEP_RESULT, campaign.HEARTBEAT, run_store.RUNS = original
    _cache_regression()
    _bounded_worker_regression()
    _accepted_result_handoff_regression()
    _integrated_bounded_worker_regression()
    _active_worker_restart_regression()
    _restart_registration_race_regression()
    _unrelated_worker_restart_regression()
    print("GUI Phase 3B campaign regression: PASS")


if __name__ == "__main__": main()
