"""Persist real episode inputs for the existing aggregate DVS formula."""
from statistics import mean
from math import isfinite
from metrics.dvs_score import PlateauTracker


def aggregate_episodes(episodes):
    required = {"evasion_rate", "completed", "max_stage", "reward"}
    if not episodes:
        return None, "Missing saved attack episode statistics."
    if not isinstance(episodes, list) or any(not isinstance(ep, dict) or not required <= ep.keys() for ep in episodes):
        return None, "Missing episode inputs: evasion_rate, completed, max_stage, reward."
    for ep in episodes:
        for key in ("evasion_rate", "max_stage", "reward"):
            value = ep[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
                return None, f"Invalid episode input: {key}."
        if (type(ep["completed"]) is not bool or not 0 <= ep["evasion_rate"] <= 1
                or type(ep["max_stage"]) is not int or not 0 <= ep["max_stage"] <= 3):
            return None, "Invalid episode completion, evasion rate or stage depth."
        if "completed_stages" in ep:
            stages = ep["completed_stages"]
            if (not isinstance(stages, list) or any(type(s) is not int or not 0 <= s <= 3 for s in stages)
                    or len(set(stages)) != len(stages)
                    or sorted(stages) != list(range(len(stages)))
                    or ep["completed"] != (set(stages) == set(range(4)))
                    or ep["max_stage"] != max(stages, default=0)):
                return None, "Episode metrics disagree with recorded stage progression."
        if ep.get("end_reason") in {"execution_stop", "step_limit", "timeout", "step_timeout"} and ep["completed"]:
            return None, "Interrupted episode incorrectly marked complete."
        if "unavailable_detections" in ep and (type(ep["unavailable_detections"]) is not int or ep["unavailable_detections"] < 0):
            return None, "Invalid unavailable detection count."
    if any(ep.get("unavailable_detections", 0) for ep in episodes):
        return None, "Detection was not evaluated for one or more episode attacks."
    tracker = PlateauTracker(patience=5)
    for ep in episodes:
        tracker.update(ep["evasion_rate"])
    count = sum(ep["completed"] is True for ep in episodes)
    return {"num_episodes": len(episodes), "completion_count": count,
            "completion_rate": count / len(episodes),
            "avg_evasion_rate": mean(ep["evasion_rate"] for ep in episodes),
            "avg_max_stage": mean(ep["max_stage"] for ep in episodes),
            "avg_reward": mean(ep["reward"] for ep in episodes),
            "plateau_detected": tracker.stagnant_count >= tracker.patience}, None


def persist_episode(run, session, reason):
    from testbed import run_store
    from defense.detection_result import detection_result
    steps = session.get("evaluation_steps", [])
    if not steps or session.get("evaluation_saved"):
        return
    evaluated = [detection_result(s) for s in steps]
    # Failed execution earns no evasion or stage-progress credit.
    evaded = [s for s, d in zip(steps, evaluated) if d is False and s.get("success") is True]
    # Stage credit is sequential progression, not an attempted stage or UI status.
    stages = getattr(session["env"], "_completed_stages", None)
    episode = {"episode_id": session["episode_id"], "end_reason": reason,
               "total_attacks": len(steps), "detected_attacks": sum(d is True for d in evaluated),
               "missed_attacks": sum(d is False for d in evaluated),
               "unavailable_detections": sum(d is None for d in evaluated),
               "detection_rate": sum(d is True for d in evaluated) / sum(d is not None for d in evaluated) if any(d is not None for d in evaluated) else None,
               "evasion_rate": len(evaded) / len(steps),
               "completed": set(stages) == set(range(4)) if stages is not None else None,
               "completed_stages": sorted(stages) if stages is not None else None,
               "max_stage": max(stages, default=0) if stages is not None else None,
               "reward": session.get("reward")}
    current = run_store.update_run(run["scenario_id"], run["run_id"])
    episodes = [ep for ep in current.get("attack_episodes", []) if ep["episode_id"] != episode["episode_id"]] + [episode]
    stats, error = aggregate_episodes(episodes)
    run_store.update_run(run["scenario_id"], run["run_id"], attack_episodes=episodes,
                         dvs_evaluation=stats, dvs_unavailable_reason=error)
    session["evaluation_saved"] = True
