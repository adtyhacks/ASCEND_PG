"""Persist real episode inputs for the existing aggregate DVS formula."""
from statistics import mean
from metrics.dvs_score import PlateauTracker


def aggregate_episodes(episodes):
    required = {"evasion_rate", "completed", "max_stage", "reward"}
    if not episodes:
        return None, "Missing completed attack episode statistics."
    if any(not required <= ep.keys() for ep in episodes):
        return None, "Missing episode inputs: evasion_rate, completed, max_stage, reward."
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
    episode = {"episode_id": session["episode_id"], "end_reason": reason,
               "total_attacks": len(steps), "detected_attacks": sum(d is True for d in evaluated),
               "missed_attacks": sum(d is False for d in evaluated),
               "unavailable_detections": sum(d is None for d in evaluated),
               "detection_rate": sum(d is True for d in evaluated) / sum(d is not None for d in evaluated) if any(d is not None for d in evaluated) else None,
               "evasion_rate": len(evaded) / len(steps),
               "completed": len(getattr(session["env"], "_completed_stages", set())) == 4,
               "max_stage": max((s["attack_stage"] for s in evaded), default=0),
               "reward": session.get("reward", 0.0)}
    current = run_store.update_run(run["scenario_id"], run["run_id"])
    episodes = [ep for ep in current.get("attack_episodes", []) if ep["episode_id"] != episode["episode_id"]] + [episode]
    stats, error = aggregate_episodes(episodes)
    run_store.update_run(run["scenario_id"], run["run_id"], attack_episodes=episodes,
                         dvs_evaluation=stats, dvs_unavailable_reason=error)
    session["evaluation_saved"] = True
