"""Offline regressions: no runtime, network, model evaluation or evidence writes."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from metrics.campaign_evaluation import aggregate_episodes, persist_episode
from metrics.dvs_score import compute_dvs
from reports.pentest_report import generate_report, render_html


def episode(**changes):
    return dict(completed=True, completed_stages=[0, 1, 2, 3],
                max_stage=3, evasion_rate=1., reward=12.,
                end_reason="campaign_complete", **changes)


class CampaignEvaluation(unittest.TestCase):
    def test_two_completed_campaigns(self):
        stats, error = aggregate_episodes([episode(), episode()])
        self.assertIsNone(error)
        self.assertEqual(stats["completion_count"], 2)
        self.assertEqual(stats["completion_rate"], 1)
        self.assertIn("2/2", compute_dvs(stats)["breakdown"]["campaign"]["detail"])

    def test_incomplete_timeout_and_detected_episodes(self):
        for reason in ("execution_stop", "step_limit", "timeout"):
            ep = episode()
            ep.update(completed=False, completed_stages=[], max_stage=0,
                      evasion_rate=0., end_reason=reason)
            stats, error = aggregate_episodes([ep, ep])
            self.assertIsNone(error)
            self.assertEqual(stats["completion_count"], 0)
            result = compute_dvs(stats)
            self.assertEqual(result["breakdown"]["evasion"]["score"], 0)
            self.assertEqual(result["score"], 7.5)

    def test_persistence_uses_actual_sequential_progression(self):
        # An undetected attempt at stage 3 does not establish stage 3 progression.
        session = dict(episode_id="a", env=SimpleNamespace(_completed_stages={0, 1}),
                       reward=4., evaluation_steps=[dict(success=True, detected=False,
                       detection_evaluated=True, attack_stage=3)])
        with patch("testbed.run_store.update_run", return_value={}) as update:
            persist_episode(dict(scenario_id="s", run_id="r"), session, "episode_reset")
        saved = update.call_args.kwargs
        self.assertEqual(saved["attack_episodes"][0]["completed_stages"], [0, 1])
        self.assertEqual(saved["dvs_evaluation"]["avg_max_stage"], 1)
        self.assertEqual(saved["dvs_evaluation"]["completion_count"], 0)

    def test_stage_depth_averages_recorded_progression(self):
        partial = episode()
        partial.update(completed=False, completed_stages=[0, 1], max_stage=1,
                       end_reason="episode_reset")
        stats, error = aggregate_episodes([partial, episode()])
        self.assertIsNone(error)
        self.assertEqual(stats["avg_max_stage"], 2)
        self.assertEqual(compute_dvs(stats)["breakdown"]["stage_depth"]["score"], 66.7)

    def test_missing_runtime_progress_or_reward_is_not_zero_filled(self):
        session = dict(episode_id="a", env=SimpleNamespace(),
                       evaluation_steps=[dict(success=True, detected=True, attack_stage=0)])
        with patch("testbed.run_store.update_run", return_value={}) as update:
            persist_episode(dict(scenario_id="s", run_id="r"), session, "episode_reset")
        self.assertIsNone(update.call_args.kwargs["dvs_evaluation"])
        self.assertTrue(update.call_args.kwargs["dvs_unavailable_reason"])

    def test_missing_invalid_evidence_is_unavailable(self):
        invalid = [None, [], [{}]]
        for field, value in (("reward", None), ("evasion_rate", float("nan")),
                             ("completed", "true"), ("max_stage", 4),
                             ("completed_stages", [0, 3]), ("unavailable_detections", 1)):
            ep = episode()
            ep[field] = value
            invalid.append([ep])
        for records in invalid:
            with self.subTest(records=records):
                report = generate_report([], {"run_metadata": {"attack_episodes": records}})
                self.assertIsNone(report["dvs"]["score"])
                self.assertTrue(report["dvs"]["reason"])
                self.assertIn("Unavailable", render_html(report))

    def test_interrupted_episode_cannot_be_completed(self):
        ep = episode()
        ep["end_reason"] = "timeout"
        self.assertIsNone(aggregate_episodes([ep])[0])

    def test_report_recomputes_stale_cache_and_keeps_all_values_consistent(self):
        records = [episode(), episode()]
        stats, _ = aggregate_episodes(records)
        metadata = dict(attack_episodes=records, dvs_evaluation={"completion_count": 0})
        original = copy.deepcopy(metadata)
        dvs = generate_report([], {"run_metadata": metadata})["dvs"]
        canonical = compute_dvs(stats)
        self.assertEqual(dvs["breakdown"], canonical["breakdown"])
        self.assertEqual(dvs["eval_summary"], canonical["eval_summary"])
        self.assertEqual(dvs["score"], sum(c["weighted"] for c in dvs["breakdown"].values()))
        for c in dvs["breakdown"].values():
            self.assertAlmostEqual(c["weighted"], c["weight"] * c["score"])
        self.assertEqual(metadata, original)
        metadata["dvs_unavailable_reason"] = "Pending result was interrupted."
        self.assertIsNone(generate_report([], {"run_metadata": metadata})["dvs"]["score"])

    def test_actual_saved_assessment_read_only(self):
        root = Path(__file__).resolve().parents[1] / "data/runs/scenario-ab12fa90ada5/run-cd38b43b9a38"
        if not root.exists():
            self.skipTest("Local assessment evidence absent")
        paths = [root / "run.json", root / "security_events.jsonl", root / "report.html"]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.exists()}
        metadata = json.loads((root / "run.json").read_text())
        attacks = [json.loads(line) for line in (root / "security_events.jsonl").read_text().splitlines()]
        attacks = [e for e in attacks if e["event_type"] == "attack_finished"]
        self.assertEqual(len(attacks), 6)
        self.assertTrue(all(e["evidence"]["detected"] is True for e in attacks))
        self.assertEqual(sum(e["evidence"]["return_status"] == "TIMEOUT" for e in attacks), 2)
        dvs = generate_report([], {"run_metadata": metadata})["dvs"]
        self.assertEqual(dvs["score"], 7.5)
        self.assertEqual(dvs["breakdown"]["campaign"]["detail"], "Campaign completion: 0/2")
        self.assertEqual(dvs["eval_summary"]["avg_max_stage"], 0)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})


if __name__ == "__main__":
    unittest.main()
