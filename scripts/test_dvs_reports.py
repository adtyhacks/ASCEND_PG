"""Pure DVS/report regressions: no services, evaluation episodes or attacks."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from metrics.dvs_score import compute_dvs
from reports.pentest_report import generate_report, render_html, render_pdf
from testbed.run_store import report_events


def evaluation(**overrides):
    return {"avg_evasion_rate": .2, "completion_rate": .5, "avg_max_stage": 1.5,
            "plateau_detected": False, "completion_count": 2, "num_episodes": 4,
            "avg_reward": 1, **overrides}


def events(status="DETECTED", severity="HIGH", detected=True):
    attack = dict(event_type="attack_finished", timestamp="2026-01-01T00:00:00Z",
                  scenario_id="s", run_id="r", generation_id="g", correlation_id="c",
                  mitre_technique="T0836", attack_stage=2, target_node="plc1",
                  severity="INFO", result="detected" if detected else "failed",
                  evidence=dict(step_name="fdi_attack", return_status=status))
    result = [attack]
    if detected:
        result.append({**attack, "event_type": "detection", "severity": severity})
    return result


class DvsReports(unittest.TestCase):
    def test_canonical_formula(self):
        stats = evaluation()
        original = copy.deepcopy(stats)
        score = compute_dvs(stats)
        self.assertEqual(score["score"], 41.0)
        self.assertEqual(score, compute_dvs(stats))
        self.assertEqual(stats, original)
        self.assertEqual(sum(c["weighted"] for c in score["breakdown"].values()), 41.0)

    def test_variable_bounded_evaluation(self):
        for evasion in (0, .5, 1):
            for completion in (0, .5, 1):
                for depth in (0, 1.5, 3):
                    for plateau in (False, True):
                        stats = evaluation(avg_evasion_rate=evasion,
                            completion_rate=completion, completion_count=int(4*completion),
                            avg_max_stage=depth, plateau_detected=plateau)
                        self.assertTrue(0 <= compute_dvs(stats)["score"] <= 100)
        self.assertLess(compute_dvs(evaluation())["score"],
                        compute_dvs(evaluation(avg_evasion_rate=.8))["score"])

    def test_missing_inputs_never_inferred_from_detection_severity_or_impact(self):
        for detected in (False, True):
            for severity in ("LOW", "HIGH"):
                source = events(detected=detected, severity=severity)
                original = copy.deepcopy(source)
                report = generate_report(report_events(source))
                self.assertIsNone(report["dvs"]["score"])
                finding = report["findings"][0]
                self.assertIsNone(finding["finding_dvs"])
                self.assertIsNone(finding["verified_impact"])
                self.assertEqual(finding["id"], "ASCEND-PG-001")
                self.assertEqual(finding["detected"], detected)
                self.assertEqual(source, original)

    def test_failed_and_timeout_get_no_impact_credit(self):
        for status in ("FAILED", "TIMEOUT"):
            report = generate_report(report_events(events(status=status, detected=False)))
            finding = report["findings"][0]
            self.assertEqual(finding["execution_result"], status)
            self.assertIsNone(finding["verified_impact"])
            self.assertIsNone(report["dvs"]["score"])

    def test_report_reuses_saved_evaluation_without_running_it(self):
        stats = evaluation()
        report = generate_report(report_events(events()),
            {"run_metadata": {"dvs_evaluation": stats}})
        self.assertEqual(report["dvs"]["score"], compute_dvs(stats)["score"])
        html = render_html(report)
        self.assertIn("41.0 / 100", html)
        self.assertIn("stage_depth", html)
        self.assertNotIn("CVSS", html)
        self.assertNotIn("cvss", report["findings"][0])
        self.assertTrue(bytes(render_pdf(report)).startswith(b"%PDF-"))

    def test_invalid_or_partial_evaluation_is_unavailable(self):
        for stats in ({}, evaluation(avg_evasion_rate=float("nan")),
                      evaluation(plateau_detected="false"), evaluation(num_episodes=0),
                      evaluation(completion_rate=.8), evaluation(avg_max_stage=4)):
            report = generate_report([], {"run_metadata": {"dvs_evaluation": stats}})
            self.assertIsNone(report["dvs"]["score"])

    def test_scoring_import_does_not_load_ppo(self):
        self.assertNotIn("stable_baselines3", sys.modules)
        self.assertNotIn("strategic.rl_env", sys.modules)

    def test_severity_and_potential_impact_do_not_change_canonical_dvs(self):
        """Canonical DVS is aggregate; a separate severity/impact model is not invented."""
        stats = {"run_metadata": {"dvs_evaluation": evaluation()}}
        for severity in ("LOW", "HIGH"):
            lifecycle = events(severity=severity)
            lifecycle.insert(0, {**lifecycle[0], "event_type": "attack_started", "severity": severity})
            source = report_events(lifecycle)
            report = generate_report(source, stats)
            self.assertEqual(report["dvs"]["score"], 41.0)
            self.assertEqual(report["findings"][0]["severity"], severity.title())
            self.assertIsNone(report["findings"][0]["verified_impact"])

    def test_current_run_report_in_memory_keeps_evidence_unchanged(self):
        import hashlib
        import json
        root = Path(__file__).resolve().parents[1] / "data/runs/scenario-ed3f39225959/run-101cb55c2063"
        if not root.is_dir():
            self.skipTest("Completed run evidence not present")
        paths = [root / name for name in ("run.json", "security_events.jsonl", "network_events.jsonl", "report.html")]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.exists()}
        source = [json.loads(line) for line in (root / "security_events.jsonl").read_text().splitlines() if line]
        report = generate_report(report_events(source), {"run_metadata": json.loads((root / "run.json").read_text())})
        self.assertIsNone(report["dvs"]["score"])
        self.assertEqual(len(report["findings"]), sum(e["event_type"] == "attack_finished" for e in source))
        self.assertNotIn("<strong>CVSS:", render_html(report))
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})


if __name__ == "__main__":
    unittest.main()
