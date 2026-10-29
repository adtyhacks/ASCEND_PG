"""Report explanation regressions; all inputs are offline and read-only."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from metrics.dvs_score import (compute_dvs, W_EVASION, W_CAMPAIGN,
                               W_STAGE_DEPTH, W_PLATEAU)
from reports.pentest_report import generate_report, render_html, render_pdf
from scripts.test_dvs_reports import evaluation
from testbed.run_store import report_events


def text(report):
    return "\n".join(report["dvs"]["explanation"]["paragraphs"])


def assessment(completed=False):
    ep = dict(episode_id="ep", completed=completed, max_stage=3 if completed else 0,
              completed_stages=list(range(4)) if completed else [], reward=1.,
              evasion_rate=1. if completed else 0., total_attacks=4 if completed else 2,
              detected_attacks=0 if completed else 2,
              end_reason="campaign_complete" if completed else "execution_stop")
    attack = dict(event_type="attack_finished", scenario_id="scenario-test", run_id="run-test",
                  correlation_id="correlation", timestamp="2026-10-08T00:00:00Z",
                  attack_stage=3 if completed else 0, mitre_technique="T0836",
                  evidence=dict(episode_id="ep", detected=not completed, success=completed,
                                return_status="UNDETECTED" if completed else "TIMEOUT"))
    return generate_report(report_events([attack]), {"run_metadata": dict(
        scenario_id="scenario-test", run_id="run-test", attack_episodes=[ep])})


class DvsExplanation(unittest.TestCase):
    def test_html_section_order_and_formula(self):
        report = assessment()
        html = render_html(report)
        title = "Understanding the Defense Vulnerability Score (DVS)"
        self.assertIn(title, html)
        self.assertLess(html.index("Contribution</th>"), html.index(title))
        self.assertLess(html.index(title), html.index("<h2>4. Findings</h2>"))
        weights = (W_EVASION, W_CAMPAIGN, W_STAGE_DEPTH, W_PLATEAU)
        formula = "DVS = " + " + ".join(f"{w:.2f} × {c}" for w, c in zip(weights, "ECSP"))
        self.assertIn(formula, text(report))
        for w in weights:
            self.assertIn(f"({w:.0%})", text(report))
        self.assertIn("2 percentage points", text(report))
        self.assertIn("5 consecutive episodes", text(report))

    def test_consistent_components_total_and_rating(self):
        report = assessment(True)
        dvs = report["dvs"]
        canonical = compute_dvs(dvs["evaluation_inputs"])
        self.assertEqual(dvs["breakdown"], canonical["breakdown"])
        self.assertEqual(dvs["score"], canonical["score"])
        self.assertEqual(dvs["score"], sum(c["weighted"] for c in dvs["breakdown"].values()))
        for c in dvs["breakdown"].values():
            self.assertAlmostEqual(c["score"] * c["weight"], c["weighted"])
            self.assertIn(c["detail"], render_html(report))
        self.assertIn(f"{dvs['score']:.1f}/100 ({dvs['rating']})", text(report))

    def test_distinct_assessments_and_step_completion(self):
        stopped, complete = assessment(), assessment(True)
        self.assertIn("2 of the 2 recorded attacks were detected", text(stopped))
        self.assertIn("1 of 1 episodes ended with a timed-out attack", text(stopped))
        self.assertIn("Campaign completion: 0/1", text(stopped))
        self.assertIn("Campaign completion: 1/1", text(complete))
        self.assertNotIn("ended with a timed-out attack", text(complete))
        self.assertNotIn("No evasion was recorded", text(complete))
        self.assertIn("Finishing an individual attack step does not automatically mean the campaign completed", text(stopped))

    def test_missing_metrics_and_missing_terminal_evidence(self):
        missing = generate_report([], {})
        self.assertIn("unavailable", text(missing))
        self.assertIn("not been treated as zero", text(missing))
        self.assertIn(missing["dvs"]["reason"], text(missing))
        for component in ("evasion", "campaign", "stage_depth", "plateau"):
            self.assertIn(f"<td>{component}</td><td>Unavailable</td>", render_html(missing))
        invalid = generate_report([], {"run_metadata": {"dvs_evaluation": evaluation(avg_evasion_rate=float("nan"))}})
        self.assertIsNone(invalid["dvs"]["score"])
        self.assertIn("invalid", text(invalid))
        report = assessment()
        no_records = generate_report([], report["campaign_info"])
        self.assertIn("Final attack outcome evidence is missing", text(no_records))
        self.assertNotIn("ended with a timed-out attack", text(no_records))

    def test_aggregate_only_and_small_nonzero_values(self):
        report = generate_report([], {"run_metadata": {"dvs_evaluation": evaluation(avg_evasion_rate=.0001, avg_max_stage=.0001)}})
        self.assertIn("Only aggregate evaluation metrics are available", text(report))
        self.assertNotIn("No evasion was recorded", text(report))
        self.assertNotIn("No sequential stage progression", text(report))

    def test_pdf_uses_same_explanation_and_remains_functional(self):
        from fpdf import FPDF
        report = assessment()
        written = []
        original_cell, original_multi = FPDF.cell, FPDF.multi_cell
        def cell(pdf, *args, **kwargs):
            written.append(args[2] if len(args) > 2 else kwargs.get("text", ""))
            return original_cell(pdf, *args, **kwargs)
        def multi(pdf, *args, **kwargs):
            written.append(args[2] if len(args) > 2 else kwargs.get("text", ""))
            return original_multi(pdf, *args, **kwargs)
        with patch.object(FPDF, "cell", cell), patch.object(FPDF, "multi_cell", multi):
            output = render_pdf(report)
        self.assertTrue(bytes(output).startswith(b"%PDF-"))
        self.assertIn(report["dvs"]["explanation"]["title"], written)
        for paragraph in report["dvs"]["explanation"]["paragraphs"]:
            self.assertIn(paragraph, written)

    def test_saved_7_5_assessment_without_evidence_changes(self):
        root = Path(__file__).resolve().parents[1] / "data/runs/scenario-ab12fa90ada5/run-cd38b43b9a38"
        if not root.exists():
            self.skipTest("Local saved evidence absent")
        paths = [p for p in root.iterdir() if p.is_file()]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        metadata = json.loads((root / "run.json").read_text())
        original = copy.deepcopy(metadata)
        events = [json.loads(line) for line in (root / "security_events.jsonl").read_text().splitlines()]
        report = generate_report(report_events(events), {"run_metadata": metadata})
        explanation = text(report)
        self.assertIn("6 of the 6 recorded attacks were detected", explanation)
        self.assertIn("2 of 2 episodes ended with a timed-out attack", explanation)
        self.assertIn("Campaign completion: 0/2", explanation)
        self.assertIn("No evasion was recorded", explanation)
        self.assertIn("No sequential stage progression", explanation)
        self.assertIn("contributes 7.5 points", explanation)
        self.assertIn("assigns a score of 50", explanation)
        self.assertIn("resulting DVS is 7.5/100", explanation)
        self.assertIn("not guaranteed security", explanation)
        self.assertEqual(metadata, original)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


if __name__ == "__main__":
    unittest.main()
