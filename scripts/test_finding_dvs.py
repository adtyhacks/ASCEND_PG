"""Finding-level scoring and render tests; no telemetry producers are invoked."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from metrics.finding_dvs import compute_finding_dvs, SOURCES, IMPACT_POINTS
from reports.pentest_report import generate_report, render_html, render_pdf
from testbed.run_store import report_events
from scripts.finding_evidence_fixtures import fixture_bundle, IDENTITY

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:01:00+00:00"


def observation(dimension, **overrides):
    return {"verified": True, "adverse": True, "source": SOURCES[dimension],
            "correlation_id": "c", "evidence_ref": "fixture:independent-measurement",
            "before": 1, "after": 0, "observed_at": "2026-01-01T00:00:30+00:00",
            **overrides}


def score(severity="HIGH", status="SUCCESS", impact=None):
    return compute_finding_dvs(severity, status, impact, correlation_id="c",
                               start_time=START, end_time=END, evidence_identity=IDENTITY,
                               evidence_bundle=supported_bundle(impact))


def supported_bundle(impact):
    """Keep original formula scenarios; supply actual supporting fixture facts."""
    from math import isfinite
    from metrics.finding_evidence import stamp
    supported = []
    for dimension, claim in (impact or {}).items():
        try:
            valid = (claim.get("verified") is True and claim.get("adverse") is True
                and claim.get("source") == SOURCES[dimension] and claim.get("correlation_id") == "c"
                and claim.get("evidence_ref") and claim["before"] != claim["after"]
                and all(isfinite(v) for v in (claim["before"], claim["after"]))
                and stamp(START) <= stamp(claim["observed_at"]) <= stamp(END))
        except (TypeError, ValueError, KeyError, OverflowError):
            valid = False
        if valid:
            supported.append(dimension)
    return fixture_bundle(supported)


def finding_events(severity="HIGH", status="DETECTED", impact=None, detected=True):
    identity = dict(scenario_id="s", run_id="r", generation_id="g", correlation_id="c",
                    mitre_technique="T0836", attack_stage=2, target_node="plc1")
    start = {**identity, "event_type": "attack_started", "timestamp": START,
             "severity": severity, "result": "started",
             "evidence": {"value_magnitude": 1.1}}
    finish = {**identity, "event_type": "attack_finished", "timestamp": END,
              "severity": "INFO", "result": "detected" if detected else "failed",
              "evidence": {"return_status": status, "verified_impact": impact,
                           "finding_evidence": supported_bundle(impact),
                           "step_name": "fdi_attack"}}
    result = [start, finish]
    if detected:
        result.append({**identity, "event_type": "detection", "timestamp": END,
                       "severity": "HIGH", "evidence": {"ml_confidence": .999}})
    return result


class FindingDvs(unittest.TestCase):
    def test_severity_and_impact(self):
        low = score("LOW")["score"]
        high = score("HIGH", impact={"integrity": observation("integrity")})["score"]
        self.assertEqual(low, 5)
        self.assertEqual(high, 25)
        self.assertGreater(high, low)
        self.assertGreater(score("HIGH")["score"], low)

    def test_each_verified_dimension_increases_score(self):
        for dimension, points in IMPACT_POINTS.items():
            with self.subTest(dimension=dimension):
                assessed = score(impact={dimension: observation(dimension)})
                self.assertEqual(assessed["score"], 15 + points)
                self.assertEqual(assessed["breakdown"][dimension]["state"], "verified_adverse")
        self.assertGreater(IMPACT_POINTS["physical_impact"], IMPACT_POINTS["integrity"])
        self.assertGreater(IMPACT_POINTS["safety_impact"], IMPACT_POINTS["integrity"])

    def test_failed_retains_independently_verified_partial_effects(self):
        assessed = score(status="FAILED", impact={d: observation(d) for d in IMPACT_POINTS})
        self.assertEqual(assessed["score"], 95)
        self.assertIsNotNone(assessed["verified_impact"])

    def test_timeout_requires_effect_before_timeout(self):
        self.assertEqual(score(status="TIMEOUT")["score"], 15)
        self.assertEqual(score(status="TIMEOUT", impact={"availability": observation("availability")})["score"], 25)
        late = observation("availability", observed_at="2026-01-01T00:02:00+00:00")
        self.assertEqual(score(status="TIMEOUT", impact={"availability": late})["score"], 15)

    def test_invalid_observations_are_neutral(self):
        for overrides in ({"source": "network_flow"}, {"source": "ml_detector"},
                          {"verified": False}, {"adverse": False}, {"before": 0},
                          {"evidence_ref": ""}, {"correlation_id": "other"},
                          {"after": float("nan")}, {"after": 10**400},
                          {"observed_at": "unknown"}, {"observed_at": "2025-12-31T00:00:00Z"}):
            self.assertEqual(score(impact={"integrity": observation("integrity", **overrides)})["score"], 15)
        self.assertEqual(score(impact={"physical_impact": observation("integrity")})["score"], 15)

    def test_deterministic_bounded_and_nonmutating(self):
        impact = {d: observation(d) for d in IMPACT_POINTS}
        original = copy.deepcopy(impact)
        self.assertEqual(score("CRITICAL", impact=impact)["score"], 100)
        self.assertEqual(score("INFORMATIONAL")["score"], 0)
        self.assertEqual(score(impact=impact), score(impact=impact))
        self.assertEqual(impact, original)
        for severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            for status in ("SUCCESS", "DETECTED", "UNDETECTED", "FAILED", "TIMEOUT"):
                self.assertTrue(0 <= score(severity, status, impact)["score"] <= 100)

    def test_missing_required_inputs_are_not_assessed(self):
        for severity, status in ((None, "SUCCESS"), ("UNKNOWN", "SUCCESS"), ("HIGH", "Unknown")):
            self.assertIsNone(score(severity, status)["score"])

    def test_detection_traffic_and_requested_magnitude_do_not_change_score(self):
        for detected in (False, True):
            source = finding_events(status="SUCCESS", detected=detected)
            source[1]["evidence"].update(network_flows=[{"packets": 10000}], ml_confidence=.99999)
            report = generate_report(report_events(source))
            finding = report["findings"][0]
            self.assertEqual(finding["finding_dvs"], 15)
            for dimension in ("operational_impact", "physical_impact", "safety_impact"):
                self.assertEqual(finding["finding_dvs_breakdown"][dimension]["points"], 0)

    def test_identity_join_and_event_preservation(self):
        source = finding_events()
        original = copy.deepcopy(source)
        report = generate_report(report_events(source))
        self.assertEqual(report["findings"][0]["id"], "ASCEND-PG-001")
        self.assertTrue(report["findings"][0]["detected"])
        self.assertEqual(source, original)
        source[0]["run_id"] = "foreign"
        self.assertIsNone(generate_report(report_events(source))["findings"][0]["finding_dvs"])

    def test_html_pdf_and_separate_campaign_score(self):
        impact = {"integrity": observation("integrity")}
        source = finding_events(impact=impact)
        evaluation = dict(avg_evasion_rate=.2, completion_rate=.5, avg_max_stage=1.5,
                          plateau_detected=False, completion_count=2, num_episodes=4, avg_reward=1)
        report = generate_report(report_events(source), {"run_metadata": {"dvs_evaluation": evaluation}})
        self.assertEqual(report["dvs"]["score"], 41)
        self.assertEqual(report["findings"][0]["finding_dvs"], 25)
        html = render_html(report)
        self.assertIn("Finding DVS:</strong> 25.0 / 100", html)
        self.assertIn("Campaign DVS / Defence Performance Score", html)
        self.assertNotIn("Finding CVSS", html)
        # Disable PDF compression to inspect the actual rendered labels in memory.
        from unittest.mock import patch
        from fpdf import FPDF
        original = FPDF.__init__
        def uncompressed(pdf, *args, **kwargs):
            original(pdf, *args, **kwargs)
            pdf.set_compression(False)
        with patch.object(FPDF, "__init__", uncompressed):
            pdf = bytes(render_pdf(report))
        self.assertIn(b"Finding DVS: 25.0 / 100", pdf)
        self.assertNotIn(b"Finding CVSS", pdf)

    def test_html_not_assessed_without_attack_start(self):
        source = finding_events()[1:]
        html = render_html(generate_report(report_events(source)))
        self.assertIn("Finding DVS:</strong> Not assessed", html)


if __name__ == "__main__":
    unittest.main()
