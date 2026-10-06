"""Evidence/severity unit tests; no services or real subprocesses."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from metrics.attack_severity import resolve_attack_severity
from metrics.finding_evidence import bind_evidence, retain_evidence, verify_impacts, passive_scada
from metrics.finding_dvs import compute_finding_dvs
from scripts.finding_evidence_fixtures import fixture_bundle, IDENTITY, START, END


def verify(bundle):
    return verify_impacts(bundle, IDENTITY, START, END)


def rebind(bundle):
    return bind_evidence(bundle, IDENTITY, START, END)


class FindingEvidence(unittest.TestCase):
    def test_canonical_severity_policy(self):
        expected = {"T0846": "LOW", "T0888": "LOW", "T0836": "HIGH", "T0835": "HIGH",
                    "T0815": "HIGH", "T0881": "HIGH", "T0806": "MEDIUM", "T0830": "HIGH",
                    "T0855": "HIGH", "T0802": "MEDIUM"}
        for technique, severity in expected.items():
            a = resolve_attack_severity({"technique_id": technique, "detected": True})
            b = resolve_attack_severity({"technique_id": technique, "detected": False})
            self.assertEqual(a, b)
            self.assertEqual(a["severity"], severity)
        self.assertEqual(resolve_attack_severity({})["severity"], "HIGH")
        self.assertEqual(resolve_attack_severity({"technique_id": "T0846", "step_name": "fdi_attack"})["severity"], "HIGH")

    def test_integrity_requires_correlated_action_and_independent_reads(self):
        bundle = fixture_bundle(["integrity"])
        self.assertEqual(verify(bundle)["integrity"]["state"], "verified_adverse")
        bundle["records"] = [r for r in bundle["records"] if r["kind"] == "write_ack"]
        self.assertEqual(verify(bundle)["integrity"]["state"], "unknown")

    def test_flags_names_and_unresolved_references_do_not_verify(self):
        claims = {"integrity": {"verified": True, "adverse": True, "source": "target_readback", "evidence_ref": "fake", "before": 1, "after": 0}}
        result = compute_finding_dvs("HIGH", "SUCCESS", claims, correlation_id="c", start_time=START, end_time=END)
        self.assertEqual(result["score"], 15)
        self.assertEqual(result["breakdown"]["integrity"]["state"], "unknown")

    def test_availability_requires_real_polling_disruption(self):
        bundle = fixture_bundle(["availability"])
        self.assertEqual(verify(bundle)["availability"]["state"], "verified_adverse")
        bundle["records"] = [r for r in bundle["records"] if r["kind"] == "disruption_attempt"]
        self.assertEqual(verify(bundle)["availability"]["state"], "unknown")

    def test_collection_requires_data_not_count_or_attempt(self):
        parsed = retain_evidence("automated_collection", "[auto_collection] 10.0.0.1 holding[0:2] = [123, 456]", "", END)
        result = verify(bind_evidence(parsed, IDENTITY, START, END))
        self.assertEqual(result["confidentiality"]["state"], "verified_adverse")
        parsed = retain_evidence("automated_collection", "total_registers: 20", "", END)
        self.assertEqual(verify(bind_evidence(parsed, IDENTITY, START, END))["confidentiality"]["state"], "unknown")
        parsed = retain_evidence("automated_collection", "[auto_collection] 10.0.0.1 holding[0:2] = []", "", END)
        self.assertEqual(verify(bind_evidence(parsed, IDENTITY, START, END))["confidentiality"]["state"], "verified_none")

    def test_physical_safety_require_explicit_independent_instrument(self):
        bundle = fixture_bundle(["integrity"])
        self.assertEqual(verify(bundle)["physical_impact"]["state"], "unknown")
        self.assertEqual(verify(bundle)["safety_impact"]["state"], "unknown")
        self.assertEqual(verify(fixture_bundle(["safety_impact"]))["safety_impact"]["state"], "verified_adverse")

    def test_unknown_differs_from_verified_none(self):
        bundle = fixture_bundle(["integrity"])
        for row in bundle["records"]:
            if row["kind"] == "state_read":
                row["values"] = [0]
        self.assertEqual(verify(rebind(bundle))["integrity"]["state"], "verified_none")
        self.assertEqual(verify(fixture_bundle([]))["integrity"]["state"], "unknown")

    def test_identity_window_and_fact_tampering_rejected(self):
        for key in IDENTITY:
            bundle = fixture_bundle(["integrity"])
            bundle["identity"][key] = "other"
            self.assertEqual(verify(bundle)["integrity"]["state"], "unknown")
            self.assertEqual(rebind(bundle)["records"], [])
        bundle = fixture_bundle(["integrity"])
        for row in bundle["records"]:
            if row["kind"] == "state_read":
                row["timestamp"] = "2026-01-02T00:00:00Z"
        self.assertEqual(verify(rebind(bundle))["integrity"]["state"], "unknown")
        bundle = fixture_bundle(["integrity"])
        bundle["records"][0]["value"] = 999
        self.assertEqual(verify(bundle)["integrity"]["state"], "unknown")

    def test_partial_effects_before_failure_and_timeout(self):
        bundle = fixture_bundle(["integrity"])
        original = copy.deepcopy(bundle)
        for status in ("FAILED", "TIMEOUT"):
            result = compute_finding_dvs("HIGH", status, correlation_id="c", start_time=START, end_time=END,
                                        evidence_bundle=bundle, evidence_identity=IDENTITY)
            self.assertEqual(result["score"], 25)
        self.assertEqual(bundle, original)

    def test_overlapping_instrument_consequences_not_counted_twice(self):
        bundle = fixture_bundle(["physical_impact", "safety_impact"])
        for row in bundle["records"]:
            if row["source"] == "independent_instrument":
                row["instrument_reference"] = "same-consequence"
        result = verify(rebind(bundle))
        self.assertEqual(sum(result[d]["state"] == "verified_adverse" for d in ("physical_impact", "safety_impact")), 1)

    def test_passive_scada_retention_does_not_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scada.jsonl"
            row = dict(observation_type="poll_result", action="poll_10.0.0.1", target="10.0.0.1", timestamp=START, registers=[3], address=0, count=1)
            path.write_text(json.dumps(row) + "\n")
            records = passive_scada(path)
            self.assertEqual(records[0]["values"], [3])
            self.assertEqual(records[0]["source"], "passive_scada")

    def test_campaign_retains_bundle_and_report_preserves_partial_effect(self):
        from unittest.mock import patch
        from gui.campaign import CampaignController
        from testbed.run_store import report_events
        from reports.pentest_report import generate_report
        controller = object.__new__(CampaignController)
        controller._sessions = {}
        request = {**IDENTITY, "campaign_id": "r", "step_name": "fdi_attack", "target_node": "plc1",
                   "technique_id": "T0836", "attack_stage": 2, "current_step": 0}
        bundle = fixture_bundle(["integrity"])
        result = dict(status="FAILED", detected=False, evaded=False, end_time=END, finding_evidence=bundle)
        with patch("gui.campaign.run_store.read_events", return_value=[]), \
             patch("gui.campaign.run_store.append_event") as append, \
             patch("gui.campaign.run_store.update_run"):
            controller._complete({"scenario_id": "s", "run_id": "r"}, request, result)
        call = append.call_args
        finished = {"scenario_id": call.args[0], "run_id": call.args[1], **call.kwargs}
        self.assertEqual(finished["evidence"]["finding_evidence"], bundle)
        started = {**IDENTITY, "event_type": "attack_started", "timestamp": START, "severity": "HIGH"}
        report = generate_report(report_events([started, finished]))
        self.assertEqual(report["findings"][0]["finding_dvs"], 25)
        self.assertEqual(report["findings"][0]["execution_result"], "FAILED")


if __name__ == "__main__":
    unittest.main()
