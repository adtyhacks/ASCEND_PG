"""Run-level summary fixtures; temporary files only, no services or report writes."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gui import reporting
from testbed import run_store


class RunSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        roots = patch.object(run_store, 'RUNS', self.root)
        roots.start(); self.addCleanup(roots.stop)

    def fixture(self, count):
        run = run_store.create_run({}, scenario_id='scenario-summary')
        root = Path(run['path'])
        events = []
        techniques = ['T0801', 'T0836', 'T0814', 'T0888']
        for i in range(count):
            common = dict(scenario_id=run['scenario_id'],run_id=run['run_id'],generation_id='g',
                          correlation_id=f'attack-{i}',timestamp='2026-01-01T00:00:00Z',
                          target_node=f'plc{i % 7 + 1}',mitre_technique=techniques[i % 4],attack_stage=0)
            status = ['SUCCESS','FAILED','TIMEOUT'][i % 3]
            events += [{**common,'event_type':'attack_started','severity':'HIGH'},
                       {**common,'event_type':'attack_finished','result':'detected' if i % 2 == 0 else 'failed',
                        'evidence':{'step_name':'fixture','return_status':status}},
                       {**common,'event_type':'evidence_observation','evidence':{'traffic':True}}]
            if i % 2 == 0:
                events += [{**common,'event_type':'detection','evidence':{'detection_method':'ml'}}]*2
        (root / 'security_events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
        (root / 'report.html').write_text('<html>Existing report fixture</html>')
        return run, events

    def test_complete_run_beyond_preview_and_no_evidence_mutation(self):
        run, source = self.fixture(105)
        root = Path(run['path'])
        before = {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir()}
        original_records = run_store.report_events(source)
        with patch('gui.reporting.generate_report', wraps=reporting.generate_report) as build:
            result = reporting.summary(run['scenario_id'], run['run_id'])
        self.assertEqual(result['finding_summary'], {'total_findings':105,'detected':53,'failed':35,
                                                    'timeout':35,'techniques':4,'targets':7})
        self.assertEqual(result['normalized_records'], 105)
        self.assertEqual(len(result['normalized_events']), 100)
        self.assertEqual(result['normalized_events'], original_records[:100])
        overview = result['assessment_overview']
        self.assertEqual(overview['severity_distribution'], {'Critical':0,'High':105,'Medium':0,'Low':0,'Informational':0})
        self.assertEqual(len(overview['attacks']), 105)
        self.assertEqual(overview['defense']['detected'], 53)
        self.assertEqual(overview['defense']['total'], 105)
        self.assertAlmostEqual(overview['defense']['detection_rate'], 1.0)
        self.assertEqual(overview['defense']['unavailable'], 52)
        self.assertEqual(overview['defense']['methods'], {'ml':53,'unknown':52})
        self.assertTrue(overview['dvs']['finding_available'])
        self.assertEqual(overview['dvs']['finding_assessed'], 105)
        self.assertFalse(overview['dvs']['campaign_available'])
        self.assertIsNone(overview['dvs']['campaign_score'])
        build.assert_called_once()
        self.assertEqual(build.call_args.args[0], original_records)
        self.assertEqual(before, {path:hashlib.sha256(path.read_bytes()).hexdigest() for path in before})

    def test_selected_run_isolated_and_detection_can_overlap_execution_failure(self):
        first, _ = self.fixture(3)
        second, _ = self.fixture(1)
        result = reporting.summary(first['scenario_id'], first['run_id'])
        self.assertEqual(result['finding_summary'], {'total_findings':3,'detected':2,'failed':1,
                                                     'timeout':1,'techniques':3,'targets':3})
        self.assertEqual(reporting.summary(second['scenario_id'], second['run_id'])['finding_summary']['total_findings'], 1)
        # Detected + TIMEOUT is counted in both dimensions, as the report records it.
        self.assertEqual(result['normalized_events'][2]['Detected'], True)

    def test_no_saved_run_has_zero_aggregates(self):
        self.assertEqual(reporting.summary()['finding_summary'], {'total_findings':0,'detected':0,'failed':0,
                                                                'timeout':0,'techniques':0,'targets':0})

    def test_saved_run_with_no_finished_attacks_has_zero_findings(self):
        run, _ = self.fixture(0)
        result = reporting.summary(run['scenario_id'], run['run_id'])
        self.assertEqual(result['finding_summary'], {'total_findings':0,'detected':0,'failed':0,
                                                   'timeout':0,'techniques':0,'targets':0})
        self.assertEqual(result['assessment_overview']['attacks'], [])
        self.assertIsNone(result['assessment_overview']['defense']['detection_rate'])
        self.assertFalse(result['assessment_overview']['dvs']['finding_available'])


if __name__ == '__main__':
    unittest.main()
