"""Severity lifecycle regression: temporary evidence, mocked producers, no attacks/services."""
import copy
import ast
import itertools
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from data.mitre_registry import TECHNIQUES
from metrics.attack_severity import resolve_attack_severity
from reports.pentest_report import _evidence_tables, generate_report, render_html
from testbed import run_store


class SeverityFlow(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.roots = patch.object(run_store, 'RUNS', Path(self.directory.name))
        self.roots.start()
        self.addCleanup(self.roots.stop)
        self.run = run_store.create_run({}, scenario_id='scenario-fixture')

    def append(self, kind, **changes):
        common = dict(category='security', event_type=kind, generation_id='g', correlation_id='c',
                      mitre_technique='T0836', evidence={'step_name': 'fdi_attack', 'return_status': 'FAILED'},
                      result='failed', timestamp='2026-01-01T00:00:00Z')
        common.update(changes)
        return run_store.append_event(self.run['scenario_id'], self.run['run_id'], **common)

    def test_low_medium_high_critical_resolved_once_and_inherited(self):
        for severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            with self.subTest(severity=severity), patch('metrics.attack_severity.resolve_attack_severity',
                    return_value={'severity': severity, 'policy': 'fixture'}) as resolver:
                start = self.append('attack_started', correlation_id=severity, result='started')
                # A duplicate start reuses the policy rather than resolving again.
                self.append('attack_started', correlation_id=severity)
                finish = self.append('attack_finished', correlation_id=severity, severity='INFO')
                detect = self.append('detection', correlation_id=severity, severity='HIGH', result='detected')
                resolver.assert_called_once()
                self.assertEqual([e['severity'] for e in (start, finish, detect)], [severity]*3)
                self.assertTrue(all(e['attack_severity'] == severity for e in (start, finish, detect)))
                finding = generate_report(run_store.report_events([detect, finish, start]))['findings'][0]
                self.assertEqual(finding['severity'], severity.title())
                self.assertEqual(finding['finding_dvs'], {'LOW': 5, 'MEDIUM': 10, 'HIGH': 15, 'CRITICAL': 20}[severity])

    def test_every_registered_method_alias_and_variant_uses_start_resolver(self):
        from scripts.ppo_step_watcher import record_attack_started
        from scripts.testbed_executor import STEP_DEFS, TECHNIQUE_TO_STEP_NAME
        covered = set()
        for technique in TECHNIQUES:
            for technique_id in [technique['id'], *technique.get('alias_ids', [])]:
                for step in [technique['default_step'], *technique.get('variants', [])]:
                    covered.add(step)
                    pending = {**self.run, 'technique_id': technique_id, 'step_name': step,
                               'target_node': 'plc1', 'target_ip': '10.0.0.1',
                               'campaign_id': self.run['run_id'], 'correlation_id': f'{technique_id}-{step}'}
                    expected = resolve_attack_severity(pending)['severity']
                    with patch('metrics.attack_severity.resolve_attack_severity', wraps=resolve_attack_severity) as resolver:
                        start = record_attack_started(pending, 'g')
                        finish = self.append('attack_finished', correlation_id=pending['correlation_id'], mitre_technique=technique_id)
                        detect = self.append('detection', correlation_id=pending['correlation_id'], mitre_technique=technique_id)
                        resolver.assert_called_once()
                    self.assertEqual([e['severity'] for e in (start, finish, detect)], [expected]*3)
        self.assertEqual(set(STEP_DEFS), covered)
        self.assertTrue(set(TECHNIQUE_TO_STEP_NAME.values()) <= covered)

    def test_failed_timeout_and_detected_do_not_change_severity(self):
        for technique, step, severity, status in (('T0836', 'fdi_attack', 'HIGH', 'FAILED'),
                ('T0836', 'fdi_attack', 'HIGH', 'TIMEOUT'), ('T0842', 'recon_fc_scan', 'LOW', 'DETECTED')):
            correlation = f'{technique}-{status}'
            start = self.append('attack_started', correlation_id=correlation, mitre_technique=technique,
                                evidence={'step_name': step}, result='started')
            finish = self.append('attack_finished', correlation_id=correlation, mitre_technique=technique,
                                 evidence={'step_name': step, 'return_status': status}, result=status)
            events = [start, finish]
            if status == 'DETECTED':
                events.append(self.append('detection', correlation_id=correlation, result='detected'))
            self.assertEqual(finish['severity'], severity)
            self.assertEqual(finish['result'], status)
            before = copy.deepcopy(events)
            for permutation in itertools.permutations(events):
                normalized = run_store.report_events(list(permutation))
                self.assertEqual(normalized[0]['Severity'], severity)
                self.assertEqual(normalized[0]['Attack Severity'], severity)
                finding = generate_report(normalized)['findings'][0]
                self.assertEqual(finding['severity'], severity.title())
                self.assertEqual(finding['finding_dvs'], 5 if severity == 'LOW' else 15)
                self.assertEqual(finding['execution_result'], status)
            self.assertEqual(events, before)

    def test_historical_start_wins_without_rewriting_evidence(self):
        start = self.append('attack_started', mitre_technique='T0842', evidence={'step_name': 'recon_fc_scan'})
        finish = {**start, 'event_type': 'attack_finished', 'severity': 'INFO', 'result': 'detected',
                  'evidence': {'return_status': 'DETECTED'}}
        detection = {**start, 'event_type': 'detection', 'severity': 'HIGH'}
        for row in (start, finish, detection):
            row.pop('attack_severity', None)
        events = [detection, finish, start]
        original = copy.deepcopy(events)
        record = run_store.report_events(events)[0]
        self.assertEqual(record['Severity'], 'LOW')
        self.assertEqual(generate_report([record])['findings'][0]['finding_dvs'], 5)
        html = _evidence_tables({'security_events': events})
        self.assertEqual(html.count('<td>LOW</td>'), 3)
        # Original forensic severities are still available in full event JSON.
        self.assertIn('&quot;severity&quot;: &quot;INFO&quot;', html)
        self.assertIn('&quot;severity&quot;: &quot;HIGH&quot;', html)
        self.assertEqual(events, original)

    def test_foreign_start_cannot_supply_severity_and_missing_is_not_info(self):
        start = self.append('attack_started')
        for field in ('scenario_id', 'run_id', 'generation_id', 'correlation_id'):
            finish = {**start, 'event_type': 'attack_finished', field: 'foreign', 'severity': 'INFO'}
            finish.pop('attack_severity')
            self.assertIsNone(run_store.report_events([start, finish])[0]['Severity'])
        orphan = self.append('attack_finished', correlation_id='orphan')
        self.assertIsNone(orphan['severity'])
        finding = generate_report(run_store.report_events([orphan]))['findings'][0]
        self.assertEqual(finding['severity'], 'Unavailable')
        self.assertIsNone(finding['finding_dvs'])

    def test_campaign_completion_producers_inherit_start(self):
        from gui.campaign import CampaignController
        controller = object.__new__(CampaignController)
        controller._sessions = {}
        start = self.append('attack_started', mitre_technique='T0842', evidence={'step_name': 'recon_fc_scan'})
        request = {**start, 'step_name': 'recon_fc_scan', 'technique_id': 'T0842',
                   'campaign_id': self.run['run_id'], 'current_step': 0, 'target_node': 'plc1'}
        controller._complete(self.run, request, {'status': 'DETECTED', 'detected': True,
                             'end_time': start['timestamp']})
        events = run_store.read_events(self.run['scenario_id'], self.run['run_id'], 'security')
        self.assertEqual([e['event_type'] for e in events], ['attack_started', 'attack_finished', 'detection'])
        self.assertEqual([e['severity'] for e in events], ['LOW']*3)
        html = render_html(generate_report(run_store.report_events(events)))
        self.assertIn('Base attack severity:</strong> LOW', html)

    def test_non_attack_event_severity_is_unchanged(self):
        network = run_store.append_event(self.run['scenario_id'], self.run['run_id'], category='network', event_type='packet')
        defense = self.append('defense_action', severity='ACTION')
        self.assertEqual(network['severity'], 'INFO')
        self.assertEqual(defense['severity'], 'ACTION')

    def test_producers_have_no_lifecycle_severity_overrides(self):
        root = Path(__file__).resolve().parents[1]
        producers = ('gui/campaign.py', 'scripts/ppo_step_watcher.py', 'scripts/controlled_campaign.py')
        calls = 0
        for producer in producers:
            tree = ast.parse((root / producer).read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', '')
                if function != 'append_event':
                    continue
                args = {arg.arg: arg.value for arg in node.keywords}
                kind = args.get('event_type')
                if isinstance(kind, ast.Constant) and kind.value in {'attack_started', 'attack_finished', 'detection'}:
                    calls += 1
                    self.assertNotIn('severity', args, producer)
        self.assertEqual(calls, 6)


if __name__ == '__main__':
    unittest.main()
