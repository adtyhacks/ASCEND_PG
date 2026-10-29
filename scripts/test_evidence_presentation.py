"""In-memory HTML/PDF fixtures; never writes reports or runs services."""
import copy
import json
import re
import sys
import unittest
from html import unescape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reports.pentest_report import (
    _evidence_cell, _evidence_tables, generate_report, render_html, render_pdf,
)


class EvidencePresentation(unittest.TestCase):
    def test_placeholder_distinctions(self):
        self.assertIn('Not applicable', _evidence_cell('N/A'))
        self.assertIn('Unavailable', _evidence_cell(None))
        self.assertIn('Empty string', _evidence_cell(''))
        for value, expected in ((0, '0'), (False, 'false'), ('unknown', 'unknown'),
                                ('unavailable', 'unavailable'), ('verified', 'verified')):
            self.assertEqual(_evidence_cell(value), expected)

    def test_large_evidence_preserved(self):
        info = {'network_events': [dict(timestamp=f't{i}', source_ip='N/A', source_node='plc1',
                    destination_ip='10.0.0.1', source_port=0, evidence={'payload': '<script>' + 'x'*5000 + 'END_PAYLOAD'},
                    correlation_id=f'correlation-{i}') for i in range(200)],
                'security_events': [dict(timestamp='t', event_type='attack_finished', ppo_step='N/A',
                    target_node='plc1', mitre_technique='T0836', result='failed', severity='HIGH',
                    detection_method='N/A', defense_action=None, correlation_id='semantic-id')]}
        before = copy.deepcopy(info)
        report = generate_report([])
        report['campaign_info'] = info
        original = copy.deepcopy(report)
        html = render_html(report)
        self.assertEqual(info, before)
        self.assertEqual(report, original)
        self.assertIn('Canonical network events from this run', html)
        self.assertIn('Semantic campaign evidence', html)
        self.assertEqual(html.count('data-evidence-table="true"'), 2)
        self.assertIn('max-height:420px', html)
        self.assertIn('position:sticky;top:0', html)
        self.assertIn('text-overflow:ellipsis', html)
        self.assertIn('correlation-199', html)
        self.assertIn('semantic-id', html)
        self.assertIn('END_PAYLOAD', html)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        table = _evidence_tables(info)
        self.assertNotIn('<th scope="col">PPO step', table)
        self.assertNotIn('<th scope="col">Defense', table)
        self.assertNotIn('<th scope="col">Detection', table)
        self.assertIn('<td>plc1</td>', table)
        self.assertIn('<td>0</td>', table)
        # Raw forensic JSON intentionally retains its original placeholders.
        self.assertIn('N/A', html)
        self.assertIn('Full event', html)
        full_events = re.findall(r'Full event</span></summary><pre>(.*?)</pre>', table, re.S)
        self.assertEqual([json.loads(unescape(payload)) for payload in full_events],
                         info['network_events'] + info['security_events'])
        self.assertIn('@media print{.evidence-table-container{max-height:none;overflow:visible}', html)

    def test_optional_zero_and_false_are_meaningful(self):
        html = _evidence_tables({'security_events': [{'ppo_step': 0, 'detected': False, 'defense_action': False}]})
        for label in ('Attack step', 'Detection', 'Defense'):
            self.assertIn(f'<th scope="col">{label}</th>', html)
        self.assertIn('<td>Attack Step 0</td>', html)
        self.assertIn('<td>false</td>', html)

    def test_pdf_renderer_remains_independent(self):
        report = generate_report([])
        before = copy.deepcopy(report)
        self.assertTrue(bytes(render_pdf(report)).startswith(b'%PDF'))
        self.assertEqual(report, before)


if __name__ == '__main__':
    unittest.main()
