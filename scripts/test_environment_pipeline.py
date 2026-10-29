"""Real data-flow regressions, with runtime execution boundaries replaced only in tests."""
import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from data.environment import sample_environment, campaign_environment, rules_from_file, ROOT
from data.mitre_registry import TECHNIQUES, get_display_technique
from defense.detection_result import detection_result, detection_label
from metrics.campaign_evaluation import persist_episode
from metrics.dvs_score import compute_dvs
from reports.pentest_report import generate_report, render_html
from testbed import run_store


class EnvironmentPipeline(unittest.TestCase):
    def test_sample_http_endpoint_never_queries_live_state(self):
        import json
        import threading
        from http.server import ThreadingHTTPServer
        from urllib.request import urlopen
        from gui.server import GuiHandler
        with patch('gui.adapter.core_request', side_effect=AssertionError('live query')):
            server = ThreadingHTTPServer(('127.0.0.1',0), GuiHandler)
            thread = threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                with urlopen(f'http://127.0.0.1:{server.server_port}/api/sample-environment') as response:
                    sample = json.load(response)
                self.assertEqual(sample['label'],'SAMPLE')
                self.assertEqual(len(sample['security_events']),3)
                self.assertEqual(sample['topology_summary']['plcs'],14)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_sample_is_static_and_never_calls_runtime(self):
        from testbed import topology
        before = topology.get_topology()
        with patch('gui.adapter.core_request', side_effect=AssertionError('runtime dependency')):
            with patch.object(topology.Topology,'from_pandapower',side_effect=AssertionError('sample simulation')):
                sample_environment.cache_clear()
                sample = sample_environment()
        self.assertIs(before, topology.get_topology())
        self.assertEqual(sample['environment_mode'], 'sample')
        self.assertEqual(sample['topology_summary']['plcs'], 14)
        self.assertEqual(sample['topology_summary']['hosts'], 17)
        self.assertTrue(sample['rules'])
        self.assertTrue(sample['pyvis_html'])
        restart = sample['security_events'][1]
        self.assertEqual(restart['technical_details']['Technique'], 'Device Restart/Shutdown')
        self.assertEqual(restart['technical_details']['Tactic'], 'Inhibit Response Function')
        self.assertIsNone(restart['detected'])

    def test_all_execution_mappings_reference_existing_rules_and_scripts(self):
        rules = {r['sid'] for r in rules_from_file(ROOT / 'detection/suricata/modbus_rules.rules')}
        for tech in TECHNIQUES:
            self.assertTrue((ROOT / tech['script']).is_file())
            self.assertTrue(set(tech['detect_sids']) <= rules)
        self.assertEqual(get_display_technique('T0830')['tactic'], 'Collection')
        self.assertEqual(get_display_technique('T0835')['tactic'], 'Inhibit Response Function')
        self.assertEqual(get_display_technique('T0842')['name'], 'Network Sniffing')
        import json
        exported = json.loads((ROOT / 'data/mitre_ics_map.json').read_text())
        for tid, row in exported.items():
            tech = get_display_technique(tid)
            if tech:
                self.assertEqual(row['technique_name'], tech['name'])
                self.assertEqual(row['tactic'], tech['tactic'])

    def test_historical_restart_positive_method_survives_failed_execution(self):
        event = dict(event_type='attack_finished', timestamp='2026-01-01T00:00:00Z',
                     mitre_technique='T0816', attack_stage=2, result='failed',
                     evidence={'step_name':'device_restart','return_status':'FAILED',
                               'detection_method':'ml','ml_confidence':.99945})
        original = copy.deepcopy(event)
        records = run_store.report_events([event])
        self.assertIs(records[0]['Detected'], True)
        report = generate_report(records)
        self.assertEqual(report['findings'][0]['execution_result'], 'FAILED')
        html = render_html(report)
        self.assertIn('Technical Details', html)
        self.assertIn('Device Restart/Shutdown', html)
        self.assertIn('Inhibit Response Function', html)
        self.assertNotIn('A. MITRE ATT&CK for ICS Mapping', html)
        self.assertEqual(event, original)

    def test_three_states_are_distinct(self):
        for value in (True, False, None):
            event = {'detected': value, 'detection_evaluated': value is not None}
            self.assertIs(detection_result(event), value)
        self.assertEqual(detection_label(False), 'Not Detected')
        self.assertIsNone(detection_result({'evidence': {'detection_method': 'unknown'}}))
        self.assertIsNone(detection_result({'detected': False, 'detection_evaluated': False}))

    def test_completed_episode_persists_existing_dvs_and_saved_environment(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(run_store, 'RUNS', Path(directory)):
            sample = sample_environment()
            run = run_store.create_run(sample['topology'])
            steps = [{'detected': False, 'detection_evaluated': True, 'success': True, 'attack_stage': s} for s in range(4)]
            session = {'episode_id':'episode-a','env':SimpleNamespace(_completed_stages=set(range(4))),
                       'evaluation_steps':steps,'reward':12.5}
            persist_episode(run, session, 'campaign_complete')
            persist_episode(run, session, 'campaign_complete')
            saved = run_store.update_run(run['scenario_id'], run['run_id'])
            self.assertEqual(len(saved['attack_episodes']), 1)
            self.assertEqual(saved['dvs_evaluation']['avg_reward'], 12.5)
            report = generate_report([], {'run_metadata':saved})
            self.assertEqual(report['dvs']['score'], compute_dvs(saved['dvs_evaluation'])['score'])
            environment = campaign_environment(saved)
            self.assertEqual(environment['topology_summary']['plcs'], 14)
            self.assertEqual(environment['rules'], [])  # no claimed live rules
            session = {'episode_id':'episode-b','env':SimpleNamespace(_completed_stages=set()),
                       'evaluation_steps':[{'detected':None,'detection_evaluated':False,'success':True,'attack_stage':0}]}
            persist_episode(run, session, 'step_limit')
            saved = run_store.update_run(run['scenario_id'], run['run_id'])
            self.assertIsNone(saved['dvs_evaluation'])
            self.assertIn('not evaluated', saved['dvs_unavailable_reason'])

    def test_executor_keeps_ml_detection_for_failed_restart(self):
        from scripts import testbed_executor as executor
        detector = SimpleNamespace(clear_flows=lambda:None, start_capture=lambda:None,
            stop_capture=lambda:None, extractor=None,
            get_verdict=lambda *a:dict(combined_detected=True,detection_evaluated=True,
                suricata_alert_count=0,suricata_signatures=[],ml_detected=True,ml_confidence=.99,
                ml_lstm_confidence=.99,ml_ae_score=.99,ml_available=True,ml_error=None,detection_method='ml'))
        now = datetime.now(timezone.utc)
        timing = dict(name='device_restart',start=now,end=now,detect_sids=[9000007],
                      techniques=['T0816'],success=False,status=executor.AttackStatus.FAILED,
                      return_code=1,stdout='',stderr='write failed',error='write failed')
        with patch.object(executor,'get_hybrid_detector',return_value=detector), patch.object(executor,'run_step',return_value=timing), patch.object(executor.time,'sleep'):
            result = executor.execute_single_attack('T0816')
        self.assertIs(result['detected'], True)
        self.assertIs(result['evaded'], False)
        self.assertEqual(result['status'], 'FAILED')

    def test_restart_uses_installed_modbus_signature(self):
        import inspect
        from pymodbus.client import ModbusTcpClient
        from attacks import device_restart
        captured = {}
        def write_coil(*args, **kwargs):
            inspect.signature(ModbusTcpClient.write_coil).bind(None, *args, **kwargs)
            captured.update(kwargs)
            return SimpleNamespace(isError=lambda:False)
        client = SimpleNamespace(connect=lambda:True, write_coil=write_coil, close=lambda:None)
        with tempfile.TemporaryDirectory() as directory, patch.object(device_restart,'ModbusTcpClient',return_value=client):
            self.assertTrue(device_restart.run_restart('10.0.0.1',502,1,6,Path(directory)/'events.jsonl'))
        self.assertEqual(captured, {'address':6,'value':True,'device_id':1})


if __name__ == '__main__':
    unittest.main()
