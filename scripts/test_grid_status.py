"""Operational grid snapshot tests; temporary retained logs, no polling/services."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gui import adapter, grid_status
from testbed.topology import Topology

NOW = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)


class FixedDate(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def stamp(seconds):
    return (NOW + timedelta(seconds=seconds)).isoformat()


class GridStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / 'core-runtime'; self.runtime.mkdir()
        self.topo = Topology(nodes=[{'bus_id':0,'name':'Lab Generator','type':'slack','voltage':1.04,'pg':10.,'pl':2.},
                                    {'bus_id':1,'name':'Lab Load','type':'pq','voltage':1.,'pg':0.,'pl':4.}],
                             edges=[(0,1)],case_name='custom_lab')
        self.run = {'scenario_id':'scenario-fixture','run_id':'run-fixture','generation_id':'g','core_session_id':7,
                    'started_at':stamp(-60),'topology_version':self.topo.canonical_snapshot()['topology_version']}
        self.marker = {'id':7,'generation_id':'g','created_at':(NOW-timedelta(seconds=59)).timestamp()}
        for name,value in [('DATA',self.root),('canonical_topology',lambda:self.topo),
                           ('get_active_run',lambda:{'state':'ACTIVE','run':self.run}),('_runtime_marker',lambda:self.marker),
                           ('get_recent_security_events',lambda *args:[])]:
            item=patch.object(adapter,name,value); item.start(); self.addCleanup(item.stop)
        item=patch.object(grid_status,'datetime',FixedDate); item.start(); self.addCleanup(item.stop)

    def write(self, path, rows):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))

    def test_ieee14_ieee30_and_canonical_values(self):
        for count in (14,30):
            self.topo=Topology(nodes=[{'bus_id':i,'name':f'Bus{i+1}','type':'pq','voltage':1+i/1000,
                                      'pg':0.,'qg':0.,'pl':0.,'ql':0.} for i in range(count)],
                               edges=[(i,i+1) for i in range(count-1)],case_name=f'case{count}')
            data=grid_status.snapshot()
            self.assertEqual(len(data['components']),count)
            self.assertEqual(data['grid']['component_count'],count)
            self.assertEqual(data['components'][-1]['model_voltage_pu'],self.topo.nodes[-1]['voltage'])
            self.assertAlmostEqual(data['grid']['model_average_voltage_pu'],sum(n['voltage'] for n in self.topo.nodes)/count)
            self.assertIsNone(data['grid']['model_generation_mw'],'Preset placeholders are not measured or calculated power')

    def test_custom_model_generation_load_and_missing_fields(self):
        before=copy.deepcopy(self.topo.to_dict())
        data=grid_status.snapshot()
        self.assertEqual([n['name'] for n in data['components']],['Lab Generator','Lab Load'])
        self.assertEqual(data['grid']['model_generation_mw'],10)
        self.assertEqual(data['grid']['model_load_mw'],6)
        self.assertEqual(data['grid']['electrical_connections'],1)
        self.assertEqual(self.topo.to_dict(),before)
        del self.topo.nodes[0]['voltage']; del self.topo.nodes[0]['pg']
        data=grid_status.snapshot()
        self.assertIsNone(data['components'][0]['model_voltage_pu'])
        self.assertIsNone(data['grid']['model_average_voltage_pu'])
        self.assertIsNone(data['grid']['model_generation_mw'])

    def test_fresh_scada_observations_only_establish_communication(self):
        path=self.runtime/'scada.jsonl'
        self.write(path,[{'timestamp':stamp(-4),'target':'10.0.0.1','observation_type':'poll_result','registers':[10400,100]},
                         {'timestamp':stamp(-3),'target':'10.0.0.2','action':'poll_failed'}])
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(adapter,'core_request') as core:
            data=grid_status.snapshot()
        core.assert_not_called()
        self.assertEqual([n['status'] for n in data['components']],['Monitoring','Offline'])
        self.assertEqual(data['network']['responding_components'],1)
        self.assertIsNone(data['grid']['healthy'])
        self.assertTrue(all(n['measured_voltage_pu'] is None for n in data['components']))
        self.assertEqual(before,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_old_foreign_and_future_observations_do_not_establish_status(self):
        self.write(self.runtime/'scada.jsonl',[{'timestamp':stamp(-61),'target':'10.0.0.1','observation_type':'poll_result','registers':[1]},
                                              {'timestamp':stamp(1),'target':'10.0.0.2','observation_type':'poll_result','registers':[1]}])
        self.assertTrue(all(n['status']=='Not available' for n in grid_status.snapshot()['components']))
        self.marker['generation_id']='foreign'
        self.assertIsNone(grid_status.snapshot()['network']['responding_components'])
        self.marker['generation_id']='g'; self.run['topology_version']='different'
        self.assertIsNone(grid_status.snapshot()['network']['responding_components'])

    def flow(self, sent=200, received=100, timestamp=-1):
        return {'event_type':'flow','flow_id':1,'timestamp':stamp(timestamp),'src_ip':'10.0.0.100','dest_ip':'10.0.0.1',
                'src_port':502,'dest_port':1234,'proto':'TCP',
                'flow':{'start':stamp(-10),'end':stamp(-8),'bytes_toserver':sent,'bytes_toclient':received}}

    def test_real_observed_flow_rate_deduplicates_cumulative_records(self):
        self.write(self.runtime/'suricata/eve.json',[self.flow(100,50,-2),self.flow()])
        data=grid_status.snapshot()
        self.assertEqual(data['network']['observed_traffic'],{'bits_per_second':1200.,'bytes':300.,'window_seconds':2.,'flow_count':1})
        self.assertIsNone(data['network']['bandwidth_capacity_bps'])

    def test_no_fabricated_rate_for_missing_invalid_or_old_flows(self):
        rows=[self.flow() for _ in range(4)]
        del rows[0]['flow']['bytes_toclient']
        rows[1]['flow']['end']=rows[1]['flow']['start']
        rows[2]['dest_ip']='192.168.1.1'
        rows[3]['flow']['start']=stamp(-65)
        self.write(self.runtime/'suricata/eve.json',rows)
        self.assertIsNone(grid_status.snapshot()['network']['observed_traffic']['bits_per_second'])
        with patch.object(adapter,'get_active_run',return_value=None):
            self.assertIsNone(grid_status.snapshot()['network']['observed_traffic']['bits_per_second'])

    def test_read_only_api_structure_without_http_server(self):
        from gui.server import GuiHandler
        data=grid_status.snapshot()
        handler=object.__new__(GuiHandler); handler.path='/api/grid-status'; handler.wfile=io.BytesIO()
        handler.send_response=MagicMock(); handler.send_header=MagicMock(); handler.end_headers=MagicMock()
        with patch('gui.server.grid_status.snapshot',return_value=data):
            handler.do_GET()
        self.assertEqual(json.loads(handler.wfile.getvalue()),data)
        handler.send_response.assert_called_once_with(200)

    def test_baseline_grid_simulation_data(self):
        self.topo = Topology(nodes=[{'bus_id': 0, 'name': 'Bus 1', 'type': 'slack', 'voltage': 1.06},
                                    {'bus_id': 1, 'name': 'Bus 2', 'type': 'pq', 'voltage': 1.0}],
                             edges=[(0, 1)], case_name='case14')
        data = grid_status.snapshot()
        self.assertIn('baseline_grid', data)
        baseline = data['baseline_grid']
        self.assertIn('summary', baseline)
        self.assertIn('bus_voltages', baseline)
        self.assertIn('line_loadings', baseline)
        self.assertIn('telemetry', baseline)
        self.assertGreater(len(baseline['bus_voltages']), 0)
        self.assertGreater(len(baseline['line_loadings']), 0)
        self.assertGreater(len(baseline['telemetry']), 0)
        self.assertEqual(baseline['summary']['electrical_buses'], len(baseline['bus_voltages']))

    def test_custom_baseline_uses_the_selected_canonical_electrical_model(self):
        self.topo = Topology.from_custom_dict({
            'case_name': 'custom_power_flow',
            'nodes': [
                {'bus_id': 0, 'name': 'Grid connection', 'type': 'slack', 'vn_kv': 110, 'voltage': 1.02},
                {'bus_id': 1, 'name': 'Plant load', 'type': 'pq', 'vn_kv': 110, 'pl': 8.0, 'ql': 2.0},
                {'bus_id': 2, 'name': 'Auxiliary load', 'type': 'pq', 'vn_kv': 110, 'pl': 3.0, 'ql': 1.0},
            ],
            'edges': [
                {'from': 0, 'to': 1, 'length_km': 2, 'r_ohm_per_km': .08, 'x_ohm_per_km': .12, 'c_nf_per_km': 8, 'max_i_ka': .4},
                {'from': 1, 'to': 2, 'length_km': 1, 'r_ohm_per_km': .1, 'x_ohm_per_km': .15, 'c_nf_per_km': 6, 'max_i_ka': .3},
            ],
        })
        baseline = grid_status.snapshot()['baseline_grid']
        self.assertNotIn('error', baseline)
        self.assertEqual(baseline['case_name'], 'custom_power_flow')
        self.assertEqual(baseline['simulation_source'], 'custom')
        self.assertEqual(baseline['summary']['electrical_buses'], 3)
        self.assertEqual(baseline['summary']['lines'], 2)
        self.assertEqual(len(baseline['bus_voltages']), 3)
        self.assertEqual(len(baseline['line_loadings']), 2)
        self.assertEqual(len(baseline['telemetry']), 2)


if __name__=='__main__':
    unittest.main()
