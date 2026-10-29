"""Custom topology regressions: temporary XML/library, no daemon or attacks."""
import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gui import adapter
from testbed import topology as model
from testbed.core_xml import validate_xml, to_session
from testbed.generate_core_topo import generate_core_xml


def definition():
    return {'case_name': 'custom_lab', 'nodes': [
        {'bus_id': 0, 'name': 'Generator', 'type': 'slack'},
        {'bus_id': 1, 'name': 'Load A', 'type': 'pq'},
        {'bus_id': 2, 'name': 'Load B', 'type': 'pq'}],
        'edges': [{'from': 0, 'to': 1}, {'from': 1, 'to': 2}]}


class CustomTopology(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        original = model._current_topology
        self.addCleanup(setattr, model, '_current_topology', original)
        self.patch = patch.object(adapter, 'DATA', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        references = self.root / 'sample_topologies'
        references.mkdir()
        for case in ('case14', 'case30'):
            (references / f'{case}.json').write_text(json.dumps({'pandapower_case': case}))

    def test_predefined_selection_and_core_consistency(self):
        for case, count in (('case14', 14), ('case30', 30)):
            selected = adapter.select_topology(case)
            self.assertEqual(selected['configuration']['selected_case'], case)
            self.assertEqual(len(selected['topology']['nodes']), count + 4)
            path = generate_core_xml(output_path=str(self.root / f'{case}.xml'), topology=model.get_topology())
            self.assertEqual(len(validate_xml(path).findall('devices/device')), count + 3)

    def test_custom_representation_roundtrip_and_addresses(self):
        original = definition()
        before = copy.deepcopy(original)
        topo = model.Topology.from_custom_dict(original)
        self.assertEqual(original, before)
        self.assertEqual(topo.edges, [(0, 1), (1, 2)])
        self.assertEqual([topo.get_ip(i) for i in range(3)], ['10.0.0.1', '10.0.0.2', '10.0.0.3'])
        self.assertEqual(model.Topology.from_dict(topo.to_dict()).canonical_snapshot(), topo.canonical_snapshot())

    def test_save_select_and_pyvis_use_same_canonical_nodes_links(self):
        selected = adapter.save_custom_topology(definition())
        self.assertTrue((self.root / 'sample_topologies/custom_lab.json').is_file())
        self.assertIn('custom_lab', {option['case_name'] for option in adapter.get_available_topologies()})
        adapter.select_topology('case14')
        selected = adapter.select_topology('custom_lab')
        snapshot = model.get_topology().canonical_snapshot()
        self.assertEqual(selected['topology'], snapshot)
        self.assertEqual({n['id'] for n in selected['visual']['nodes']}, {n['id'] for n in snapshot['nodes']})
        nodes = json.loads(re.search(r'nodes = new vis.DataSet\((.*?)\);', selected['pyvis_html'], re.S).group(1))
        edges = json.loads(re.search(r'edges = new vis.DataSet\((.*?)\);', selected['pyvis_html'], re.S).group(1))
        self.assertEqual({n['id'] for n in nodes}, {n['id'] for n in snapshot['nodes']})
        self.assertEqual({(e['from'], e['to']) for e in edges}, {(e['from'], e['to']) for e in snapshot['links']})

    def test_custom_core_xml_and_gui_session_projection(self):
        topo = model.Topology.from_custom_dict(definition())
        with patch('testbed.generate_core_topo.load_case', side_effect=AssertionError('No preset reload')):
            path = generate_core_xml(output_path=str(self.root / 'custom.xml'), topology=topo)
        xml = validate_xml(path)
        snapshot = topo.canonical_snapshot()
        nodes = xml.findall('networks/network') + xml.findall('devices/device')
        self.assertEqual({(int(n.get('id')), n.get('name')) for n in nodes},
                         {(n['core_id'], n['hostname']) for n in snapshot['nodes']})
        ids = {n['id']: n['core_id'] for n in snapshot['nodes']}
        self.assertEqual({frozenset((int(e.get('node1')), int(e.get('node2')))) for e in xml.findall('links/link')},
                         {frozenset((ids[e['from']], ids[e['to']])) for e in snapshot['links'] if e['core_link']})
        text = Path(path).read_text()
        self.assertIn('--case 3', text)
        self.assertIn('--targets 10.0.0.1 10.0.0.2 10.0.0.3', text)
        self.assertIn('Generator', text)
        session = to_session(xml, 42)
        self.assertEqual(session.id, 42)
        self.assertEqual(len(session.nodes), 7)
        self.assertEqual(len(session.links), 6)
        self.assertTrue(all(n.canvas == 1 and n.position.x >= 0 and n.position.y >= 0 for n in session.nodes.values()))
        self.assertIn('canvas', session.metadata)

    def test_invalid_definition_never_changes_selection_or_library(self):
        selected = model.Topology.from_custom_dict(definition())
        model.set_topology(selected)
        bad = []
        for modify in (lambda d: d.update(case_name='../escape'), lambda d: d.update(nodes=[]),
                       lambda d: d['nodes'][1].update(bus_id=7), lambda d: d['nodes'][1].update(ip='10.0.0.66'),
                       lambda d: d['nodes'][0].update(type='invalid'), lambda d: d['nodes'][0].update(voltage=float('nan')),
                       lambda d: d.update(edges=[[0, 9]]), lambda d: d.update(edges=[[0, 0]]),
                       lambda d: d.update(edges=[[0, 1], [1, 0]])):
            value = definition(); modify(value); bad.append(value)
        bad += [None, [], {'case_name':'case14','nodes':definition()['nodes']}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                adapter.save_custom_topology(value)
            self.assertIs(model.get_topology(), selected)
        self.assertFalse((self.root / 'sample_topologies/custom_lab.json').exists())

    def test_running_marker_blocks_predefined_and_custom_changes(self):
        selected = model.Topology.from_custom_dict(definition())
        model.set_topology(selected)
        marker = self.root / 'core-runtime/session.json'
        marker.parent.mkdir(); marker.write_text('{"id":42}')
        with self.assertRaisesRegex(ValueError, 'owned CORE'):
            adapter.select_topology('case30')
        with self.assertRaisesRegex(ValueError, 'owned CORE'):
            adapter.save_custom_topology(definition())
        self.assertIs(model.get_topology(), selected)
        self.assertEqual(marker.read_text(), '{"id":42}')

    def test_start_core_passes_selected_model_and_identical_snapshot(self):
        from gui.campaign import CampaignController
        selected = model.Topology.from_custom_dict(definition())
        request = MagicMock(side_effect=[{'state':'STOPPED'}, {'session_id':42}])
        controller = CampaignController(request=request, topology=lambda: selected)
        with patch('gui.campaign.generate_core_xml', return_value='/tmp/custom.xml') as generate, \
             patch('gui.campaign.run_store.create_run', return_value={'scenario_id':'s','run_id':'r'}) as create, \
             patch('gui.campaign.run_store.update_run', return_value={'scenario_id':'s','run_id':'r','generation_id':'g'}), \
             patch.object(controller, '_runtime', return_value={'id':42,'generation_id':'g'}):
            controller.start_core()
        self.assertIs(generate.call_args.kwargs['topology'], selected)
        create.assert_called_once_with(selected.canonical_snapshot())
        request.assert_called_with('start', xml='/tmp/custom.xml')

    def test_saved_selection_survives_gui_restart(self):
        adapter.save_custom_topology(definition())
        expected = model.get_topology().canonical_snapshot()
        with patch.object(model, 'SELECTION_PATH', self.root / 'topology_selection.json'):
            model._current_topology = None
            self.assertEqual(model.get_topology().canonical_snapshot(), expected)


if __name__ == '__main__':
    unittest.main()
