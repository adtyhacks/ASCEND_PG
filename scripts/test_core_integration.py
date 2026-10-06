"""Focused regression tests; no daemon or application dependencies required."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from testbed.generate_core_topo import generate_core_xml
from testbed.core_xml import validate_xml
from testbed.core_services import SERVICE, node_templates


class CoreXmlTests(unittest.TestCase):
    def generate(self, directory, case=14):
        nodes = [{"bus_id": i, "voltage": 1.0, "plc_type": "generic_modbus"} for i in range(case)]
        with patch("testbed.generate_core_topo.load_case", return_value=SimpleNamespace(num_buses=case, nodes=nodes)):
            return Path(generate_core_xml(case, str(Path(directory) / "topology.xml")))

    def test_both_sizes_and_startup_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            for case in (14, 30):
                path = self.generate(directory, case)
                root = validate_xml(path)
                self.assertEqual(len(root.findall("devices/device")), case + 3)
                self.assertEqual(len(root.findall("links/link")), case + 3)
                text = path.read_text()
                self.assertNotIn("UserDefined", text)
                self.assertIn("--targets", text)
                self.assertIn(f"--bus-id {case - 1}", text)
                self.assertIn(f"--case {case}", text)
                self.assertIn("--node-json", text)

    def test_duplicate_ip_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.generate(directory)
            root = ET.parse(path)
            interfaces = root.findall("links/link/iface1")
            interfaces[1].set("ip4", interfaces[0].get("ip4"))
            root.write(path)
            with self.assertRaisesRegex(ValueError, "Duplicate IP"):
                validate_xml(path)

    def test_unregistered_service_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.generate(directory)
            path.write_text(path.read_text().replace(SERVICE, "UserDefined"))
            with self.assertRaisesRegex(ValueError, "Unsupported/unregistered"):
                validate_xml(path)

    def test_missing_startup_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.generate(directory)
            root = ET.parse(path)
            templates = root.find("service_configurations/service/templates")
            templates.remove(templates[0])
            root.write(path)
            with self.assertRaisesRegex(ValueError, "Missing service"):
                validate_xml(path)

    def test_unsafe_xml_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.xml"
            path.write_text('<!DOCTYPE scenario [<!ENTITY x "bad">]><scenario/>')
            with self.assertRaisesRegex(ValueError, "DTD"):
                validate_xml(path)

    def test_quote_configured_interpreter(self):
        with patch.dict(os.environ, {"ASCEND_APP_PYTHON": "/tmp/path with spaces/python"}):
            scripts = node_templates("plc", 30, "10.0.0.30", 29)
            self.assertIn("'/tmp/path with spaces/python'", scripts["ascend-start.sh"])
            self.assertIn("socket.create_connection", scripts["ascend-validate.sh"])


class CoreLifecycleTests(unittest.TestCase):
    def test_gui_launch_attaches_owned_session_directly(self):
        from scripts import core_session as manager
        session = SimpleNamespace(id=7, state=manager.w.SessionState.RUNTIME)
        with patch.object(manager, "owned_session", return_value=session), \
                patch.dict(os.environ, {"DISPLAY": ":0", "ASCEND_CORE_GUI": "/configured/core-gui"}), \
                patch.object(manager.os, "access", return_value=True), \
                patch.object(manager.subprocess, "Popen", return_value=SimpleNamespace(pid=123)) as launch:
            result = manager.perform(MagicMock(), {"action": "gui"})
        self.assertEqual(result, {"session_id": 7, "gui_pid": 123})
        launch.assert_called_once_with(
            ["/configured/core-gui", "--session", "7"], cwd=manager.ROOT,
            stdout=manager.subprocess.DEVNULL, stderr=manager.subprocess.DEVNULL,
            start_new_session=True,
        )

    def test_grpc_hub_interfaces_are_unique(self):
        from testbed.core_xml import to_session
        with tempfile.TemporaryDirectory() as directory:
            path = CoreXmlTests().generate(directory, 30)
            session = to_session(validate_xml(path), 123)
            ids = [link.iface2.id for link in session.links]
            self.assertEqual(len(ids), 33)
            self.assertEqual(len(set(ids)), 33)

    def test_startup_failure_deletes_only_allocated_session(self):
        from scripts import core_session as manager
        with tempfile.TemporaryDirectory() as directory:
            path = CoreXmlTests().generate(directory)
            state = Path(directory) / "state.json"
            c = MagicMock()
            c.address = "localhost:50051"
            c.create_session.return_value = SimpleNamespace(id=123)
            c.start_session.return_value = (False, ["service failed"])
            c.delete_session.return_value = True
            with patch.object(manager, "STATE", state), patch.object(manager, "preflight"), patch.object(manager, "register"):
                with self.assertRaisesRegex(RuntimeError, "service failed"):
                    manager.perform(c, {"action": "start", "xml": str(path)})
            c.delete_session.assert_called_once_with(123)
            self.assertFalse(state.exists())

    def test_reused_session_id_is_not_deleted(self):
        from scripts import core_session as manager
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text('{"id": 123, "token": "ours", "endpoint": "localhost:50051"}')
            c = MagicMock()
            c.address = "localhost:50051"
            c.check_session.return_value = True
            c.get_session.return_value = SimpleNamespace(metadata={"ascend_owner": "someone-else"})
            with patch.object(manager, "STATE", state):
                with self.assertRaisesRegex(RuntimeError, "ownership mismatch"):
                    manager.perform(c, {"action": "stop"})
            c.delete_session.assert_not_called()

    def test_failed_cleanup_retains_session_id(self):
        from scripts import core_session as manager
        with tempfile.TemporaryDirectory() as directory:
            path = CoreXmlTests().generate(directory)
            state = Path(directory) / "state.json"
            c = MagicMock()
            c.address = "localhost:50051"
            c.create_session.return_value = SimpleNamespace(id=123)
            c.start_session.return_value = (False, ["service failed"])
            c.delete_session.return_value = False
            with patch.object(manager, "STATE", state), patch.object(manager, "preflight"), patch.object(manager, "register"):
                with self.assertRaisesRegex(RuntimeError, "cleanup failed for session 123"):
                    manager.perform(c, {"action": "start", "xml": str(path)})
            self.assertTrue(state.exists())


if __name__ == "__main__":
    unittest.main()
