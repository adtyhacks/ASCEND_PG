"""HTTP regressions for GUI startup reads; no CORE or campaign actions."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

from gui import adapter, imports
from gui.server import GuiHandler
from testbed import run_store, topology


class QuietGuiHandler(GuiHandler):
    def log_message(self, _format, *_args):
        return


class GuiStartupApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.data = cls.root / "data"
        cls.data.mkdir()
        cls.patchers = [
            patch.object(topology, "SELECTION_PATH", cls.data / "topology_selection.json"),
            patch.object(adapter, "DATA", cls.data),
            patch.object(imports, "PATH", cls.data / "imported_topology.json"),
            patch.object(run_store, "RUNS", cls.data / "runs"),
            patch("testbed.visualize_topology.render_topology", return_value="<html><body>topology</body></html>"),
        ]
        for patcher in cls.patchers:
            patcher.start()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietGuiHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        for patcher in reversed(cls.patchers):
            patcher.stop()
        cls.temporary.cleanup()

    def setUp(self):
        topology.SELECTION_PATH.unlink(missing_ok=True)
        imports.PATH.unlink(missing_ok=True)
        topology._current_topology = None
        topology._selection_fingerprint = None
        adapter._active_cache.clear()

    def request(self, path: str) -> tuple[int, dict]:
        try:
            with urlopen(self.base + path) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def write_selection(self, value: dict) -> None:
        topology.SELECTION_PATH.write_text(json.dumps(value), encoding="utf-8")
        topology._current_topology = None
        topology._selection_fingerprint = None

    def test_default_ieee14_startup_without_core_or_events(self):
        topology_status, topology_body = self.request("/api/topology")
        battle_status, battle_body = self.request("/api/live-battle?limit=10")
        config_status, config_body = self.request("/api/network-configuration")

        self.assertEqual((topology_status, battle_status, config_status), (200, 200, 200))
        self.assertEqual(topology_body["topology"]["case_name"], "case14")
        self.assertEqual(config_body["case_name"], "case14")
        self.assertGreater(config_body["node_count"], 0)
        self.assertIsNone(battle_body["active_run"])
        self.assertEqual(battle_body["network_events"], [])
        self.assertEqual(battle_body["security_events"], [])
        self.assertEqual(battle_body["limit"], 10)

    def test_legacy_ieee_selection_resolves_named_preset_before_validation(self):
        self.write_selection({
            "case_name": "case30",
            "nodes": [{"bus_id": 0, "type": "pq"}, {"bus_id": 1, "type": "pq"}],
            "edges": [],
        })

        topology_status, topology_body = self.request("/api/topology")
        battle_status, battle_body = self.request("/api/live-battle?limit=10")
        config_status, config_body = self.request("/api/network-configuration")

        self.assertEqual((topology_status, battle_status, config_status), (200, 200, 200))
        self.assertEqual(topology_body["topology"]["case_name"], "case30")
        self.assertEqual(config_body["case_name"], "case30")
        self.assertEqual(battle_body["topology"]["case_name"], "case30")
        self.assertEqual(battle_body["network_events"], [])

    def test_genuinely_invalid_custom_selection_remains_400(self):
        self.write_selection({
            "case_name": "custom_invalid",
            "nodes": [{"bus_id": 0, "type": "pq"}],
            "edges": [],
        })

        for path in ("/api/topology", "/api/live-battle?limit=10", "/api/network-configuration"):
            status, body = self.request(path)
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_request")
            self.assertEqual(body["error"]["message"], "Custom electrical topology must contain exactly one slack bus.")

    def test_live_battle_distinguishes_malformed_limit(self):
        for value in ("bad", "0", "501"):
            status, body = self.request(f"/api/live-battle?limit={value}")
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_request")
            self.assertEqual(body["error"]["message"], "limit must be an integer between 1 and 500")


if __name__ == "__main__":
    unittest.main()
