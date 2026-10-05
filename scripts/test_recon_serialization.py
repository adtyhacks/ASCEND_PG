"""Deterministic recon logging regression; no network or runtime execution."""
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime, timedelta
from pathlib import Path

from attacks.recon_step import log_event, nmap_sweep
from testbed.ip_config import get_plc_ip


class ReconSerializationTests(unittest.TestCase):
    def test_sweep_preserves_requested_range_and_discovers_core_plcs(self):
        for case in (14, 30):
            targets = [get_plc_ip(bus) for bus in range(case)]
            output = "\n".join(
                f"Host: {ip} () Ports: 502/open/tcp//mbap///" for ip in targets
            )
            for subnet in ("10.0.0.0/24", "10.0.0.1-30", "10.0.0.8/29"):
                with self.subTest(case=case, subnet=subnet), tempfile.TemporaryDirectory() as directory:
                    with patch("attacks.recon_step.subprocess.run",
                               return_value=SimpleNamespace(stdout=output)) as run:
                        found = nmap_sweep(subnet, Path(directory) / "recon.jsonl")
                    self.assertEqual(found, targets)
                    run.assert_called_once_with(
                        ["nmap", "-p", "502", "--open", "-T4", "--host-timeout", "10s",
                         "--max-retries", "1", "-oG", "-", subnet],
                        capture_output=True, text=True, timeout=120,
                    )

    def test_device_identification_bytes_and_nested_values(self):
        cases = [
            ({0: b"ASCEND-PG", 1: b"PLC-B0", 2: b"2.0"},
             {"0": "ASCEND-PG", "1": "PLC-B0", "2": "2.0"}),
            ({0: [b"vendor", {"product": b"PLC", "binary": b"\xff\x00"}],
              1: b"", 2: "unchanged", 3: None, 4: 7},
             {"0": ["vendor", {"product": "PLC", "binary": "ff00"}],
              "1": "", "2": "unchanged", "3": None, "4": 7}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs" / "recon.jsonl"
            for info, expected in cases:
                event = {"stage": "recon", "technique": "T0888",
                         "action": "device_id_query_result",
                         "target": "10.0.0.1", "info": info}
                log_event(path, event)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), len(cases))
            for line, (_, expected) in zip(lines, cases):
                with self.subTest(info=expected):
                    record = json.loads(line)
                    timestamp = record.pop("timestamp")
                    self.assertEqual(datetime.fromisoformat(timestamp).utcoffset(), timedelta(0))
                    self.assertEqual(record, {
                        "stage": "recon", "technique": "T0888",
                        "action": "device_id_query_result", "target": "10.0.0.1",
                        "info": expected,
                    })


if __name__ == "__main__":
    unittest.main()
