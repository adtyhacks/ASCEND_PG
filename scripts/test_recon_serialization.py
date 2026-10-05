"""Deterministic recon logging regression; no network or runtime execution."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from attacks.recon_step import log_event


class ReconSerializationTests(unittest.TestCase):
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
