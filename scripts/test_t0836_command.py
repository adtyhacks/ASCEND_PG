"""Focused T0836 command-construction regression; executes no attack."""
import unittest

from scripts.testbed_executor import build_step


class T0836CommandTests(unittest.TestCase):
    def test_fdi_value_is_present_once_as_scaled_integer(self):
        magnitude = 1.077777777777778
        step = build_step(
            "T0836",
            target_ip="10.0.0.14",
            register_address=40002,
            value_magnitude=magnitude,
        )

        self.assertIsNotNone(step)
        args = step["args"]
        self.assertEqual(args.count("-a"), 1)
        self.assertEqual(args[args.index("-a") + 1], "40002")
        self.assertEqual(args.count("-v"), 1)
        value = args[args.index("-v") + 1]
        self.assertEqual(value, str(round(9999 * magnitude)))
        self.assertIsInstance(int(value), int)


if __name__ == "__main__":
    unittest.main()
