"""Focused T0855 command-construction regression; executes no attack."""
import unittest

from attacks.cmd_inject_coil import str2bool
from scripts.testbed_executor import WSL_LOG_PATH, build_step


class T0855CommandTests(unittest.TestCase):
    def test_coil_command_has_one_address_and_one_boolean_value(self):
        magnitude = 0.9444444444444445
        step = build_step(
            "T0855",
            target_ip="10.0.0.6",
            register_address=40034,
            value_magnitude=magnitude,
        )

        self.assertIsNotNone(step)
        self.assertEqual(step["name"], "cmd_inject_coil")
        args = step["args"]

        self.assertEqual(args.count("--target"), 1)
        self.assertEqual(args[args.index("--target") + 1], "10.0.0.6")
        self.assertEqual(args.count("--address"), 1)
        self.assertEqual(args[args.index("--address") + 1], "40034")
        self.assertEqual(args.count("--value"), 1)
        value = args[args.index("--value") + 1]
        self.assertEqual(value, "True")
        self.assertIs(str2bool(value), True)
        self.assertNotEqual(value, str(magnitude))

        self.assertEqual(args[args.index("--count") + 1], "5")
        self.assertEqual(args[args.index("--log") + 1], WSL_LOG_PATH)


if __name__ == "__main__":
    unittest.main()
