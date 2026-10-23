# SPDX-License-Identifier: GPL-3.0-or-later
"""Object-free counter checker controls and exact command-line modes."""

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-counter-object.py"


class CounterObjectCliTests(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(CHECKER), *arguments],
                              cwd=ROOT, text=True, capture_output=True)

    def test_self_test_runs_real_transfer_controls_without_an_object(self):
        result = self.invoke("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        controls = json.loads(result.stdout)["transfer_controls"]
        self.assertGreaterEqual(len(controls), 37)
        self.assertEqual(controls["le_equality32_oob"], "refused")
        self.assertEqual(controls["constant_left_clamp32_high_alias"], "refused")
        self.assertEqual(controls["le_healthy_index31"], "accepted")
        self.assertEqual(controls["constant_left_clamp64"], "accepted")

    def test_self_test_refuses_mixed_object_modes(self):
        for arguments in (("--mode", "counts"), ("missing.o",), ("--self-test-mutants",)):
            with self.subTest(arguments=arguments):
                result = self.invoke("--self-test", *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--self-test accepts no other arguments", result.stderr)

    def test_object_modes_still_require_both_inputs_and_exact_options(self):
        for arguments in ((), ("--mode", "counts"), ("missing.o",),
                          ("--self-test-mutants",), ("--self-t",)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
        result = self.invoke("missing.o", "--mode", "counts")
        self.assertEqual(result.returncode, 2)
        self.assertIn("counter object refused:", result.stderr)
        result = self.invoke("--self-test-m", "missing.o", "--mode", "counts")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --self-test-m", result.stderr)


if __name__ == "__main__":
    unittest.main()
