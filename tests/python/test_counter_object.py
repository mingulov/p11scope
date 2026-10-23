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

    def test_bank_proof_profile_is_explicit_and_counts_only(self):
        result = self.invoke("--profile", "counts-bank-proof", "--mode", "counts", "missing.o")
        self.assertEqual(result.returncode, 2)
        self.assertIn("counter object refused:", result.stderr)
        for mode in ("timestamps", "latency"):
            with self.subTest(mode=mode):
                result = self.invoke("--profile", "counts-bank-proof", "--mode", mode,
                                     "missing.o")
                self.assertEqual(result.returncode, 2)
                self.assertIn("bank proof requires counts", result.stderr)
        result = self.invoke("--self-test", "--profile", "counts-bank-proof")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--self-test accepts no other arguments", result.stderr)

    def test_bank_proof_controls_preserve_inactive_and_owned_return_boundaries(self):
        result = self.invoke("--self-test-bank-proof")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], "p11scope-counter-bank-controls/v1")
        controls = report["controls"]
        for name in ("inactive_entry", "precommit_return_after_commit",
                     "absent_return_preserves_other_start", "absent_return_preserves_lost_debt",
                     "old_bank_keeps_original_transaction", "missing_route_retires_start",
                     "failed_retirement_keeps_debt", "full_width_transaction"):
            self.assertEqual(controls[name], "accepted", name)
        for arguments in (("--mode", "counts"), ("missing.o",),
                          ("--profile", "counts-bank-proof"), ("--self-test-mutants",)):
            with self.subTest(arguments=arguments):
                result = self.invoke("--self-test-bank-proof", *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--self-test-bank-proof accepts no other arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
