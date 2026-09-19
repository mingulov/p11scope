# SPDX-License-Identifier: GPL-3.0-or-later
"""Subset-oracle behavior: python3 -I tests/python/test_subset_oracle.py."""

import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
ORACLE = runpy.run_path(str(ROOT / "scripts/check-subset-oracle.py"))
ZERO_RV = "0x0000000000000000"


class SubsetOracleTests(unittest.TestCase):
    def run_oracle(self, records, functions, mutate_evidence=None, *, cli=False):
        evidence = CHECKER["evidence_fixture"](
            CHECKER["LEGACY_SURFACES"], sources=("manifest",)
        )
        evidence.update(table_entries=68, slots=68, attached_probes=136)
        if mutate_evidence:
            mutate_evidence(evidence)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.jsonl"
            observed = Path(directory) / "observed.json"
            report.write_text("".join(json.dumps(record) + "\n" for record in records))
            observed.write_text(json.dumps({"functions": functions, "evidence": evidence}))
            if cli:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "scripts/check-subset-oracle.py"),
                        str(report),
                        str(observed),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                )
                return result.returncode, result.stdout + result.stderr
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ORACLE["check_subset_oracle"](report, observed)
            return status, output.getvalue()

    @staticmethod
    def teardown(trace=None, nodeid="test_ok"):
        properties = [] if trace is None else [["pkcs11_rv_trace", trace]]
        return {"when": "teardown", "nodeid": nodeid, "user_properties": properties}

    @staticmethod
    def call(function="C_Initialize", rv=0):
        return {"fn": function, "rv": rv}

    @staticmethod
    def captured(function="C_Initialize", calls=1, rv_count=1):
        return {"names": [function], "calls": calls, "rv_counts": {ZERO_RV: rv_count}}

    def assert_rejected(self, records, functions, mutate_evidence=None):
        status, output = self.run_oracle(records, functions, mutate_evidence)
        self.assertEqual(status, 1, output)
        return output

    def test_nonempty_report_without_trace_is_rejected(self):
        output = self.assert_rejected([self.teardown()], [])
        self.assertIn("no independent PKCS#11 calls", output)

    def test_empty_trace_is_rejected(self):
        output = self.assert_rejected([self.teardown([])], [])
        self.assertIn("0 total calls logged", output)

    def test_excluded_only_trace_is_rejected(self):
        excluded = (
            "src/pkcs11_check/testcases/test_interface.py::"
            "TestInterfaceV32::test_v32_interface_negotiated"
        )
        self.assertEqual(ORACLE["KNOWN_ORACLE_MISATTRIBUTION_NODEIDS"], {excluded})
        output = self.assert_rejected(
            [self.teardown([self.call()], nodeid=excluded)], []
        )
        self.assertIn("excluded 1 teardown record", output)
        self.assertIn("no independent PKCS#11 calls", output)

    def test_actual_trace_pair_passes(self):
        status, output = self.run_oracle(
            [self.teardown([self.call()])], [self.captured()], cli=True
        )
        self.assertEqual(status, 0, output)

    def test_call_phase_copy_is_not_double_counted(self):
        call = {
            "when": "call",
            "nodeid": "test_ok",
            "user_properties": [["pkcs11_rv_trace", [self.call()]]],
        }
        status, output = self.run_oracle(
            [call, self.teardown([self.call()])], [self.captured()]
        )
        self.assertEqual(status, 0, output)

    def test_missing_captured_pair_is_rejected(self):
        output = self.assert_rejected(
            [self.teardown([self.call("C_Finalize")])], [self.captured()]
        )
        self.assertIn("C_Finalize", output)
        self.assertIn("capture has 0", output)

    def test_insufficient_capture_count_is_rejected(self):
        output = self.assert_rejected(
            [self.teardown([self.call(), self.call()])], [self.captured()]
        )
        self.assertIn("oracle logged 2, capture has 1", output)

    def test_surplus_capture_passes(self):
        status, output = self.run_oracle(
            [self.teardown([self.call()])],
            [self.captured(), self.captured("C_Login", calls=3, rv_count=3)],
        )
        self.assertEqual(status, 0, output)
        self.assertIn("capture-only: C_Login calls=3", output)

    def test_dirty_evidence_is_rejected(self):
        output = self.assert_rejected(
            [self.teardown([self.call()])],
            [self.captured()],
            lambda evidence: evidence.update(event_loss=1),
        )
        self.assertIn("terminal evidence:", output)

    def test_no_probe_evidence_is_rejected(self):
        output = self.assert_rejected(
            [self.teardown([self.call()])],
            [self.captured()],
            lambda evidence: evidence.update(attached_probes=0),
        )
        self.assertIn("no probes attached", output)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    raise SystemExit(
        0 if result.testsRun > 0 and result.wasSuccessful() and not result.skipped else 1
    )
