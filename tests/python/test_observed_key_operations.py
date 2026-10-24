#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observer-side RSA oracle: observed units must match the independent ledger.

The application ledger (built by test_key_operation_ledger's workload
builder, the same fixed 68-call SoftHSM shape) is the independent
denominator. Canned observer outputs under
tests/fixtures/key-operations/observed/ stand in for the installed
`p11scope/inventory/v1` document's `object_observations` section until the
Joint driver lands: only clean.json is accepted, and each twin must be
refused naming its targeted condition. Fixture `encoded_bytes` is
illustrative, never asserted. No fixture, input, output or diagnostic here
carries PIN, key, payload, handle or arbitrary bytes.

Run: python3 -I tests/python/test_observed_key_operations.py -v
"""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualify_key_operations", ROOT / "scripts" / "qualify-key-operations.py"
)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)
APP_SPEC = importlib.util.spec_from_file_location(
    "key_operation_ledger_tests",
    ROOT / "tests" / "python" / "test_key_operation_ledger.py",
)
APP_TESTS = importlib.util.module_from_spec(APP_SPEC)
APP_SPEC.loader.exec_module(APP_TESTS)
OBSERVED = ROOT / "tests" / "fixtures" / "key-operations" / "observed"


def observed(name):
    with open(OBSERVED / name, encoding="utf-8") as stream:
        return json.load(stream)


class ObservedRsaTests(unittest.TestCase):
    maxDiff = 4096

    def assert_refused(self, rows, doc, token):
        with self.assertRaises(ORACLE.OracleRefusal) as caught:
            ORACLE.compare(rows, doc)
        self.assertIn(token, str(caught.exception))

    def test_observed_rsa_units_match_independent_ledger(self):
        result = ORACLE.compare(APP_TESTS.application_rows(), observed("clean.json"))
        self.assertTrue(result.get("match"))
        application = result.get("application", {})
        self.assertEqual(application.get("api_calls"), 68)
        self.assertEqual(application.get("operations"),
                         {"sign": {"completed": 10, "failed": 0},
                          "verify": {"completed": 10, "failed": 2}})
        calls = application.get("calls_by_function", {})
        self.assertEqual((calls.get("C_Sign"), calls.get("C_SignUpdate"), calls.get("C_Verify")),
                         (9, 9, 12))
        seen = result.get("observed", {})
        self.assertEqual(seen.get("sign"), {"started": 10, "completed": 10, "failed": 0})
        self.assertEqual(seen.get("verify"), {"started": 12, "completed": 10, "failed": 2})

    def test_cancellation_twin_is_refused(self):
        self.assert_refused(APP_TESTS.application_rows(), observed("cancelled.json"),
                            "cancelled")

    def test_metadata_conflict_twin_is_refused(self):
        self.assert_refused(APP_TESTS.application_rows(),
                            observed("metadata-conflict.json"), "metadata_conflicting")

    def test_reused_handle_twin_is_refused(self):
        self.assert_refused(APP_TESTS.application_rows(), observed("reused-handle.json"),
                            "handle_reuse")

    def test_missing_return_twin_is_refused(self):
        self.assert_refused(APP_TESTS.application_rows(), observed("missing-return.json"),
                            "unknown")

    def test_loss_twin_is_refused(self):
        self.assert_refused(APP_TESTS.application_rows(), observed("loss.json"), "loss")

    def test_inventory_document_dispatch(self):
        rows = APP_TESTS.application_rows()
        doc = {"schema": "p11scope/inventory/v1",
               "object_observations": observed("clean.json")}
        result = ORACLE.compare(rows, doc)
        self.assertTrue(result.get("match"))
        seen = result.get("observed", {})
        self.assertEqual(seen.get("verify", {}).get("failed"), 2)

    def test_unexpected_schema_is_refused(self):
        rows = APP_TESTS.application_rows()
        doc = {"schema": "p11scope/inventory/v9",
               "object_observations": observed("clean.json")}
        with self.assertRaises(ORACLE.OracleRefusal):
            ORACLE.compare(rows, doc)

    def test_unavailable_status_is_refused(self):
        doc = observed("clean.json")
        doc["status"] = "unavailable"
        doc["reason"] = "authority_lost"
        self.assert_refused(APP_TESTS.application_rows(), doc, "unavailable")

    def test_unknown_fields_enums_and_equation_are_refused(self):
        rows = APP_TESTS.application_rows()
        with self.subTest("extra key"):
            doc = observed("clean.json")
            doc["key_operations"][0]["signature"] = "forbidden-bytes"
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("unexpected fields", str(caught.exception))
            self.assertNotIn("forbidden-bytes", str(caught.exception))
        with self.subTest("bad enum"):
            doc = observed("clean.json")
            doc["key_operations"][0]["category"] = "C_Fabricated"
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertNotIn("C_Fabricated", str(caught.exception))
        with self.subTest("equation"):
            doc = observed("clean.json")
            doc["key_operations"][0]["started"] = 999
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("equation", str(caught.exception))

    def test_message_contexts_and_secondary_roles_never_count(self):
        rows = APP_TESTS.application_rows()
        with self.subTest("message unit"):
            doc = observed("clean.json")
            extra = copy.deepcopy(doc["key_operations"][0])
            extra.update(category="message_sign", unit="message_contexts", started=2,
                         completed=2)
            doc["key_operations"].append(extra)
            doc["budgets"]["key_rows"]["occupied"] = 3
            self.assert_refused(rows, doc, "message_contexts")
        with self.subTest("secondary role"):
            doc = observed("clean.json")
            doc["key_operations"][0]["role"] = "wrapped_object"
            self.assert_refused(rows, doc, "wrapped_object")

    def test_application_ledger_mismatch_is_refused(self):
        rows = APP_TESTS.application_rows()
        rows.remove(next(r for r in rows if r["kind"] == "call" and r["fn"] == "C_SignUpdate"))
        self.assert_refused(APP_TESTS.resequence(rows), observed("clean.json"), "application")

    def test_cli_accepts_clean_pair_and_refuses_twins(self):
        command = [sys.executable, str(ROOT / "scripts/qualify-key-operations.py")]
        with tempfile.TemporaryDirectory(prefix="p11scope-observed-rsa-") as directory:
            application = Path(directory, "application.jsonl")
            application.write_text("".join(json.dumps(row) + "\n"
                                           for row in APP_TESTS.application_rows()),
                                   encoding="utf-8")
            clean = Path(directory, "clean.json")
            clean.write_text(json.dumps(observed("clean.json")), encoding="utf-8")
            twin = Path(directory, "cancelled.json")
            twin.write_text(json.dumps(observed("cancelled.json")), encoding="utf-8")
            result = subprocess.run(command + [str(application), str(clean)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout).get("match"))
            result = subprocess.run(command + [str(application), str(twin)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stdout, "")
            self.assertIn("cancelled", result.stderr)

    def test_observer_input_bounds(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-observed-bounds-") as directory:
            path = Path(directory, "observer.json")
            with self.subTest("oversize"):
                path.write_text('{"pad": "' + "x" * (ORACLE.MAX_OBSERVER_BYTES + 1) + '"}',
                                encoding="utf-8")
                with self.assertRaises(ORACLE.OracleRefusal):
                    ORACLE.read_observer_file(path)
            with self.subTest("duplicate keys"):
                path.write_text('{"version": 1, "version": 2}\n', encoding="utf-8")
                with self.assertRaises(ORACLE.OracleRefusal):
                    ORACLE.read_observer_file(path)
            with self.subTest("non-object"):
                path.write_text('[1, 2]\n', encoding="utf-8")
                with self.assertRaises(ORACLE.OracleRefusal):
                    ORACLE.read_observer_file(path)


if __name__ == "__main__":
    unittest.main()
