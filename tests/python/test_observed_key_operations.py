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

S1 twins preserve historical observed-parent comparisons and the current
physical 68/instance 65 topology, including the actual stopped-child disclosure.
They keep the exact operation/mechanism ledger denominator and unavailable
journal guard. Lifetime EVENTS and actual stop accounting remain separate
live-controller receipts, never invented Inventory fields.

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


def full_doc(section, edges):
    return {"schema": "p11scope/inventory/v1",
            "object_observations": section, "edges": edges}


def mech_row(mechanism=0x40, name="CKM_SHA256_RSA_PKCS",
             operations=("sign", "verify"), calls=55, errors=3,
             last_seen_ns=190, functions=("C_SignInit", "C_VerifyInit"),
             returns=((0, "CKR_OK"),), truncated=False):
    return {"mechanism": mechanism, "mechanism_hex": f"0x{mechanism:x}",
            "name": name, "operations": list(operations), "calls": calls,
            "errors": errors, "last_seen_ns": last_seen_ns,
            "evidence": {"functions": list(functions),
                         "returns": [{"rv": rv, "rv_hex": f"0x{rv:x}", "name": rname}
                                     for rv, rname in returns],
                         "truncated": truncated}}


def keygen_row():
    return mech_row(mechanism=0x0, name="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    operations=("generate_key_pair",), calls=1, errors=0,
                    functions=("C_GenerateKeyPair",))


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


    def test_non_list_row_arrays_are_refused(self):
        rows = APP_TESTS.application_rows()
        for field in ("key_operations", "unknown_key_operations"):
            for bad in (None, 123):
                with self.subTest(field=field, bad=repr(bad)):
                    doc = observed("clean.json")
                    doc[field] = bad
                    with self.assertRaises(ORACLE.OracleRefusal) as caught:
                        ORACLE.compare(rows, doc)
                    self.assertIn("unexpected fields", str(caught.exception))

    def test_cli_refuses_non_list_rows_without_traceback(self):
        command = [sys.executable, str(ROOT / "scripts/qualify-key-operations.py")]
        with tempfile.TemporaryDirectory(prefix="p11scope-observed-nonlist-") as directory:
            application = Path(directory, "application.jsonl")
            application.write_text("".join(json.dumps(row) + "\n"
                                           for row in APP_TESTS.application_rows()),
                                   encoding="utf-8")
            bad = observed("clean.json")
            bad["key_operations"] = None
            observer = Path(directory, "observer.json")
            observer.write_text(json.dumps(bad), encoding="utf-8")
            result = subprocess.run(command + [str(application), str(observer)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stdout, "")
            self.assertIn("unexpected fields", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_mechanism_dimension_is_checked_when_edges_present(self):
        rows = APP_TESTS.application_rows()
        edges = [{"mechanisms": [keygen_row(), mech_row()]}]
        result = ORACLE.compare(rows, full_doc(observed("clean.json"), edges))
        self.assertTrue(result.get("match"))
        seen = result.get("observed", {})
        self.assertIn("mechanism", seen)
        self.assertEqual(seen.get("mechanism"),
                         {"mechanism": 64, "mechanism_hex": "0x40",
                          "name": "CKM_SHA256_RSA_PKCS",
                          "operations": ["sign", "verify"]})
        application = result.get("application", {})
        self.assertEqual(application.get("mechanism"), "CKM_SHA256_RSA_PKCS")

    def test_bare_section_leaves_mechanism_unknown(self):
        result = ORACLE.compare(APP_TESTS.application_rows(), observed("clean.json"))
        self.assertTrue(result.get("match"))
        seen = result.get("observed", {})
        self.assertIn("mechanism", seen)
        self.assertIsNone(seen.get("mechanism"))

    def test_mechanism_twins_are_refused(self):
        rows = APP_TESTS.application_rows()
        other_sign = mech_row(mechanism=0x41, name="CKM_SHA1_RSA_PKCS",
                              operations=("sign",))
        wrong_hex = mech_row()
        wrong_hex["mechanism_hex"] = "0x41"
        cases = [
            ("null mechanisms", [{"mechanisms": None}], "missing expected mechanism"),
            ("keygen only", [{"mechanisms": [keygen_row()]}],
             "missing expected mechanism"),
            ("empty edges", [], "missing expected mechanism"),
            ("sign under other id", [{"mechanisms": [mech_row(), other_sign]}],
             "inconsistent_mechanism"),
            ("name mismatch", [{"mechanisms": [mech_row(name=None)]}],
             "unexpected mechanism name"),
            ("hostile name", [{"mechanisms": [mech_row(name="HOSTILE-MECH-NAME")]}],
             "unexpected mechanism name"),
            ("hex mismatch", [{"mechanisms": [wrong_hex]}], "mechanism hex"),
            ("operations incomplete",
             [{"mechanisms": [mech_row(operations=("sign",))]}],
             "missing expected operations"),
            ("truncated provenance", [{"mechanisms": [mech_row(truncated=True)]}],
             "truncated"),
            ("zero calls", [{"mechanisms": [mech_row(calls=0)]}],
             "without calls"),
            ("edges not a list", {"mechanisms": [mech_row()]},
             "unexpected edges shape"),
            ("mechanisms not a list", [{"mechanisms": {"0x40": {}}}],
             "unexpected mechanisms shape"),
            ("row missing keys", [{"mechanisms": [{"mechanism": 64}]}],
             "unexpected fields"),
            ("operations out of order",
             [{"mechanisms": [mech_row(operations=("verify", "sign"))]}],
             "mechanism operations out of order"),
            ("mechanism ids out of order",
             [{"mechanisms": [mech_row(), keygen_row()]}],
             "mechanism rows out of order"),
            ("duplicate mechanism id",
             [{"mechanisms": [mech_row(), mech_row()]}],
             "mechanism rows out of order"),
        ]
        for label, edges, token in cases:
            with self.subTest(label):
                doc = full_doc(observed("clean.json"), edges)
                with self.assertRaises(ORACLE.OracleRefusal) as caught:
                    ORACLE.compare(rows, doc)
                self.assertIn(token, str(caught.exception))
                self.assertNotIn("HOSTILE-MECH-NAME", str(caught.exception))

    def test_row_budget_occupancy_cannot_exceed_limit(self):
        rows = APP_TESTS.application_rows()
        with self.subTest("key rows over limit"):
            doc = observed("clean.json")
            base = {"object": 11, "category": "sign", "role": "key",
                    "metadata_at_use": "rsa_2048", "unit": "operations",
                    "started": 0, "completed": 0, "failed": 0, "cancelled": 0,
                    "unknown": 0, "active": 0, "key_join_lost": 0}
            for index in range(2, 65537):
                doc["key_operations"].append(dict(base, instance=f"i{index}"))
            doc["key_operations"].sort(key=lambda item: (item["instance"], item["object"],
                                                         item["category"], item["role"],
                                                         item["metadata_at_use"]))
            doc["budgets"]["key_rows"]["occupied"] = len(doc["key_operations"])
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("exceeds", str(caught.exception))
        with self.subTest("object rows over limit"):
            doc = observed("clean.json")
            template = doc["objects"][0]
            for obj_id in range(13, 13 + 65535):
                row = copy.copy(template)
                row["object"] = obj_id
                doc["objects"].append(row)
            doc["objects"].sort(key=lambda item: item["object"])
            doc["budgets"]["object_rows"]["occupied"] = len(doc["objects"])
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("exceeds", str(caught.exception))

    def test_gap_rows_cannot_exceed_capacity(self):
        rows = APP_TESTS.application_rows()
        doc = observed("clean.json")
        doc["gaps"]["rows"] = [{"subject": "model", "reason": "loss",
                                "repeats": 1}] * 257
        with self.assertRaises(ORACLE.OracleRefusal) as caught:
            ORACLE.compare(rows, doc)
        self.assertIn("too many", str(caught.exception))

    def test_metadata_block_cells_are_validated(self):
        rows = APP_TESTS.application_rows()
        fields = ("class", "key_type", "token", "value_len", "modulus_bits",
                  "ec_params")
        for block in ("requested", "established"):
            for field in fields:
                with self.subTest(block=block, field=field):
                    doc = observed("clean.json")
                    doc["objects"][0][block][field] = "HOSTILE-PAYLOAD"
                    with self.assertRaises(ORACLE.OracleRefusal) as caught:
                        ORACLE.compare(rows, doc)
                    self.assertNotIn("HOSTILE-PAYLOAD", str(caught.exception))
        with self.subTest("scalar out of range"):
            doc = observed("clean.json")
            doc["objects"][0]["requested"]["class"] = {"status": "value",
                                                       "value": 999999}
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("invalid metadata scalar", str(caught.exception))
        for field, value in (("class", 5), ("key_type", 5), ("token", True),
                             ("value_len", 8), ("modulus_bits", 1536)):
            with self.subTest("scalar outside its field", field=field):
                doc = observed("clean.json")
                doc["objects"][0]["established"][field] = {"status": "value",
                                                           "value": value}
                with self.assertRaises(ORACLE.OracleRefusal) as caught:
                    ORACLE.compare(rows, doc)
                self.assertIn("invalid metadata scalar", str(caught.exception))
        with self.subTest("bad status"):
            doc = observed("clean.json")
            doc["objects"][0]["established"]["modulus_bits"] = {"status": "BOGUS",
                                                                "value": 2048}
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("metadata field status", str(caught.exception))
            self.assertNotIn("BOGUS", str(caught.exception))
        with self.subTest("bad curve"):
            doc = observed("clean.json")
            doc["objects"][0]["requested"]["ec_params"] = {"status": "value",
                                                           "value": "not-a-curve"}
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("unexpected metadata curve", str(caught.exception))
            self.assertNotIn("not-a-curve", str(caught.exception))
        with self.subTest("missing value key"):
            doc = observed("clean.json")
            doc["objects"][0]["established"]["token"] = {"status": "value"}
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("unexpected fields", str(caught.exception))
        with self.subTest("valid curve accepted"):
            doc = observed("clean.json")
            doc["objects"][0]["requested"]["ec_params"] = {"status": "value",
                                                           "value": "secp256r1"}
            result = ORACLE.compare(rows, doc)
            self.assertTrue(result.get("match"))

    def test_all_zero_non_cell_rows_are_tolerated(self):
        rows = APP_TESTS.application_rows()
        zero = {"started": 0, "completed": 0, "failed": 0, "cancelled": 0,
                "unknown": 0, "active": 0, "key_join_lost": 0}
        cases = [
            ("zero digest category", {"instance": "i1", "object": 11,
                                      "category": "digest", "role": "key",
                                      "metadata_at_use": "rsa_2048",
                                      "unit": "operations"}),
            ("zero secondary role", {"instance": "i1", "object": 11,
                                      "category": "sign",
                                      "role": "wrapped_object",
                                      "metadata_at_use": "rsa_2048",
                                      "unit": "operations"}),
            ("zero message unit", {"instance": "i1", "object": 11,
                                    "category": "message_sign", "role": "key",
                                    "metadata_at_use": "rsa_2048",
                                    "unit": "message_contexts"}),
            ("zero other metadata", {"instance": "i1", "object": 11,
                                      "category": "sign", "role": "key",
                                      "metadata_at_use": "rsa_1024",
                                      "unit": "operations"}),
        ]
        for label, key in cases:
            with self.subTest(label):
                doc = observed("clean.json")
                doc["key_operations"].append(dict(key, **zero))
                doc["key_operations"].sort(key=lambda item: (item["instance"],
                                                             item["object"],
                                                             item["category"],
                                                             item["role"],
                                                             item["metadata_at_use"]))
                doc["budgets"]["key_rows"]["occupied"] = 3
                result = ORACLE.compare(rows, doc)
                self.assertTrue(result.get("match"))
                seen = result.get("observed", {})
                self.assertEqual(seen.get("sign"), {"started": 10, "completed": 10,
                                                    "failed": 0})
        with self.subTest("nonzero digest still refused"):
            doc = observed("clean.json")
            row = {"instance": "i1", "object": 11, "category": "digest",
                   "role": "key", "metadata_at_use": "rsa_2048",
                   "unit": "operations", "started": 1, "completed": 1,
                   "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
                   "key_join_lost": 0}
            doc["key_operations"].append(row)
            doc["key_operations"].sort(key=lambda item: (item["instance"],
                                                         item["object"],
                                                         item["category"],
                                                         item["role"],
                                                         item["metadata_at_use"]))
            doc["budgets"]["key_rows"]["occupied"] = 3
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE.compare(rows, doc)
            self.assertIn("unexpected observed category digest",
                          str(caught.exception))

    def test_oracle_tables_match_frozen_schema(self):
        with open(ROOT / "docs" / "schema"
                  / "inventory-v1-object-observations.schema.json",
                  encoding="utf-8") as stream:
            schema = json.load(stream)
        defs = schema["$defs"]
        enums = [
            ("STATUSES", ORACLE.STATUSES, schema["properties"]["status"]["enum"]),
            # The script carries the new S1 unavailable reason ahead of the
            # schema file; the union stays correct once the schema freeze
            # adds it, when this line can go back to a plain comparison.
            ("REASONS", ORACLE.REASONS,
             set(schema["properties"]["reason"]["enum"]) | {"journal_unavailable"}),
            ("SESSION_ORIGINS", ORACLE.SESSION_ORIGINS,
             defs["session_row"]["properties"]["origin"]["enum"]),
            ("SESSION_STATUSES", ORACLE.SESSION_STATUSES,
             defs["session_row"]["properties"]["status"]["enum"]),
            ("OBJECT_ORIGINS", ORACLE.OBJECT_ORIGINS,
             defs["object_row"]["properties"]["origin"]["enum"]),
            ("LIFETIMES", ORACLE.LIFETIMES,
             defs["object_row"]["properties"]["lifetime"]["enum"]),
            ("ATTRIBUTIONS", ORACLE.ATTRIBUTIONS,
             defs["object_row"]["properties"]["attribution"]["enum"]),
            ("METADATA_KEYS", ORACLE.METADATA_KEYS,
             defs["metadata_block"]["required"]),
            ("QUERY_STATUSES", ORACLE.QUERY_STATUSES,
             defs["query_status"]["enum"]),
            ("METADATA_LABELS", ORACLE.METADATA_LABELS,
             defs["metadata_label"]["enum"]),
            ("CATEGORIES", ORACLE.CATEGORIES, defs["category"]["enum"]),
            ("ROLES", ORACLE.ROLES, defs["role"]["enum"]),
            ("UNITS", ORACLE.UNITS, defs["unit"]["enum"]),
            ("UNKNOWN_REASONS", ORACLE.UNKNOWN_REASONS,
             defs["unknown_reason"]["enum"]),
            ("GAP_SUBJECTS", ORACLE.GAP_SUBJECTS,
             defs["gap_row"]["properties"]["subject"]["enum"]),
            ("GAP_REASONS", ORACLE.GAP_REASONS, defs["gap_reason"]["enum"]),
            ("CURVE_LABELS", ORACLE.CURVE_LABELS,
             [name for name in
              defs["metadata_field_curve"]["properties"]["value"]["enum"]
              if name is not None]),
        ]
        for label, pinned, expected in enums:
            with self.subTest(label):
                self.assertEqual(set(pinned), set(expected))
        with self.subTest("CREATIONS plus null"):
            creation = defs["object_row"]["properties"]["creation"]["enum"]
            self.assertEqual(set(creation), set(ORACLE.CREATIONS) | {None})
        with self.subTest("object label plus null"):
            label = defs["object_row"]["properties"]["label"]["enum"]
            self.assertEqual(set(label), set(ORACLE.METADATA_LABELS) | {None})
        with self.subTest("curve status agrees with scalar status"):
            curve = defs["metadata_field_curve"]["properties"]["status"]["enum"]
            self.assertEqual(set(curve), set(ORACLE.FIELD_STATUSES))
        key_sets = [
            ("SECTION_KEYS", ORACLE.SECTION_KEYS, schema["required"]),
            ("SESSION_ROW_KEYS", ORACLE.SESSION_ROW_KEYS,
             defs["session_row"]["required"]),
            ("OBJECT_ROW_KEYS", ORACLE.OBJECT_ROW_KEYS,
             defs["object_row"]["required"]),
            ("KEY_ROW_KEYS", ORACLE.KEY_ROW_KEYS, defs["key_row"]["required"]),
            ("UNKNOWN_ROW_KEYS", ORACLE.UNKNOWN_ROW_KEYS,
             defs["unknown_row"]["required"]),
            ("GAP_ROW_KEYS", ORACLE.GAP_ROW_KEYS, defs["gap_row"]["required"]),
            ("BUDGET_KEYS", ORACLE.BUDGET_KEYS,
             schema["properties"]["budgets"]["required"]),
            ("ROW_BUDGET_KEYS", ORACLE.ROW_BUDGET_KEYS,
             defs["row_budget"]["required"]),
            ("UNKNOWN_BUDGET_KEYS", ORACLE.UNKNOWN_BUDGET_KEYS,
             schema["properties"]["budgets"]["properties"]["unknown_rows"]
             ["required"]),
        ]
        for label, pinned, expected in key_sets:
            with self.subTest(label):
                self.assertEqual(set(pinned), set(expected))
        with self.subTest("version const"):
            self.assertEqual(schema["properties"]["version"]["const"], 1)
            self.assertEqual(ORACLE.OBSERVATIONS_VERSION, 1)
        with self.subTest("row budget consts"):
            self.assertEqual(defs["row_budget"]["properties"]["limit"]["const"],
                             ORACLE.ROW_BUDGET_LIMIT)
            self.assertEqual(defs["row_budget"]["properties"]["occupied"]
                             ["maximum"], ORACLE.ROW_BUDGET_LIMIT)
        with self.subTest("gaps capacity"):
            self.assertEqual(schema["properties"]["gaps"]["properties"]["rows"]
                             ["maxItems"], ORACLE.GAPS_CAPACITY)
        block = defs["metadata_block"]["properties"]
        self.assertEqual(set(ORACLE.METADATA_FIELD_VALUES) | {"ec_params"},
                         set(block))
        for field, accepted in ORACLE.METADATA_FIELD_VALUES.items():
            with self.subTest("scalar field", field=field):
                cell = defs[block[field]["$ref"].rsplit("/", 1)[-1]]
                self.assertEqual(set(cell["required"]), set(ORACLE.FIELD_KEYS))
                self.assertEqual(set(cell["properties"]["status"]["enum"]),
                                 set(ORACLE.FIELD_STATUSES))
                self.assertEqual(set(cell["properties"]["value"]["enum"]),
                                 set(accepted) | {None})
        with self.subTest("u64 maxima"):
            self.assertEqual(defs["row_budget"]["properties"]["refused"]
                             ["maximum"], ORACLE.MAX_WORD)
            self.assertEqual(schema["properties"]["revision"]["maximum"],
                             ORACLE.MAX_WORD)


# S1 twins: the installed RSA capture as v0.5.0 reports it (no key-operation
# feed). Every number below is derived from the ledger workload
# (test_key_operation_ledger.application_rows: 68 calls) and the S1 reducer
# rules (src/semantics_edge.rs attribution, src/kinds.rs descriptors):
# 68 entries on the edge; operations calls 65 (68 minus the 3 COUNT_ONLY
# setup calls), started 23 (22 OK inits + the GenerateKeyPair direct call),
# completed 21, failed 2; mechanism 0x40 with 55 attributed sign/verify
# calls, 3 errors, 6 functions and returns {OK, SIGNATURE_INVALID,
# BUFFER_TOO_SMALL}; mechanism 0x0 with the single keygen call.
S1_RSA_FUNCTIONS = ("C_Sign", "C_SignFinal", "C_SignInit", "C_SignUpdate",
                    "C_Verify", "C_VerifyInit")
S1_RSA_RETURNS = ((0, "CKR_OK"), (0xC0, "CKR_SIGNATURE_INVALID"),
                 (0x150, "CKR_BUFFER_TOO_SMALL"))
S1_EVIDENCE_KEYS = ("state_reconciliations", "session_cancel_ambiguities",
                    "session_cancel_unknown_flags", "operation_state_imports",
                    "auth_state_ambiguities", "semantic_capture_failures",
                    "async_duplicates", "async_evictions", "unmatched_closes")


def s1_section(status="unavailable", reason="journal_unavailable"):
    return {"version": 1, "revision": 7, "status": status, "reason": reason,
            "sessions": [], "objects": [], "key_operations": [],
            "unknown_key_operations": [],
            "gaps": {"rows": [], "suppressed": 0},
            "budgets": {
                "key_rows": {"limit": 65536, "occupied": 0, "refused": 0},
                "object_rows": {"limit": 65536, "occupied": 0, "refused": 0},
                "unknown_rows": {"occupied": 0}, "encoded_bytes": 0,
                "allocation_refused": False, "refusal_reason": "none"}}


def s1_operations(calls=65, started=23, completed=21, cancelled=0, failed=2,
                  unknown=0, orphans=0, dropped=0, active=None):
    return {"calls": calls, "started": started, "completed": completed,
            "cancelled": cancelled, "failed": failed, "unknown": unknown,
            "orphans": orphans, "dropped": dropped, "last_seen_ns": 190,
            "active": [] if active is None else active,
            "evidence": {name: 0 for name in S1_EVIDENCE_KEYS}}


def s1_zero_operations():
    return s1_operations(calls=0, started=0, completed=0, failed=0)


def s1_rsa_row():
    return mech_row(mechanism=0x40, name="CKM_SHA256_RSA_PKCS",
                    operations=("sign", "verify"), calls=55, errors=3,
                    functions=S1_RSA_FUNCTIONS, returns=S1_RSA_RETURNS)


def s1_edge(count=68, mechanisms=None, operations=None,
            semantics="observed", coverage=None):
    if mechanisms is None:
        mechanisms = [keygen_row(), s1_rsa_row()]
    if operations is None:
        operations = s1_operations()
    if coverage is None:
        coverage = {"state": "counted", "since_ns": 110, "until_ns": None,
                    "first_ns": None, "lossy": False, "reason": None,
                    "detail": None}
    return {"caller": "c0", "module": "m0",
            "mapping": {"state": "mapped", "reason": None,
                        "first_seen_ns": 110, "last_seen_ns": 190,
                        "interruptions": 0},
            "entries": {"count": count, "saturated": False,
                        "cap": 18446744073709551615, "first_seen_ns": 110,
                        "last_seen_ns": 190, "in_flight": False,
                        "observation": "observed", "coverage": coverage},
            "semantics": semantics, "mechanisms": mechanisms,
            "operations": operations}


def s1_doc(section=None, edges=None):
    if section is None:
        section = s1_section()
    if edges is None:
        edges = [s1_edge()]
    return {"schema": "p11scope/inventory/v1",
            "object_observations": section, "edges": edges}


def s1_rsa_mechanisms(doc):
    return [row for edge in doc["edges"] for row in edge["mechanisms"]
            if row["mechanism"] == 0x40]


def s1_current_doc():
    """Current b58 held-RSA capture shape, hand-built from the actual receipt.

    Physical 68 and semantic 65 remain separate; the three COUNT_ONLY setup
    calls are not semantic API observations. The stopped instance retains its
    own 65/23/21/2 and 1+55 mechanism facts while the parent withholds a summary.
    """
    doc = s1_doc()
    edge = doc["edges"][0]
    child = {"caller": "c0", "module": "m0", "instance": "i0",
             "entries": {"unit": "api_entries", "count": None,
                         "observation": "unavailable"},
             "api_returns": {"unit": "api_returns", "count": 65,
                             "saturated": False, "historical_only_returns": 0},
             "semantics": "observed", "operations": edge["operations"],
             "mechanisms": edge["mechanisms"],
             "coverage": {"lossy": True,
                          "reasons": ["capture_stopped", "semantic_loss"]}}
    edge.update(semantics="unknown (per-edge summary withheld; see semantic children)",
                operations=None, mechanisms=None)
    doc.update(scope="pid:41", callers=[{"id": "c0", "pid": 41,
                                       "start_time": 110, "retired": False}],
               modules=[{"id": "m0", "admission": {"state": "admitted",
                         "class": "operator", "endpoints": 68, "reasons": []}}],
               instances=[{"id": "i0", "caller": "c0", "module": "m0",
                           "state": "uncertain", "reason": "semantic_loss",
                           "first_seen_ns": 110, "last_seen_ns": 190}],
               semantic_edges=[child], gaps_suppressed=0,
               observation={"lane": "native", "lifecycle": {
                   "ring_loss": 0, "malformed": 0, "failed_quanta": 0},
                   "semantic_capture": {"status": "stopped", "admitted_endpoints": 68,
                       "refused_endpoints": 0, "continuity_cuts": 0, "unrouted_returns": 0,
                       "stop_quiescence": "quiesced", "final_drain": True}})
    return doc


class CurrentS1ModeTests(unittest.TestCase):
    """The actual stopped child topology, with no loss/identity fallback."""
    def check(self, doc):
        return ORACLE.compare_s1(APP_TESTS.application_rows(), doc)

    def test_actual_stopped_child_shape_passes_without_promoting_parent(self):
        doc = s1_current_doc()
        result = self.check(doc)
        self.assertTrue(result["match"])
        self.assertEqual(result["observed"]["entries"], 68)
        self.assertEqual(result["observed"]["operations"]["calls"], 65)
        self.assertEqual(result["observed"]["semantic_source"], {
            "caller": "c0", "module": "m0", "instance": "i0", "api_returns": 65,
            "coverage": {"lossy": True, "reasons": ["capture_stopped", "semantic_loss"]}})
        self.assertIsNone(doc["edges"][0]["operations"])
        self.assertIsNone(doc["edges"][0]["mechanisms"])

    def test_clean_observed_child_control_passes(self):
        doc = s1_current_doc()
        doc["instances"][0].update(state="observed", reason=None)
        doc["semantic_edges"][0]["coverage"] = {"lossy": False, "reasons": []}
        self.assertTrue(self.check(doc)["match"])

    def test_bad_children_never_fall_back_to_a_healthy_legacy_parent(self):
        for key, value in (("instances", None), ("semantic_edges", [])):
            with self.subTest(key=key):
                doc = s1_current_doc()
                doc["edges"] = [s1_edge()]
                doc[key] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)

    def test_missing_null_empty_or_extra_graph_rows_are_refused(self):
        for key in ("callers", "modules", "edges", "instances", "semantic_edges"):
            for mode in ("missing", "null", "empty", "duplicate"):
                with self.subTest(key=key, mode=mode):
                    doc = s1_current_doc()
                    if mode == "missing":
                        del doc[key]
                    elif mode == "null":
                        doc[key] = None
                    elif mode == "empty":
                        doc[key] = []
                    else:
                        doc[key].append(copy.deepcopy(doc[key][0]))
                    with self.assertRaises(ORACLE.OracleRefusal):
                        self.check(doc)

    def test_foreign_or_orphan_graph_references_are_refused(self):
        cases = [("scope", None, "system"), ("callers", "pid", 42),
                 ("callers", "id", "c1"), ("callers", "start_time", None),
                 ("callers", "retired", True), ("modules", "id", "m1"),
                 ("edges", "caller", "c1"), ("edges", "module", "m1"),
                 ("instances", "caller", "c1"), ("instances", "module", "m1"),
                 ("instances", "id", "i1"), ("semantic_edges", "instance", "i1"),
                 ("semantic_edges", "caller", "c1"), ("semantic_edges", "module", "m1")]
        for key, field, value in cases:
            with self.subTest(key=key, field=field):
                doc = s1_current_doc()
                if field is None:
                    doc[key] = value
                else:
                    doc[key][0][field] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)

    def test_mixed_unrelated_child_cannot_supply_the_expected_counts(self):
        doc = s1_current_doc()
        foreign = copy.deepcopy(doc["semantic_edges"][0])
        foreign.update(caller="c1", module="m1", instance="i1")
        doc["semantic_edges"] = [foreign]
        with self.assertRaises(ORACLE.OracleRefusal):
            self.check(doc)

    def test_exact_physical_and_semantic_denominators_are_separate(self):
        for key, field, value in (("entries", "count", 67), ("entries", "count", 65),
                                  ("entries", "in_flight", True), ("entries", "saturated", True),
                                  ("api_returns", "count", 68), ("api_returns", "count", 64),
                                  ("api_returns", "count", None), ("api_returns", "saturated", True),
                                  ("api_returns", "historical_only_returns", 1),
                                  ("api_returns", "unit", "calls")):
            with self.subTest(key=key, field=field, value=value):
                doc = s1_current_doc()
                row = doc["edges"][0] if key == "entries" else doc["semantic_edges"][0]
                row[key][field] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)
        doc = s1_current_doc()
        doc["semantic_edges"][0]["entries"]["count"] = 68
        with self.assertRaises(ORACLE.OracleRefusal):
            self.check(doc)

    def test_native_lifecycle_and_final_capture_twins_are_refused(self):
        cases = [("lane", None, "scan"), ("lifecycle", "ring_loss", 1),
                 ("lifecycle", "malformed", 1), ("lifecycle", "failed_quanta", None),
                 ("semantic_capture", "status", "active"),
                 ("semantic_capture", "final_drain", False),
                 ("semantic_capture", "stop_quiescence", "unproven"),
                 ("semantic_capture", "refused_endpoints", 1),
                 ("semantic_capture", "continuity_cuts", 1),
                 ("semantic_capture", "unrouted_returns", 1)]
        for key, field, value in cases:
            with self.subTest(key=key, field=field):
                doc = s1_current_doc()
                if field is None:
                    doc["observation"][key] = value
                else:
                    doc["observation"][key][field] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)

    def test_only_the_exact_R59_stopped_reasons_are_accepted(self):
        for reasons in (["semantic_loss"], ["capture_stopped"], [],
                        ["capture_stopped", "semantic_loss", "task_retired"],
                        ["capture_stopped", "instance_retired", "semantic_loss"],
                        ["capture_stopped", "semantic_loss", "before_semantic_boundary"],
                        ["capture_stopped", "semantic_loss", "semantic_loss"],
                        ["semantic_loss", "capture_stopped"], ["unknown"]):
            with self.subTest(reasons=reasons):
                doc = s1_current_doc()
                doc["semantic_edges"][0]["coverage"]["reasons"] = reasons
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)
        for state, reason in (("retired", "task_retired"), ("uncertain", "instance_unproven"),
                              ("observed", "semantic_loss")):
            doc = s1_current_doc()
            doc["instances"][0].update(state=state, reason=reason)
            with self.subTest(state=state, reason=reason), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)

    def test_parent_generic_unknown_or_semantic_payload_is_refused(self):
        for field, value in (("semantics", "unknown (semantic capture withheld)"),
                             ("operations", s1_operations()), ("mechanisms", [s1_rsa_row()])):
            doc = s1_current_doc()
            doc["edges"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)

    def test_child_operations_and_mechanisms_remain_exact(self):
        for field, value in (("calls", 64), ("started", 22), ("completed", 20),
                             ("failed", 1), ("cancelled", 1), ("unknown", 1),
                             ("orphans", 1), ("dropped", 1)):
            with self.subTest(field=field):
                doc = s1_current_doc()
                doc["semantic_edges"][0]["operations"][field] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)
        for index, field, value in ((0, "calls", 2), (0, "errors", 1),
                                    (1, "calls", 54), (1, "errors", 2)):
            with self.subTest(index=index, field=field):
                doc = s1_current_doc()
                doc["semantic_edges"][0]["mechanisms"][index][field] = value
                with self.assertRaises(ORACLE.OracleRefusal):
                    self.check(doc)
        for missing in (0, 1):
            doc = s1_current_doc()
            del doc["semantic_edges"][0]["mechanisms"][missing]
            with self.subTest(missing=missing), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)
        doc = s1_current_doc()
        doc["semantic_edges"][0]["operations"]["evidence"]["semantic_capture_failures"] = 1
        with self.assertRaises(ORACLE.OracleRefusal):
            self.check(doc)
        doc = s1_current_doc()
        doc["semantic_edges"][0]["mechanisms"][1]["operations"].insert(0, "digest")
        with self.assertRaises(ORACLE.OracleRefusal):
            self.check(doc)

    def test_manifest_mapping_and_gap_controls_are_not_relaxed(self):
        for field, value in (("class", "heuristic"), ("state", "refused"),
                             ("endpoints", 0), ("reasons", ["unproven"])):
            doc = s1_current_doc()
            doc["modules"][0]["admission"][field] = value
            with self.subTest(field=field), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)
        for field, value in (("state", "ended"), ("interruptions", 1)):
            doc = s1_current_doc()
            doc["edges"][0]["mapping"][field] = value
            with self.subTest(field=field), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)
        for value in (None, False, 1):
            doc = s1_current_doc()
            doc["gaps_suppressed"] = value
            with self.subTest(suppressed=value), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)

    def test_current_required_fields_cannot_be_unknown_or_boolean_counts(self):
        for group, key in (("api_returns", "unit"), ("api_returns", "count"),
                           ("api_returns", "saturated"), ("api_returns", "historical_only_returns"),
                           ("entries", "observation"), ("coverage", "reasons"),
                           ("coverage", "lossy")):
            doc = s1_current_doc()
            del doc["semantic_edges"][0][group][key]
            with self.subTest(group=group, key=key), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)
        for group, key in (("lifecycle", "ring_loss"), ("semantic_capture", "continuity_cuts"),
                           ("semantic_capture", "refused_endpoints"), ("semantic_capture", "unrouted_returns")):
            doc = s1_current_doc()
            doc["observation"][group][key] = False
            with self.subTest(group=group, key=key), self.assertRaises(ORACLE.OracleRefusal):
                self.check(doc)

    def test_current_child_cli_positive_and_loss_negative(self):
        with tempfile.TemporaryDirectory(prefix="rsa-current-child-") as directory:
            application = Path(directory) / "application.jsonl"
            application.write_text("".join(json.dumps(row) + "\n" for row in APP_TESTS.application_rows()))
            observer = Path(directory) / "inventory.json"
            command = [sys.executable, "-I", str(ROOT / "scripts/qualify-key-operations.py"),
                       "--s1", str(application), str(observer)]
            doc = s1_current_doc()
            observer.write_text(json.dumps(doc))
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["observed"]["semantic_source"]["api_returns"], 65)
            doc["semantic_edges"][0]["coverage"]["reasons"].append("task_retired")
            observer.write_text(json.dumps(doc))
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("Traceback", result.stderr)


class S1ModeTests(unittest.TestCase):
    maxDiff = 4096

    def assert_s1_refused(self, rows, doc, tokens):
        with self.assertRaises(ORACLE.OracleRefusal) as caught:
            ORACLE.compare_s1(rows, doc)
        message = str(caught.exception)
        for token in tokens:
            self.assertIn(token, message)

    def test_s1_healthy_twin_passes(self):
        result = ORACLE.compare_s1(APP_TESTS.application_rows(), s1_doc())
        self.assertTrue(result.get("match"))
        self.assertEqual(result.get("mode"), "s1")
        application = result.get("application", {})
        self.assertEqual(application.get("api_calls"), 68)
        self.assertEqual(application.get("call_split"),
                         {"sign": 31, "verify": 24, "setup": 13})
        self.assertEqual(application.get("per_function"),
                         {"C_Sign": {"0x0": 8, "0x150": 1},
                          "C_Verify": {"0x0": 10, "0xc0": 2}})
        self.assertEqual(application.get("mechanism"), "CKM_SHA256_RSA_PKCS")
        seen = result.get("observed", {})
        self.assertEqual(seen.get("entries"), 68)
        self.assertEqual(seen.get("operations"),
                         {"calls": 65, "started": 23, "completed": 21,
                          "cancelled": 0, "failed": 2, "unknown": 0,
                          "orphans": 0, "dropped": 0, "active": 0})
        self.assertEqual(seen.get("mechanisms"),
                         [{"mechanism": 0, "mechanism_hex": "0x0",
                           "name": "CKM_RSA_PKCS_KEY_PAIR_GEN",
                           "operations": ["generate_key_pair"],
                           "calls": 1, "errors": 0},
                          {"mechanism": 64, "mechanism_hex": "0x40",
                           "name": "CKM_SHA256_RSA_PKCS",
                           "operations": ["sign", "verify"],
                           "calls": 55, "errors": 3}])
        json.dumps(result)

    def test_s1_zero_count_edge_passes_when_empty(self):
        with self.subTest("zero content"):
            doc = s1_doc()
            doc["edges"].append(
                s1_edge(count=0,
                        mechanisms=[
                            mech_row(
                                mechanism=0x0,
                                name="CKM_RSA_PKCS_KEY_PAIR_GEN",
                                operations=("generate_key_pair",),
                                calls=0, errors=0,
                                functions=("C_GenerateKeyPair",)),
                            mech_row(
                                mechanism=0x40,
                                name="CKM_SHA256_RSA_PKCS",
                                operations=("sign", "verify"),
                                calls=0, errors=0,
                                functions=S1_RSA_FUNCTIONS,
                                returns=S1_RSA_RETURNS)],
                        operations=s1_zero_operations()))
            result = ORACLE.compare_s1(APP_TESTS.application_rows(), doc)
            self.assertTrue(result.get("match"))
            seen = result.get("observed", {})
            self.assertEqual(seen.get("entries"), 68)
            self.assertEqual(seen.get("operations"),
                             {"calls": 65, "started": 23, "completed": 21,
                              "cancelled": 0, "failed": 2, "unknown": 0,
                              "orphans": 0, "dropped": 0, "active": 0})
        with self.subTest("absent content"):
            doc = s1_doc()
            edge = s1_edge(count=0, mechanisms=[])
            del edge["operations"]
            doc["edges"].append(edge)
            result = ORACLE.compare_s1(APP_TESTS.application_rows(), doc)
            self.assertTrue(result.get("match"))
            self.assertEqual(result.get("observed", {}).get("entries"), 68)

    def test_s1_reasons_carry_journal_unavailable(self):
        self.assertIn("journal_unavailable", ORACLE.REASONS)

    def test_s1_section_twins_are_refused(self):
        clean = observed("clean.json")

        def populated(doc):
            doc["object_observations"] = clean

        def bootstrap(doc):
            doc["object_observations"]["reason"] = "bootstrap_unavailable"

        def section_gap(doc):
            doc["object_observations"]["gaps"]["rows"] = [
                {"subject": "model", "reason": "loss", "repeats": 1}]

        def suppressed_gap(doc):
            doc["object_observations"]["gaps"]["suppressed"] = 1

        def edges_missing(doc):
            del doc["edges"]

        def edges_not_list(doc):
            doc["edges"] = {"count": 68}

        def edges_empty(doc):
            doc["edges"] = []

        def smuggled_key_row(doc):
            section = doc["object_observations"]
            section["sessions"] = copy.deepcopy(clean["sessions"])
            section["objects"] = copy.deepcopy(clean["objects"])
            section["key_operations"] = copy.deepcopy(
                clean["key_operations"][:1])
            section["budgets"]["key_rows"]["occupied"] = 1
            section["budgets"]["object_rows"]["occupied"] = len(
                clean["objects"])

        def smuggled_unknown_row(doc):
            section = doc["object_observations"]
            section["unknown_key_operations"] = [
                {"category": "sign", "reason": "unbound",
                 "unit": "operations", "completed": 0, "failed": 0,
                 "cancelled": 0, "unknown": 0, "active": 0}]
            section["budgets"]["unknown_rows"]["occupied"] = 1

        def smuggled_session_row(doc):
            doc["object_observations"]["sessions"] = [
                {"session": 1, "origin": "opened", "status": "live"}]

        def section_missing(doc):
            del doc["object_observations"]

        cases = [
            ("object observations populated", populated,
             ["needs unavailable", "populated"]),
            ("bootstrap reason instead of journal", bootstrap,
             ["needs reason journal_unavailable", "bootstrap_unavailable"]),
            ("section gap row", section_gap, ["observation gap"]),
            ("suppressed section gap", suppressed_gap,
             ["suppressed observation gaps"]),
            ("edges missing", edges_missing, ["needs edges"]),
            ("edges not a list", edges_not_list, ["unexpected edges shape"]),
            ("no edges", edges_empty,
             ["entries total 0", "expected 68"]),
            ("key row while unavailable", smuggled_key_row,
             ["needs no key-operation rows"]),
            ("unknown row while unavailable", smuggled_unknown_row,
             ["needs no unknown key-operation rows"]),
            ("session row while unavailable", smuggled_session_row,
             ["needs no session rows"]),
            ("section missing", section_missing,
             ["missing object observations"]),
        ]
        for label, mutate, tokens in cases:
            with self.subTest(label):
                doc = s1_doc()
                mutate(doc)
                self.assert_s1_refused(APP_TESTS.application_rows(), doc,
                                       tokens)

    def test_s1_bare_section_is_refused(self):
        self.assert_s1_refused(APP_TESTS.application_rows(), s1_section(),
                               ["inventory envelope"])

    def test_s1_edge_twins_are_refused(self):
        def drop_sign_function(doc):
            row = s1_rsa_mechanisms(doc)[0]
            row["evidence"]["functions"].remove("C_Sign")

        def wrong_return(doc):
            row = s1_rsa_mechanisms(doc)[0]
            entry = next(item for item in row["evidence"]["returns"]
                         if item["rv"] == 0xC0)
            entry.update(rv=0xC1, rv_hex="0xc1", name=None)

        def drop_rsa_row(doc):
            edge = doc["edges"][0]
            edge["mechanisms"] = [row for row in edge["mechanisms"]
                                  if row["mechanism"] != 0x40]

        def drop_keygen_row(doc):
            edge = doc["edges"][0]
            edge["mechanisms"] = [row for row in edge["mechanisms"]
                                  if row["mechanism"] != 0x0]

        def total_off_by_one(doc):
            doc["edges"][0]["entries"]["count"] = 67

        def rsa_calls_short(doc):
            s1_rsa_mechanisms(doc)[0]["calls"] = 54

        def rsa_errors_short(doc):
            s1_rsa_mechanisms(doc)[0]["errors"] = 2

        def keygen_calls_wrong(doc):
            doc["edges"][0]["mechanisms"][0]["calls"] = 2

        def extra_mechanism(doc):
            doc["edges"][0]["mechanisms"].append(
                mech_row(mechanism=0x41, name="CKM_SHA1_RSA_PKCS",
                         operations=("digest",), calls=1, errors=0,
                         functions=("C_DigestInit",)))

        def rsa_name_missing(doc):
            s1_rsa_mechanisms(doc)[0]["name"] = None

        def rsa_operations_short(doc):
            s1_rsa_mechanisms(doc)[0]["operations"] = ["sign"]

        def rsa_operations_extra(doc):
            s1_rsa_mechanisms(doc)[0]["operations"].insert(0, "digest")

        def rsa_truncated(doc):
            s1_rsa_mechanisms(doc)[0]["evidence"]["truncated"] = True

        def extra_function(doc):
            row = s1_rsa_mechanisms(doc)[0]
            row["evidence"]["functions"].append("C_Encrypt")
            row["evidence"]["functions"].sort()

        def return_name_wrong(doc):
            row = s1_rsa_mechanisms(doc)[0]
            entry = next(item for item in row["evidence"]["returns"]
                         if item["rv"] == 0xC0)
            entry["name"] = "CKR_OK"

        def return_missing(doc):
            row = s1_rsa_mechanisms(doc)[0]
            row["evidence"]["returns"] = [
                item for item in row["evidence"]["returns"]
                if item["rv"] != 0x150]

        def mechanisms_null(doc):
            doc["edges"][0]["mechanisms"] = None

        def mechanisms_not_list(doc):
            doc["edges"][0]["mechanisms"] = {"0x40": {}}

        def operations_null(doc):
            doc["edges"][0]["operations"] = None

        def operations_short(doc):
            doc["edges"][0]["operations"]["completed"] = 20

        def operations_failed_short(doc):
            doc["edges"][0]["operations"]["failed"] = 1

        def operations_calls_short(doc):
            doc["edges"][0]["operations"]["calls"] = 64

        def operations_started_short(doc):
            doc["edges"][0]["operations"]["started"] = 22

        def operations_orphan(doc):
            doc["edges"][0]["operations"]["orphans"] = 1

        def operations_unknown(doc):
            doc["edges"][0]["operations"]["unknown"] = 1

        def operations_cancelled(doc):
            doc["edges"][0]["operations"]["cancelled"] = 1

        def operations_dropped(doc):
            doc["edges"][0]["operations"]["dropped"] = 1

        def operations_active(doc):
            doc["edges"][0]["operations"]["active"] = [
                {"category": "sign", "state": "in_progress", "count": 1}]

        def operations_evidence(doc):
            doc["edges"][0]["operations"]["evidence"][
                "semantic_capture_failures"] = 1

        def coverage_lossy(doc):
            doc["edges"][0]["entries"]["coverage"]["lossy"] = True

        def coverage_not_counted(doc):
            doc["edges"][0]["entries"]["coverage"].update(
                state="unknown", lossy=None, reason="loss",
                detail="repeated fixture gap")

        def semantics_withheld(doc):
            doc["edges"][0]["semantics"] = \
                "unknown (semantic capture withheld)"

        def entries_missing(doc):
            del doc["edges"][0]["entries"]

        def coverage_missing(doc):
            del doc["edges"][0]["entries"]["coverage"]

        def coverage_state_bogus(doc):
            doc["edges"][0]["entries"]["coverage"]["state"] = "BOGUS-STATE"

        def mechanism_ids_out_of_order(doc):
            edge = doc["edges"][0]
            edge["mechanisms"] = list(reversed(edge["mechanisms"]))

        def operations_active_bad_state(doc):
            doc["edges"][0]["operations"]["active"] = [
                {"category": "sign", "state": "BOGUS", "count": 1}]

        def operations_evidence_missing_key(doc):
            del doc["edges"][0]["operations"]["evidence"][
                "semantic_capture_failures"]

        def operations_evidence_extra_key(doc):
            doc["edges"][0]["operations"]["evidence"][
                "future_counter"] = 999

        def zero_count_bogus_mech(doc):
            doc["edges"].append(
                s1_edge(count=0,
                        mechanisms=[
                            mech_row(mechanism=0x41,
                                     name="CKM_SHA1_RSA_PKCS",
                                     operations=("digest",),
                                     calls=99, errors=0,
                                     functions=("C_DigestInit",))],
                        operations=s1_zero_operations()))

        def zero_count_garbage_ops(doc):
            doc["edges"].append(
                s1_edge(count=0, mechanisms=[],
                        operations=s1_operations(calls=9999, started=0,
                                                 completed=0, failed=0)))

        def zero_count_allowed_mech_with_calls(doc):
            row = s1_rsa_row()
            row["calls"] = 1
            row["errors"] = 0
            doc["edges"].append(
                s1_edge(count=0, mechanisms=[row],
                        operations=s1_zero_operations()))

        def zero_count_bogus_mech_zero_calls(doc):
            doc["edges"].append(
                s1_edge(count=0,
                        mechanisms=[
                            mech_row(mechanism=0x41,
                                     name="CKM_SHA1_RSA_PKCS",
                                     operations=("digest",),
                                     calls=0, errors=0,
                                     functions=("C_DigestInit",))],
                        operations=s1_zero_operations()))

        def zero_count_mech_errors(doc):
            row = s1_rsa_row()
            row["calls"] = 0
            row["errors"] = 1
            doc["edges"].append(
                s1_edge(count=0, mechanisms=[row],
                        operations=s1_zero_operations()))

        def zero_count_ops_started(doc):
            doc["edges"].append(
                s1_edge(count=0, mechanisms=[],
                        operations=s1_operations(calls=0, started=1,
                                                 completed=0, failed=0)))

        cases = [
            ("one sign result missing", drop_sign_function,
             ["misses expected functions", "C_Sign"]),
            ("wrong return code", wrong_return,
             ["unexpected S1 return", "0xc1"]),
            ("mechanism missing on the edge", drop_rsa_row,
             ["missing expected mechanism", "CKM_SHA256_RSA_PKCS"]),
            ("keygen mechanism missing", drop_keygen_row,
             ["missing expected mechanism", "CKM_RSA_PKCS_KEY_PAIR_GEN"]),
            ("call total off by one", total_off_by_one,
             ["entries total 67", "expected 68"]),
            ("mechanism calls short", rsa_calls_short,
             ["calls/errors 54/3", "expected 55/3"]),
            ("mechanism errors short", rsa_errors_short,
             ["calls/errors 55/2", "expected 55/3"]),
            ("keygen calls wrong", keygen_calls_wrong,
             ["CKM_RSA_PKCS_KEY_PAIR_GEN", "expected 1/0"]),
            ("extra mechanism row", extra_mechanism,
             ["unexpected S1 mechanism", "0x41"]),
            ("mechanism name mismatch", rsa_name_missing,
             ["unexpected mechanism name"]),
            ("mechanism operations short", rsa_operations_short,
             ["missing expected operations"]),
            ("mechanism operations extra", rsa_operations_extra,
             ["unexpected operations"]),
            ("truncated provenance", rsa_truncated, ["truncated"]),
            ("extra function", extra_function, ["unexpected S1 functions"]),
            ("return name wrong", return_name_wrong,
             ["0xc0", "unexpected name"]),
            ("return missing", return_missing,
             ["misses expected returns", "0x150"]),
            ("mechanisms null", mechanisms_null,
             ["missing expected mechanism"]),
            ("mechanisms not a list", mechanisms_not_list,
             ["unexpected mechanisms shape"]),
            ("operations null", operations_null, ["needs S1 operations"]),
            ("operations completed short", operations_short,
             ["S1 operations completed 20", "expected 21"]),
            ("operations failed short", operations_failed_short,
             ["S1 operations failed 1", "expected 2"]),
            ("operations calls short", operations_calls_short,
             ["S1 operations calls 64", "expected 65"]),
            ("operations started short", operations_started_short,
             ["S1 operations started 22", "expected 23"]),
            ("operations orphan", operations_orphan,
             ["S1 operations orphans 1"]),
            ("operations unknown", operations_unknown,
             ["S1 operations unknown 1"]),
            ("operations cancelled", operations_cancelled,
             ["S1 operations cancelled 1"]),
            ("operations dropped", operations_dropped,
             ["S1 operations dropped 1"]),
            ("operations active", operations_active,
             ["S1 operations active 1"]),
            ("operations evidence", operations_evidence,
             ["S1 operations evidence", "semantic_capture_failures"]),
            ("coverage lossy", coverage_lossy, ["lossy"]),
            ("coverage not counted", coverage_not_counted,
             ["not counted", "unknown"]),
            ("semantics withheld", semantics_withheld,
             ["semantics is not observed"]),
            ("entries missing", entries_missing,
             ["unexpected S1 edge shape"]),
            ("coverage missing", coverage_missing,
             ["unexpected S1 coverage shape"]),
            ("coverage state bogus", coverage_state_bogus,
             ["unexpected S1 coverage state"]),
            ("mechanism ids out of order", mechanism_ids_out_of_order,
             ["mechanism rows out of order"]),
            ("operations active bad state", operations_active_bad_state,
             ["unexpected S1 active state"]),
            ("operations evidence missing key",
             operations_evidence_missing_key,
             ["S1 operations evidence", "is not a counter"]),
            ("operations evidence extra key",
             operations_evidence_extra_key,
             ["unexpected fields"]),
            ("zero-count edge with bogus mechanism",
             zero_count_bogus_mech,
             ["unexpected S1 mechanism", "0x41"]),
            ("zero-count edge with garbage operations",
             zero_count_garbage_ops,
             ["S1 zero-count edge", "operations calls 9999"]),
            ("zero-count edge with allowed mechanism calls",
             zero_count_allowed_mech_with_calls,
             ["S1 zero-count edge", "mechanism calls 1"]),
            ("zero-count edge with bogus mechanism, zero calls",
             zero_count_bogus_mech_zero_calls,
             ["unexpected S1 mechanism", "0x41"]),
            ("zero-count edge with mechanism errors",
             zero_count_mech_errors,
             ["S1 zero-count edge", "mechanism errors 1"]),
            ("zero-count edge with started operations",
             zero_count_ops_started,
             ["S1 zero-count edge", "operations started 1"]),
        ]
        for label, mutate, tokens in cases:
            with self.subTest(label):
                doc = s1_doc()
                mutate(doc)
                self.assert_s1_refused(APP_TESTS.application_rows(), doc,
                                       tokens)

    def test_s1_refusals_never_echo_untrusted_strings(self):
        def hostile_function(doc):
            row = s1_rsa_mechanisms(doc)[0]
            row["evidence"]["functions"].append("HOSTILE-FUNCTION-NAME")
            row["evidence"]["functions"].sort()

        def hostile_return_name(doc):
            row = s1_rsa_mechanisms(doc)[0]
            row["evidence"]["returns"][0]["name"] = "HOSTILE-RETURN-NAME"

        def hostile_coverage(doc):
            doc["edges"][0]["entries"]["coverage"]["state"] = "HOSTILE-STATE"

        def hostile_semantics(doc):
            doc["edges"][0]["semantics"] = "HOSTILE-SEMANTICS"

        def hostile_active(doc):
            doc["edges"][0]["operations"]["active"] = [
                {"category": "sign", "state": "HOSTILE", "count": 1}]

        cases = [
            ("function", hostile_function, "HOSTILE-FUNCTION-NAME",
             "unexpected S1 functions"),
            ("return name", hostile_return_name, "HOSTILE-RETURN-NAME",
             "unexpected name"),
            ("coverage state", hostile_coverage, "HOSTILE-STATE",
             "unexpected S1 coverage state"),
            ("semantics", hostile_semantics, "HOSTILE-SEMANTICS",
             "semantics is not observed"),
            ("active state", hostile_active, "HOSTILE",
             "unexpected S1 active state"),
        ]
        for label, mutate, secret, token in cases:
            with self.subTest(label):
                doc = s1_doc()
                mutate(doc)
                with self.assertRaises(ORACLE.OracleRefusal) as caught:
                    ORACLE.compare_s1(APP_TESTS.application_rows(), doc)
                self.assertIn(token, str(caught.exception))
                self.assertNotIn(secret, str(caught.exception))

    def test_s1_application_twins_are_refused(self):
        with self.subTest("ledger missing a sign result"):
            rows = APP_TESTS.application_rows()
            rows.remove(next(row for row in rows
                             if row["kind"] == "call"
                             and row["fn"] == "C_Sign"
                             and row["phase"] == "terminal"))
            self.assert_s1_refused(APP_TESTS.resequence(rows), s1_doc(),
                                   ["application ledger refused"])
        with self.subTest("ledger with a wrong return code"):
            rows = APP_TESTS.application_rows()
            row = next(row for row in rows
                       if row["kind"] == "call" and row["fn"] == "C_Verify"
                       and row["rv"] == 0)
            row["rv"] = 0xC1
            self.assert_s1_refused(rows, s1_doc(),
                                   ["application ledger refused",
                                    "unexpected application return value"])

    def test_s1_application_checks_are_reachable(self):
        application = ORACLE.LEDGER.validate_ledger(
            APP_TESTS.application_rows())
        with self.subTest("wrong call split"):
            rows = APP_TESTS.application_rows()
            moved = next(row for row in rows
                         if row.get("kind") == "call"
                         and row.get("operation"))
            moved["operation"] = 0
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE._check_s1_application(rows, application)
            self.assertIn("application call split",
                          str(caught.exception))
        with self.subTest("wrong per-function tally"):
            rows = APP_TESTS.application_rows()
            row = next(row for row in rows
                       if row.get("kind") == "call"
                       and row["fn"] == "C_Sign" and row["rv"] == 0)
            row["rv"] = 0xC0
            with self.assertRaises(ORACLE.OracleRefusal) as caught:
                ORACLE._check_s1_application(rows, application)
            self.assertIn("application C_Sign results",
                          str(caught.exception))

    def test_s1_cli_accepts_twin_and_refuses_mutations(self):
        command = [sys.executable,
                   str(ROOT / "scripts/qualify-key-operations.py"), "--s1"]
        with tempfile.TemporaryDirectory(prefix="p11scope-s1-rsa-") as directory:
            application = Path(directory, "application.jsonl")
            application.write_text("".join(json.dumps(row) + "\n"
                                           for row in APP_TESTS.application_rows()),
                                   encoding="utf-8")
            healthy = Path(directory, "healthy.json")
            healthy.write_text(json.dumps(s1_doc()), encoding="utf-8")
            result = subprocess.run(command + [str(application), str(healthy)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            passed = json.loads(result.stdout)
            self.assertTrue(passed.get("match"))
            self.assertEqual(passed.get("mode"), "s1")
            twin = s1_doc()
            twin["edges"][0]["entries"]["count"] = 67
            observer = Path(directory, "twin.json")
            observer.write_text(json.dumps(twin), encoding="utf-8")
            result = subprocess.run(command + [str(application), str(observer)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stdout, "")
            self.assertIn("entries total", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            populated = s1_doc(section=observed("clean.json"))
            observer.write_text(json.dumps(populated), encoding="utf-8")
            result = subprocess.run(command + [str(application), str(observer)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stdout, "")
            self.assertIn("needs unavailable", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
