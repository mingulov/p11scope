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
            ("REASONS", ORACLE.REASONS, schema["properties"]["reason"]["enum"]),
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


if __name__ == "__main__":
    unittest.main()
