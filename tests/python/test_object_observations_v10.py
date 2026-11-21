# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Frozen H9 v10 object_observations contract agrees with its golden fixture.

docs/schema/inventory-v1-object-observations-v10.schema.json is the frozen
section-version-10 consumer contract; tests/fixtures/key-operations/
object-observations-v10.json is the hand-reviewed populated example
carrying relaxed-dialect metadata (widened class/key-type sets, ranged
value_len/modulus_bits, secp256k1/brainpool curves and labels, inferred
keys on every proved row). These tests validate the golden against the
schema (exact keys, enums, integer bounds, row equations and sort
orders) with a small dependency-free checker for the frozen subset, so
the schema cannot drift from its example. The Rust suite
(key_operation_schema_v10_pins_unknown_mechanism_contract) separately
proves the renderer emits exactly these keys and enums.

encoded_bytes in the golden is illustrative, not self-measured: the byte
count of a document cannot equal a number stored inside it. The renderer
test asserts measured equality on live output instead.

Run: python3 -I tests/python/test_object_observations_v10.py -v
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (
        ROOT
        / "docs"
        / "schema"
        / "inventory-v1-object-observations-v10.schema.json"
    ).read_text(encoding="utf-8")
)
GOLDEN = json.loads(
    (
        ROOT
        / "tests"
        / "fixtures"
        / "key-operations"
        / "object-observations-v10.json"
    ).read_text(encoding="utf-8")
)
U64_MAX = 18446744073709551615

ESTABLISHED_LABELS = (
    "rsa_1024",
    "rsa_2048",
    "rsa_3072",
    "rsa_4096",
    "rsa_other",
    "aes_128",
    "aes_192",
    "aes_256",
    "aes_other",
    "ec_p256",
    "ec_p384",
    "ec_p521",
)
PQC_LABELS = (
    "ml_dsa_44",
    "ml_dsa_65",
    "ml_dsa_87",
    "ml_kem_512",
    "ml_kem_768",
    "ml_kem_1024",
    "slh_dsa_sha2_128s",
    "slh_dsa_shake_128s",
    "slh_dsa_sha2_128f",
    "slh_dsa_shake_128f",
    "slh_dsa_sha2_192s",
    "slh_dsa_shake_192s",
    "slh_dsa_sha2_192f",
    "slh_dsa_shake_192f",
    "slh_dsa_sha2_256s",
    "slh_dsa_shake_256s",
    "slh_dsa_sha2_256f",
    "slh_dsa_shake_256f",
)
NEWSITE_LABELS = (
    "x25519",
    "x448",
    "ed25519",
    "ed448",
    "hkdf_96",
    "hkdf_128",
    "hkdf_192",
    "hkdf_256",
    "hkdf_384",
    "hkdf_other",
    "generic_96",
    "generic_128",
    "generic_192",
    "generic_256",
    "generic_384",
    "generic_other",
)
RELAXED_LABELS = (
    "ec_secp256k1",
    "ec_brainpoolp256r1",
    "ec_brainpoolp384r1",
)
RELAXED_CURVES = (
    "secp256k1",
    "brainpoolp256r1",
    "brainpoolp384r1",
)
V7_KEY_TYPES = frozenset((0, 1, 2, 3, 4, 16, 31, 64, 65, 66, 73, 74, 75))
V7_VALUE_LENS = frozenset((12, 16, 24, 32, 48))
V7_MODULUS_BITS = frozenset((1024, 2048, 3072, 4096, 8192))
FIELD_REASONS = (
    "template truncated (first 8 attributes captured)",
    "template value outside approved finite set",
    "curve unusable for key type",
    "template partly read",
)


def resolve(node):
    while isinstance(node, dict) and "$ref" in node and len(node) == 1:
        assert node["$ref"].startswith("#/$defs/"), node["$ref"]
        node = SCHEMA["$defs"][node["$ref"][len("#/$defs/"):]]
    return node


def check(node, value, path):
    """Validate value against the frozen-subset schema node."""
    node = resolve(node)
    if "anyOf" in node:
        errors = []
        for option in node["anyOf"]:
            try:
                check(option, value, path)
                return
            except AssertionError as error:
                errors.append(str(error))
        raise AssertionError(f"{path}: no anyOf branch matched: {errors}")
    if "const" in node:
        assert value == node["const"], f"{path}: {value!r} != const {node['const']!r}"
    if "enum" in node:
        assert value in node["enum"], f"{path}: {value!r} not in {node['enum']}"
    if "type" in node:
        kinds = node["type"] if isinstance(node["type"], list) else [node["type"]]
        assert any(
            (kind == "object" and isinstance(value, dict))
            or (kind == "array" and isinstance(value, list))
            or (kind == "string" and isinstance(value, str))
            or (kind == "integer" and isinstance(value, int) and not isinstance(value, bool))
            or (kind == "null" and value is None)
            for kind in kinds
        ), f"{path}: {value!r} mismatches type {node['type']}"
    if isinstance(value, int) and not isinstance(value, bool):
        assert value >= node.get("minimum", 0), f"{path}: {value} below minimum"
        assert value <= node.get("maximum", U64_MAX), f"{path}: {value} above maximum"
    if isinstance(value, str) and "pattern" in node:
        import re

        assert re.match(node["pattern"] + r"\Z", value), f"{path}: {value!r} mismatches {node['pattern']}"
    if isinstance(value, dict):
        for key in node.get("required", []):
            assert key in value, f"{path}: missing required key {key!r}"
        if node.get("additionalProperties") is False:
            for key in value:
                assert key in node.get("properties", {}), f"{path}: extra key {key!r}"
        for key, sub in node.get("properties", {}).items():
            if key in value:
                check(sub, value[key], f"{path}.{key}")
    if isinstance(value, list):
        assert len(value) <= node.get("maxItems", len(value)), f"{path}: too many items"
        for index, item in enumerate(value):
            check(node.get("items", {}), item, f"{path}[{index}]")


class ObjectObservationsV10Contract(unittest.TestCase):
    def test_golden_validates_against_frozen_v10_schema(self):
        check(SCHEMA, GOLDEN, "object_observations")

    def test_key_row_equations_hold(self):
        for row in GOLDEN["key_operations"]:
            total = (
                row["completed"]
                + row["failed"]
                + row["cancelled"]
                + row["unknown"]
                + row["active"]
                + row["key_join_lost"]
            )
            self.assertEqual(row["started"], total, row)

    def test_rows_are_sorted_by_frozen_key_order(self):
        self.assertEqual(
            [row["session"] for row in GOLDEN["sessions"]],
            sorted(row["session"] for row in GOLDEN["sessions"]),
        )
        self.assertEqual(
            [row["object"] for row in GOLDEN["objects"]],
            sorted(row["object"] for row in GOLDEN["objects"]),
        )
        keys = [
            (row["instance"], row["object"], row["category"], row["role"], row["metadata_at_use"])
            for row in GOLDEN["key_operations"]
        ]
        self.assertEqual(keys, sorted(keys))
        unknown = [(row["category"], row["reason"]) for row in GOLDEN["unknown_key_operations"]]
        self.assertEqual(unknown, sorted(unknown))

    def test_unknown_rows_carry_no_starts(self):
        for row in GOLDEN["unknown_key_operations"]:
            self.assertNotIn("started", row, row)

    def test_schema_freezes_pool_refusal_at_false(self):
        budgets = SCHEMA["properties"]["budgets"]["properties"]
        self.assertEqual(budgets["allocation_refused"], {"const": False, "description": budgets["allocation_refused"]["description"]})
        self.assertEqual(budgets["refusal_reason"]["const"], "none")

    def test_schema_object_label_enum_is_twelve_plus_pqc_plus_newsite_plus_relaxed(self):
        """Object views label with PQC, new-site and relaxed sets too; `unknown` stays row-level."""
        labels = SCHEMA["$defs"]["object_row"]["properties"]["label"]["enum"]
        self.assertEqual(
            set(labels) - {None},
            set(ESTABLISHED_LABELS) | set(PQC_LABELS) | set(NEWSITE_LABELS) | set(RELAXED_LABELS),
        )
        self.assertNotIn("unknown", labels)

    def test_schema_reason_enum_is_the_closed_four(self):
        for name in ("metadata_field_class", "metadata_field_key_type",
                     "metadata_field_token", "metadata_field_value_len",
                     "metadata_field_modulus_bits", "metadata_field_curve",
                     "metadata_field_parameter_set"):
            cell = SCHEMA["$defs"][name]
            self.assertEqual(
                set(cell["properties"]["reason"]["enum"]),
                set(FIELD_REASONS) | {None}, name)

    def test_golden_carries_relaxed_content(self):
        """The v10 golden earns version 10: relaxed content plus unknown-row ids."""
        self.assertEqual(GOLDEN["version"], 10)
        self.assertEqual(SCHEMA["properties"]["version"]["const"], 10)
        self.assertIn("unattributed", GOLDEN)
        seen_label = {
            row["metadata_at_use"] for row in GOLDEN["key_operations"]
        } | {row["label"] for row in GOLDEN["objects"] if row["label"] is not None}
        self.assertTrue(
            seen_label & set(RELAXED_LABELS),
            f"no relaxed label in golden: {sorted(seen_label)}",
        )
        seen_object_label = {
            row["label"] for row in GOLDEN["objects"] if row["label"] is not None
        }
        self.assertTrue(
            seen_object_label & set(RELAXED_LABELS),
            f"no relaxed object label in golden: {sorted(seen_object_label)}",
        )
        seen_sources = set()
        seen_reasons = set()
        seen_key_type = set()
        seen_value_len = set()
        seen_modulus = set()
        seen_curve = set()
        for row in GOLDEN["objects"]:
            for block in (row["requested"], row["established"]):
                self.assertIn("parameter_set", block, row)
                for cell in block.values():
                    if cell["source"] is not None:
                        seen_sources.add(cell["source"])
                    if cell["reason"] is not None:
                        seen_reasons.add(cell["reason"])
                if block["key_type"]["value"] is not None:
                    seen_key_type.add(block["key_type"]["value"])
                if block["value_len"]["value"] is not None:
                    seen_value_len.add(block["value_len"]["value"])
                if block["modulus_bits"]["value"] is not None:
                    seen_modulus.add(block["modulus_bits"]["value"])
                if block["ec_params"]["value"] is not None:
                    seen_curve.add(block["ec_params"]["value"])
            self.assertIn("parameter_set", row["queries"], row)
        self.assertIn("creation_success", seen_sources, "no promoted source in golden")
        self.assertIn("query", seen_sources, "no queried source in golden")
        self.assertEqual(
            seen_reasons, set(FIELD_REASONS),
            f"golden must exercise all four reasons: {sorted(seen_reasons)}",
        )
        self.assertTrue(
            seen_key_type - V7_KEY_TYPES,
            f"no relaxed key type in golden: {sorted(seen_key_type)}",
        )
        self.assertIn(19, seen_key_type, "no DES key type in golden")
        self.assertIn(43, seen_key_type, "no HMAC key type in golden")
        self.assertTrue(
            seen_modulus - V7_MODULUS_BITS,
            f"no relaxed modulus in golden: {sorted(seen_modulus)}",
        )
        self.assertTrue(
            seen_curve & set(RELAXED_CURVES),
            f"no relaxed curve in golden: {sorted(seen_curve)}",
        )

    def test_golden_key_rows_carry_inferred_keys(self):
        """v9 sections carry inferred keys on every proved row (v7 shapes)."""
        self.assertTrue(GOLDEN["key_operations"], "no proved rows in golden")
        for row in GOLDEN["key_operations"]:
            self.assertIn("inferred_family", row, row)
            self.assertIn("inferred_size", row, row)
            self.assertIn(row["inferred_family"]["status"],
                          ("inferred", "unknown", "conflicting", "unsupported"))
            self.assertIn(row["inferred_size"]["status"],
                          ("inferred", "unknown", "conflicting", "unsupported"))

    def test_schema_ranges_are_the_closed_relaxed_bounds(self):
        """value_len/modulus_bits are closed ranges, not open integers."""
        value = SCHEMA["$defs"]["metadata_field_value_len"]["properties"]["value"]
        self.assertEqual(value["type"], ["integer", "null"])
        self.assertEqual((value["minimum"], value["maximum"]), (1, 4096))
        modulus = SCHEMA["$defs"]["metadata_field_modulus_bits"]["properties"]["value"]
        self.assertEqual(modulus["type"], ["integer", "null"])
        self.assertEqual((modulus["minimum"], modulus["maximum"]), (256, 16384))

    def test_golden_first_observed_rows_carry_no_reasons(self):
        """Query-only rows stay reason-free (t3 I1 shape)."""
        first_observed = [row for row in GOLDEN["objects"] if row["origin"] == "first_observed"]
        self.assertTrue(first_observed, "no first-observed row in golden")
        for row in first_observed:
            for block in (row["requested"], row["established"]):
                for name, cell in block.items():
                    self.assertIsNone(cell["reason"], (row["object"], name))

    def test_golden_earns_v10_with_unknown_row_ids(self):
        """Some unknown row carries mechanism content (the v10 trigger)."""
        self.assertTrue(
            any(row.get("mechanisms") or row.get("further_mechanism_terminals", 0) > 0
                for row in GOLDEN["unknown_key_operations"]),
            "no unknown-row mechanism content in golden",
        )

    def test_unknown_row_mechanism_shape_is_bounded(self):
        """mechanisms is required (possibly empty), entries are {id, count},
        at most eight, u64-bounded; further count is optional."""
        unknown = SCHEMA["$defs"]["unknown_row"]
        self.assertIn("mechanisms", unknown["required"])
        self.assertNotIn("further_mechanism_terminals", unknown["required"])
        mechs = unknown["properties"]["mechanisms"]
        self.assertEqual(mechs["maxItems"], 8)
        self.assertEqual(mechs["items"]["required"], ["id", "count"])
        self.assertFalse(mechs["items"]["additionalProperties"])
        for key in ("id", "count"):
            cell = mechs["items"]["properties"][key]
            self.assertEqual(cell["type"], "integer")
            self.assertEqual((cell["minimum"], cell["maximum"]), (0, U64_MAX))
        further = unknown["properties"]["further_mechanism_terminals"]
        self.assertEqual(further["type"], "integer")
        self.assertEqual((further["minimum"], further["maximum"]), (0, U64_MAX))
        for row in GOLDEN["unknown_key_operations"]:
            self.assertIn("mechanisms", row, row)
            self.assertLessEqual(len(row["mechanisms"]), 8, row)
            for entry in row["mechanisms"]:
                self.assertEqual(sorted(entry.keys()), ["count", "id"], row)


if __name__ == "__main__":
    unittest.main()
