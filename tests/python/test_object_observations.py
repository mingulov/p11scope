# SPDX-License-Identifier: GPL-3.0-or-later
"""Frozen H9 object_observations contract agrees with its golden fixture.

docs/schema/inventory-v1-object-observations.schema.json is the frozen
Task 4 consumer contract; tests/fixtures/key-operations/object-observations.json
is the hand-reviewed populated example. These tests validate the golden
against the schema (exact keys, enums, integer bounds, row equations and
sort orders) with a small dependency-free checker for the frozen subset,
so the schema cannot drift from its example. The Rust suite
(key_operation_schema_contract) separately proves the renderer emits
exactly these keys and enums.

encoded_bytes in the golden is illustrative, not self-measured: the byte
count of a document cannot equal a number stored inside it. The renderer
test asserts measured equality on live output instead.

Run: python3 -I tests/python/test_object_observations.py -v
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (ROOT / "docs" / "schema" / "inventory-v1-object-observations.schema.json").read_text(
        encoding="utf-8"
    )
)
GOLDEN = json.loads(
    (ROOT / "tests" / "fixtures" / "key-operations" / "object-observations.json").read_text(
        encoding="utf-8"
    )
)
U64_MAX = 18446744073709551615


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


class ObjectObservationsContract(unittest.TestCase):
    def test_golden_validates_against_frozen_schema(self):
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


if __name__ == "__main__":
    unittest.main()
