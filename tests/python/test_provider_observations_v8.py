# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Frozen Task 7 v8 provider/token/mechanism contract agrees with its golden.

docs/schema/inventory-v1-object-observations-v8.schema.json is the frozen
section-version-8 consumer contract (v0.8.0 keymeta Task 7, spec section
17.5; the v8 number comes from the shared section-version allocator, spec
section 10.1); tests/fixtures/key-operations/provider-observations-v8.json
is the hand-reviewed populated example carrying provider_info, token and
mechanism rows, all eight named gaps, one refused (non-UTF8) string field
and one proved instance attachment. These tests validate the golden
against the schema (exact keys, enums, integer bounds and sort orders)
with a small dependency-free checker for the frozen subset, so the
schema cannot drift from its example. The Rust suite
(info_schema_v8_pins_task7_section_contract) separately proves
the renderer emits exactly these keys and enums.

Run: python3 -I tests/python/test_provider_observations_v8.py -v
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT / "docs" / "schema" / "inventory-v1-object-observations-v8.schema.json"
)
GOLDEN_PATH = (
    ROOT / "tests" / "fixtures" / "key-operations" / "provider-observations-v8.json"
)
U64_MAX = 18446744073709551615

GAP_REASONS = (
    "info_aliased_endpoint",
    "info_return_deferred",
    "info_caller_unavailable",
    "mechanism_info_refused",
    "info_token_rows_refused",
    "info_mechanism_rows_refused",
    "info_token_departed_folded",
    "info_mechanism_departed_folded",
)

# Excluded bytes (§17.2) must have no key anywhere in the contract or the
# golden: no serial, label, session count, memory size or clock reading.
# PIN *lengths* (pin_min_len/pin_max_len) are allowlisted policy state and
# are the only pin-named keys permitted.
FORBIDDEN_KEY_SUBSTRINGS = (
    "serial",
    "label",
    "utctime",
    "sessioncount",
    "session_count",
    "memory",
    "password",
)
PIN_KEYS = frozenset({"pin_min_len", "pin_max_len"})


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def walk_keys(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(key)
            walk_keys(value, found)
    elif isinstance(node, list):
        for value in node:
            walk_keys(value, found)


def assert_closed(schema_node, path, test):
    test.assertIsInstance(schema_node, dict, path)
    if schema_node.get("type") == "object":
        test.assertIs(
            schema_node.get("additionalProperties"),
            False,
            f"{path} must be closed",
        )
        for name, child in schema_node.get("properties", {}).items():
            assert_closed(child, f"{path}.{name}", test)
    if "items" in schema_node:
        assert_closed(schema_node["items"], f"{path}[]", test)
    for name, child in schema_node.get("$defs", {}).items():
        assert_closed(child, f"{path}#$defs.{name}", test)


class ProviderObservationsV8Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_json(SCHEMA_PATH)
        cls.golden = load_json(GOLDEN_PATH)

    def test_schema_is_closed_v8(self):
        self.assertEqual(self.schema["properties"]["version"]["const"], 8)
        assert_closed(self.schema, "$", self)
        defs = self.schema["$defs"]
        for name in ("provider_info", "token_row", "mechanism_row", "gap_row"):
            self.assertIn(name, defs)

    def test_schema_gap_reasons_are_closed(self):
        gap = self.schema["$defs"]["gap_row"]
        self.assertEqual(
            gap["properties"]["reason"]["enum"], list(GAP_REASONS)
        )

    def test_schema_has_no_excluded_key(self):
        found = []
        walk_keys(self.schema, found)
        lowered = [key.lower() for key in found]
        for key in lowered:
            for forbidden in FORBIDDEN_KEY_SUBSTRINGS:
                self.assertNotIn(
                    forbidden, key, f"excluded key {key!r} in schema"
                )
            if "pin" in key:
                self.assertIn(key, PIN_KEYS, f"unexpected pin key {key!r}")

    def test_golden_section_shape(self):
        section = self.golden["provider_observations"]
        self.assertEqual(section["version"], 8)
        self.assertEqual(
            set(section.keys()), {"version", "tokens", "mechanisms", "gaps"}
        )

    def test_golden_token_rows(self):
        tokens = self.golden["provider_observations"]["tokens"]
        self.assertGreaterEqual(len(tokens), 2)
        order = []
        for row in tokens:
            keys = set(row.keys())
            self.assertTrue(
                {
                    "module",
                    "caller",
                    "slot",
                    "manufacturer",
                    "model",
                    "hardware_major",
                    "hardware_minor",
                    "firmware_major",
                    "firmware_minor",
                    "flags",
                    "pin_min_len",
                    "pin_max_len",
                    "completions",
                    "changes",
                }
                <= keys,
                f"token row keys: {sorted(keys)}",
            )
            self.assertTrue(
                keys
                <= {
                    "module",
                    "caller",
                    "slot",
                    "manufacturer",
                    "manufacturer_reason",
                    "model",
                    "model_reason",
                    "hardware_major",
                    "hardware_minor",
                    "firmware_major",
                    "firmware_minor",
                    "flags",
                    "pin_min_len",
                    "pin_max_len",
                    "completions",
                    "changes",
                    "instance",
                },
                f"token row keys: {sorted(keys)}",
            )
            for key in ("slot", "flags", "completions", "changes"):
                self.assertIsInstance(row[key], int)
                self.assertGreaterEqual(row[key], 0)
                self.assertLessEqual(row[key], U64_MAX)
            order.append((row["module"], row["caller"], row["slot"]))
        self.assertEqual(order, sorted(order), "tokens sorted by module/caller/slot")

    def test_golden_refused_string_shape(self):
        refused = [
            row
            for row in self.golden["provider_observations"]["tokens"]
            if row["manufacturer"] is None
        ]
        self.assertEqual(len(refused), 1, "one refused-manufacturer token row")
        self.assertEqual(refused[0]["manufacturer_reason"], "non_utf8_bytes")

    def test_golden_instance_attached_only_when_proven(self):
        tokens = self.golden["provider_observations"]["tokens"]
        proven = [row for row in tokens if "instance" in row]
        unproven = [row for row in tokens if "instance" not in row]
        self.assertEqual([row["instance"] for row in proven], ["i7"])
        self.assertGreaterEqual(len(unproven), 1)

    def test_golden_mechanism_rows(self):
        mechanisms = self.golden["provider_observations"]["mechanisms"]
        self.assertGreaterEqual(len(mechanisms), 2)
        order = []
        for row in mechanisms:
            keys = set(row.keys())
            self.assertTrue(
                {
                    "module",
                    "caller",
                    "slot",
                    "mechanism",
                    "min_key_size",
                    "max_key_size",
                    "flags",
                    "completions",
                    "changes",
                }
                <= keys,
                f"mechanism row keys: {sorted(keys)}",
            )
            self.assertTrue(
                keys
                <= {
                    "module",
                    "caller",
                    "slot",
                    "mechanism",
                    "min_key_size",
                    "max_key_size",
                    "flags",
                    "completions",
                    "changes",
                    "instance",
                },
                f"mechanism row keys: {sorted(keys)}",
            )
            # Raw mechanism-dependent numbers: integers, never unit strings.
            for key in ("min_key_size", "max_key_size", "flags"):
                self.assertIsInstance(row[key], int)
            order.append((row["module"], row["caller"], row["slot"], row["mechanism"]))
        self.assertEqual(
            order, sorted(order), "mechanisms sorted by module/caller/slot/id"
        )

    def test_golden_gaps_cover_all_reasons(self):
        gaps = self.golden["provider_observations"]["gaps"]
        self.assertEqual(
            [row["reason"] for row in gaps], list(GAP_REASONS)
        )
        for row in gaps:
            self.assertEqual(set(row.keys()), {"reason", "count"})
            self.assertIsInstance(row["count"], int)
            self.assertGreater(row["count"], 0)

    def test_golden_module_provider_info(self):
        modules = self.golden["modules"]
        self.assertGreaterEqual(len(modules), 1)
        info = modules[0]["provider_info"]
        self.assertEqual(
            set(info.keys()),
            {
                "cryptoki_major",
                "cryptoki_minor",
                "manufacturer",
                "description",
                "flags",
                "library_major",
                "library_minor",
            },
        )
        self.assertIsInstance(info["flags"], int)

    def test_golden_has_no_excluded_key(self):
        found = []
        walk_keys(self.golden, found)
        lowered = [key.lower() for key in found]
        for key in lowered:
            for forbidden in FORBIDDEN_KEY_SUBSTRINGS:
                self.assertNotIn(
                    forbidden, key, f"excluded key {key!r} in golden"
                )
            if "pin" in key:
                self.assertIn(key, PIN_KEYS, f"unexpected pin key {key!r}")


if __name__ == "__main__":
    unittest.main()
