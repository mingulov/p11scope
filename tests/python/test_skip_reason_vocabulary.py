# SPDX-License-Identifier: GPL-3.0-or-later
"""Producer-to-validator skip-reason vocabulary (audit F-13, Package A).

The observer's public skip reasons are string constants in
src/render.rs (`capture_skipped_out`); the release oracle accepts only
the reasons in scripts/check-capture-evidence.py
(DISCOVERY_REASONS/ENTRY_REASONS). F-13: the producer emitted
"physical identity is ambiguous; ..." while the validator rejected it,
so honest output failed the release gate. These tests read the actual
producer constants out of render.rs, feed every one through the real
validator, and require the two vocabularies to agree in both
directions — a reason added at either end without the other fails here.

Run: python3 -I tests/python/test_skip_reason_vocabulary.py -v
"""

import re
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
RENDER_RS = ROOT / "src" / "render.rs"
SCHEMA_DOC = ROOT / "docs" / "schema" / "observed-profile-v2.md"

# The named public-reason constants `capture_skipped_out` renders, plus the
# gated "null pointer" literal it passes through for null slots.
PRODUCER_CONSTANTS = (
    "DISCOVERY_UNAVAILABLE",
    "ENTRY_UNAVAILABLE",
    "TABLE_UNAVAILABLE",
    "SHARED_OVERLAY_UNCERTAINTY",
    "PHYSICAL_IDENTITY_AMBIGUITY",
    # SYSPLAN residual F-14: refused future-minor table at the scan gate.
    "UNSUPPORTED_TABLE_VERSION",
    "STATIC_GAP_INCOMPLETE",
    "STATIC_GAP_RECOVERED",
    # OD34: fixed product-limit skips name their limit.
    "PROCESS_VIEW_CAPACITY_EXHAUSTED",
    "LOADER_CONTEXT_CAPACITY_EXHAUSTED",
    "LOADER_SCAN_LEDGER_EXCEEDED",
    "LOADER_ARM_LEDGER_FULL",
    # Never-stop discovery gaps: one bad manifest object, pre-arm path,
    # or live-ring dequeue gaps without aborting siblings.
    "MANIFEST_OBJECT_UNAVAILABLE",
    "PREARM_OBJECT_UNAVAILABLE",
    "DISCOVERY_TRANSPORT_UNAVAILABLE",
    # Run-tree scope gaps: survivors, degradation, unreadable
    # membership — filed under their own subject with finite reasons.
    "RUN_TREE_SURVIVORS",
    "RUN_TREE_DEGRADED",
    "RUN_TREE_MEMBERSHIP_UNKNOWN",
)


def producer_constant(name):
    """The exact string value of a `const NAME: &str = "..."` in render.rs."""
    text = RENDER_RS.read_text(encoding="utf-8")
    match = re.search(
        r'const %s: &str =\s*\n?\s*"((?:[^"\\]|\\.)*)"' % re.escape(name),
        text,
    )
    assert match is not None, f"producer constant {name} missing from render.rs"
    return match.group(1).replace('\\"', '"').replace("\\\\", "\\")


def producer_reasons():
    """(entry_reasons, discovery_reasons, run_tree_reasons) as the producer
    defines them.

    Entry granularity (function subjects and the one gated null) renders
    "null pointer" or ENTRY_UNAVAILABLE; discovery scope renders one of the
    fourteen discovery reasons; the run-tree scope renders one of its three
    reasons under its own subject. The split mirrors `capture_skipped_out`'s
    branches; the strings themselves come from the source, never from a
    copy pasted into this test.
    """
    const = {name: producer_constant(name) for name in PRODUCER_CONSTANTS}
    body = RENDER_RS.read_text(encoding="utf-8")
    assert '"null pointer"' in body, "producer lost its null-slot literal"
    entry = {"null pointer", const["ENTRY_UNAVAILABLE"]}
    discovery = {
        const["DISCOVERY_UNAVAILABLE"],
        const["TABLE_UNAVAILABLE"],
        const["SHARED_OVERLAY_UNCERTAINTY"],
        const["PHYSICAL_IDENTITY_AMBIGUITY"],
        const["UNSUPPORTED_TABLE_VERSION"],
        const["STATIC_GAP_INCOMPLETE"],
        const["STATIC_GAP_RECOVERED"],
        const["PROCESS_VIEW_CAPACITY_EXHAUSTED"],
        const["LOADER_CONTEXT_CAPACITY_EXHAUSTED"],
        const["LOADER_SCAN_LEDGER_EXCEEDED"],
        const["LOADER_ARM_LEDGER_FULL"],
        const["MANIFEST_OBJECT_UNAVAILABLE"],
        const["PREARM_OBJECT_UNAVAILABLE"],
        const["DISCOVERY_TRANSPORT_UNAVAILABLE"],
    }
    run_tree = {
        const["RUN_TREE_SURVIVORS"],
        const["RUN_TREE_DEGRADED"],
        const["RUN_TREE_MEMBERSHIP_UNKNOWN"],
    }
    assert len(entry) == 2 and len(discovery) == 14 and len(run_tree) == 3, const
    return entry, discovery, run_tree


class SkipReasonVocabularyTests(unittest.TestCase):
    def test_validator_accepts_exactly_the_producer_vocabulary(self):
        entry, discovery, run_tree = producer_reasons()
        # Two-way: a producer reason the validator rejects fails here, and
        # so does a validator reason the producer never emits.
        self.assertEqual(set(CHECKER["ENTRY_REASONS"]), entry)
        self.assertEqual(set(CHECKER["DISCOVERY_REASONS"]), discovery)
        self.assertEqual(set(CHECKER["RUN_TREE_REASONS"]), run_tree)

    def test_every_producer_reason_passes_bounded_skip(self):
        entry, discovery, run_tree = producer_reasons()
        for reason in sorted(entry):
            item = {"name": "C_Initialize", "reason": reason}
            self.assertTrue(CHECKER["bounded_skip"](item), item)
        for reason in sorted(discovery):
            item = {"name": CHECKER["DISCOVERY_SUBJECT"], "reason": reason}
            self.assertFalse(CHECKER["bounded_skip"](item), item)
        for reason in sorted(run_tree):
            item = {"name": CHECKER["RUN_TREE_SUBJECT"], "reason": reason}
            self.assertFalse(CHECKER["bounded_skip"](item), item)

    def test_gated_null_skip_matches_plan_subject(self):
        # The one entry-granularity skip whose subject is not a standard
        # function: `capture_skipped_out`'s gated_null branch renames an
        # unlinked table's null slot to plan::UNKNOWN_FUNCTION_NAME.
        plan = (ROOT / "src" / "plan.rs").read_text(encoding="utf-8")
        match = re.search(r'UNKNOWN_FUNCTION_NAME: &str = "([^"]*)"', plan)
        self.assertIsNotNone(match, "plan subject constant missing")
        expected = {"name": match.group(1), "reason": "null pointer"}
        self.assertEqual(CHECKER["UNKNOWN_NULL_SKIP"], expected)
        self.assertTrue(CHECKER["bounded_skip"](dict(expected)))

    def test_schema_doc_names_every_public_reason(self):
        entry, discovery, run_tree = producer_reasons()
        doc = SCHEMA_DOC.read_text(encoding="utf-8")
        for reason in sorted(entry | discovery | run_tree):
            self.assertIn(reason, doc, f"schema doc omits {reason!r}")


if __name__ == "__main__":
    unittest.main()
