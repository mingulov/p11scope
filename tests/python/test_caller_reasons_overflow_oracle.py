#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Trace terminal `caller_reasons_overflow` twins for scripts/check-capture-evidence.py.

The producer (`src/trace.rs::evidence_line_with_caller_overflow`) carries
the caller-reasons fold past the 4096-caller cap as a counted
`caller_reasons_overflow` object (`folded_lines`, `folded_rows`), and omits
the field while under the cap. The oracle's exact terminal key set must
accept the field when present and validate its shape exactly, while
absence under the cap stays pinned behavior — never a pre-added key.

No root, no BPF, no observer: pure oracle twins over the checker's own
terminal-document fixtures.
"""

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "scripts" / "check-capture-evidence.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_capture_evidence", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()

TERMINAL_KEYS = {
    "privacy_mode": "allowlisted",
    "capture_aborted": None,
    "final_drain": False,
    "counters_available": True,
    "trace_truncated": False,
}


def terminal_evidence(**overrides):
    """A valid terminal trace EVIDENCE object, as the canary trace lanes feed it."""
    evidence = copy.deepcopy(
        CHECKER.document_fixture(CHECKER.evidence_fixture({}))["evidence"]
    )
    evidence.update(TERMINAL_KEYS)
    evidence.update(overrides)
    return evidence


class CallerReasonsOverflowOracleTests(unittest.TestCase):
    def test_over_cap_terminal_evidence_carries_counted_overflow(self):
        # Three folded (function, rv) pairs over ten rendered lines: the
        # oracle accepts the counted gap beside the terminal keys.
        evidence = terminal_evidence(
            caller_reasons_overflow={"folded_lines": 10, "folded_rows": 3}
        )
        CHECKER.exact_profile_v3_selection(evidence, terminal=True)

    def test_under_cap_terminal_evidence_has_no_overflow_key(self):
        # Absence under the cap is itself pinned: the fixture carries no
        # overflow field and still validates exactly.
        evidence = terminal_evidence()
        self.assertNotIn("caller_reasons_overflow", evidence)
        CHECKER.exact_profile_v3_selection(evidence, terminal=True)

    def test_malformed_overflow_shape_rejected(self):
        # The allowance is exact: anything but two positive u64 counts —
        # missing or extra keys, zero, negative, boolean, uncountable, or
        # a non-object — fails closed.
        bad = [
            {},
            {"folded_lines": 10},
            {"folded_rows": 3},
            {"folded_lines": 10, "folded_rows": 3, "extra": 1},
            {"folded_lines": 0, "folded_rows": 3},
            {"folded_lines": 10, "folded_rows": 0},
            {"folded_lines": -1, "folded_rows": 3},
            {"folded_lines": True, "folded_rows": 3},
            {"folded_lines": 2**64, "folded_rows": 3},
            {"folded_lines": "10", "folded_rows": 3},
            {"folded_lines": 10, "folded_rows": None},
            "folded",
            10,
            None,
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(AssertionError):
                    CHECKER.exact_profile_v3_selection(
                        terminal_evidence(caller_reasons_overflow=value),
                        terminal=True,
                    )

    def test_overflow_key_rejected_outside_terminal_documents(self):
        # The fold is a trace-terminal disclosure only: profile documents
        # never carry it, so the exact set still refuses it there.
        document = CHECKER.document_fixture(CHECKER.evidence_fixture({}))
        document["evidence"]["caller_reasons_overflow"] = {
            "folded_lines": 1,
            "folded_rows": 1,
        }
        with self.assertRaises(AssertionError):
            CHECKER.exact_profile_v3_selection(document)


if __name__ == "__main__":
    unittest.main()
