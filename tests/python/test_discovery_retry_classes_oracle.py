#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""`discovery_retry_classes` twins for scripts/check-capture-evidence.py.

The producer (`src/render.rs::Evidence`) publishes the complete per-class
discovery retry breakdown behind the generic `skipped` rows whenever
discovery retried, and omits the key — never null — when it never did.
The oracle's exact evidence key set must accept the key in every current
lane (profile, metrics, terminal trace) and validate its shape exactly:
keys are a nonempty subset of the six noise labels, values are positive
u64 counts (only nonzero classes appear).

No root, no BPF, no observer: pure oracle twins over the checker's own
document fixtures.
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

# The live 20-minute profile shape: four nonzero classes, exact counts.
LIVE_BREAKDOWN = {
    "maps-snapshot": 84,
    "other": 106,
    "process-ended": 14,
    "process-view": 13635,
}

TERMINAL_KEYS = {
    "privacy_mode": "allowlisted",
    "capture_aborted": None,
    "final_drain": False,
    "counters_available": True,
    "trace_truncated": False,
}


# Absent-key marker: `None` is itself a malformed value (a null object
# must be rejected, never read as absent), so omission needs its own word.
ABSENT = object()


def metrics_document(breakdown=LIVE_BREAKDOWN):
    """A valid metrics document carrying the breakdown (or omitting it)."""
    document = CHECKER.document_fixture(
        CHECKER.evidence_fixture({}),
        schema=CHECKER.METRICS_SCHEMA,
        mode="metrics",
        privacy="aggregate-only",
    )
    if breakdown is not ABSENT:
        document["evidence"]["discovery_retry_classes"] = copy.deepcopy(breakdown)
    return document


def profile_document(breakdown=LIVE_BREAKDOWN):
    """A valid profile-v3 document carrying the breakdown (or omitting it)."""
    document = CHECKER.document_fixture(CHECKER.evidence_fixture({}))
    if breakdown is not ABSENT:
        document["evidence"]["discovery_retry_classes"] = copy.deepcopy(breakdown)
    return document


def terminal_evidence(breakdown=LIVE_BREAKDOWN):
    """A valid terminal trace EVIDENCE object, as the trace lanes feed it."""
    evidence = copy.deepcopy(
        CHECKER.document_fixture(CHECKER.evidence_fixture({}))["evidence"]
    )
    evidence.update(TERMINAL_KEYS)
    if breakdown is not ABSENT:
        evidence["discovery_retry_classes"] = copy.deepcopy(breakdown)
    return evidence


class DiscoveryRetryClassesOracleTests(unittest.TestCase):
    def test_live_breakdown_rides_metrics_profile_and_terminal(self):
        # The producer's live shape validates through the real consumer
        # in every current lane.
        CHECKER.exact_metrics_schema(metrics_document())
        CHECKER.exact_profile_v3_selection(profile_document())
        CHECKER.exact_profile_v3_selection(terminal_evidence(), terminal=True)

    def test_absent_key_stays_valid_in_every_lane(self):
        # Absence when discovery never retried is itself pinned: the
        # fixtures carry no breakdown field and still validate exactly.
        metrics = metrics_document(ABSENT)
        self.assertNotIn("discovery_retry_classes", metrics["evidence"])
        CHECKER.exact_metrics_schema(metrics)
        profile = profile_document(ABSENT)
        self.assertNotIn("discovery_retry_classes", profile["evidence"])
        CHECKER.exact_profile_v3_selection(profile)
        terminal = terminal_evidence(ABSENT)
        self.assertNotIn("discovery_retry_classes", terminal)
        CHECKER.exact_profile_v3_selection(terminal, terminal=True)

    def test_malformed_breakdown_shape_rejected(self):
        # The allowance is exact: a nonempty object with known labels and
        # positive u64 counts, never null. Anything else — present-but-empty,
        # an unknown label, a zero/non-positive/uncountable value, or a
        # non-object — fails closed in every lane.
        bad = [
            {},
            {"other": 2, "bogus-label": 1},
            {"other": 0},
            {"other": -1},
            {"other": True},
            {"other": 2**64},
            {"other": "106"},
            {"other": None},
            {"other": 1.5},
            None,
            [],
            "other",
            106,
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(AssertionError):
                    CHECKER.exact_metrics_schema(metrics_document(value))
                with self.assertRaises(AssertionError):
                    CHECKER.exact_profile_v3_selection(profile_document(value))
                with self.assertRaises(AssertionError):
                    CHECKER.exact_profile_v3_selection(
                        terminal_evidence(value), terminal=True
                    )

    def test_historical_metrics_predates_the_key(self):
        # Retained v2-metrics documents predate the breakdown like the other
        # additive v3 disclosures, so the key is refused there.
        historical = CHECKER.document_fixture(
            CHECKER.evidence_fixture({}),
            schema=CHECKER.HISTORICAL_METRICS_SCHEMA,
            mode="metrics",
            privacy="aggregate-only",
        )
        self.assertNotIn("discovery_retry_classes", historical["evidence"])
        CHECKER.exact_historical_metrics_schema(historical)
        historical["evidence"]["discovery_retry_classes"] = dict(LIVE_BREAKDOWN)
        with self.assertRaises(AssertionError):
            CHECKER.exact_historical_metrics_schema(historical)


if __name__ == "__main__":
    unittest.main()
