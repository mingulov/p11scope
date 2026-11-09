# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Benign loader-hit evidence: closed-set, invariant, and complete rule.

Direct checker tests (no subprocess): `benign_hits` exonerates fully
accounted loader hits, never exceeds `hits`, and stays optional so old
reports verify under the old rule.
"""

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-capture-evidence.py"
MOD = runpy.run_path(str(CHECKER))


def loader(hits=0, benign=None, unproven=0, strategies_hit=0):
    aggregate = {
        "strategies": {
            "debug_state_every_hit": strategies_hit,
            "dlopen_return": 0,
            "unavailable": 0,
        },
        "dlopen_timing": {
            "qualified_pre_constructor": 0,
            "known_pre_relocation": 0,
            "unproven": unproven,
            "none": 0,
            "pause_protected": 0,
        },
        "initial_set_timing": {
            "qualified_pre_constructor": 0,
            "known_pre_relocation": 0,
            "unproven": 0,
            "none": 0,
            "pause_protected": 0,
        },
        "initial_set_capture": {"eligible": 0, "none": 0, "pause_protected": 0},
        "hits": hits,
        "state_read_failures": 0,
    }
    if benign is not None:
        aggregate["benign_hits"] = benign
    return aggregate


class BenignLoaderEvidenceTests(unittest.TestCase):
    def test_closed_set_accepts_benign_hits(self):
        MOD["exact_loader_discovery"](
            {"loader_discovery": loader(hits=1, benign=1, unproven=1, strategies_hit=1)}
        )

    def test_closed_set_still_refuses_unknown_keys(self):
        aggregate = loader(hits=1, benign=1, unproven=1, strategies_hit=1)
        aggregate["injected"] = 0
        with self.assertRaises(AssertionError):
            MOD["exact_loader_discovery"]({"loader_discovery": aggregate})

    def test_complete_rule_exonerates_benign(self):
        self.assertTrue(
            MOD["loader_discovery_complete"](
                loader(hits=1, benign=1, unproven=1, strategies_hit=1)
            )
        )

    def test_complete_rule_keeps_partial_hits_lossy(self):
        self.assertFalse(
            MOD["loader_discovery_complete"](
                loader(hits=2, benign=1, unproven=1, strategies_hit=1)
            )
        )

    def test_missing_key_defaults_to_zero(self):
        aggregate = loader(hits=1, unproven=1, strategies_hit=1)
        self.assertNotIn("benign_hits", aggregate)
        MOD["exact_loader_discovery"]({"loader_discovery": aggregate})
        self.assertFalse(MOD["loader_discovery_complete"](aggregate))

    def test_invariant_refuses_benign_above_hits(self):
        with self.assertRaisesRegex(AssertionError, "above"):
            MOD["exact_loader_discovery"](
                {"loader_discovery": loader(hits=1, benign=2, unproven=1, strategies_hit=1)}
            )


if __name__ == "__main__":
    unittest.main()
