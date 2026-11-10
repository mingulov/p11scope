#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Privileged-runner curation message: the wide profile is the default build.

Since v0.7.0 made 2,112 slots the default profile, the wide-Detailed
curation refusal must not claim a default build lacks the wide cells or
tell the operator to rebuild with --features wide-detailed-2112: a
binary missing them was built --no-default-features.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/run-privileged-lib-tests.sh"


class WideCurationMessageTest(unittest.TestCase):
    def test_refusal_names_no_default_features_as_the_cause(self):
        text = RUNNER.read_text()
        self.assertNotIn(
            "a default build lacks these; rebuild with --features wide-detailed-2112",
            text,
            "stale: the default build carries the wide cells since v0.7.0",
        )
        self.assertIn(
            "a --no-default-features build lacks these; rebuild with default features",
            text,
        )


if __name__ == "__main__":
    unittest.main()
