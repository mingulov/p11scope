# SPDX-License-Identifier: GPL-3.0-or-later
"""Ignored-test inventory: every #[ignore] is a tracked obligation.

scripts/check-ignored-tests.py scans the workspace Rust sources for real
`#[ignore]` attributes and compares them both ways against
tests/ignored-tests.json, and requires every `privileged` entry to be
curated in scripts/run-privileged-lib-tests.sh. These tests prove the
checked-in inventory matches the sources, then exercise each failure
mode on synthetic fixture trees so a regression in the checker cannot
hide behind a clean real tree.

Run: python3 -I tests/python/test_ignored_tests.py -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-ignored-tests.py"
INVENTORY = ROOT / "tests" / "ignored-tests.json"

CELLS = {
    "privileged": "test cell",
    "feature": "test cell",
    "performance": "test cell",
}


def write_fixture(root, sources, entries, registered):
    """A minimal checkable tree: sources {rel: text}, inventory, runner."""
    for rel, text in sources.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    inv = root / "tests" / "ignored-tests.json"
    inv.parent.mkdir(parents=True, exist_ok=True)
    inv.write_text(
        json.dumps(
            {"schema": "p11scope/ignored-tests/v1",
             "cells": CELLS,
             "sites": entries},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    runner = root / "scripts" / "run-privileged-lib-tests.sh"
    runner.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f"{name}=(\n"
        + "".join(f"{item}\n" for item in items)
        + "# end\n)\n"
        for name, items in (
            ("DEFAULT_TESTS", registered),
            ("ALTERNATIVE_TESTS", []),
            ("LONG_TESTS", []),
            ("SKIP_TESTS", []),
        )
    )
    runner.write_text(body, encoding="utf-8")


def run_checker(root):
    return subprocess.run(
        [sys.executable, "-I", str(CHECKER), "--root", str(root)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


LIB_RS = "mod a;\nmod m;\n"

A_RS = """\
#[test]
fn t_plain() {}

#[test]
#[ignore = "privileged: needs the lane"]
fn t_priv() {}

#[test]
#[ignore]
fn t_timing() {}

// A prose mention of `#[ignore]` must not count as a site.
const NOTE: &str = "#[ignore = \\"in a string\\"]";
"""

M_RS = """\
macro_rules! sweep {
    ($name:ident) => {
        #[test]
        #[ignore = "privileged: sweep cell"]
        fn $name() {}
    };
}

sweep!(t_sweep);

#[cfg(feature = "wide")]
sweep!(t_wide);
"""

SOURCES = {"src/lib.rs": LIB_RS, "src/a.rs": A_RS, "src/m.rs": M_RS}

ENTRIES = [
    {"file": "src/a.rs", "path": "a::t_priv",
     "reason": "privileged: needs the lane", "cell": "privileged"},
    {"file": "src/a.rs", "path": "a::t_timing",
     "reason": "", "cell": "performance"},
    {"file": "src/m.rs", "path": "m::sweep!",
     "reason": "privileged: sweep cell", "cell": "privileged"},
]

REGISTERED = ["a::t_priv", "m::t_sweep"]


class IgnoredTestsTests(unittest.TestCase):
    def test_checked_in_inventory_matches_the_sources(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inventoried = len(json.loads(INVENTORY.read_text(encoding="utf-8"))
                           ["sites"])
        self.assertIn(f"all {inventoried} inventoried site(s) match",
                      result.stdout)
        self.assertIn("privileged curation verified", result.stdout)

    def test_an_extra_ignored_test_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = dict(SOURCES)
            sources["src/a.rs"] += (
                '\n#[test]\n#[ignore = "privileged: sneaked in"]\n'
                "fn t_new() {}\n"
            )
            write_fixture(root, sources, ENTRIES, REGISTERED)
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_new has no inventory entry", result.stdout)

    def test_a_removed_inventory_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES[1:], REGISTERED)
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_priv has no inventory entry", result.stdout)

    def test_an_inventory_entry_without_a_site_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = list(ENTRIES) + [
                {"file": "src/a.rs", "path": "a::t_gone",
                 "reason": "privileged: removed", "cell": "privileged"},
            ]
            write_fixture(root, SOURCES, entries, REGISTERED)
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("no matching #[ignore] site for src/a.rs a::t_gone",
                      result.stdout)

    def test_an_unregistered_privileged_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["m::t_sweep"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("privileged a::t_priv is not curated", result.stdout)

    def test_comment_and_string_mentions_are_not_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED)
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 3 inventoried site(s) match", result.stdout)

    def test_macro_expansions_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["a::t_priv"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("expands to m::t_sweep, not curated", result.stdout)

    def test_feature_gated_expansions_are_exempt(self):
        # m::t_wide is gated on cargo feature "wide" and unregistered; the
        # fixture in the other tests already relies on this passing.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED)
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
