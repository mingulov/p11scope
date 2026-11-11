#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Scan-only layout-evidence twins for scripts/check-capture-evidence.py.

Controller ruling 00:20 (v0.7.1): the oracle's "scan-only => PARTIAL" rule
(`exact_discovery_semantics`) must follow the mechanisms ruling — a standard
provider admitted by scan with layout evidence (interface linkage, sole
complete table, typed getter export) is not PARTIAL on that ground, while a
scan-only module without layout evidence stays PARTIAL.

The oracle sees the JSON evidence only, so it proxies the three product legs
through the scan table fields: `linkage == "interface"` is the interface leg
itself, and a fully export-verified table (`exports_agreeing == entries` on a
non-heuristic linkage) is the sole-complete / typed-getter-export leg. No
root, no BPF, no observer: pure oracle twins.
"""

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


def scan_table(*, linkage="exports", entries=68, agreeing=68, version=(2, 40)):
    """One SoftHSM-shaped scan table; the twin varies one field."""
    return {
        "version": list(version),
        "entries": entries,
        "source": "scan",
        "file_offset": 0x1000,
        "linkage": linkage,
        "exports_agreeing": agreeing,
    }


def scan_only_evidence(tables, completeness):
    return {
        "discovery": [
            {
                "sources": ["scan"],
                "corroborated": False,
                "corroboration": ["single_source"],
                "tables": tables,
            }
        ],
        "discovery_conflicts": 0,
        "completeness": completeness,
    }


class ScanOnlyLayoutOracleTests(unittest.TestCase):
    maxDiff = 4096

    def test_export_verified_scan_only_module_may_be_complete(self):
        # The container-leg shape: one 2.40 table, every ordinal verified
        # against the object's own .dynsym (sole-complete / typed-getter
        # leg). COMPLETE must no longer be refused on that ground.
        evidence = scan_only_evidence([scan_table()], "COMPLETE")
        CHECKER.exact_discovery_semantics(evidence)

    def test_interface_linked_scan_only_module_may_be_complete(self):
        # The softokn-like shape: the provider's own "PKCS 11" interface
        # record names the table, so per-ordinal export agreement is not
        # required — interface linkage alone is layout evidence.
        table = scan_table(linkage="interface", agreeing=0)
        evidence = scan_only_evidence([table], "COMPLETE")
        CHECKER.exact_discovery_semantics(evidence)

    def test_live_return_with_full_export_agreement_may_be_complete(self):
        # A live return outranks `exports` in the linkage priority without
        # erasing the agreement behind it (clean-metrics docstring); the
        # operative evidence is still the full export verification.
        table = scan_table(linkage="live_return")
        evidence = scan_only_evidence([table], "COMPLETE")
        CHECKER.exact_discovery_semantics(evidence)

    def test_heuristic_scan_only_module_stays_partial(self):
        table = scan_table(linkage="heuristic", agreeing=0)
        evidence = scan_only_evidence([table], "COMPLETE")
        with self.assertRaises(AssertionError):
            CHECKER.exact_discovery_semantics(evidence)

    def test_partially_agreeing_scan_only_module_stays_partial(self):
        table = scan_table(agreeing=67)
        evidence = scan_only_evidence([table], "COMPLETE")
        with self.assertRaises(AssertionError):
            CHECKER.exact_discovery_semantics(evidence)

    def test_tableless_scan_only_module_stays_partial(self):
        evidence = scan_only_evidence([], "COMPLETE")
        with self.assertRaises(AssertionError):
            CHECKER.exact_discovery_semantics(evidence)

    def test_unwitnessed_scan_only_module_stays_partial(self):
        table = scan_table(agreeing=None)
        evidence = scan_only_evidence([table], "COMPLETE")
        with self.assertRaises(AssertionError):
            CHECKER.exact_discovery_semantics(evidence)

    def test_mixed_tables_scan_only_module_stays_partial(self):
        tables = [scan_table(), scan_table(linkage="heuristic", agreeing=0)]
        evidence = scan_only_evidence(tables, "COMPLETE")
        with self.assertRaises(AssertionError):
            CHECKER.exact_discovery_semantics(evidence)

    def test_partial_verdict_accepted_with_and_without_layout_evidence(self):
        # The rule gates COMPLETE only: PARTIAL stays the honest verdict
        # for an unevidenced module and is never refused for an evidenced
        # one (other gaps may still force it).
        CHECKER.exact_discovery_semantics(
            scan_only_evidence([scan_table(linkage="heuristic", agreeing=0)], "PARTIAL")
        )
        CHECKER.exact_discovery_semantics(scan_only_evidence([scan_table()], "PARTIAL"))


if __name__ == "__main__":
    unittest.main()
