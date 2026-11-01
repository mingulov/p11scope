#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract for the hosted privileged lib-test workflow.

privileged-tests.yml copies its toolchain setup from ci.yml, and the
hosted_pipeline_* contract tests read ci.yml only. These tests pin the
same two-way agreement bpf-kernels.yml has (bpf-linker, nightly, release
compiler through the version file, clang, action revisions) and the
coverage design: the curated runner, not a blanket --ignored; a shard
matrix that matches SHARDS; and a summary job that proves every listed
cell ran exactly once and passed.

Run: python3 -I tests/python/test_privileged_tests_workflow.py -v
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
PRIV_YML = ROOT / ".github" / "workflows" / "privileged-tests.yml"
RELEASE_RUST_VERSION = ROOT / ".release-rust-version"

_SPEC = importlib.util.spec_from_file_location(
    "bpf_kernels_contract", Path(__file__).with_name("test_bpf_kernels_contract.py"))
_BPF = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BPF)


def renamed(problems):
    return [p.replace("bpf-kernels.yml", "privileged-tests.yml") for p in problems]


class PrivilegedTestsWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = CI_YML.read_text(encoding="utf-8")
        self.yml = PRIV_YML.read_text(encoding="utf-8")

    def test_toolchain_and_action_pins_match_ci(self):
        release = RELEASE_RUST_VERSION.read_text(encoding="utf-8").strip()
        problems = (_BPF.check_bpf_linker(self.ci, self.yml)
                    + _BPF.check_nightly(self.ci, self.yml)
                    + _BPF.check_release_toolchain(self.yml, release)
                    + _BPF.check_clang(self.ci, self.yml)
                    + _BPF.check_action_pins(self.ci, self.yml))
        self.assertEqual([], renamed(problems))

    def test_shard_matrix_matches_the_shard_count(self):
        shards = re.findall(r"^\s*SHARDS:\s*(\d+)\s*$", self.yml, re.M)
        self.assertEqual(len(shards), 1, "SHARDS must be defined once")
        matrix = re.search(r"shard:\s*\[([0-9,\s]+)\]", self.yml)
        self.assertIsNotNone(matrix, "privileged-shard has no shard matrix")
        values = [int(v) for v in matrix.group(1).split(",") if v.strip()]
        self.assertEqual(values, list(range(int(shards[0]))))

    def test_cells_come_from_the_curated_runner(self):
        self.assertIn("scripts/run-privileged-lib-tests.sh --list", self.yml)
        self.assertIn('scripts/run-privileged-lib-tests.sh "$in/lib-tests"', self.yml)
        self.assertNotIn("--include-long", self.yml)
        self.assertNotRegex(self.yml, r"lib-tests[^\n]*--ignored")
        # The default list must be nonempty and match its declared count.
        self.assertIn('test "$count" -eq "$declared"', self.yml)

    def test_failures_and_skips_fail_the_shard(self):
        self.assertIn("grep -E '^(FAIL|SKIP) '", self.yml)
        self.assertIn('test "$rc" -eq 0', self.yml)
        self.assertIn("fail-fast: false", self.yml)

    def test_summary_proves_every_cell_ran_once_and_passed(self):
        summary = self.yml.split("privileged-summary:", 1)
        self.assertEqual(len(summary), 2, "no privileged-summary job")
        body = summary[1]
        self.assertIn("needs: [privileged-build, privileged-shard]", body)
        self.assertIn("if: ${{ !cancelled() }}", body)
        self.assertIn('diff -u "$RUNNER_TEMP/want.txt" "$RUNNER_TEMP/ran.txt"', body)
        self.assertIn("MISSING results for shard", body)
        self.assertIn("awk '$1 != \"PASS\"'", body)

    def test_guest_kernels_have_pinned_sums(self):
        match = re.search(r"kernel:\s*\[host,([^\]]*)\]", self.yml)
        self.assertIsNotNone(match, "public-cli has no host + guest kernel matrix")
        guests = [k.strip() for k in match.group(1).split(",") if k.strip()]
        self.assertTrue(guests)
        sums = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"
        for kernel in guests:
            self.assertTrue((sums / f"{kernel}.sums").is_file(), f"missing sums for {kernel}")
        self.assertIn("sha256sum --check", self.yml)

    def test_workflow_cancels_superseded_runs(self):
        self.assertIn("cancel-in-progress: true", self.yml)


if __name__ == "__main__":
    unittest.main()
