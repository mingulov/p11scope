#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract for the hosted privileged lib-test workflow.

privileged-tests.yml copies its toolchain setup from ci.yml, and the
hosted_pipeline_* contract tests read ci.yml only. These tests pin the
same two-way agreement bpf-kernels.yml has (bpf-linker, nightly, release
compiler through the version file, clang, action revisions) and the
coverage design: the curated runner, not a blanket --ignored; a shard
matrix that matches SHARDS; a summary job that proves every listed cell
ran exactly once and passed, enforces the floor file
tests/privileged-campaign.json and judges P11SCOPE_CELL_BRANCH lines; a
campaign input (default/long/all); checked doctor rows; a journal second
flavor and a journal-proof build; and the generic cell-script template.

Run: python3 -I tests/python/test_privileged_tests_workflow.py -v
"""

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
PRIV_YML = ROOT / ".github" / "workflows" / "privileged-tests.yml"
RELEASE_RUST_VERSION = ROOT / ".release-rust-version"
CAMPAIGN = ROOT / "tests" / "privileged-campaign.json"

_SPEC = importlib.util.spec_from_file_location(
    "bpf_kernels_contract", Path(__file__).with_name("test_bpf_kernels_contract.py"))
_BPF = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BPF)


def renamed(problems):
    return [p.replace("bpf-kernels.yml", "privileged-tests.yml") for p in problems]


def job_body(yml, name):
    """The YAML text of one top-level job (jobs are 2-space keys)."""
    bounds = [match.start() for match in
              re.finditer(r"^  \S[^:\n]*:", yml, re.M)]
    start = yml.index(f"  {name}:")
    following = [bound for bound in bounds if bound > start]
    end = min(following) if following else len(yml)
    return yml[start:end]


def check_floor_and_branches(want, full_lines, campaign):
    """Mirror of the summary's floor and branch step, for fake-result tests.

    want is the set of listed selectors, full_lines the PASS/FAIL/SKIP result
    lines, campaign the parsed floor file. Returns (checked, notes) or raises
    SystemExit on the same failures the workflow reports.
    """
    assert campaign.get("schema") == "p11scope/privileged-campaign/v1", "floor schema"
    floor = campaign["default_floor"]
    cells = campaign["default_cells"]
    assert floor == len(cells), "floor count must equal the listed names"
    assert len(cells) == len(set(cells)), "floor names must be unique"
    notes = [f"floor {floor}, listed {len(want)}"]
    if len(want) < floor:
        raise SystemExit(f"listed count {len(want)} dropped below the floor {floor}")
    missing = sorted(set(cells) - set(want))
    if missing:
        raise SystemExit("curated names disappeared without a reviewed floor edit: " + ", ".join(missing[:5]))
    notes.append(f"floor ok: all {len(cells)} curated names listed")
    branches = {}
    for line in full_lines:
        parts = line.split()
        if len(parts) >= 2:
            branches[parts[1]] = line
    checked = 0
    for cell, rule in sorted(campaign.get("branch_expectations", {}).items()):
        expected = rule.get("ci")
        status = rule.get("status", "expected")
        if status == "pending":
            notes.append(f"BRANCH pending {cell}")
            continue
        if cell not in branches:
            if cell not in want:
                notes.append(f"BRANCH skip {cell}: not in this campaign")
                continue
            raise SystemExit(f"missing result for branched cell {cell}")
        found = re.findall(r"branch=([A-Za-z0-9_.-]+)", branches[cell])
        notes.append(f"BRANCH {cell} expected {expected} found {found or 'none'}")
        if expected not in found:
            raise SystemExit(f"cell {cell} did not take the expected {expected} branch on CI")
        checked += 1
    notes.append(f"branch ok: {checked} expected cells judged")
    return checked, notes


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
        self.assertNotRegex(self.yml, r"lib-tests[^\n]*--ignored")
        # The default list must be nonempty and match its declared count.
        self.assertIn('test "$count" -eq "$declared"', self.yml)
        # Long cells run only through the campaign input, never by default.
        self.assertIn("--include-long", self.yml)
        self.assertIn("inputs.campaign", self.yml)

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

    def test_filesystem_jobs_run_their_curated_groups(self):
        for job, flag, package, section in (
            ("privileged-btrfs", "--include-btrfs", "btrfs-progs", "btrfs"),
            ("privileged-overlay", "--include-overlay", "e2fsprogs",
             "overlay"),
        ):
            with self.subTest(job=job):
                body = job_body(self.yml, job)
                self.assertIn("needs: privileged-build", body)
                self.assertIn(flag, body)
                self.assertIn(package, body)
                # Selectors derive from the curated --list section with
                # a count check, never from a hand-kept copy. The
                # declared-count parse must accept the header's
                # `, …` suffix after the number.
                self.assertIn(f"/^{section} \\(/", body)
                self.assertIn(
                    "s/^" + section + r" (\([0-9][0-9]*\)[,)].*/", body)
                self.assertIn('test "$count" -eq "$declared"', body)
                # Failures, skips and leaked mounts fail the job.
                self.assertIn("grep -E '^(FAIL|SKIP) '", body)
                self.assertIn('test "$rc" -eq 0', body)
                self.assertIn("if: ${{ always() }}", body)
                self.assertIn("losetup -a", body)
        overlay = job_body(self.yml, "privileged-overlay")
        # The copy-up RED cell rides along through the expected-failure
        # gate: it must still fail with its signature (XFAIL), so a fix
        # or a changed failure breaks the job loudly.
        self.assertIn("overlay_copy_up_userspace_edge_absent", overlay)
        self.assertIn("--include-expected-failures", overlay)
        self.assertIn("^XFAIL ", overlay)
        btrfs = job_body(self.yml, "privileged-btrfs")
        self.assertIn("--teardown", btrfs)

    def test_campaign_input_selects_default_long_and_all(self):
        self.assertIn("campaign:", self.yml)
        self.assertIn("[default, long, all]", self.yml)
        self.assertIn("long|all", self.yml)
        self.assertIn("--include-long", self.yml)
        # Schedules run only on the default branch, so the weekly campaign is
        # a dispatch, never a schedule trigger.
        self.assertIn("schedules run only on the default branch", self.yml.lower())
        self.assertNotIn("schedule:", self.yml)

    def test_floor_file_is_consistent_and_pinned_to_the_runner(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        self.assertEqual(campaign.get("schema"), "p11scope/privileged-campaign/v1")
        floor = campaign["default_floor"]
        cells = campaign["default_cells"]
        self.assertEqual(floor, len(cells))
        self.assertEqual(len(cells), len(set(cells)))
        # The floor names are the runner's DEFAULT_TESTS plus the default
        # build's alternative member, in runner order.
        runner = (ROOT / "scripts" / "run-privileged-lib-tests.sh").read_text(encoding="utf-8")
        def array(name):
            body = re.search(rf"{name}=\(\n(.*?)\n\)", runner, re.S).group(1)
            return [line.strip() for line in body.splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        expected = array("DEFAULT_TESTS") + ["attach::tests::full_root_load_refusal_is_classified"]
        self.assertEqual(cells, expected)
        self.assertIn("privileged-inputs-default/selectors.txt", self.yml)
        self.assertIn("tests/privileged-campaign.json", self.yml)
        self.assertIn("dropped below the floor", self.yml)
        self.assertIn("without a reviewed floor edit", self.yml)

    def test_summary_judges_branches_against_the_table(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        expectations = campaign.get("branch_expectations", {})
        self.assertIn("inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64",
                      expectations)
        self.assertEqual(expectations["inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"]["ci"],
                         "lossless")
        self.assertIn("branch=", self.yml)
        self.assertIn("P11SCOPE_CELL_BRANCH", self.yml)
        self.assertIn("did not take the expected", self.yml)
        self.assertIn("pending", self.yml)

    def test_floor_count_drop_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        cells = campaign["default_cells"]
        want = set(cells[:-1])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in want]
        with self.assertRaisesRegex(SystemExit, "dropped below the floor"):
            check_floor_and_branches(want, full, campaign)

    def test_floor_name_disappearance_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        cells = campaign["default_cells"]
        swapped = "attach::tests::renamed_cell_for_test"
        want = set(cells[1:]) | {swapped}
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in want]
        with self.assertRaisesRegex(SystemExit, "without a reviewed floor edit"):
            check_floor_and_branches(want, full, campaign)

    def test_floor_green_with_fake_results(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        want = set(campaign["default_cells"])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in sorted(want)]
        checked, notes = check_floor_and_branches(want, full, campaign)
        self.assertEqual(checked, 0)
        self.assertTrue(any("floor ok" in note for note in notes))

    def test_branch_pending_is_allowed_absent(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        want = set(campaign["default_cells"])
        full = [f"PASS {name} rc=0 seconds=1 :: test result: ok. 1 passed" for name in sorted(want)]
        checked, notes = check_floor_and_branches(want, full, campaign)
        self.assertTrue(any("pending" in note for note in notes))

    def test_branch_expected_passes_with_fake_results(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        want = {"cell::a"}
        full = ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed branch=lossless"]
        checked, _ = check_floor_and_branches(want, full, campaign)
        self.assertEqual(checked, 1)

    def test_branch_missing_fails(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "did not take the expected lossless branch"):
            check_floor_and_branches({"cell::a"},
                                     ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed"],
                                     campaign)

    def test_branch_wrong_arm_fails(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "did not take the expected lossless branch"):
            check_floor_and_branches({"cell::a"},
                                     ["PASS cell::a rc=0 seconds=1 :: test result: ok. 1 passed branch=skipped"],
                                     campaign)

    def test_branch_missing_result_fails_when_listed(self):
        campaign = {"schema": "p11scope/privileged-campaign/v1", "default_floor": 1,
                    "default_cells": ["cell::a"],
                    "branch_expectations": {"cell::a": {"ci": "lossless", "status": "expected"}}}
        with self.assertRaisesRegex(SystemExit, "missing result for branched cell"):
            check_floor_and_branches({"cell::a"}, [], campaign)

    def test_doctor_rows_are_checked_in_both_jobs(self):
        for name in ("uprobe-multi attach (own libc)", "uretprobe vs seccomp"):
            self.assertIn(name, self.yml)
        self.assertNotIn('doctor >"$TMPDIR/doctor.txt" 2>&1 || true', self.yml)
        self.assertIn("doctor-status.txt", self.yml)
        self.assertIn("functional doctor row", self.yml)
        self.assertIn("cli-out/cells/doctor.out", self.yml)

    def test_second_flavor_build_and_cells(self):
        self.assertIn("flavor: [default, journal]", self.yml)
        self.assertIn("P11SCOPE_JOURNAL", self.yml)
        self.assertIn("privileged-second-flavor", self.yml)
        self.assertIn("privileged-inputs-journal", self.yml)
        self.assertIn("second_flavor", self.yml)
        self.assertIn("journal exact-list mismatch", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        self.assertEqual(len(second["cells"]), 5)
        self.assertIn("attach::tests::sealed_session_drain_linkage_is_behavioral", second["cells"])
        self.assertIn("inventory::privileged_tests::privileged_key_operations_linked_lane_pumps_live_discovery",
                      second["cells"])

    def test_journal_proof_build_and_tests(self):
        self.assertIn("P11SCOPE_JOURNAL_PROOF=1", self.yml)
        self.assertIn("root_proof_tests", self.yml)
        self.assertIn("test result: ok. 2 passed", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        self.assertEqual(len(campaign["journal_proof"]["cells"]), 2)

    def test_cell_script_template_proof(self):
        self.assertIn("scripts/ci/run-cell-script.sh public-cli-host", self.yml)
        self.assertIn("scripts/ci/check-cell-results.py", self.yml)
        self.assertIn("--allow-nonqualifying run-short", self.yml)
        self.assertIn("WP-3", self.yml)
        self.assertIn("WP-7", self.yml)


if __name__ == "__main__":
    unittest.main()
