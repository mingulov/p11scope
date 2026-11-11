#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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


def check_second_flavor_presence(cells, listed, pending):
    """Mirror of the privileged-second-flavor presence step, for fake-list tests.

    cells is the campaign's second_flavor cell list, listed the journal
    build's `--list` output, pending the tolerated-absent set. Returns the
    wanted list, or raises SystemExit on the same absent-cell failure the
    workflow reports.
    """
    wanted = []
    for cell in cells:
        present = (f"\n{cell}\n" in f"\n{listed}\n"
                   or f"\n{cell} :: " in listed)
        if present:
            wanted.append(cell)
        elif cell in pending:
            continue
        else:
            raise SystemExit(f"expected journal cell absent from the binary: {cell}")
    assert wanted, "no journal cells present"
    return wanted


def check_counter_flavor_presence(cells, listed, pending):
    """Mirror of the privileged-counter-flavor presence step, for fake-list tests.

    cells is the campaign's counter_flavor cell list, listed the FULL-512
    build's `--list` output, pending the tolerated-absent set. Returns the
    wanted list, or raises SystemExit on the same absent-cell failure the
    workflow reports.
    """
    wanted = []
    for cell in cells:
        present = (f"\n{cell}\n" in f"\n{listed}\n"
                   or f"\n{cell} :: " in listed)
        if present:
            wanted.append(cell)
        elif cell in pending:
            continue
        else:
            raise SystemExit(f"expected counter cell absent from the binary: {cell}")
    assert wanted, "no counter cells present"
    return wanted


def journal_proof_test_names(source):
    """Fully-qualified #[test] names under root_proof_tests, the source of truth.

    source is the text of src/semantics_objects/journal/root_proof_tests.rs,
    the module the workflow's proof step runs by filter.
    """
    names = re.findall(r"^#\[test\]\nfn (\w+)", source, re.M)
    return [f"semantics_objects::journal::root_proof_tests::{name}" for name in names]


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
        # The copy-up cell is a normal overlay-campaign pass now (it
        # rides the curated --list selectors like the K1 twins, never a
        # hand-kept name): no expected-failure gate may remain for it.
        self.assertNotIn("overlay_copy_up_userspace_edge_absent", overlay)
        self.assertNotIn("--include-expected-failures", overlay)
        self.assertNotIn("copyup-cell", overlay)
        self.assertNotIn("^XFAIL ", overlay)
        btrfs = job_body(self.yml, "privileged-btrfs")
        self.assertIn("--teardown", btrfs)

    def test_btrfs_job_runs_the_discover_subvolume_cell(self):
        # The ignored discover twin's CI cover: a second loop mount, a
        # runner-owned subdir, the cell script as the runner user (never
        # under sudo: the fence refuses root), and the shared judge
        # requiring exactly its row. The cleanup step tears down both
        # mounts, and the leak check covers the shared parent.
        btrfs = job_body(self.yml, "privileged-btrfs")
        self.assertIn("scripts/ci/discover-btrfs-subvol.sh", btrfs)
        self.assertNotIn("sudo -n scripts/ci/discover-btrfs-subvol.sh",
                         btrfs)
        self.assertIn("discover-btrfs.img", btrfs)
        self.assertIn("discover-btrfs-mnt", btrfs)
        self.assertIn('install -d -m 700 -o "$(id -u)" -g "$(id -g)"',
                      btrfs)
        self.assertIn("scripts/ci/check-cell-results.py", btrfs)
        self.assertIn("--require discover-btrfs-subvol", btrfs)
        self.assertIn("discover-cell/", btrfs)
        self.assertIn(
            '"$out/discover-btrfs.img" "$out/discover-btrfs-mnt"', btrfs)

    def test_privileged_input_downloads_match_uploads(self):
        # Every privileged-inputs download must name an artifact a
        # build job uploads; a renamed producer with a stale consumer
        # fails the job at the download step with zero cells run.
        steps = re.finditer(
            r"uses: actions/(upload|download)-artifact@\S+[^\n]*\n"
            r"(?P<indent>[ ]+)with:\n"
            r"(?P<body>(?:(?P=indent)[ ]+[^\n]*\n)+)",
            self.yml)
        uploads = set()
        downloads = []
        for step in steps:
            name = re.search(r"^\s+name: (\S.*\S|\S)\s*$",
                             step.group("body"), re.M)
            if name is None:
                continue
            if step.group(1) == "upload":
                uploads.add(name.group(1))
            else:
                downloads.append(name.group(1))
        self.assertTrue(downloads, "no named artifact downloads found")
        for name in downloads:
            if name.startswith("privileged-inputs"):
                self.assertIn(name, uploads,
                              f"download {name} has no producing upload")

    def test_ia32_job_installs_i386_token_tooling(self):
        # The ia32-only leg carries no amd64 SoftHSM, so token setup
        # needs the i386 softhsm2-util alongside the i386 library.
        ia32 = job_body(self.yml, "public-cli-ia32")
        self.assertRegex(ia32, r"(?<!lib)softhsm2:i386")

    def test_ia32_gate_uses_the_shared_cell_checker(self):
        # The two ia32 cells route through judge and pass with the
        # owned-provider-counts taxonomy, so the gate must be the
        # shared closed-set checker (as the host leg is), never a
        # hand-rolled comparison against a single value no script
        # in this pipeline emits.
        ia32 = job_body(self.yml, "public-cli-ia32")
        self.assertIn("scripts/ci/check-cell-results.py", ia32)
        self.assertIn("--require profile-pid-ia32", ia32)
        self.assertIn("--require run-ia32", ia32)
        self.assertNotIn('!= "qualified"', ia32)

    def test_shard_step_exports_the_discover_helper(self):
        # The exit-mappings cell resolves p11scope-discover through
        # P11SCOPE_DISCOVER_BIN: the staged layout keeps it under bin/,
        # not beside lib-tests.
        shard = job_body(self.yml, "privileged-shard")
        self.assertIn('P11SCOPE_DISCOVER_BIN="$in/bin/p11scope-discover"', shard)

    def test_campaign_input_selects_default_long_and_all(self):
        self.assertIn("campaign:", self.yml)
        self.assertIn("[default, long, all]", self.yml)
        self.assertIn("long|all", self.yml)
        self.assertIn("--include-long", self.yml)
        # Schedules run only on the default branch, so the weekly campaign is
        # a dispatch, never a schedule trigger.
        self.assertIn("schedules run only on the default branch", self.yml.lower())
        self.assertNotIn("schedule:", self.yml)

    def test_tag_pushes_trigger_nothing(self):
        self.assertEqual([], _BPF.check_no_tag_triggers(self.yml))

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

    def test_default_shards_do_not_depend_on_journal_build(self):
        self.assertNotIn("flavor: [default, journal]", self.yml)
        self.assertIn("privileged-build-journal:", self.yml)
        shard_needs = re.search(r"privileged-shard:\s*\n\s*needs:\s*([^\n]+)", self.yml)
        self.assertIsNotNone(shard_needs, "privileged-shard has no needs")
        self.assertEqual(shard_needs.group(1).strip(), "privileged-build")
        second_needs = re.search(r"privileged-second-flavor:\s*\n\s*needs:\s*([^\n]+)", self.yml)
        self.assertIsNotNone(second_needs, "privileged-second-flavor has no needs")
        self.assertEqual(second_needs.group(1).strip(), "privileged-build-journal")

    def test_proof_build_is_cached(self):
        self.assertIn("target/proof/debug/.fingerprint", self.yml)

    def test_summary_downloads_only_default_and_shards(self):
        summary = self.yml.split("privileged-summary:", 1)[1]
        block = summary.split("privileged-second-flavor:", 1)[0]
        self.assertIn("pattern: privileged-shard-*", block)
        self.assertIn("name: privileged-inputs-default", block)

    def test_filesystem_campaigns_download_default_inputs(self):
        for job, follower in (("privileged-btrfs:", "privileged-overlay:"),
                              ("privileged-overlay:", "release-build:")):
            block = self.yml.split(job, 1)[1].split(follower, 1)[0]
            self.assertIn("name: privileged-inputs-default", block,
                          f"{job} must download the decoupled default inputs")
        self.assertNotIn("name: privileged-inputs\n", self.yml,
                           "stale single-flavor inputs download remains")

    def test_second_flavor_build_and_cells(self):
        self.assertIn("privileged-build-journal:", self.yml)
        self.assertIn("P11SCOPE_JOURNAL", self.yml)
        self.assertIn("privileged-second-flavor", self.yml)
        self.assertIn("privileged-inputs-journal", self.yml)
        self.assertIn("second_flavor", self.yml)
        self.assertIn("journal exact-list mismatch", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        self.assertEqual(len(second["cells"]), 7)
        self.assertIn("inventory::manifest_e2e_tests::privileged_inventory_pid_key_operations_mt_sign_rows_exact",
                      second["cells"])
        self.assertIn("attach::tests::sealed_session_drain_linkage_is_behavioral", second["cells"])
        self.assertIn("inventory::privileged_tests::privileged_key_operations_linked_lane_pumps_live_discovery",
                      second["cells"])
        self.assertIn("inventory::privileged_tests::privileged_key_operations_linked_healthy_routes_without_coverage_failed",
                      second["cells"])
        # The WU-2a tolerance is spent: every second-flavor cell exists,
        # so an absent cell must fail the job, never print PENDING.
        self.assertEqual(second.get("pending", []), [])

    def test_second_flavor_absent_cell_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        cells = second["cells"]
        pending = set(second.get("pending", []))
        listed = "\n".join(cells[1:]) + "\n"
        with self.assertRaisesRegex(SystemExit, "expected journal cell absent"):
            check_second_flavor_presence(cells, listed, pending)

    def test_second_flavor_all_present_passes(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        second = campaign["second_flavor"]
        cells = second["cells"]
        pending = set(second.get("pending", []))
        listed = "\n".join(cells) + "\n"
        self.assertEqual(check_second_flavor_presence(cells, listed, pending), cells)

    def test_counter_flavor_build_and_cells(self):
        # The wide default build omits counter objects, so the 36
        # counter/select-endpoint cells refuse there; the FULL-512
        # counter campaign runs their positive arms from the journal
        # build (which is FULL capacities with counter objects) on
        # every push, like the journal flavor. When 0.7.x restores
        # wide companions, the twins flip back and this campaign stays
        # as the FULL positive.
        self.assertIn("privileged-counter-flavor:", self.yml)
        self.assertIn("privileged-inputs-journal", job_body(self.yml, "privileged-counter-flavor"),
                      "counter flavor reuses the FULL-512 journal build")
        self.assertIn("counter_flavor", self.yml)
        self.assertIn("counter exact-list mismatch", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        self.assertEqual(len(counter["cells"]), 36)
        # One member per counter group, so a silently dropped group fails.
        members = (
            "attach::counter_banks::tests::counter_object_preflight_loads_all_modes",
            "attach::counter_banks::tests::counter_bank_mode_objects_load_lp64",
            "metrics::counter_reader::tests::counter_bank_session_old_return_survives_append_lp64",
            "metrics::counter_reader::tests::counter_bank_session_boundary_511_512_counts_growth_multi_lp64",
            "metrics::counter_reader::tests::counter_bank_session_useful_8192_latency_growth_multi_lp64",
            "metrics::counter_reader::tests::counter_engine_stages_first_512_counts_multi_lp64",
            "metrics::counter_reader::tests::counter_engine_growth_latency_multi_lp64",
            "metrics::counter_reader::tests::counter_start_raises_nofile_from_soft_1024_lp64",
            "metrics::counter_reader::tests::counter_collection_reads_live_and_terminal_lp64",
            "metrics::counter_reader::tests::counter_singles_stop_prints_detach_estimate_lp64",
            "metrics::counter_reader::tests::counter_cli_profile_latency_matches_workload_ledger_lp64",
            "metrics::counter_reader::tests::counter_cli_run_counts_with_owned_child_lp64",
            "metrics::counter_reader::tests::selected_detail_cli_profile_counts_resolves_live_plan_and_conserves_aggregate_lp64",
            "metrics::counter_reader::tests::selected_detail_system_scope_refuses_live_plan_lp64",
            "metrics::k0_live_cells::k0_live_detail_matches_ledger_counts_lp64",
            "metrics::k0_live_cells::k0_live_run_gateless_exit_matches_main_counts_lp64",
        )
        for cell in members:
            with self.subTest(cell=cell):
                self.assertIn(cell, counter["cells"])
        self.assertEqual(counter.get("pending", []), [])

    def test_counter_flavor_absent_cell_fails(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        cells = counter["cells"]
        pending = set(counter.get("pending", []))
        listed = "\n".join(cells[1:]) + "\n"
        with self.assertRaisesRegex(SystemExit, "expected counter cell absent"):
            check_counter_flavor_presence(cells, listed, pending)

    def test_counter_flavor_all_present_passes(self):
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        counter = campaign["counter_flavor"]
        cells = counter["cells"]
        pending = set(counter.get("pending", []))
        listed = "\n".join(cells) + "\n"
        self.assertEqual(check_counter_flavor_presence(cells, listed, pending), cells)

    def test_counter_flavor_cells_are_default_campaign_twins(self):
        # Every counter-flavor cell also runs in the default sharded
        # campaign, where the wide binary takes the exact-refusal twin
        # arm; the same test name proves the refusal on wide and the
        # positive on FULL.
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        default = set(campaign["default_cells"])
        for cell in campaign["counter_flavor"]["cells"]:
            with self.subTest(cell=cell):
                self.assertIn(cell, default)

    def test_counter_flavor_verifies_the_full512_curation(self):
        # Like the journal flavor, the counter run verifies the
        # FULL-512 curation explicitly, so a silent gating change
        # fails instead of flipping coverage.
        counter = job_body(self.yml, "privileged-counter-flavor")
        self.assertIn("run-privileged-lib-tests.sh \"$in/lib-tests\" "
                      "\"$out/run\" --full-512", counter,
                      "counter-flavor run must verify the FULL-512 curation")

    def test_journal_proof_build_and_tests(self):
        self.assertIn("P11SCOPE_JOURNAL_PROOF=1", self.yml)
        self.assertIn("root_proof_tests", self.yml)
        self.assertIn("test result: ok. 2 passed", self.yml)
        campaign = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
        self.assertEqual(len(campaign["journal_proof"]["cells"]), 2)
        # The floor names are pinned to the #[test] fns under the module the
        # workflow runs: a rename must update the floor, not rot it.
        source = (ROOT / "src" / "semantics_objects" / "journal"
                  / "root_proof_tests.rs").read_text(encoding="utf-8")
        self.assertEqual(campaign["journal_proof"]["cells"],
                         journal_proof_test_names(source))

    def test_build_jobs_refuse_flavor_environment(self):
        # Every image-building prove step refuses a leaked flavor/size
        # override; the journal job exempts only its intended =1.
        jobs = {}
        for match in re.finditer(
                r"^  (privileged-build-journal|privileged-build|release-build):\s*$",
                self.yml, re.M):
            jobs[match.group(1)] = match.start()
        self.assertEqual(set(jobs),
                         {"privileged-build", "privileged-build-journal", "release-build"})
        starts = sorted(jobs.items(), key=lambda kv: kv[1])
        bodies = {}
        for index, (name, start) in enumerate(starts):
            end = starts[index + 1][1] if index + 1 < len(starts) else len(self.yml)
            bodies[name] = self.yml[start:end]
        refused = {
            "privileged-build": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL=",
                                 "P11SCOPE_JOURNAL_PROOF=", "P11SCOPE_BIRTH_MARKER=",
                                 "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
            "release-build": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL=",
                              "P11SCOPE_JOURNAL_PROOF=", "P11SCOPE_BIRTH_MARKER=",
                              "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
            "privileged-build-journal": {"P11SCOPE_SMALL_", "P11SCOPE_JOURNAL_PROOF=",
                                         "P11SCOPE_BIRTH_MARKER=",
                                         "RUSTFLAGS=", "CARGO_ENCODED_RUSTFLAGS="},
        }
        for name, body in sorted(bodies.items()):
            prove = re.search(r"grep -E '\^\(.*?\)'", body)
            self.assertIsNotNone(prove, f"{name} has no prove-step refusal")
            for token in sorted(refused[name]):
                self.assertIn(token, prove.group(0), f"{name} refusal misses {token}")
        journal = bodies["privileged-build-journal"]
        self.assertIn('test "${P11SCOPE_JOURNAL:-}" = 1', journal)
        journal_pattern = re.search(r"grep -E '\^\(.*?\)'", journal).group(0)
        rest = journal_pattern.replace("P11SCOPE_JOURNAL_PROOF=", "")
        self.assertNotIn("P11SCOPE_JOURNAL=", rest,
                         "journal prove must exempt its intended P11SCOPE_JOURNAL=1")

    def test_cell_script_template_proof(self):
        self.assertIn("scripts/ci/run-cell-script.sh public-cli-host", self.yml)
        self.assertIn("scripts/ci/check-cell-results.py", self.yml)
        self.assertIn("--allow-nonqualifying trace-pid", self.yml)
        self.assertIn("--expected-failure profile-cgroup", self.yml)
        self.assertNotIn("--expected-failure inventory-cgroup", self.yml)
        self.assertNotIn("--allow-nonqualifying run-short", self.yml)
        self.assertIn("--require doctor", self.yml)
        self.assertIn("--require profile-pid", self.yml)
        self.assertIn("--require trace-pid", self.yml)
        self.assertIn("--require fifo-refused", self.yml)
        self.assertIn("WP-3", self.yml)
        self.assertIn("WP-7", self.yml)

    def test_public_cli_gate_qualifies_inventory_cgroup(self):
        # The decided no-witness shape qualifies on every leg, so the
        # uniform inline gate must not list inventory-cgroup in
        # expected_cells — while still requiring the cell itself.
        # The wide default build additionally lists the 9
        # counter/select-endpoint cells as expected failures.
        job = job_body(self.yml, "public-cli")
        gate = re.search(r"expected_cells = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(gate, "public-cli has no expected_cells gate")
        self.assertEqual(set(re.findall(r'"([^"]+)"', gate.group(1))),
                         {"profile-cgroup", "trace-cgroup",
                          "profile-pid-ia32", "run-ia32",
                          "counter-latency-mt",
                          "counter-counts-pid", "counter-timestamps-pid",
                          "counter-latency-pid", "counter-counts-system",
                          "counter-timestamps-system",
                          "counter-latency-system",
                          "select-endpoint-pid", "select-endpoint-system"})
        need = re.search(r"need = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(need, "public-cli has no need set")
        self.assertIn("inventory-cgroup", need.group(1),
                      "the gate must still require the inventory-cgroup cell")

    def test_minimal_setcap_leg_runs_on_host_and_guests(self):
        job = job_body(self.yml, "public-cli")
        # Host leg through the template; guests inside the vng wrapper.
        self.assertIn("run-cell-script.sh minimal-setcap", job)
        self.assertIn("qualify-public-cli-vng.sh", job)
        self.assertIn("libcap2-bin", job)
        # One uniform gate over the minimal results for both legs, with
        # every row required: a dropped row must fail, not shrink cover.
        self.assertIn("minimal-cells/results.jsonl", job)
        for cell in ("doctor-minimal-p4", "doctor-minimal-p3",
                     "profile-pid-p4", "profile-pid-p3",
                     "missing-cap-cap_bpf-p4", "missing-cap-cap_bpf-p3",
                     "missing-cap-cap_perfmon-p4",
                     "missing-cap-cap_perfmon-p3",
                     "missing-cap-cap_checkpoint_restore-p4",
                     "missing-cap-cap_checkpoint_restore-p3",
                     "missing-cap-cap_dac_read_search-p4",
                     "missing-cap-cap_dac_read_search-p3",
                     "missing-cap-cap_sys_ptrace-p4",
                     "missing-cap-cap_sys_ptrace-p3",
                     "inventory-system", "run-minimal",
                     "run-child-drops-caps", "postsetup-drops-sysadmin",
                     "postsetup-inventory-drops-sysadmin",
                     "run-sudo", "run-user-nobody",
                     "run-kill-on-timeout", "trace-sudo-out",
                     "inventory-sudo-event-log",
                     "inventory-sudo-fifo-out",
                     "profile-sudo-fifo-out",
                     "inventory-diff-sudo-fifo-out",
                     "inventory-sudo-stderr-fifo",
                     "daemonset-doctor", "daemonset-profile",
                     "daemonset-inventory"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        # Artifacts carry the minimal evidence.
        self.assertIn("minimal-cells/logs/*.out", job)
        self.assertIn("minimal.log", job)

    def test_witness_cli_matrix_runs_host_and_the_five_pinned_guests(self):
        job = job_body(self.yml, "witness-cli")
        match = re.search(r"kernel:\s*\[(.*?)\]", job)
        self.assertIsNotNone(match, "witness-cli has no kernel matrix")
        kernels = [kernel.strip() for kernel in match.group(1).split(",")]
        self.assertEqual(kernels,
                         ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                          "v7.4-rc1"])
        sums = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"
        for kernel in kernels[1:]:
            self.assertTrue((sums / f"{kernel}.sums").is_file(),
                            f"missing sums for {kernel}")
        self.assertIn("sha256sum --check", job)
        self.assertIn("kernel deb set changed", job)

    def test_witness_cli_builds_and_runs_the_p28_cells(self):
        job = job_body(self.yml, "witness-cli")
        self.assertIn("--no-run --test prearm_witness_cli", job)
        self.assertIn("cargo", job)
        self.assertIn('sudo -n scripts/ci/run-witness-cli.sh "$WITNESS_TESTBIN" "$out/cells"',
                      job)
        # One kernel-parameterized guest call with no per-kernel cell
        # list: the twin runs everywhere including v6.6.157.
        invocations = [line for line in job.splitlines()
                       if "witness-cli-vng.sh" in line
                       and not line.strip().startswith("#")]
        self.assertEqual(
            invocations,
            ['            scripts/ci/witness-cli-vng.sh "$WITNESS_TESTBIN" "$out" "${{ matrix.kernel }}"'])
        self.assertIn("scripts/ci/check-cell-results.py", job)
        for cell in ("privileged_profile_pid_prearm_clean_exact_counts",
                     "privileged_profile_cgroup_prearm_clean_exact_counts",
                     "privileged_profile_system_prearm_clean_exact_counts",
                     "privileged_profile_metrics_system_prearm_clean_exact_counts",
                     "privileged_profile_pid_prearm_twin_exact_window",
                     "privileged_trace_system_prearm_clean_exact_counts"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        self.assertNotIn("--expected-failure", job)
        self.assertNotIn("--allow-nonqualifying", job)
        self.assertIn("witness-cli-${{ matrix.kernel }}", job)

    def test_container_image_cell_builds_and_judges(self):
        job = job_body(self.yml, "container-image")
        # A self-contained FULL musl build: the image holds this commit's
        # static observer, and the build-time guards prove FULL defaults
        # (no size overrides, default features).
        self.assertIn("x86_64-unknown-linux-musl", job)
        self.assertIn("--bin p11scope", job)
        self.assertIn("musl-tools", job)
        self.assertIn("P11SCOPE_SMALL_", job)
        # The permanent cell runs the committed lane script against those
        # musl bytes and judges every row with the shared checker: exact
        # counts on the host and in the second container, then both
        # refusals. No smoke, no expected failures.
        self.assertIn("scripts/matrix/verify-container-image.sh", job)
        self.assertIn("--observer-bin", job)
        self.assertIn("scripts/ci/check-cell-results.py", job)
        # The checker is not executable (100644, like the other CI helpers);
        # the judge step must run it through the interpreter, as the other
        # lanes do, or the step dies with Permission denied on a green cell.
        self.assertIn("python3 -I scripts/ci/check-cell-results.py", job)
        for cell in ("host-exact", "container-exact",
                     "refusal-pidns", "refusal-cap"):
            with self.subTest(cell=cell):
                self.assertIn(f"--require {cell}", job)
        self.assertNotIn("--expected-failure", job)
        self.assertNotIn("--allow-nonqualifying", job)
        self.assertIn("name: container-image", job)

    def test_journal_proof_builds_at_full_capacities(self):
        # The private proof refuses SMALL/WIDE/unsafe/P0 (build.rs): its
        # pins were validated at FULL, so the proof step builds FULL
        # (--no-default-features) in its own target dir while the
        # product stays wide. The proof configuration itself never
        # changes: the same filter must select the same 2 tests.
        step = re.search(
            r"Build P11SCOPE_JOURNAL_PROOF=1 and run root_proof_tests"
            r"[\s\S]*?test result: ok\. 2 passed",
            self.yml)
        self.assertIsNotNone(step, "proof step with the 2-test gate")
        self.assertIn("--no-default-features", step.group(0),
                      "proof step must build FULL capacities, not the wide default")
        self.assertIn("--target-dir target/proof", step.group(0),
                      "proof build must keep its separate target dir")

    def test_journal_flavor_verifies_the_full512_curation(self):
        # The journal flavor builds FULL (--no-default-features), where
        # the 21 wide-only cells do not exist; its --list and the
        # second-flavor run verify the FULL-512 curation explicitly, so
        # a silent gating change fails instead of flipping coverage.
        journal = job_body(self.yml, "privileged-build-journal")
        self.assertIn("--no-default-features", journal)
        self.assertIn("--list --full-512", journal,
                      "journal --list must verify the FULL-512 curation")
        second = job_body(self.yml, "privileged-second-flavor")
        self.assertIn("run-privileged-lib-tests.sh \"$in/lib-tests\" "
                      "\"$out/run\" --full-512", second,
                      "second-flavor run must verify the FULL-512 curation")

    def test_counter_cells_are_required_positives_on_the_wide_build(self):
        # The wide default build carries counter objects, so the 9
        # counter/select-endpoint cells run positive: neither the host
        # template leg nor the shared workflow judge may declare them
        # as expected failures.
        cells = ("counter-latency-mt",
                 "counter-counts-pid", "counter-timestamps-pid",
                 "counter-latency-pid", "counter-counts-system",
                 "counter-timestamps-system", "counter-latency-system",
                 "select-endpoint-pid", "select-endpoint-system")
        job = job_body(self.yml, "public-cli")
        host_leg = job.split("qualify-public-cli-vng.sh")[0]
        for cell in cells:
            with self.subTest(cell=cell):
                self.assertNotIn(f"--expected-failure {cell}", host_leg,
                                 f"host template leg must not excuse {cell}")
        expected = re.search(r"expected_cells = \{(.*?)\}", job, re.S)
        self.assertIsNotNone(expected, "workflow judge expected_cells set")
        for cell in cells:
            with self.subTest(cell=cell):
                self.assertNotIn(f'"{cell}"', expected.group(1),
                                 f"workflow judge must not excuse {cell}")
        self.assertIn("--require counter-latency-mt", host_leg,
                      "host template leg must require the mt counter cell")


if __name__ == "__main__":
    unittest.main()
