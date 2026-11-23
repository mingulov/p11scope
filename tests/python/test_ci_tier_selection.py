#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for CI tier selection (scripts/ci/select-cells.py).

Every job in each workflow belongs to the selection universe, and every
gated job's YAML carries exactly its run_<job> predicate; the excused
jobs (mechanism, failure-driven and delivery calls) are pinned by name.
Synthetic diffs select the expected tier and cells: quick on development
branches, the BPF set on BPF/toolchain/lockfile changes, full on CI or
unknown paths and everywhere else. Kernel matrices are single-sourced in
the selector: these tests pin the lists and their sums files instead of
YAML literals, and pin that the YAML renders them through dynamic
matrices.

Run: python3 -I tests/python/test_ci_tier_selection.py -v
"""

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SELECT_PATH = ROOT / "scripts" / "ci" / "select-cells.py"
_SPEC = importlib.util.spec_from_file_location("select_cells", SELECT_PATH)
SELECT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SELECT)

WORKFLOWS = ("ci", "privileged-tests", "bpf-kernels")
SUMS_DIR = ROOT / "tests" / "fixtures" / "vng-kernel-sha256sums"

# Universe jobs with no run_ predicate in their YAML, pinned by name:
# the mechanism (select, and ci's always-first dedupe), the
# failure-driven quarantine, and the delivery calls (pinned independent
# of every check job by the delivery contract).
EXCUSED = {
    "ci": {"dedupe", "select", "quarantine", "package-delivery",
           "docker-delivery", "kubernetes-delivery"},
    "privileged-tests": {"select"},
    "bpf-kernels": {"select"},
}

# Dynamic kernel matrices per workflow: job id to select output name.
DYNAMIC_MATRICES = {
    "privileged-tests": {
        "public-cli": "matrix_public_cli",
        "witness-cli": "matrix_witness_cli",
        "run-tree": "matrix_run_tree",
    },
    "bpf-kernels": {
        "bpf-load-kernels": "matrix_bpf_load",
        "bpf-load-gate1-kernels": "matrix_bpf_gate1",
        "lib-cells-kernels": "matrix_lib_cells",
    },
}


def workflow_text(name):
    return (ROOT / ".github" / "workflows" / f"{name}.yml").read_text(
        encoding="utf-8")


def workflow_jobs(name):
    return yaml.safe_load(workflow_text(name))["jobs"]


def select(workflow, event, ref, classes, tier_input="full", **kwargs):
    """SELECT.build_selection with test defaults."""
    arguments = {"delivery_task": "checks", "dedupe_run": True,
                 "release_preview": False, "privileged_e2e": False,
                 "pkcs11_full": False}
    arguments.update(kwargs)
    return SELECT.build_selection(
        workflow, event, ref, "a" * 40, tier_input, classes, "dev/v0.8.0",
        **arguments)


def states(selection):
    return {job: entry["state"]
            for job, entry in selection["jobs"].items()}


class TierSelectionTests(unittest.TestCase):
    maxDiff = 4096

    def test_every_workflow_job_is_in_the_universe(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                self.assertEqual(set(workflow_jobs(name)),
                                 set(SELECT.UNIVERSE[name]))

    def test_every_job_is_gated_or_excused_by_name(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                universe = set(SELECT.UNIVERSE[name])
                gated = set(SELECT.GATED[name])
                self.assertLess(gated, universe)
                self.assertEqual(universe - gated, EXCUSED[name])
                jobs = workflow_jobs(name)
                for job in sorted(gated):
                    predicate = (f"needs.select.outputs."
                                 f"{SELECT.output_name(job)} == 'true'")
                    self.assertIn(predicate, jobs[job].get("if", ""),
                                  f"{name} {job} lacks its run predicate")
                for job in sorted(universe - gated):
                    text = workflow_text(name)
                    start = text.index(f"  {job}:")
                    bounds = [match.start() for match in
                              re.finditer(r"^  \S[^:\n]*:", text, re.M)]
                    end = min([bound for bound in bounds if bound > start],
                              default=len(text))
                    self.assertNotIn("needs.select.outputs.run_",
                                     text[start:end],
                                     f"{name} {job} carries an unlisted run "
                                     "predicate")

    def test_select_job_wiring(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                job = workflow_jobs(name)["select"]
                if name == "ci":
                    self.assertEqual(job["needs"], "dedupe")
                else:
                    self.assertNotIn("needs", job)
                steps = job["steps"]
                self.assertEqual(
                    steps[0]["uses"],
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
                self.assertEqual(steps[0]["with"]["fetch-depth"], 0)
                choose = steps[1]
                self.assertEqual(choose["id"], "choose")
                self.assertEqual(choose["env"]["P11SCOPE_CI_WORKFLOW"], name)
                self.assertEqual(choose["run"],
                                 "python3 -I scripts/ci/select-cells.py")
                expected = {"tier", "base", "path_classes", "selection"}
                expected.update(SELECT.output_name(job_name)
                                for job_name in SELECT.GATED[name])
                expected.update(DYNAMIC_MATRICES.get(name, {}).values())
                self.assertEqual(set(job["outputs"]), expected)

    def test_no_inputs_interpolation_inside_run_blocks(self):
        # Dispatch inputs travel through env into the selector; a
        # ${{ inputs.* }} inside run: would reintroduce unvalidated
        # interpolation the selector never sees.
        for name in WORKFLOWS:
            text = workflow_text(name)
            for match in re.finditer(r"run: \|(.*?)(?=\n      - |\n  \S)",
                                     text, re.S):
                self.assertNotIn("${{ inputs", match.group(1),
                                 f"{name} interpolates inputs inside run:")
            for match in re.finditer(r"run: ([^\n|][^\n]*)", text):
                self.assertNotIn("${{ inputs", match.group(1),
                                 f"{name} interpolates inputs inside run:")

    def test_run_outputs_cover_exactly_the_gated_set(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                selection, matrices = select(
                    name, "push", "refs/heads/dev/v0.8.0", {"known"})
                with tempfile.TemporaryDirectory(
                        prefix="select-outputs-") as directory:
                    path = str(Path(directory) / "outputs")
                    os.environ["GITHUB_OUTPUT"] = path
                    try:
                        SELECT.write_outputs(selection, matrices)
                    finally:
                        del os.environ["GITHUB_OUTPUT"]
                    keys = {line.split("=", 1)[0] for line in
                            Path(path).read_text(
                                encoding="utf-8").splitlines()}
                expected = {"tier", "base", "path_classes", "selection"}
                expected.update(SELECT.output_name(job)
                                for job in SELECT.GATED[name])
                expected.update(matrices)
                self.assertEqual(keys, expected)

    def test_selection_document_shape(self):
        selection, _ = select("ci", "push", "refs/heads/test/x", {"known"})
        self.assertEqual(selection["schema"], "p11scope/ci-selection/v1")
        for key in ("workflow", "event", "ref", "sha", "base", "tier",
                    "bpf_extra", "path_classes", "jobs"):
            self.assertIn(key, selection)
        self.assertEqual(set(selection["jobs"]), set(SELECT.UNIVERSE["ci"]))
        for job, entry in selection["jobs"].items():
            with self.subTest(job=job):
                self.assertIn(entry["state"],
                              ("selected", "conditional", "not-selected"))
                if entry["state"] == "selected":
                    self.assertIsNone(entry["reason"])
                else:
                    # Deselected and conditional jobs name their reason:
                    # the gate summary lists every skipped cell from it.
                    self.assertTrue(entry["reason"], "reason required")

    def test_push_to_development_branches_selects_quick(self):
        for ref in ("refs/heads/test/x", "refs/heads/task/x"):
            with self.subTest(ref=ref):
                selection, _ = select("ci", "push", ref, {"known"})
                self.assertEqual(selection["tier"], "quick")
                self.assertFalse(selection["bpf_extra"])
                current = states(selection)
                for job in ("lint", "audit", "tests", "contracts",
                            "scripts"):
                    self.assertEqual(current[job], "selected")
                self.assertEqual(current["bpf-noninterference"],
                                 "not-selected")
                self.assertEqual(current["coverage"], "not-selected")
                self.assertEqual(current["coverage-report"], "not-selected")
                selection, matrices = select(
                    "privileged-tests", "push", ref, {"known"})
                current = states(selection)
                for job in ("privileged-build", "privileged-shard",
                            "privileged-summary", "privileged-btrfs",
                            "privileged-overlay", "release-build",
                            "system-scale", "public-cli", "public-cli-ia32",
                            "legacy32-shape", "root-integration",
                            "witness-cli", "run-tree", "pkcs11-check-smoke",
                            "pkcs11-check-providers"):
                    self.assertEqual(current[job], "selected", job)
                for job in ("privileged-build-journal",
                            "privileged-second-flavor",
                            "privileged-counter-flavor", "browser-cells",
                            "container-image", "pkcs11-check-full",
                            "pkcs11-check-providers-full"):
                    self.assertEqual(current[job], "not-selected", job)
                for name in ("matrix_public_cli", "matrix_witness_cli",
                             "matrix_run_tree"):
                    self.assertEqual(matrices[name]["kernel"],
                                     ["host", "v6.6.157", "v7.3.1"])
                selection, _ = select("bpf-kernels", "push", ref, {"known"})
                current = states(selection)
                self.assertEqual(current["bpf-load-build"], "selected")
                self.assertEqual(current["bpf-load-host"], "selected")
                for job in ("kvm-probe", "bpf-load-kernels",
                            "bpf-load-gate1-build", "bpf-load-gate1-kernels",
                            "lib-cells-kernels"):
                    self.assertEqual(current[job], "not-selected", job)

    def test_branch_prefixes_require_their_slash(self):
        # startsWith(refs/heads/test/) must not match refs/heads/testx.
        for ref in ("refs/heads/testx", "refs/heads/taskx",
                    "refs/heads/spike/x", "refs/heads/dev-x"):
            with self.subTest(ref=ref):
                selection, _ = select("ci", "push", ref, {"known"})
                self.assertEqual(selection["tier"], "full")

    def test_bpf_toolchain_and_lockfile_paths_add_the_bpf_set(self):
        representatives = {
            # The ebpf crate's own toolchain and lockfile read as BPF:
            # the crate prefix rules first, and every class here feeds
            # the same BPF set.
            "bpf": ["crates/ebpf/native/x.c", "crates/ebpf-common/src/x.rs",
                    "crates/ebpf/rust-toolchain.toml",
                    "crates/ebpf/Cargo.lock", "build.rs",
                    "build_support/x.rs"],
            "toolchain": [".release-rust-version", "rust-toolchain.toml"],
            "lockfile": ["Cargo.lock", "third-party/licenses/x.txt"],
        }
        for expected, paths in representatives.items():
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(SELECT.classify_path(path), expected)
        for cls in ("bpf", "toolchain", "lockfile"):
            with self.subTest(cls=cls):
                selection, matrices = select(
                    "ci", "push", "refs/heads/test/x", {"known", cls})
                self.assertEqual(selection["tier"], "quick")
                self.assertTrue(selection["bpf_extra"])
                current = states(selection)
                self.assertEqual(current["bpf-noninterference"], "selected")
                # Coverage still stays on the full tier.
                self.assertEqual(current["coverage"], "not-selected")
                selection, matrices = select(
                    "privileged-tests", "push", "refs/heads/test/x",
                    {"known", cls})
                current = states(selection)
                for job in ("privileged-build-journal",
                            "privileged-second-flavor",
                            "privileged-counter-flavor"):
                    self.assertEqual(current[job], "selected", job)
                for job, kernels in SELECT.CLI_FULL_KERNELS.items():
                    output = f"matrix_{job.replace('-', '_')}"
                    self.assertEqual(matrices[output]["kernel"], kernels)
                selection, _ = select(
                    "bpf-kernels", "push", "refs/heads/test/x",
                    {"known", cls})
                current = states(selection)
                for job in ("kvm-probe", "bpf-load-kernels",
                            "bpf-load-gate1-build", "bpf-load-gate1-kernels",
                            "lib-cells-kernels"):
                    self.assertEqual(current[job], "selected", job)

    def test_ci_unknown_and_undeterminable_diffs_force_full(self):
        for path in (".github/workflows/ci.yml", ".github/ci-nightly-ref",
                     "scripts/ci/select-cells.py"):
            with self.subTest(path=path):
                self.assertEqual(SELECT.classify_path(path), "ci")
                selection, _ = select(
                    "ci", "push", "refs/heads/test/x",
                    SELECT.classify_paths([path]))
                self.assertEqual(selection["tier"], "full")
        self.assertEqual(SELECT.classify_path("brand-new-dir/x"), "unknown")
        selection, _ = select("ci", "push", "refs/heads/test/x",
                              {"known", "unknown"})
        self.assertEqual(selection["tier"], "full")
        selection, _ = select("ci", "push", "refs/heads/test/x", None)
        self.assertEqual(selection["tier"], "full")
        self.assertIsNone(selection["path_classes"])

    def test_every_tracked_path_is_classified(self):
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, text=True,
                             capture_output=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        paths = [path for path in out.stdout.split("\0") if path]
        self.assertGreater(len(paths), 1000)
        # A fixture name carries spaces: NUL separation keeps it one path.
        self.assertIn("tests/fixtures/prepared-abi-driver/consumed source "
                      "with spaces.rs", paths)
        unknown = [path for path in paths
                   if SELECT.classify_path(path) == "unknown"]
        self.assertEqual(unknown, [])

    def test_dev_main_pull_request_and_foreign_events_run_full(self):
        cases = [("push", "refs/heads/dev/v0.8.0"),
                 ("push", "refs/heads/main"),
                 ("pull_request", "refs/pull/1/merge"),
                 ("issue_comment", "refs/heads/test/x")]
        for event, ref in cases:
            with self.subTest(event=event, ref=ref):
                for name in WORKFLOWS:
                    selection, _ = select(name, event, ref, {"known"})
                    self.assertEqual(selection["tier"], "full", name)

    def test_dispatch_tiers(self):
        selection, _ = select("privileged-tests", "workflow_dispatch",
                              "refs/heads/test/cand", {"known"})
        self.assertEqual(selection["tier"], "full")
        selection, _ = select("privileged-tests", "workflow_dispatch",
                              "refs/heads/test/cand", {"known"},
                              tier_input="quick")
        self.assertEqual(selection["tier"], "quick")
        current = states(selection)
        self.assertEqual(current["browser-cells"], "not-selected")
        self.assertEqual(current["privileged-shard"], "selected")
        selection, _ = select("privileged-tests", "workflow_dispatch",
                              "refs/heads/test/cand", {"known"},
                              tier_input="integration")
        self.assertEqual(selection["tier"], "integration")
        current = states(selection)
        self.assertEqual(current["pkcs11-check-full"], "selected")
        self.assertEqual(current["pkcs11-check-providers-full"], "selected")
        selection, _ = select("ci", "workflow_dispatch",
                              "refs/heads/test/cand", {"known"},
                              tier_input="integration",
                              release_preview=True)
        self.assertEqual(
            states(selection)["release-preview"], "selected")
        # An explicit quick dispatch still fails closed on CI diffs.
        selection, _ = select("ci", "workflow_dispatch",
                              "refs/heads/test/cand", {"ci"},
                              tier_input="quick")
        self.assertEqual(selection["tier"], "full")

    def test_unknown_tier_and_misplaced_tier_fail(self):
        with self.assertRaisesRegex(ValueError, "unknown tier"):
            SELECT.validate_tier("turbo", "workflow_dispatch")
        with self.assertRaisesRegex(ValueError, "dispatches only"):
            SELECT.validate_tier("quick", "push")
        self.assertEqual(SELECT.validate_tier("", "push"), "full")

    def test_cells_and_kernels_inputs_are_rejected_before_wiring(self):
        saved = dict(os.environ)
        os.environ.update(P11SCOPE_CI_WORKFLOW="ci",
                          GITHUB_EVENT_NAME="push",
                          GITHUB_REF="refs/heads/test/x",
                          GITHUB_SHA="a" * 40,
                          P11SCOPE_CI_CELLS="browser")
        try:
            with self.assertRaisesRegex(ValueError, "cells"):
                SELECT.main()
            os.environ["P11SCOPE_CI_CELLS"] = ""
            os.environ["P11SCOPE_CI_KERNELS"] = "v6.6.157"
            with self.assertRaisesRegex(ValueError, "kernels"):
                SELECT.main()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_delivery_dispatch_and_dedupe_deselect_ordinary_jobs(self):
        selection, _ = select("ci", "workflow_dispatch", "refs/heads/main",
                              {"known"}, delivery_task="packages")
        current = states(selection)
        self.assertEqual(current["package-delivery"], "selected")
        self.assertEqual(current["docker-delivery"], "not-selected")
        for job in ("lint", "coverage", "quarantine", "release-preview"):
            self.assertEqual(current[job], "not-selected", job)
        selection, _ = select("ci", "push", "refs/heads/test/x", {"known"},
                              dedupe_run=False)
        current = states(selection)
        for job in ("lint", "coverage", "quarantine"):
            self.assertEqual(current[job], "not-selected", job)
            self.assertIn("deduped",
                          selection["jobs"][job]["reason"])

    def test_schedule_keeps_the_current_nightly_set(self):
        selection, _ = select("privileged-tests", "schedule",
                              "refs/heads/main", {"known"})
        self.assertEqual(selection["tier"], "schedule")
        current = states(selection)
        for job in ("release-build", "pkcs11-check-full",
                    "pkcs11-check-providers-full"):
            self.assertEqual(current[job], "selected", job)
        for job in ("privileged-build", "privileged-shard",
                    "pkcs11-check-smoke"):
            self.assertEqual(current[job], "not-selected", job)

    def test_unknown_workflow_fails(self):
        with self.assertRaisesRegex(ValueError, "unknown workflow"):
            SELECT.build_selection("nope", "push", "refs/heads/test/x",
                                   "a" * 40, "full", {"known"},
                                   "dev/v0.8.0")

    def test_kernel_lists_cover_every_matrix(self):
        self.assertEqual(
            SELECT.CLI_FULL_KERNELS["public-cli"],
            ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
             "v7.4-rc2"])
        self.assertEqual(SELECT.CLI_FULL_KERNELS["witness-cli"],
                         SELECT.CLI_FULL_KERNELS["public-cli"])
        self.assertEqual(
            SELECT.CLI_FULL_KERNELS["run-tree"],
            ["host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1"])
        self.assertEqual(SELECT.CLI_QUICK_KERNELS,
                         ["host", "v6.6.157", "v7.3.1"])
        for job, kernels in SELECT.CLI_FULL_KERNELS.items():
            with self.subTest(job=job):
                for kernel in SELECT.CLI_QUICK_KERNELS:
                    self.assertIn(kernel, kernels)
        self.assertEqual(SELECT.BPF_POSITIVE_KERNELS,
                         ["v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                          "v7.4-rc2"])
        self.assertEqual(SELECT.BPF_REFUSAL_ROWS, [
            {"kernel": "v6.1.188", "refusal_control": True},
            {"kernel": "v5.15.221", "refusal_control": True,
             "denial_branch": "denied"},
        ])
        self.assertEqual(SELECT.LIB_CELL_KERNELS,
                         ["v6.6.157", "v6.12.111"])

    def test_kernel_sums_cover_the_lists_exactly(self):
        kernels = set()
        for job_kernels in SELECT.CLI_FULL_KERNELS.values():
            kernels.update(kernel for kernel in job_kernels
                           if kernel != "host")
        kernels.update(SELECT.BPF_POSITIVE_KERNELS)
        kernels.update(row["kernel"] for row in SELECT.BPF_REFUSAL_ROWS)
        kernels.update(SELECT.LIB_CELL_KERNELS)
        sums = {path.stem for path in SUMS_DIR.glob("*.sums")}
        self.assertEqual(sums, kernels)
        line = re.compile(r"^[0-9a-f]{64}  (\S+)$")
        for kernel in sorted(kernels):
            with self.subTest(kernel=kernel):
                rows = (SUMS_DIR / f"{kernel}.sums").read_text(
                    encoding="utf-8").splitlines()
                self.assertTrue(rows)
                for row in rows:
                    self.assertRegex(row, line)

    def test_yaml_kernel_matrices_come_from_select(self):
        for name, jobs in DYNAMIC_MATRICES.items():
            parsed = workflow_jobs(name)
            for job, output in jobs.items():
                with self.subTest(workflow=name, job=job):
                    strategy = parsed[job]["strategy"]
                    self.assertIs(strategy["fail-fast"], False)
                    self.assertEqual(
                        strategy["matrix"],
                        "${{ fromJSON(needs.select.outputs."
                        f"{output}) }}}}")

    def test_static_matrices_stay_literal(self):
        ci = workflow_jobs("ci")
        self.assertEqual(ci["contracts"]["strategy"]["matrix"]["shard"],
                         [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(ci["coverage"]["strategy"]["matrix"]["partition"],
                         ["rest", "contracts:1/6", "contracts:2/6",
                          "contracts:3/6", "contracts:4/6", "contracts:5/6",
                          "contracts:6/6"])
        priv = workflow_jobs("privileged-tests")
        self.assertEqual(
            priv["privileged-shard"]["strategy"]["matrix"]["shard"],
            [0, 1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(
            [row["provider"] for row in
             priv["pkcs11-check-providers"]["strategy"]["matrix"]["include"]],
            ["kryoptic", "haskoki", "nss-softokn"])
        self.assertEqual(
            [row["provider"] for row in
             priv["pkcs11-check-providers-full"]["strategy"]["matrix"]
             ["include"]],
            ["kryoptic", "haskoki"])

    def test_emitted_matrices_match_the_tier(self):
        _, matrices = select("privileged-tests", "push",
                             "refs/heads/test/x", {"known"})
        for name in ("matrix_public_cli", "matrix_witness_cli",
                     "matrix_run_tree"):
            self.assertEqual(matrices[name],
                             {"kernel": ["host", "v6.6.157", "v7.3.1"]})
        _, matrices = select("privileged-tests", "push", "refs/heads/dev/x",
                             {"known"})
        for job, kernels in SELECT.CLI_FULL_KERNELS.items():
            output = f"matrix_{job.replace('-', '_')}"
            self.assertEqual(matrices[output], {"kernel": kernels})
        _, matrices = select("bpf-kernels", "push", "refs/heads/dev/x",
                             {"known"})
        self.assertEqual(matrices["matrix_bpf_load"], {
            "kernel": ["v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                       "v7.4-rc2"],
            "include": [
                {"kernel": "v6.1.188", "refusal_control": True},
                {"kernel": "v5.15.221", "refusal_control": True,
                 "denial_branch": "denied"},
            ]})
        self.assertEqual(matrices["matrix_bpf_gate1"], {
            "kernel": ["v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1",
                       "v7.4-rc2"]})
        self.assertEqual(matrices["matrix_lib_cells"],
                         {"kernel": ["v6.6.157", "v6.12.111"]})

    def test_gate_child_counts_follow_the_matrices(self):
        selection, _ = select("privileged-tests", "push",
                              "refs/heads/test/x", {"known"})
        jobs = selection["jobs"]
        for job in ("public-cli", "witness-cli", "run-tree"):
            self.assertEqual(jobs[job]["children"], 3, job)
        self.assertEqual(jobs["privileged-shard"]["children"], 8)
        self.assertEqual(jobs["pkcs11-check-providers"]["children"], 3)
        selection, _ = select("bpf-kernels", "push", "refs/heads/dev/x",
                              {"known"})
        jobs = selection["jobs"]
        self.assertEqual(jobs["bpf-load-kernels"]["children"], 7)
        self.assertEqual(jobs["bpf-load-gate1-kernels"]["children"], 5)
        self.assertEqual(jobs["lib-cells-kernels"]["children"], 2)
        selection, _ = select("ci", "push", "refs/heads/dev/x", {"known"})
        jobs = selection["jobs"]
        self.assertEqual(jobs["contracts"]["names"],
                         [f"contracts-{index}" for index in range(1, 9)])
        self.assertEqual(jobs["coverage"]["children"], 7)
        self.assertIsNone(jobs["lint"]["children"])

    def test_nightly_ref_names_the_dev_branch(self):
        path = ROOT / ".github" / "ci-nightly-ref"
        self.assertTrue(path.is_file())
        self.assertEqual(SELECT.read_base_branch(), "dev/v0.8.0")

    def make_repo(self, base):
        """A fixture repo: dev branch plus a feature branch off it."""
        saved = SELECT.ROOT
        repo = Path(base) / "repo"
        repo.mkdir()
        env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

        def git(*arguments):
            return subprocess.run(["git", *arguments], cwd=repo, env=env,
                                  text=True, capture_output=True,
                                  timeout=60)

        self.addCleanup(setattr, SELECT, "ROOT", saved)
        SELECT.ROOT = repo
        self.assertEqual(git("init", "-q", "-b", "main").returncode, 0)
        (repo / "tracked").write_text("base\n")
        self.assertEqual(git("add", "tracked").returncode, 0)
        self.assertEqual(git("commit", "-qm", "base").returncode, 0)
        self.assertEqual(git("branch", "dev/v0.8.0").returncode, 0)
        self.assertEqual(git("checkout", "-q", "-b", "test/x").returncode, 0)
        (repo / "tracked").write_text("feature\n")
        (repo / "new.rs").write_text("fn f() {}\n")
        self.assertEqual(git("add", ".").returncode, 0)
        self.assertEqual(git("commit", "-qm", "feature").returncode, 0)
        self.assertEqual(
            git("remote", "add", "origin", str(repo)).returncode, 0)
        return git, repo

    def test_changed_paths_diff_the_dev_merge_base(self):
        with tempfile.TemporaryDirectory(prefix="select-base-") as base:
            git, repo = self.make_repo(base)
            sha = git("rev-parse", "HEAD").stdout.strip()
            paths = SELECT.changed_paths("push", "refs/heads/test/x", sha,
                                         "dev/v0.8.0")
            self.assertEqual(sorted(paths), ["new.rs", "tracked"])

    def test_changed_paths_on_dev_diff_the_pushed_range(self):
        with tempfile.TemporaryDirectory(prefix="select-range-") as base:
            git, repo = self.make_repo(base)
            self.assertEqual(git("checkout", "-q", "dev/v0.8.0").returncode,
                             0)
            before = git("rev-parse", "HEAD").stdout.strip()
            (repo / "second").write_text("more\n")
            self.assertEqual(git("add", ".").returncode, 0)
            self.assertEqual(git("commit", "-qm", "second").returncode, 0)
            sha = git("rev-parse", "HEAD").stdout.strip()
            event = Path(base) / "event.json"
            event.write_text(json.dumps({"before": before}))
            saved = os.environ.get("GITHUB_EVENT_PATH")
            os.environ["GITHUB_EVENT_PATH"] = str(event)
            try:
                paths = SELECT.changed_paths(
                    "push", "refs/heads/dev/v0.8.0", sha, "dev/v0.8.0")
            finally:
                if saved is None:
                    del os.environ["GITHUB_EVENT_PATH"]
                else:
                    os.environ["GITHUB_EVENT_PATH"] = saved
            self.assertEqual(paths, ["second"])

    def test_changed_paths_fail_closed_without_a_remote(self):
        with tempfile.TemporaryDirectory(prefix="select-noremote-") as base:
            git, repo = self.make_repo(base)
            self.assertEqual(git("remote", "remove", "origin").returncode, 0)
            sha = git("rev-parse", "HEAD").stdout.strip()
            self.assertIsNone(SELECT.changed_paths(
                "push", "refs/heads/test/x", sha, "dev/v0.8.0"))


if __name__ == "__main__":
    unittest.main()
