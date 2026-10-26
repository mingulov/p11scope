# SPDX-License-Identifier: GPL-3.0-or-later
"""Ignored-test inventory: every #[ignore] is a tracked obligation.

scripts/check-ignored-tests.py scans the workspace Rust sources for real
`#[ignore]` attributes and compares them both ways against
tests/ignored-tests.json: every `privileged` entry must be curated in
scripts/run-privileged-lib-tests.sh, every `feature` entry must name a
non-empty owning lane in `owner`, the wide-featured sites (wide `owner`
entries plus feature-gated macro expansions) must exactly match the
runner's WIDE_DETAILED_2112_TESTS list, and every `live-kernel` or
`privileged` integration entry must be curated in the runner's
INTEGRATION_TESTS list. These tests prove the checked-in inventory
matches the sources, then exercise each failure mode on synthetic
fixture trees so a regression in the checker cannot hide behind a clean
real tree. Final groups drive the runner's wide-list and integration
modes against fake binaries: a matching binary is accepted, a default
or incomplete one is refused cleanly.

Run: python3 -I tests/python/test_ignored_tests.py -v
"""

import json
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-ignored-tests.py"
INVENTORY = ROOT / "tests" / "ignored-tests.json"
RUNNER = ROOT / "scripts" / "run-privileged-lib-tests.sh"
CHECKER_MOD = runpy.run_path(str(CHECKER))

CELLS = {
    "privileged": "test cell",
    "live-kernel": "test cell",
    "feature": "test cell",
    "performance": "test cell",
    "helper": "test cell",
}

WIDE_OWNER = "wide-detailed-2112 runner"

# The exact wide-featured lib tests: the four wide-gated fns plus the
# five wide-gated detailed_sweep_test! expansions. Pinned literally so a
# runner edit that drops or renames one fails here, not silently.
WIDE_EXPECTED = [
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_2112_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n511_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n513_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2048_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_detailed_n2049_lp64",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_worker_exit",
    "attach::inventory::activation::privileged_tests::privileged_task4_highslot_2048_nonleader_exec",
    "attach::inventory::activation::privileged_tests::privileged_detailed_2112_stop_publishes_before_cleanup",
]


INTEGRATION_EXPECTED = [
    "tests/entry_object_paired.rs:paired_default_and_unsafe_objects_satisfy_the_entry_contract",
    "tests/exec_task_continuity.rs:exec_task_core_shapes_kernel_load_without_attachment",
    "tests/identity_iter_standalone.rs:identity_loader_strict_gate_requires_btf_and_both_programs",
    "tests/inventory_identity.rs:d4_btrfs_scan_backends_match_exact_fixture_population",
    "tests/inventory_identity.rs:kernel_identity_positive_cell_rejects_refusal",
    "tests/object_producer_activation.rs:counter_bank_btf_maps_and_programs_load",
    "tests/run_abandon_report.rs:second_sigint_during_teardown_publishes_truthful_report_and_exits_130",
]

INTEGRATION_SOURCES = {
    "tests/foo.rs": (
        '#[test]\n'
        '#[ignore = "needs the kernel lane"]\n'
        'fn t_live() {}\n'
    ),
}

INTEGRATION_ENTRY = {
    "file": "tests/foo.rs", "path": "t_live",
    "reason": "needs the kernel lane", "cell": "live-kernel",
}

# The two src/ live-kernel cells no runner executes: each needs a SKIP
# entry with a reason, pinned literally so a dropped curation fails here.
SRC_LIVE_KERNEL_SKIP_EXPECTED = [
    "attach::identity_iter::tests::privileged_identity_nonleader_anchor_installs_nothing",
    "discovery::sweep_attribution::tests::d4_zombie_cells::privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins",
]


def write_fixture(root, sources, entries, registered, wide_registered=(),
                  integration_registered=(), counter_proof_registered=(),
                  counter_artifacts_registered=()):
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
            ("WIDE_DETAILED_2112_TESTS", wide_registered),
            ("INTEGRATION_TESTS", integration_registered),
            ("COUNTER_BANK_PROOF_TESTS", counter_proof_registered),
            ("COUNTER_ARTIFACTS_TESTS", counter_artifacts_registered),
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

FEATURE_SOURCES = {
    "src/lib.rs": "mod f;\n",
    "src/f.rs": (
        '#[test]\n'
        '#[ignore = "needs feature x"]\n'
        'fn t_feat() {}\n'
    ),
}

FEATURE_ENTRY = {
    "file": "src/f.rs", "path": "f::t_feat",
    "reason": "needs feature x", "cell": "feature",
}

LIVE_KERNEL_SOURCES = {
    "src/lib.rs": "mod k;\n",
    "src/k.rs": (
        '#[test]\n'
        '#[ignore = "needs the hand-run lane"]\n'
        'fn t_live_kernel() {}\n'
    ),
}

LIVE_KERNEL_ENTRY = {
    "file": "src/k.rs", "path": "k::t_live_kernel",
    "reason": "needs the hand-run lane", "cell": "live-kernel",
}


def write_fake_binary(path, ignored):
    """An executable stub answering `--list --ignored` with canned tests."""
    lines = "".join(f"echo '{name}: test'\n" for name in ignored)
    path.write_text("#!/bin/sh\n" + lines, encoding="utf-8")
    path.chmod(0o755)


def write_fake_integration_binary(depsdir, stem, ignored):
    """A fake built integration binary: deps/<stem>-<hash>, executable."""
    path = depsdir / f"{stem}-0123456789abcdef"
    write_fake_binary(path, ignored)
    return path


def run_runner(*args):
    return subprocess.run(
        [str(RUNNER), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def runner_array_lines(path, name):
    """Ordered entries of one `NAME=(...)` shell array, comments stripped.

    Quoted reason lines are kept whole (a `#` inside quotes is data);
    test lines strip `#` comments. Empty lines contribute nothing.
    """
    text = Path(path).read_text(encoding="utf-8")
    head = f"{name}=(\n"
    start = text.index(head) + len(head)
    end = text.index("\n)", start)
    lines = []
    for line in text[start:end].splitlines():
        stripped = line.strip()
        if stripped.startswith('"'):
            lines.append(stripped)
        else:
            entry = line.split("#")[0].strip()
            if entry:
                lines.append(entry.split()[0])
    return lines


class IgnoredTestsTests(unittest.TestCase):
    def test_checked_in_inventory_matches_the_sources(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inventoried = len(json.loads(INVENTORY.read_text(encoding="utf-8"))
                           ["sites"])
        self.assertIn(f"all {inventoried} inventoried site(s) match",
                      result.stdout)
        self.assertIn("privileged, feature-owner and integration "
                      "curation verified", result.stdout)

    def test_an_extra_ignored_test_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = dict(SOURCES)
            sources["src/a.rs"] += (
                '\n#[test]\n#[ignore = "privileged: sneaked in"]\n'
                "fn t_new() {}\n"
            )
            write_fixture(root, sources, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("a::t_new has no inventory entry", result.stdout)

    def test_a_removed_inventory_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES[1:], REGISTERED,
                          ["m::t_wide"])
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
            write_fixture(root, SOURCES, entries, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("no matching #[ignore] site for src/a.rs a::t_gone",
                      result.stdout)

    def test_an_unregistered_privileged_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["m::t_sweep"],
                          ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("privileged a::t_priv is not curated", result.stdout)

    def test_comment_and_string_mentions_are_not_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 3 inventoried site(s) match", result.stdout)

    def test_macro_expansions_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, ["a::t_priv"],
                          ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("expands to m::t_sweep, not curated", result.stdout)

    def test_feature_gated_expansions_require_wide_curation(self):
        # m::t_wide is gated on cargo feature "wide": exempt from the
        # default lists, but it must be curated in WIDE_DETAILED_2112_TESTS.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("m::t_wide", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_list_member_without_a_wide_site_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          ["f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_member_from_non_privileged_expansion_fails(self):
        # Only a privileged macro entry owns the wide campaign: a
        # feature-gated expansion of a performance-gated macro must not
        # satisfy a WIDE list member.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = {"src/lib.rs": "mod m;\n", "src/m.rs": M_RS}
            entries = [
                {"file": "src/m.rs", "path": "m::sweep!",
                 "reason": "performance: sweep cell",
                 "cell": "performance"},
            ]
            write_fixture(root, sources, entries, [], ["m::t_wide"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("m::t_wide", result.stdout)
        self.assertIn("not a wide-owned inventory site or a "
                      "feature-gated expansion", result.stdout)

    def test_feature_entry_without_owner_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, FEATURE_SOURCES, [FEATURE_ENTRY], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("owner", result.stdout)

    def test_feature_entry_with_empty_owner_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("owner", result.stdout)

    def test_feature_entry_with_whitespace_owner_fails(self):
        # A whitespace-only owner is refused as blank (not merely as
        # unknown): pinning the message kills a strip() regression even
        # though the closed owner set would also reject it.
        for owner in ("   ", "\t\n"):
            with self.subTest(owner=owner):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    entry = dict(FEATURE_ENTRY, owner=owner)
                    write_fixture(root, FEATURE_SOURCES, [entry], [])
                    result = run_checker(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("non-empty owner", result.stdout)

    def test_counter_bank_proof_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-bank-proof build")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("COUNTER_BANK_PROOF_TESTS", result.stdout)

    def test_counter_bank_proof_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-bank-proof build")
            write_fixture(root, FEATURE_SOURCES, [entry], [],
                          counter_proof_registered=["src/f.rs:f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_counter_bank_proof_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          counter_proof_registered=["src/f.rs:f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("COUNTER_BANK_PROOF_TESTS", result.stdout)

    def test_counter_artifacts_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-artifacts build")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("COUNTER_ARTIFACTS_TESTS", result.stdout)

    def test_counter_artifacts_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="counter-artifacts build")
            write_fixture(root, FEATURE_SOURCES, [entry], [],
                          counter_artifacts_registered=["src/f.rs:f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_counter_artifacts_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          counter_artifacts_registered=["src/f.rs:f::t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_nope", result.stdout)
        self.assertIn("COUNTER_ARTIFACTS_TESTS", result.stdout)

    def test_feature_entry_with_unknown_owner_fails(self):
        # A typo'd owner ("wide-detailed-2112" without " runner") must
        # fail closed instead of silently exempting the test from
        # wide curation.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner="wide-detailed-2112")
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown owner", result.stdout)
        self.assertIn("wide-detailed-2112", result.stdout)

    def test_wide_owned_feature_entry_must_be_wide_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner=WIDE_OWNER)
            write_fixture(root, FEATURE_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("f::t_feat", result.stdout)
        self.assertIn("WIDE_DETAILED_2112_TESTS", result.stdout)

    def test_wide_owned_feature_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(FEATURE_ENTRY, owner=WIDE_OWNER)
            write_fixture(root, FEATURE_SOURCES, [entry], [], ["f::t_feat"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_src_live_kernel_entry_must_be_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, LIVE_KERNEL_SOURCES, [LIVE_KERNEL_ENTRY],
                          [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("k::t_live_kernel", result.stdout)
        self.assertIn("not curated", result.stdout)

    def test_src_live_kernel_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, LIVE_KERNEL_SOURCES, [LIVE_KERNEL_ENTRY],
                          ["k::t_live_kernel"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_src_live_kernel_cells_are_skip_curated(self):
        lists = CHECKER_MOD["runner_lists"](str(RUNNER))
        for name in SRC_LIVE_KERNEL_SKIP_EXPECTED:
            with self.subTest(name=name):
                self.assertIn(name, lists["SKIP_TESTS"])

    def test_skip_reasons_align_with_skip_tests(self):
        tests = runner_array_lines(RUNNER, "SKIP_TESTS")
        reasons = runner_array_lines(RUNNER, "SKIP_REASONS")
        self.assertEqual(
            len(tests), len(reasons),
            f"SKIP_TESTS={len(tests)} SKIP_REASONS={len(reasons)}",
        )
        for name, needs_fixture in [
            ("metrics::counter_reader::tests::"
             "counter_cli_profile_counts_matches_workload_ledger_lp64", True),
            ("metrics::counter_reader::tests::"
             "counter_cli_profile_timestamps_matches_workload_ledger_lp64", True),
            ("metrics::counter_reader::tests::"
             "counter_cli_profile_latency_matches_workload_ledger_lp64", True),
            ("metrics::counter_reader::tests::"
             "counter_cli_run_counts_with_owned_child_lp64", False),
        ]:
            with self.subTest(name=name):
                self.assertIn(name, tests)
                reason = reasons[tests.index(name)]
                self.assertIn("needs root", reason)
                self.assertIn("by hand", reason)
                if needs_fixture:
                    self.assertIn(
                        "P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER", reason)
                    self.assertIn(
                        "P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD", reason)
                else:
                    self.assertIn("no fixture", reason)

    def test_runner_list_refuses_skip_misalignment(self):
        text = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^SKIP_REASONS=\(\n(.*?)\n\)", text, re.M | re.S)
        self.assertIsNotNone(match, "real runner has no SKIP_REASONS list")
        lines = match.group(1).splitlines()
        dropped = "\n".join(
            line for line in lines
            if not line.strip().startswith('"needs punch-hole support'))
        self.assertLess(len(dropped.splitlines()), len(lines),
                        "fixture must drop one reason")
        broken = text[:match.start(1)] + dropped + text[match.end(1):]
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / "run-privileged-lib-tests.sh"
            runner.write_text(broken, encoding="utf-8")
            runner.chmod(0o755)
            binary = Path(tmp) / "libtest-empty"
            write_fake_binary(binary, [])
            result = subprocess.run(
                [str(runner), "--list", str(binary)],
                capture_output=True, text=True, cwd=ROOT,
            )
        self.assertNotEqual(
            result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("differ in length", result.stderr)

    def test_checker_prints_exact_per_list_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, SOURCES, ENTRIES, REGISTERED, ["m::t_wide"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "ignored-tests counts: DEFAULT_TESTS=2 ALTERNATIVE_TESTS=0 "
            "LONG_TESTS=0 SKIP_TESTS=0 WIDE_DETAILED_2112_TESTS=1 "
            "COUNTER_BANK_PROOF_TESTS=0 COUNTER_ARTIFACTS_TESTS=0 "
            "INTEGRATION_TESTS=0",
            result.stdout,
        )

    def test_real_tree_per_list_counts_are_exact(self):
        result = run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for pin in (
            "DEFAULT_TESTS=119",
            "ALTERNATIVE_TESTS=2",
            "LONG_TESTS=16",
            "SKIP_TESTS=67",
            "WIDE_DETAILED_2112_TESTS=9",
            "COUNTER_BANK_PROOF_TESTS=0",
            "COUNTER_ARTIFACTS_TESTS=2",
            "INTEGRATION_TESTS=7",
        ):
            with self.subTest(pin=pin):
                self.assertIn(pin, result.stdout)

    def test_wide_list_mode_accepts_a_wide_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-wide"
            write_fake_binary(binary, WIDE_EXPECTED + ["plain::t_one"])
            result = run_runner("--list", "--wide-detailed-2112",
                                str(binary))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("wide-detailed-2112 (9)", result.stdout)
        for name in WIDE_EXPECTED:
            self.assertIn(name, result.stdout)
        self.assertIn("verify: wide-detailed-2112 curation matches "
                      "the binary (9 tests)", result.stdout)

    def test_wide_list_mode_refuses_a_default_binary(self):
        # A default binary carries none of the wide tests: the mode must
        # refuse (exit 1, missing tests named) instead of printing a
        # verify receipt or an empty PASS.
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-default"
            write_fake_binary(binary, ["plain::t_one", "plain::t_two"])
            result = run_runner("--list", "--wide-detailed-2112",
                                str(binary))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("wide-detailed-2112", result.stderr)
        self.assertIn("absent from the binary", result.stderr)
        self.assertIn("privileged_task4_detailed_2112_lp64", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_wide_list_mode_refuses_a_duplicated_listing(self):
        # A binary listing one curated member twice selects two tests,
        # not exactly one: the mode must refuse instead of deduping
        # the duplicate away and printing a verify receipt.
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "libtest-dup"
            write_fake_binary(binary, WIDE_EXPECTED + [WIDE_EXPECTED[0]])
            result = run_runner("--list", "--wide-detailed-2112",
                                str(binary))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("more than one", result.stderr)
        self.assertIn(WIDE_EXPECTED[0], result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_entry_without_curation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, INTEGRATION_SOURCES, [INTEGRATION_ENTRY],
                          [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_live", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_privileged_integration_entry_requires_curation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = dict(INTEGRATION_ENTRY, cell="privileged")
            write_fixture(root, INTEGRATION_SOURCES, [entry], [])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_live", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_integration_entry_passes_when_curated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, INTEGRATION_SOURCES, [INTEGRATION_ENTRY],
                          [], integration_registered=["tests/foo.rs:t_live"])
            result = run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all 1 inventoried site(s) match", result.stdout)

    def test_integration_member_without_an_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, {"src/lib.rs": ""}, [], [],
                          integration_registered=["tests/foo.rs:t_nope"])
            result = run_checker(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("t_nope", result.stdout)
        self.assertIn("INTEGRATION_TESTS", result.stdout)

    def test_integration_list_mode_accepts_curated_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "entry_object_paired",
                ["paired_default_and_unsafe_objects_satisfy_the_entry_contract"])
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment",
                 "noise::t_other"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "object_producer_activation",
                ["counter_bank_btf_maps_and_programs_load"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("integration (7)", result.stdout)
        for entry in INTEGRATION_EXPECTED:
            self.assertIn(entry, result.stdout)
        self.assertIn("verify: integration curation selects exactly one "
                      "test per entry (7 entries)", result.stdout)

    def test_integration_list_mode_refuses_zero_selection(self):
        # The inventory_identity binary below is missing one of its two
        # curated tests: the entry selects nothing and must be refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("integration", result.stderr)
        self.assertIn("d4_btrfs_scan_backends_match_exact_fixture_population",
                      result.stderr)
        self.assertIn("selects 0 tests", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_missing_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("run_abandon_report", result.stderr)
        self.assertIn("no test binary", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_duplicated_selection(self):
        # The inventory_identity binary below lists one of its two
        # curated tests twice: the entry selects two tests, not exactly
        # one, and must be refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("d4_btrfs_scan_backends_match_exact_fixture_population",
                      result.stderr)
        self.assertIn("selects 2 tests", result.stderr)
        self.assertNotIn("verify:", result.stdout)

    def test_integration_list_mode_refuses_ambiguous_binary(self):
        # Two executables match one stem (a stale rebuild left behind):
        # the entry no longer identifies its binary, so it is refused.
        with tempfile.TemporaryDirectory() as tmp:
            deps = Path(tmp) / "deps"
            deps.mkdir()
            write_fake_integration_binary(
                deps, "exec_task_continuity",
                ["exec_task_core_shapes_kernel_load_without_attachment"])
            extra = deps / "exec_task_continuity-fedcba9876543210"
            write_fake_binary(extra, ["exec_task_core_shapes_kernel_load_without_attachment"])
            write_fake_integration_binary(
                deps, "identity_iter_standalone",
                ["identity_loader_strict_gate_requires_btf_and_both_programs"])
            write_fake_integration_binary(
                deps, "inventory_identity",
                ["d4_btrfs_scan_backends_match_exact_fixture_population",
                 "kernel_identity_positive_cell_rejects_refusal"])
            write_fake_integration_binary(
                deps, "run_abandon_report",
                ["second_sigint_during_teardown_publishes_truthful_report_and_exits_130"])
            result = run_runner("--list-integration", str(deps))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("exec_task_continuity", result.stderr)
        self.assertIn("more than one test binary", result.stderr)
        self.assertNotIn("verify:", result.stdout)


if __name__ == "__main__":
    unittest.main()
