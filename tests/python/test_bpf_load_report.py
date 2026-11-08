#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-kernel BPF load report: every root loaded, stats present, headroom kept.

Drives scripts/bpf-load-report.py through its real CLI on small owned JSONL
fixtures in the verifier-stats probe record format. Exit 0 only when every
root passes; the processed count of every root is printed either way.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/bpf-load-report.py"
DRIVER = ROOT / "scripts/check-bpf-load-kernels.sh"
RELEASE_MATCH = ROOT / "scripts/bpf-guest-release.sh"
BUDGETS_FILE = ROOT / "tests/bpf-verifier-budgets.json"
COUNTER_BUDGETS_FILE = ROOT / "tests/counter-bpf-verifier-budgets.json"
KERNEL = "v6.1.188-test"
OBSERVER = "ab" * 32
# The driver's default kernel list (scripts/check-bpf-load-kernels.sh)
# plus the 7.0 guest and the 7.4-rc1 newest-mainline cell the budgets
# also cover. Variant-group members split this set instead of carrying
# it whole (see below). Each budget-key namespace (prefix before "/")
# pins its own kernel set; all five namespaces currently cover the
# same measured 6-kernel set.
EXPECTED_BUDGET_KERNELS = frozenset({
    "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14", "v7.3.1", "v7.4-rc1",
})
EXPECTED_GATE1_BUDGET_KERNELS = frozenset({
    "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14", "v7.3.1", "v7.4-rc1",
})
EXPECTED_BUDGET_KERNELS_BY_NAMESPACE = {
    "detailed": EXPECTED_BUDGET_KERNELS,
    "inventory": EXPECTED_BUDGET_KERNELS,
    "detailed-gate1": EXPECTED_GATE1_BUDGET_KERNELS,
    "journal-gate1": EXPECTED_GATE1_BUDGET_KERNELS,
    "prearm-witness": EXPECTED_BUDGET_KERNELS,
}
# Hook slots whose program loads only on some kernels: each kernel budgets
# exactly one member of each group, and a missing row for the other member
# is accepted (it simply does not load there). Mirrors
# EXCLUSIVE_VARIANT_GROUPS in scripts/bpf-load-report.py.
# The gate-1 Detailed and journal objects carry the same hook slots
# under their own key prefixes.
EXCLUSIVE_VARIANT_GROUPS = [
    frozenset({f"{prefix}/p11_image_exec_release", f"{prefix}/p11_image_mmap_release"})
    for prefix in ("detailed", "detailed-gate1", "journal-gate1")
] + [
    frozenset({f"{prefix}/p11_inst_vma_copy", f"{prefix}/p11_inst_vma_retcopy"})
    for prefix in ("detailed", "detailed-gate1", "journal-gate1")
] + [
    # The witness departure family (src/attach/prearm_witness.rs):
    # Linux 6.6-7.2 loads the exit/exec pair, 7.3+ the single rename,
    # exclusive by construction. Two overlapping pairs sharing the
    # single, so each pair keeps the one-member-per-kernel shape.
    frozenset({"prearm-witness/p11_pw_depart_exit", "prearm-witness/p11_pw_depart"}),
    frozenset({"prearm-witness/p11_pw_depart_exec", "prearm-witness/p11_pw_depart"}),
]
# Counter objects load only where the verifier accepts them (6.6+); the
# old kernels keep the specified refusal, so the counter file pins its
# own kernel set. Each counter object loads 15 programs (the 13 defaults
# plus the 2 bank roots, including the sched lifecycle pair that every
# counter profile run loads); the probe file's 16th load is the lone
# Detailed return, which BTF grouping ignores when scoring counter
# modes. Every loaded counter program has a cell for each 6.6+ kernel
# and nothing else.
EXPECTED_COUNTER_BUDGET_KERNELS = frozenset({
    "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14", "v7.3.1", "v7.4-rc1",
})
_COUNTER_MODES = ("counts", "timestamps", "latency")
_COUNTER_ROOTS = (
    "dl_debug_state", "function_list_entry", "function_list_return",
    "interface_entry", "interface_list_entry", "interface_list_return",
    "interface_list_worker", "interface_return",
    "p11_counter_bank_entry", "p11_counter_bank_return",
    "p11_entry", "p11_return",
    "sched_process_exec", "sched_process_exit", "task_newtask",
)
EXPECTED_COUNTER_BUDGET_PROGRAMS = frozenset(
    f"counter-{mode}/{root}"
    for mode in _COUNTER_MODES for root in _COUNTER_ROOTS
)


def budgets_files():
    """Every checked-in verifier-budgets file the caps apply to."""
    files = sorted(ROOT.glob("tests/*budgets*.json"))
    assert BUDGETS_FILE in files, (
        f"{BUDGETS_FILE.name} is missing from {sorted(path.name for path in files)}")
    return files


def check_budgets_shape(path):
    """Every namespace pins its own kernel set; a missing cell fails.

    Each budget-key namespace (prefix before "/") carries one kernel
    set for its non-variant programs, compared against that
    namespace's pinned set. Variant-group members are the exception:
    each kernel budgets exactly one member of each group, so a group
    member carries a strict subset and the members partition their
    namespace's kernel set. The report's budgeted-but-missing FAIL
    only fires for roots carrying a cell for the requested kernel, so
    a root silently dropped from one kernel's column would pass with
    no rows at all. This pin fails such a file, including a dropped
    namespace. Raises AssertionError naming the mismatch.
    """
    document = json.loads(Path(path).read_text(encoding="ascii"))
    programs = document["programs"]
    assert programs, "budgets file names no programs"
    observed = {name.split("/", 1)[0] if "/" in name else ""
              for name in programs}
    assert observed == set(EXPECTED_BUDGET_KERNELS_BY_NAMESPACE), (
        f"budget namespaces {sorted(observed)} differ from "
        f"{sorted(EXPECTED_BUDGET_KERNELS_BY_NAMESPACE)}")
    grouped = set().union(*EXCLUSIVE_VARIANT_GROUPS)
    by_namespace = {}
    for name, cells in programs.items():
        if name in grouped:
            continue
        namespace = name.split("/", 1)[0]
        by_namespace.setdefault(namespace, {})[name] = frozenset(cells)
    for namespace in sorted(by_namespace):
        expected = EXPECTED_BUDGET_KERNELS_BY_NAMESPACE[namespace]
        kernel_sets = by_namespace[namespace]
        first, *rest = sorted(kernel_sets)
        for name in rest:
            assert kernel_sets[name] == kernel_sets[first], (
                f"{name} kernels {sorted(kernel_sets[name])} differ from "
                f"{first} {sorted(kernel_sets[first])}")
        assert kernel_sets[first] == expected, (
            f"{namespace} budget kernels {sorted(kernel_sets[first])} "
            f"differ from {sorted(expected)}")
    for group in EXCLUSIVE_VARIANT_GROUPS:
        for member in sorted(group):
            assert member in programs, (
                f"variant group {sorted(group)} is missing {member}")
        namespaces = {member.split("/", 1)[0] for member in group}
        assert len(namespaces) == 1, (
            f"variant group {sorted(group)} spans namespaces "
            f"{sorted(namespaces)}")
        expected = EXPECTED_BUDGET_KERNELS_BY_NAMESPACE[next(iter(namespaces))]
        covered = {}
        for member in sorted(group):
            for kernel in programs[member]:
                assert kernel not in covered, (
                    f"{kernel} budgets two members of {sorted(group)}")
                covered[kernel] = member
        assert set(covered) == expected, (
            f"variant group {sorted(group)} covers {sorted(covered)}, "
            f"expected {sorted(expected)}")


def check_budgets_cap(path):
    """Every budget cell is a positive int within the file's own headroom cap.

    Budgets are defined as measured-plus-margin capped at 95% of the
    limit, but the gate checks measured headroom, not budget headroom,
    so an over-cap cell would pass everywhere. This pin fails such a
    file. The cap is limit x (1 - min_headroom_percent/100) read from
    the same file, compared with exact integer arithmetic. Raises
    AssertionError naming the offending cell.
    """
    document = json.loads(Path(path).read_text(encoding="ascii"))
    limit = document["limit"]
    headroom = document["min_headroom_percent"]
    assert isinstance(limit, int) and not isinstance(limit, bool) and limit > 0, (
        f"limit {limit!r} is not a positive int")
    assert (isinstance(headroom, int) and not isinstance(headroom, bool)
            and 0 <= headroom < 100), (
        f"min_headroom_percent {headroom!r} is not a percent")
    ceiling = limit * (100 - headroom)
    for program in sorted(document["programs"]):
        for kernel in sorted(document["programs"][program]):
            budget = document["programs"][program][kernel]
            assert isinstance(budget, int) and not isinstance(budget, bool), (
                f"{program} {kernel}: budget {budget!r} is not an int")
            assert budget > 0, (
                f"{program} {kernel}: budget {budget} is not positive")
            assert budget * 100 <= ceiling, (
                f"{program} {kernel}: budget {budget} exceeds "
                f"limit {limit} x (1 - {headroom}/100)")


def check_counter_budgets_shape(path):
    """Counter banks pin their own kernel set and the six bank programs."""
    document = json.loads(Path(path).read_text(encoding="ascii"))
    programs = document["programs"]
    assert set(programs) == EXPECTED_COUNTER_BUDGET_PROGRAMS, (
        f"counter programs {sorted(programs)} differ from "
        f"{sorted(EXPECTED_COUNTER_BUDGET_PROGRAMS)}")
    kernel_sets = {name: frozenset(cells) for name, cells in programs.items()}
    first, *rest = sorted(kernel_sets)
    for name in rest:
        assert kernel_sets[name] == kernel_sets[first], (
            f"{name} kernels {sorted(kernel_sets[name])} differ from "
            f"{first} {sorted(kernel_sets[first])}")
    assert kernel_sets[first] == EXPECTED_COUNTER_BUDGET_KERNELS, (
        f"counter budget kernels {sorted(kernel_sets[first])} differ from "
        f"{sorted(EXPECTED_COUNTER_BUDGET_KERNELS)}")

next_program_id = 100


def load_row(root, *, loaded=True, errno=0, stats_present=True,
             processed=1000, limit=1000000, auxiliary=None, pid=111,
             btf_id=77):
    global next_program_id
    next_program_id += 1
    return {
        "record": "load", "pid": pid, "root": root,
        "btf_resolved": auxiliary is None and root != "unresolved",
        "btf_fd": 4, "btf_id": btf_id, "returned_btf_id": btf_id,
        "root_type_id": 1,
        "returned_fd": 5 if loaded else -1,
        "program_id": next_program_id if loaded else 0,
        "program_type": 2, "returned_program_type": 2 if loaded else 0,
        "program_flags": 0, "expected_attach_type": 0,
        "insn_count": 100, "relocated_fnv1a64": "123456789abcdef0",
        "loaded": loaded, "errno": errno, "stats_present": stats_present,
        "processed": processed, "limit": limit, "auxiliary": auxiliary,
    }


def summary_row(records, *, pid=111, write_failures=0, overflow=False):
    return {"record": "probe-summary", "pid": pid, "records": records,
            "write_failures": write_failures, "overflow": overflow}


def aux_row(kind="aya-helper113", *, loaded=False, errno=13, pid=111):
    return load_row("unresolved", loaded=loaded, errno=errno, processed=1,
                    auxiliary={"kind": kind, "name": "", "template_fnv1a64": "0" * 16,
                               "map": None},
                    pid=pid)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "scripts/bpf-load-report.py is missing")
        self.temporary = tempfile.TemporaryDirectory(prefix="bpf-load-report-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write_jsonl(self, name, rows):
        path = self.root / name
        with path.open("w", encoding="ascii") as stream:
            for row in rows:
                stream.write(json.dumps(row) + "\n")
        return path

    def write_loads(self, name, loads, **summary_kwargs):
        return self.write_jsonl(name, [*loads, summary_row(len(loads), **summary_kwargs)])

    def write_budgets(self, programs, **kwargs):
        path = self.root / "budgets.json"
        document = {"limit": 1000000, "min_headroom_percent": 5,
                    "programs": programs, **kwargs}
        path.write_text(json.dumps(document), encoding="ascii")
        return path

    def run_report(self, *jsonl, budgets=None, object_name=None,
                   kernel=KERNEL):
        command = [sys.executable, "-I", str(SCRIPT), "--kernel", kernel,
                   "--observer-sha256", OBSERVER]
        if budgets is not None:
            command += ["--budgets", str(budgets)]
        if object_name is not None:
            command += ["--object", object_name]
        command += [str(path) for path in jsonl]
        return subprocess.run(command, capture_output=True, text=True, timeout=30)

    def test_everything_under_budget_passes(self):
        loads = [load_row("p11_entry", processed=472892),
                 load_row("p11_return", processed=640280)]
        budgets = self.write_budgets({"p11_entry": {KERNEL: 800000},
                                      "p11_return": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("p11_entry", result.stdout)
        self.assertIn("472892", result.stdout)
        self.assertIn("640280", result.stdout)

    def test_refused_root_fails_and_names_it(self):
        loads = [load_row("p11_entry", processed=472892),
                 load_row("p11_return", loaded=False, errno=7,
                          stats_present=False, processed=0)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("p11_return", result.stdout)
        self.assertIn("FAIL", result.stdout)
        self.assertIn("refused errno=7", result.stdout)
        # The passing root is still printed with its count.
        self.assertIn("472892", result.stdout)

    def test_root_over_budget_fails_with_both_numbers(self):
        loads = [load_row("p11_return", processed=640280)]
        budgets = self.write_budgets({"p11_return": {KERNEL: 600000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("p11_return", result.stdout)
        self.assertIn("640280", result.stdout)
        self.assertIn("600000", result.stdout)

    def test_budgeted_but_missing_root_fails(self):
        loads = [load_row("p11_entry", processed=472892)]
        budgets = self.write_budgets({"p11_entry": {KERNEL: 800000},
                                      "p11_return": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("p11_return", result.stdout)
        self.assertIn("result=FAIL", result.stdout)

    def test_variant_group_missing_other_member_passes(self):
        loads = [load_row("p11_inst_vma_retcopy", processed=2500)]
        budgets = self.write_budgets({"p11_inst_vma_retcopy": {KERNEL: 3000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)

    def test_variant_group_both_variants_measured_fails(self):
        loads = [load_row("p11_inst_vma_copy", processed=2500),
                 load_row("p11_inst_vma_retcopy", processed=2500)]
        budgets = self.write_budgets({"p11_inst_vma_copy": {KERNEL: 3000},
                                      "p11_inst_vma_retcopy": {KERNEL: 3000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("both variants loaded", result.stdout)

    def test_variant_group_both_variants_measured_fails_namespaced(self):
        loads = [load_row("p11_image_exec_release", processed=400),
                 load_row("p11_image_mmap_release", processed=400)]
        budgets = self.write_budgets({"detailed/p11_image_exec_release": {KERNEL: 500},
                                      "detailed/p11_image_mmap_release": {KERNEL: 500}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("both variants loaded", result.stdout)

    def test_variant_group_members_are_detailed_unique_roots(self):
        # Either member must assign its BTF group to the Detailed object;
        # an unknown root fails the whole gate on that kernel.
        text = SCRIPT.read_text(encoding="ascii")
        block = text[text.index("DETAILED_UNIQUE_ROOTS"):
                     text.index("KNOWN_ROOTS")]
        for member in ["p11_image_exec_release", "p11_image_mmap_release",
                       "p11_inst_vma_copy", "p11_inst_vma_retcopy"]:
            self.assertIn(f'"{member}"', block)

    def test_low_headroom_fails_even_under_budget(self):
        loads = [load_row("p11_return", processed=960000)]
        budgets = self.write_budgets({"p11_return": {KERNEL: 970000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("p11_return", result.stdout)

    def test_low_headroom_fails_without_budgets(self):
        loads = [load_row("p11_return", processed=960000)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("p11_return", result.stdout)

    def test_empty_file_fails(self):
        result = self.run_report(self.write_jsonl("empty.jsonl", []))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)

    def test_auxiliary_rows_are_ignored(self):
        loads = [aux_row(), aux_row("aya-name", loaded=True, errno=0),
                 load_row("p11_entry", processed=472892)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("result=PASS", result.stdout)
        self.assertNotIn("unresolved", result.stdout)

    def test_repeated_root_keeps_largest_count(self):
        loads = [load_row("p11_return", processed=640280),
                 load_row("p11_return", processed=640281)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("640281", result.stdout)
        self.assertNotIn("640280", result.stdout)

    def test_missing_stats_fail_and_name_the_kernel(self):
        loads = [load_row("p11_entry", stats_present=False, processed=0)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(KERNEL, result.stdout)
        self.assertIn("p11_entry", result.stdout)

    def test_short_summary_fails(self):
        loads = [load_row("p11_entry", processed=472892)]
        path = self.write_jsonl("short.jsonl", [*loads, summary_row(0)])
        result = self.run_report(path)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)

    def test_probe_error_record_fails(self):
        loads = [load_row("p11_entry", processed=472892),
                 {"record": "probe-error", "reason": "record-bound"}]
        path = self.write_jsonl("error.jsonl", [*loads, summary_row(len(loads))])
        result = self.run_report(path)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)

    def test_unresolved_success_is_ignored_but_unresolved_failure_fails(self):
        ignored = [dict(load_row("unresolved", processed=2)),
                   load_row("p11_entry", processed=472892)]
        result = self.run_report(self.write_loads("ok.jsonl", ignored))
        self.assertEqual(result.returncode, 0, result.stderr)
        failed = [dict(load_row("unresolved", loaded=False, errno=7,
                                stats_present=False, processed=0)),
                  load_row("p11_entry", processed=472892)]
        result = self.run_report(self.write_loads("bad.jsonl", failed))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("unresolved", result.stdout)

    def test_observed_root_without_budget_fails(self):
        loads = [load_row("p11_entry", processed=472892),
                 load_row("p11_return", processed=640280)]
        budgets = self.write_budgets({"p11_entry": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads), budgets=budgets)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("p11_return", result.stdout)

    def test_missing_input_fails_without_traceback(self):
        result = self.run_report(self.root / "absent.jsonl")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("result=FAIL", result.stdout)

    def test_budgets_file_gives_every_program_the_same_kernel_set(self):
        self.assertTrue(BUDGETS_FILE.is_file(),
                        "tests/bpf-verifier-budgets.json is missing")
        try:
            check_budgets_shape(BUDGETS_FILE)
        except AssertionError as error:
            self.fail(str(error))

    def test_budgets_cells_respect_the_headroom_cap(self):
        try:
            files = budgets_files()
        except AssertionError as error:
            self.fail(str(error))
        for path in files:
            try:
                check_budgets_cap(path)
            except AssertionError as error:
                self.fail(f"{path.name}: {error}")

    def test_counter_budgets_file_gives_every_program_the_same_kernel_set(self):
        self.assertTrue(COUNTER_BUDGETS_FILE.is_file(),
                        "tests/counter-bpf-verifier-budgets.json is missing")
        try:
            check_counter_budgets_shape(COUNTER_BUDGETS_FILE)
        except AssertionError as error:
            self.fail(str(error))

    def test_object_namespaces_budget_lookup(self):
        loads = [load_row("p11_entry", processed=472892)]
        budgets = self.write_budgets({"detailed/p11_entry": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("detailed/p11_entry", result.stdout)

    def test_object_scopes_missing_check_to_that_object(self):
        loads = [load_row("p11_entry", processed=472892)]
        budgets = self.write_budgets({"detailed/p11_entry": {KERNEL: 800000},
                                      "inventory/p11_return": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="inventory")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("inventory/p11_return", result.stdout)

    def test_object_distinguishes_shared_program_names(self):
        loads = [load_row("interface_return", processed=900)]
        budgets = self.write_budgets({"detailed/interface_return": {KERNEL: 1000},
                                      "inventory/interface_return": {KERNEL: 500}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="inventory")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("900", result.stdout)
        self.assertIn("500", result.stdout)

    def test_object_requires_namespaced_budget_keys(self):
        loads = [load_row("p11_entry", processed=472892)]
        budgets = self.write_budgets({"p11_entry": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("detailed/p11_entry", result.stdout)
        self.assertIn("no budget", result.stdout)

    def test_detailed_gate1_selects_detailed_groups(self):
        # The gate-1 Detailed object carries the same unique roots, so
        # --object detailed-gate1 scores exactly the Detailed BTF
        # groups; only the budget-key prefix differs.
        loads = self.mixed_doctor_loads()
        budgets = self.write_budgets({
            "detailed-gate1/p11_image_query": {KERNEL: 512},
            "detailed-gate1/interface_entry": {KERNEL: 95853},
            "detailed-gate1/interface_return": {KERNEL: 863427},
            "detailed-gate1/interface_list_worker": {KERNEL: 606073},
        })
        result = self.run_report(self.write_loads("doctor.jsonl", loads),
                                 budgets=budgets,
                                 object_name="detailed-gate1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("detailed-gate1/interface_entry", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("84937", result.stdout)
        self.assertNotIn("p11_usage_entry", result.stdout)

    def test_detailed_gate1_missing_program_is_not_masked(self):
        # A Detailed program the gate-1 object stopped loading FAILs
        # missing under detailed-gate1/*, not silently covered by the
        # Inventory copy of the same root.
        loads = self.mixed_doctor_loads(drop_detailed_worker=True)
        budgets = self.write_budgets({
            "detailed-gate1/p11_image_query": {KERNEL: 512},
            "detailed-gate1/interface_entry": {KERNEL: 95853},
            "detailed-gate1/interface_return": {KERNEL: 863427},
            "detailed-gate1/interface_list_worker": {KERNEL: 606073},
        })
        result = self.run_report(self.write_loads("doctor.jsonl", loads),
                                 budgets=budgets,
                                 object_name="detailed-gate1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("detailed-gate1/interface_list_worker", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)

    def test_driver_anchors_guest_release_on_version_boundary(self):
        # The release check must accept the exact version or a `-`-suffixed
        # release only; a bare prefix also matches a different kernel
        # (6.1.1880 for 6.1.188). A release-candidate tag (v7.4-rc1) boots
        # the dotted triplet (7.4.0-070400rc1-generic) and must match only
        # its own rc number. Run the shared release_ok function.
        self.assertTrue(RELEASE_MATCH.is_file(),
                        "scripts/bpf-guest-release.sh is missing")
        match_text = RELEASE_MATCH.read_text(encoding="ascii")
        start = match_text.index("release_ok() {\n")
        end = match_text.index("\n}\n", start) + 3
        function = match_text[start:end]
        self.assertEqual(match_text.count("release_ok() {"), 1)
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        # The match lives in the shared file, never copied per driver.
        self.assertIn('. "$SCRIPT_DIR/bpf-guest-release.sh"', text)
        self.assertNotIn("release_ok() {", text)
        # The doctor, inventory, counter and witness guests all use it.
        self.assertEqual(text.count('if release_ok "$KERNEL" '), 4)
        cases = [
            ("v6.1.188", "6.1.188", True),
            ("v6.1.188", "6.1.188-0601188-generic", True),
            ("v6.1.188", "6.1.1880", False),
            ("v6.1.188", "6.1.1880-generic", False),
            ("v6.1.188", "6.1.18", False),
            ("v7.4-rc1", "7.4.0-070400rc1-generic", True),
            ("v7.4-rc1", "7.4.0-070400rc1", True),
            ("v7.4-rc1", "7.4.0-070400rc10-generic", False),
            ("v7.4-rc1", "7.4.0-070400rc2-generic", False),
            ("v7.4-rc1", "7.4.1-070401-generic", False),
            ("v7.4-rc1", "7.40.0-070400rc1-generic", False),
        ]
        for tag, release, expected in cases:
            result = subprocess.run(
                ["sh", "-c", function + 'release_ok "$1" "$2"', "sh", tag, release],
                capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, expected,
                             (tag, release, result.returncode, result.stderr))

    def test_gate1_and_journal_drivers_share_the_release_match(self):
        # The gate-1 and journal drivers boot the same kernel tags, so
        # a release-candidate guest (v7.4-rc1 boots 7.4.0-070400rc1-*)
        # must match there too, through the one shared release_ok, and
        # each driver's guest must use it. No driver keeps a local
        # copy: divergence is impossible by construction.
        shared = (ROOT / "scripts" / "bpf-guest-release.sh").read_text(encoding="ascii")
        self.assertEqual(shared.count("release_ok() {"), 1)
        for name in ("check-bpf-load-kernels.sh", "check-bpf-load-gate1.sh",
                     "check-bpf-load-journal.sh"):
            other = (ROOT / "scripts" / name).read_text(encoding="ascii")
            with self.subTest(driver=name):
                self.assertIn('. "$SCRIPT_DIR/bpf-guest-release.sh"', other)
                self.assertNotIn("release_ok() {", other)
                self.assertGreaterEqual(
                    other.count('if release_ok "$KERNEL" "$GUEST_RELEASE"; then'), 1)
                self.assertNotIn('"${KERNEL#v}"|"${KERNEL#v}-"*)', other)

    def test_driver_scores_inventory_side_against_budgets(self):
        # The 72 inventory budget cells exist (pinned by the budgets-shape
        # test above); the driver must pass them on the inventory side so
        # an inventory regression fails the gate. Real guest runs prove
        # the scoring; this pins the wiring against revert.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn('--budgets "$BUDGETS" --object inventory', text)

    def test_driver_scores_witness_side_against_budgets(self):
        # The prearm-witness budget cells exist (pinned by the
        # budgets-shape test above); the driver must pass them on the
        # witness side so a witness regression fails the gate. Real
        # guest runs prove the scoring; this pins the wiring against
        # revert.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn('--budgets "$BUDGETS" --object prearm-witness', text)

    def bpf_loop_probe_row(self, errno):
        # The controller-allowlisted functional probe shape: `call 181;
        # exit`, kprobe type, refused (5.15 EINVAL, 6.1 and later EACCES).
        row = load_row("unresolved", loaded=False, errno=errno,
                       stats_present=False, processed=0)
        row.update({"program_type": 2, "insn_count": 2,
                    "relocated_fnv1a64": EXPECTED_BPF_LOOP_PROBE_FNV})
        return row

    def test_expected_bpf_loop_probe_refusal_passes(self):
        # The probe errno is tied to the kernel: EINVAL (22) only on
        # v5.15.*, EACCES (13) everywhere else. Each passes on its own
        # kernel.
        for kernel, errno in (("v5.15.221", 22), (KERNEL, 13)):
            loads = [self.bpf_loop_probe_row(errno),
                     load_row("p11_entry", processed=472892)]
            result = self.run_report(self.write_loads("probe.jsonl", loads),
                                     kernel=kernel)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("result=PASS", result.stdout)
            self.assertIn("EXPECTED", result.stdout)
            self.assertIn("expected bpf_loop probe refusal", result.stdout)
            self.assertIn(f"errno={errno}", result.stdout)

    def test_bpf_loop_probe_errno_on_the_wrong_kernel_still_fails(self):
        # EINVAL on 6.1+ (helper 181 exists there) and EACCES on 5.15
        # (helper 181 is unknown there) are not the expected probe
        # refusals; each fails like any other refused load.
        for kernel, errno in (("v5.15.221", 13), (KERNEL, 22)):
            loads = [self.bpf_loop_probe_row(errno),
                     load_row("p11_entry", processed=472892)]
            result = self.run_report(self.write_loads("probe.jsonl", loads),
                                     kernel=kernel)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("result=FAIL", result.stdout)
            self.assertIn("unresolved", result.stdout)
            self.assertNotIn("EXPECTED", result.stdout)

    def test_expected_bpf_loop_probe_refusal_passes_namespaced(self):
        loads = [self.bpf_loop_probe_row(13),
                 load_row("p11_entry", processed=472892)]
        budgets = self.write_budgets({"detailed/p11_entry": {KERNEL: 800000}})
        result = self.run_report(self.write_loads("probe.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("detailed/unresolved", result.stdout)
        self.assertIn("EXPECTED", result.stdout)

    def test_nearby_unresolved_refusals_still_fail(self):
        # The allowlist is exact: any drift in fingerprint, program type,
        # instruction count, or errno fails like any other refused load.
        # The base uses the 5.15 kernel with its EINVAL probe, so every
        # errno variant (including EACCES and the log-exhaustion ENOSPC
        # plus ENOMEM/EFAULT) fails there; the kernel-tie test above
        # covers the 6.1 side.
        base = self.bpf_loop_probe_row(22)
        variants = []
        for key, value in (("relocated_fnv1a64", "27ef27a73ecc6271"),
                           ("relocated_fnv1a64", "0" * 16),
                           ("program_type", 5),
                           ("insn_count", 3),
                           ("errno", 7),
                           ("errno", 1),
                           ("errno", 13),
                           ("errno", 28),
                           ("errno", 12),
                           ("errno", 14)):
            variant = dict(base)
            variant[key] = value
            variants.append(variant)
        for variant in variants:
            loads = [variant, load_row("p11_entry", processed=472892)]
            result = self.run_report(self.write_loads("probe.jsonl", loads),
                                     kernel="v5.15.221")
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("result=FAIL", result.stdout)
            self.assertIn("unresolved", result.stdout)
            self.assertNotIn("EXPECTED", result.stdout)

    def test_probe_shaped_refusal_under_a_real_root_still_fails(self):
        # The allowlist binds the probe shape to root "unresolved": the
        # same refused shape under a real root fails like any other
        # refused load instead of hiding as EXPECTED. The healthy
        # companion uses another root so the refused group holds the
        # probe shape alone. Uses the 6.1 kernel's EACCES errno so the
        # root alone decides.
        variant = self.bpf_loop_probe_row(13)
        variant["root"] = "p11_entry"
        loads = [variant, load_row("p11_return", processed=472892)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("p11_entry", result.stdout)
        self.assertNotIn("EXPECTED", result.stdout)

    def test_probe_plus_foreign_unresolved_refusal_still_fails(self):
        # The allowlist quantifier is all(): a group holding the probe
        # plus a foreign BTF-less refused load must FAIL, not hide the
        # foreign refusal behind the probe. Kills the all->any mutant.
        probe = self.bpf_loop_probe_row(13)
        foreign = self.bpf_loop_probe_row(1)
        foreign["relocated_fnv1a64"] = "0" * 16
        loads = [probe, foreign, load_row("p11_entry", processed=472892)]
        result = self.run_report(self.write_loads("probe.jsonl", loads))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("unresolved", result.stdout)
        self.assertNotIn("EXPECTED", result.stdout)

    def test_probe_fingerprint_matches_the_attached_source_bytes(self):
        # The allowlisted fingerprint is the FNV-1a 64 of the exact
        # BPF_LOOP_PROBE_INSNS bytes in src/attach.rs, not a magic string:
        # recompute it from the source literal and require the report
        # script to carry the same value.
        source = (ROOT / "src" / "attach.rs").read_text(encoding="utf-8")
        match = re.search(
            r"BPF_LOOP_PROBE_INSNS[^=]*=\s*\[(.*?)\];", source, re.S)
        self.assertIsNotNone(match, "BPF_LOOP_PROBE_INSNS literal not found")
        raw = bytes(int(byte, 16)
                    for byte in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
        self.assertEqual(len(raw), 16, "probe is two instructions")
        value = 14695981039346656037
        for byte in raw:
            value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
        script = SCRIPT.read_text(encoding="ascii")
        match = re.search(
            r"BPF_LOOP_PROBE_FNV1A64\s*=\s*\"([0-9a-f]{16})\"", script)
        self.assertIsNotNone(
            match, "report script carries no BPF_LOOP_PROBE_FNV1A64 pin")
        self.assertEqual(match.group(1), f"{value:016x}")
        self.assertEqual(match.group(1), EXPECTED_BPF_LOOP_PROBE_FNV)

    def test_driver_runs_one_counter_command_per_mode(self):
        # Per-mode guests: probe rows key programs by root name only while
        # all three bank objects export the same two roots, so one combined
        # run would collide in by_root. Real guest runs prove the loads;
        # this pins the per-mode command and probe file against revert.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn("profile --system --mode metrics --attach-backend multi --counter-mode", text)
        self.assertIn("counter-$MODE-probe-", text)

    def test_driver_scores_counter_loads_per_object(self):
        # Each mode's probe file is scored under its own object name, so
        # the shared root names never mix counts across modes.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn('--object "counter-$MODE"', text)

    def test_positive_driver_never_counts_old_refusals_as_loads(self):
        text = DRIVER.read_text(encoding="ascii")
        self.assertNotIn("v5.15.*|v6.1.*)", text)
        self.assertNotIn("counter-mode-unavailable-on-kernel", text)
        self.assertIn("check-multi-host-refusal.py", text)

    def test_driver_comment_no_longer_calls_counter_mode_unwired(self):
        # Activation wired --counter-mode; the comment must describe the
        # post-activation gate (per-mode probe files) instead.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertNotIn("unwired", text)
        self.assertIn("counter-<mode>-probe-", text)

    def test_driver_scores_counter_loads_with_budgets(self):
        # Numeric bank budgets close the missing-program and growth gaps:
        # each mode scores against its counter object under the counter
        # budgets file, so a silent drop or a sub-95% cost doubling fails.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn("COUNTER_BUDGETS", text)
        self.assertIn("counter-bpf-verifier-budgets.json", text)
        self.assertIn('--budgets "$COUNTER_BUDGETS"', text)
        self.assertIn('--object "counter-$MODE"', text)

    def test_combined_refusal_control_uses_host_eligibility_reason(self):
        text = (ROOT / "scripts/check-multi-host-refusal.py").read_text()
        for lead in ("live capture needs CAP_",
                     "live capture refused: ",
                     "live capture unavailable: ",
                     "live capture did not start: "):
            self.assertIn(lead, text)
        self.assertIn('"capture_positive": False', text)

    def test_counter_positive_loads_force_multi(self):
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn("--attach-backend multi --counter-mode $MODE", text)

    def e2big_program_via_driver_pipeline(self, probe_path):
        # Historical 6.1 at-load extraction, retained as a cheap errno twin
        # proves the grep logic distinguishes a real E2BIG counter row
        # from auxiliary-only refused rows. This historical classifier does
        # not create a current old-kernel positive obligation.
        pipeline = (
            f"grep -E '\"loaded\": ?false' {probe_path} "
            f"| grep -E '\"auxiliary\": ?null' "
            f"| grep -v -E '\"root\": ?\"unresolved\"' "
            f"| grep -E '\"errno\": ?7([^0-9]|$)' "
            f"| sed -n 's/.*\"root\": *\"\\([^\"]*\\)\".*/\\1/p' "
            f"| sort -u | head -n 1"
        )
        result = subprocess.run(
            pipeline, shell=True, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_61_e2big_extraction_names_the_counter_program(self):
        # Positive: auxiliary refused rows plus the bpf_loop probe plus
        # a real E2BIG counter row yield the counter program name.
        aux = aux_row("aya-helper113", loaded=False, errno=13)
        probe = self.bpf_loop_probe_row(13)
        refused = load_row("function_list_return", loaded=False, errno=7,
                           stats_present=True, processed=1000001,
                           btf_id=41)
        path = self.write_loads("probe-61.jsonl", [aux, probe, refused])
        self.assertEqual(
            self.e2big_program_via_driver_pipeline(path),
            "function_list_return")

    def test_61_e2big_extraction_with_only_auxiliary_rows_finds_nothing(self):
        # Twin: auxiliary probes alone do not prove a historical E2BIG
        # counter-program refusal.
        aux = aux_row("aya-helper113", loaded=False, errno=13)
        probe = self.bpf_loop_probe_row(13)
        loaded = load_row("p11_return", processed=645449, btf_id=40)
        path = self.write_loads("probe-aux-only.jsonl",
                                [aux, probe, loaded])
        self.assertEqual(
            self.e2big_program_via_driver_pipeline(path), "")

    def test_61_e2big_extraction_ignores_errno_70(self):
        # Twin: a named counter row refused with errno 70 is not E2BIG;
        # the digit is anchored, so the extraction yields nothing.
        aux = aux_row("aya-helper113", loaded=False, errno=13)
        probe = self.bpf_loop_probe_row(13)
        refused = load_row("function_list_return", loaded=False, errno=70,
                           stats_present=True, processed=1000001,
                           btf_id=41)
        path = self.write_loads("probe-errno70.jsonl",
                                [aux, probe, refused])
        self.assertEqual(
            self.e2big_program_via_driver_pipeline(path), "")

    def test_positive_counter_and_inventory_runs_check_for_crashes(self):
        text = DRIVER.read_text(encoding="ascii")
        self.assertGreaterEqual(text.count("panicked at|traceback"), 2)

    def test_refusal_control_is_not_a_verifier_cost_measurement(self):
        text = (ROOT / "scripts/check-multi-host-refusal.py").read_text()
        self.assertNotIn("LD_PRELOAD", text)
        self.assertNotIn("counter-mode-unavailable-on-kernel", text)

    def test_driver_never_quotes_doctor_counter_modes_footer(self):
        # Under the LD_PRELOAD probe the counter-modes footer is a gate
        # artifact (the probe rewrites log_level, breaking bpf_loop
        # detection), never product behaviour. The gate checks only the
        # host program preflight line in doctor output; the footer prefix
        # must not appear anywhere in the driver.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertNotIn("counter modes:", text)
        self.assertIn("never scores or quotes that footer", text)

    def test_driver_scores_counter_on_failure(self):
        # A failed 6.6+ counter run still falls through to per-program
        # scoring like inventory does, instead of `continue` past the
        # detail exactly when it is needed.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        rc_idx = text.index("counter-$MODE profile exited rc=")
        rc_case = text[rc_idx:text.index("esac", rc_idx)]
        self.assertIn("FAILED=1", rc_case)
        self.assertNotIn("continue", rc_case)
        crash_idx = text.index("counter-$MODE profile crashed or left no log")
        crash_end = text.index("\n        fi", crash_idx)
        crash_block = text[crash_idx:crash_end]
        self.assertIn("FAILED=1", crash_block)
        self.assertNotIn("continue", crash_block)

    def mixed_doctor_loads(self, *, drop_detailed_worker=False):
        # One file holding Detailed rows (BTF 45, with a Detailed-only
        # root) and Inventory rows (BTF 48, with an Inventory-only root)
        # under different BTF ids, as doctor's probe file does now that
        # doctor loads both objects. The shared names carry different
        # counts per object so cross-object max mixing is visible.
        detailed = [
            load_row("p11_image_query", processed=445, btf_id=45),
            load_row("interface_entry", processed=83350, btf_id=45),
            load_row("interface_return", processed=750806, btf_id=45),
        ]
        if not drop_detailed_worker:
            detailed.append(
                load_row("interface_list_worker", processed=527020,
                         btf_id=45))
        inventory = [
            load_row("p11_usage_entry_lp64", processed=873, btf_id=48),
            load_row("interface_entry", processed=84937, btf_id=48),
            load_row("interface_return", processed=453148, btf_id=48),
            load_row("interface_list_worker", processed=404787, btf_id=48),
        ]
        return detailed + inventory

    def mixed_doctor_budgets(self):
        # Test-only budgets above the fixture counts (grouping, not the
        # real per-kernel pins, is under test here).
        return self.write_budgets({
            "detailed/p11_image_query": {KERNEL: 512},
            "detailed/interface_entry": {KERNEL: 95853},
            "detailed/interface_return": {KERNEL: 863427},
            "detailed/interface_list_worker": {KERNEL: 606073},
            "inventory/p11_usage_entry_lp64": {KERNEL: 1025},
            "inventory/interface_entry": {KERNEL: 97386},
            "inventory/interface_return": {KERNEL: 520000},
            "inventory/interface_list_worker": {KERNEL: 465000},
        })

    def test_mixed_doctor_file_scores_each_object_correctly(self):
        # Doctor loads Detailed and Inventory in one probed process; the
        # scorer must group by BTF id and score each object from its own
        # rows only. Detailed keeps its own counts (not the Inventory
        # max), Inventory keeps its own, and neither side fails on the
        # other's unique roots.
        loads = self.mixed_doctor_loads()
        budgets = self.mixed_doctor_budgets()
        result = self.run_report(self.write_loads("doctor.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("detailed/interface_entry", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("84937", result.stdout)
        self.assertNotIn("p11_usage_entry", result.stdout)
        result = self.run_report(self.write_loads("doctor.jsonl", loads),
                                 budgets=budgets, object_name="inventory")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("inventory/interface_entry", result.stdout)
        self.assertIn("84937", result.stdout)
        self.assertNotIn("83350", result.stdout)
        self.assertNotIn("p11_image_query", result.stdout)

    def test_missing_detailed_program_is_not_masked_by_inventory_copy(self):
        # Detailed stopped loading interface_list_worker but Inventory
        # still carries it: scoring as detailed must FAIL missing, not
        # silently use the Inventory count.
        loads = self.mixed_doctor_loads(drop_detailed_worker=True)
        budgets = self.mixed_doctor_budgets()
        result = self.run_report(self.write_loads("doctor.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("detailed/interface_list_worker", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)

    def test_group_matching_two_objects_fails_by_btf_id(self):
        # A BTF group holding both Inventory-only and counter-only roots
        # matches two objects: it FAILs naming its BTF id, whichever
        # object is scored.
        loads = [
            load_row("p11_usage_entry_lp64", processed=873, btf_id=48),
            load_row("p11_counter_bank_entry", processed=4125, btf_id=48),
            load_row("p11_image_query", processed=445, btf_id=45),
        ]
        budgets = self.write_budgets({
            "detailed/p11_image_query": {KERNEL: 512},
        })
        result = self.run_report(self.write_loads("mixed.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("btf-48-ambiguous", result.stdout)
        self.assertIn("matches two objects", result.stdout)

    def test_group_matching_no_object_fails_by_btf_id(self):
        # A BTF group holding only a foreign root matches no object: it
        # FAILs naming its BTF id instead of silently passing.
        loads = [
            load_row("p11_image_query", processed=445, btf_id=45),
            load_row("p11_foreign_probe", processed=100, btf_id=49),
        ]
        budgets = self.write_budgets({
            "detailed/p11_image_query": {KERNEL: 512},
        })
        result = self.run_report(self.write_loads("mixed.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("btf-49-unknown", result.stdout)
        self.assertIn("matches no object", result.stdout)
        self.assertIn("p11_foreign_probe", result.stdout)

    def mixed_journal_loads(self):
        # One file holding journal rows (BTF 61, with the journal pair
        # plus a Detailed-only root the journal object also carries)
        # and Inventory rows (BTF 48) under different BTF ids, as the
        # linked inventory run's probe file does. The shared names
        # carry different counts per object so cross-object max mixing
        # is visible.
        journal = [
            load_row("p11_entry_journal", processed=99123, btf_id=61),
            load_row("p11_return_journal", processed=234567, btf_id=61),
            load_row("p11_image_query", processed=445, btf_id=61),
            load_row("interface_entry", processed=83350, btf_id=61),
            load_row("interface_return", processed=750806, btf_id=61),
        ]
        inventory = [
            load_row("p11_usage_entry_lp64", processed=873, btf_id=48),
            load_row("interface_entry", processed=84937, btf_id=48),
            load_row("interface_return", processed=453148, btf_id=48),
        ]
        return journal + inventory

    def mixed_journal_budgets(self):
        # Test-only budgets above the fixture counts (grouping, not the
        # real per-kernel pins, is under test here).
        return self.write_budgets({
            "journal/p11_entry_journal": {KERNEL: 120000},
            "journal/p11_return_journal": {KERNEL: 300000},
            "journal/p11_image_query": {KERNEL: 512},
            "journal/interface_entry": {KERNEL: 95853},
            "journal/interface_return": {KERNEL: 863427},
            "inventory/p11_usage_entry_lp64": {KERNEL: 1025},
            "inventory/interface_entry": {KERNEL: 97386},
            "inventory/interface_return": {KERNEL: 520000},
        })

    def test_mixed_journal_inventory_file_scores_journal_only(self):
        # The linked inventory run loads the journal object (semantic
        # lane) and the Inventory object (broad) in one probed
        # process; the scorer must group by BTF id and score the
        # journal object from its own rows only. The journal pair
        # identifies the group even though it also carries
        # Detailed-only roots (the journal object is a Detailed
        # object with the entry/return pair swapped).
        loads = self.mixed_journal_loads()
        budgets = self.mixed_journal_budgets()
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("journal/p11_entry_journal", result.stdout)
        self.assertIn("journal/p11_return_journal", result.stdout)
        self.assertIn("journal/interface_entry", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("84937", result.stdout)
        self.assertNotIn("p11_usage_entry", result.stdout)
        # The other direction separates too: Inventory keeps its own
        # counts and never sees the journal pair.
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="inventory")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("inventory/interface_entry", result.stdout)
        self.assertIn("84937", result.stdout)
        self.assertNotIn("83350", result.stdout)
        self.assertNotIn("p11_entry_journal", result.stdout)

    def test_journal_gate1_selects_journal_groups_only(self):
        # A gate-1 build gates the journal object too: --object
        # journal-gate1 scores exactly the journal BTF groups under
        # journal-gate1/ keys, never the Inventory copies, and a
        # journal/ key does not stand in for a missing gate-1 key.
        loads = self.mixed_journal_loads()
        budgets = self.write_budgets({
            "journal-gate1/p11_entry_journal": {KERNEL: 120000},
            "journal-gate1/p11_return_journal": {KERNEL: 300000},
            "journal-gate1/p11_image_query": {KERNEL: 512},
            "journal-gate1/interface_entry": {KERNEL: 95853},
            "journal-gate1/interface_return": {KERNEL: 863427},
        })
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal-gate1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("journal-gate1/p11_return_journal", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("84937", result.stdout)
        self.assertNotIn("p11_usage_entry", result.stdout)
        loads = [load for load in loads if load["root"] != "p11_return_journal"]
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal-gate1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("journal-gate1/p11_return_journal", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)

    def test_journal_group_does_not_supply_detailed_coverage(self):
        # The journal group carries p11_image_query, a Detailed-only
        # root, but it is a journal group, not a Detailed one:
        # scoring as detailed must FAIL missing instead of borrowing
        # the journal count.
        loads = self.mixed_journal_loads()
        budgets = self.write_budgets({
            "detailed/p11_image_query": {KERNEL: 512},
        })
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("detailed/p11_image_query", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)

    def test_journal_group_with_inventory_root_is_ambiguous(self):
        # A BTF group holding both the journal pair and an
        # Inventory-only root matches two objects: it FAILs naming
        # its BTF id, whichever object is scored.
        loads = [
            load_row("p11_entry_journal", processed=99123, btf_id=61),
            load_row("p11_usage_entry_lp64", processed=873, btf_id=61),
        ]
        budgets = self.write_budgets({
            "journal/p11_entry_journal": {KERNEL: 120000},
        })
        result = self.run_report(self.write_loads("mixed.jsonl", loads),
                                 budgets=budgets, object_name="journal")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("btf-61-ambiguous", result.stdout)
        self.assertIn("matches two objects", result.stdout)

    def test_journal_missing_root_fails(self):
        # The journal return root never loaded: scoring as journal
        # must FAIL missing, naming the budgeted row.
        loads = [load for load in self.mixed_journal_loads()
                 if load["root"] != "p11_return_journal"]
        budgets = self.mixed_journal_budgets()
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("journal/p11_return_journal", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)

    def test_journal_root_over_budget_fails_with_both_numbers(self):
        loads = [load_row("p11_entry_journal", processed=99123, btf_id=61),
                 load_row("p11_return_journal", processed=234567, btf_id=61)]
        budgets = self.write_budgets({
            "journal/p11_entry_journal": {KERNEL: 120000},
            "journal/p11_return_journal": {KERNEL: 200000}})
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("journal/p11_return_journal", result.stdout)
        self.assertIn("234567", result.stdout)
        self.assertIn("200000", result.stdout)

    def test_journal_low_headroom_fails_even_under_budget(self):
        loads = [load_row("p11_entry_journal", processed=960000, btf_id=61),
                 load_row("p11_return_journal", processed=1000, btf_id=61)]
        budgets = self.write_budgets({
            "journal/p11_entry_journal": {KERNEL: 970000},
            "journal/p11_return_journal": {KERNEL: 2000}})
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets, object_name="journal")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("journal/p11_entry_journal", result.stdout)

    def mixed_gate1_loads(self):
        # One file holding gate-1 Detailed rows (BTF 77, with a
        # Detailed-only root) and Inventory rows (BTF 48) under
        # different BTF ids, as a gate-1 doctor probe file does. The
        # shared names carry different counts per object so
        # cross-object max mixing is visible.
        detailed = [
            load_row("p11_image_query", processed=445, btf_id=77),
            load_row("interface_entry", processed=5606, btf_id=77),
            load_row("interface_return", processed=352188, btf_id=77),
        ]
        inventory = [
            load_row("p11_usage_entry_lp64", processed=873, btf_id=48),
            load_row("interface_entry", processed=84937, btf_id=48),
        ]
        return detailed + inventory

    def mixed_gate1_budgets(self):
        # Test-only budgets above the fixture counts (grouping, not
        # the real per-kernel pins, is under test here).
        return self.write_budgets({
            "detailed-gate1/p11_image_query": {KERNEL: 512},
            "detailed-gate1/interface_entry": {KERNEL: 6500},
            "detailed-gate1/interface_return": {KERNEL: 405017},
            "inventory/p11_usage_entry_lp64": {KERNEL: 1025},
            "inventory/interface_entry": {KERNEL: 97386},
        })

    def test_mixed_gate1_inventory_file_scores_gate1_only(self):
        # A gate-1 doctor run loads the gate-1 Detailed object and the
        # ordinary Inventory object in one probed process; the scorer
        # must group by BTF id and score the gate-1 object from its
        # own rows only, namespaced as detailed-gate1/.
        loads = self.mixed_gate1_loads()
        budgets = self.mixed_gate1_budgets()
        result = self.run_report(self.write_loads("gate1.jsonl", loads),
                                 budgets=budgets,
                                 object_name="detailed-gate1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("detailed-gate1/p11_image_query", result.stdout)
        self.assertIn("detailed-gate1/interface_entry", result.stdout)
        self.assertIn("5606", result.stdout)
        self.assertNotIn("84937", result.stdout)
        self.assertNotIn("p11_usage_entry", result.stdout)

    def test_gate1_missing_root_fails(self):
        # The Detailed-only root never loaded, leaving a shared-only
        # group: scoring as detailed-gate1 keeps that group's rows
        # (like detailed) but FAILs the budgeted root missing.
        loads = [load for load in self.mixed_gate1_loads()
                 if load["root"] != "p11_image_query"]
        budgets = self.mixed_gate1_budgets()
        result = self.run_report(self.write_loads("gate1.jsonl", loads),
                                 budgets=budgets,
                                 object_name="detailed-gate1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("detailed-gate1/p11_image_query", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)
        self.assertIn("detailed-gate1/interface_entry", result.stdout)
        self.assertIn("5606", result.stdout)

    def mixed_witness_loads(self):
        # A profile --cgroup /sys/fs/cgroup --prearm-module probe
        # file: the witness BTF group (old-kernel departure pair)
        # plus the Detailed group the profile run loads beside it.
        return [
            load_row("p11_pw_unmap", processed=3997, btf_id=61),
            load_row("p11_pw_depart_exit", processed=4028, btf_id=61),
            load_row("p11_pw_depart_exec", processed=4028, btf_id=61),
            load_row("p11_pw_torn", processed=92, btf_id=61),
            load_row("p11_pw_migrate", processed=3552, btf_id=61),
            load_row("p11_pw_walk", processed=3964, btf_id=61),
            load_row("interface_entry", processed=83350, btf_id=62),
            load_row("p11_image_query", processed=512, btf_id=62),
        ]

    def mixed_witness_budgets(self):
        return self.write_budgets({
            "prearm-witness/p11_pw_unmap": {KERNEL: 5000},
            "prearm-witness/p11_pw_depart_exit": {KERNEL: 5000},
            "prearm-witness/p11_pw_depart_exec": {KERNEL: 5000},
            "prearm-witness/p11_pw_torn": {KERNEL: 500},
            "prearm-witness/p11_pw_migrate": {KERNEL: 5000},
            "prearm-witness/p11_pw_walk": {KERNEL: 5000},
            "detailed/interface_entry": {KERNEL: 90000},
            "detailed/p11_image_query": {KERNEL: 600},
        })

    def test_mixed_witness_detailed_file_scores_witness_only(self):
        loads = self.mixed_witness_loads()
        budgets = self.mixed_witness_budgets()
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("prearm-witness/p11_pw_walk", result.stdout)
        self.assertIn("3964", result.stdout)
        self.assertNotIn("83350", result.stdout)
        self.assertNotIn("interface_entry", result.stdout)
        # The other direction separates too: Detailed keeps its own
        # counts and never sees the witness roots.
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="detailed")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("detailed/interface_entry", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("3964", result.stdout)
        self.assertNotIn("p11_pw_", result.stdout)

    def test_witness_missing_root_fails(self):
        loads = [load for load in self.mixed_witness_loads()
                 if load["root"] != "p11_pw_walk"]
        budgets = self.mixed_witness_budgets()
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("prearm-witness/p11_pw_walk", result.stdout)
        self.assertIn("missing from probe rows", result.stdout)
        # The group itself is recognized: only the dropped root is
        # missing, never the whole witness object as foreign.
        self.assertNotIn("matches no object", result.stdout)
        self.assertIn("prearm-witness/p11_pw_unmap", result.stdout)

    def test_witness_root_over_budget_fails_with_both_numbers(self):
        loads = [load_row("p11_pw_walk", processed=3964, btf_id=61),
                 load_row("p11_pw_unmap", processed=3997, btf_id=61)]
        budgets = self.write_budgets({
            "prearm-witness/p11_pw_walk": {KERNEL: 5000},
            "prearm-witness/p11_pw_unmap": {KERNEL: 3000}})
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("prearm-witness/p11_pw_unmap", result.stdout)
        self.assertIn("3997", result.stdout)
        self.assertIn("3000", result.stdout)

    def test_witness_group_with_detailed_root_is_ambiguous(self):
        # A BTF group holding both a witness root and a
        # Detailed-only root matches two objects: it FAILs naming
        # its BTF id, whichever object is scored.
        loads = [
            load_row("p11_pw_walk", processed=3964, btf_id=61),
            load_row("p11_image_query", processed=512, btf_id=61),
        ]
        budgets = self.write_budgets({
            "prearm-witness/p11_pw_walk": {KERNEL: 5000},
        })
        result = self.run_report(self.write_loads("mixed.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("btf-61-ambiguous", result.stdout)
        self.assertIn("matches two objects", result.stdout)

    def test_witness_depart_pair_loads_without_variant_conflict(self):
        # Old kernels load the exit/exec pair and no single: the two
        # overlapping pairs each see exactly one member, so no
        # both-variants failure fires.
        loads = self.mixed_witness_loads()
        budgets = self.mixed_witness_budgets()
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)

    def test_witness_depart_triple_loads_fail_both_variants(self):
        # The loader names one departure family per kernel
        # (exclusive by construction); a probe row set carrying the
        # pair plus the single is refused as an impossible load set.
        loads = self.mixed_witness_loads() + [
            load_row("p11_pw_depart", processed=4028, btf_id=61)]
        budgets = self.write_budgets({
            **{f"prearm-witness/{load['root']}": {KERNEL: 5000}
               for load in loads if load["root"].startswith("p11_pw_")},
        })
        result = self.run_report(self.write_loads("witness.jsonl", loads),
                                 budgets=budgets, object_name="prearm-witness")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("both variants loaded", result.stdout)

    def test_witness_variant_members_are_witness_unique_roots(self):
        # Every witness root must assign its BTF group to the witness
        # object; an unknown root fails the whole gate on that kernel.
        text = SCRIPT.read_text(encoding="ascii")
        block = text[text.index("WITNESS_UNIQUE_ROOTS"):
                     text.index("KNOWN_ROOTS")]
        for member in ["p11_pw_unmap", "p11_pw_depart_exit",
                       "p11_pw_depart_exec", "p11_pw_depart",
                       "p11_pw_torn", "p11_pw_migrate", "p11_pw_walk"]:
            self.assertIn(f'"{member}"', block)

    def mixed_identity_journal_loads(self):
        # The linked inventory probe file: the journal group plus the
        # two identity BTF groups the kernel session's probe-then-fresh
        # load leaves behind (anchor + target programs each time).
        return self.mixed_journal_loads() + [
            load_row("p11_anchor_vma", processed=22001, btf_id=63),
            load_row("p11_identity_vma", processed=15044, btf_id=63),
            load_row("p11_anchor_vma", processed=22001, btf_id=64),
            load_row("p11_identity_vma", processed=15044, btf_id=64),
        ]

    def test_mixed_identity_journal_gate1_scores_journal_only(self):
        # The identity groups are known and out of scope for the
        # journal gate: journal-gate1 keeps its own counts, and the
        # identity roots never read as foreign.
        loads = self.mixed_identity_journal_loads()
        budgets = self.write_budgets({
            "journal-gate1/p11_entry_journal": {KERNEL: 120000},
            "journal-gate1/p11_return_journal": {KERNEL: 300000},
            "journal-gate1/p11_image_query": {KERNEL: 512},
            "journal-gate1/interface_entry": {KERNEL: 95853},
            "journal-gate1/interface_return": {KERNEL: 863427},
        })
        result = self.run_report(self.write_loads("journal.jsonl", loads),
                                 budgets=budgets,
                                 object_name="journal-gate1")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("journal-gate1/p11_entry_journal", result.stdout)
        self.assertIn("83350", result.stdout)
        self.assertNotIn("matches no object", result.stdout)
        self.assertNotIn("p11_anchor_vma", result.stdout)
        self.assertNotIn("p11_identity_vma", result.stdout)

    def test_identity_object_scores_identity_only(self):
        loads = self.mixed_identity_journal_loads()
        budgets = self.write_budgets({
            "identity/p11_anchor_vma": {KERNEL: 30000},
            "identity/p11_identity_vma": {KERNEL: 30000},
        })
        result = self.run_report(self.write_loads("identity.jsonl", loads),
                                 budgets=budgets, object_name="identity")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("result=PASS", result.stdout)
        self.assertIn("identity/p11_anchor_vma", result.stdout)
        self.assertIn("22001", result.stdout)
        self.assertNotIn("83350", result.stdout)
        self.assertNotIn("p11_entry_journal", result.stdout)

    def test_identity_group_with_detailed_root_is_ambiguous(self):
        # A BTF group holding both an identity root and a
        # Detailed-only root matches two objects: it FAILs naming
        # its BTF id, whichever object is scored.
        loads = [
            load_row("p11_anchor_vma", processed=22001, btf_id=61),
            load_row("p11_image_query", processed=512, btf_id=61),
        ]
        budgets = self.write_budgets({
            "identity/p11_anchor_vma": {KERNEL: 30000},
        })
        result = self.run_report(self.write_loads("mixed.jsonl", loads),
                                 budgets=budgets, object_name="identity")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("result=FAIL", result.stdout)
        self.assertIn("btf-61-ambiguous", result.stdout)
        self.assertIn("matches two objects", result.stdout)

    def test_identity_members_are_identity_unique_roots(self):
        # Both identity roots must assign their BTF group to the
        # identity object; an unknown root fails the whole gate.
        text = SCRIPT.read_text(encoding="ascii")
        block = text[text.index("IDENTITY_UNIQUE_ROOTS"):
                     text.index("KNOWN_ROOTS")]
        for member in ["p11_anchor_vma", "p11_identity_vma"]:
            self.assertIn(f'"{member}"', block)


# The FNV-1a 64 of `call 181; exit` (BPF_LOOP_PROBE_INSNS), cross-checked
# against src/attach.rs by the fingerprint test above.
EXPECTED_BPF_LOOP_PROBE_FNV = "27ef27a73ecc6270"


class DriverHarnessTests(unittest.TestCase):
    """Run the real driver/helper/scorers with owned fake guest devices."""

    def setUp(self):
        # Fake guests share host paths: their owned workspace must satisfy
        # the guest's /var/tmp contract, regardless of CI's outer TMPDIR.
        self.temp = tempfile.TemporaryDirectory(prefix="bpf-driver-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.events = self.work / "events.jsonl"
        self.cache = self.work / "cache"
        config = self.cache / "virtme-ng/v7.0.14/amd64/boot/config-7.0.14-test"
        config.parent.mkdir(parents=True)
        config.write_text("owned test config\n")
        rows = {"doctor": [load_row("p11_image_query", processed=100)],
                "inventory": [load_row("p11_usage_entry_lp64", processed=100)],
                "profile": [load_row("p11_counter_bank_entry", processed=100)],
                "witness": [load_row("p11_pw_unmap", processed=3997),
                            load_row("p11_pw_depart_exit", processed=4028),
                            load_row("p11_pw_depart_exec", processed=4028),
                            load_row("p11_pw_torn", processed=92),
                            load_row("p11_pw_migrate", processed=3552),
                            load_row("p11_pw_walk", processed=3964)]}
        (self.work / "rows.json").write_text(json.dumps(rows))
        budgets = {"limit": 1000000, "min_headroom_percent": 5,
                   "programs": {name: {"v7.0.14": 1000} for name in
                                ("detailed/p11_image_query", "inventory/p11_usage_entry_lp64")}}
        budgets["programs"].update(
            {f"prearm-witness/{root}": {"v7.0.14": 10000} for root in
             ("p11_pw_unmap", "p11_pw_depart_exit", "p11_pw_depart_exec",
              "p11_pw_torn", "p11_pw_migrate", "p11_pw_walk")})
        self.budgets = self.work / "budgets.json"
        self.budgets.write_text(json.dumps(budgets))
        budgets["programs"] = {"counter-" + mode + "/p11_counter_bank_entry": {"v7.0.14": 1000}
                               for mode in _COUNTER_MODES}
        self.counter_budgets = self.work / "counter-budgets.json"
        self.counter_budgets.write_text(json.dumps(budgets))
        tool = self.bin / "tool"
        tool.write_text("#!" + sys.executable + "\n" + r'''
import json,os,pathlib,subprocess,sys,tempfile
name=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]
with open(os.environ['FAKE_EVENTS'],'a') as log:
    log.write(json.dumps({'tool':name,'args':args})+'\n')
if name=='vng':
    command=args[args.index('--exec')+1]
    out=pathlib.Path(args[args.index('--rwdir')+1])
    if os.environ.get('FAKE_BAD_HELPER')=='missing': (out/'guest-env.sh').unlink()
    if os.environ.get('FAKE_BAD_HELPER')=='bad': (out/'guest-env.sh').write_text('return 0\n')
    sys.exit(subprocess.run(['/bin/sh','-c',command]).returncode)
if name=='mkfs.ext4': sys.exit(0)
if name=='id': print('0');sys.exit(0)
if name=='uname': print('7.0.14-test');sys.exit(0)
if name=='stat': print('0:700');sys.exit(0)
if name=='losetup':
    if '-f' in args: print('/dev/loop23')
    sys.exit(0)
if name=='mount':
    sys.exit(1 if 'ext4' in args and os.environ.get('FAKE_FAIL_MOUNT') else 0)
if name=='umount': sys.exit(0)
if name=='mktemp': print(tempfile.mkdtemp(prefix='guest-work-',dir=os.environ['FAKE_WORK']));sys.exit(0)
if name=='cp':
    if args[-1].startswith('/boot/'): sys.exit(0)
    os.execv('/bin/cp',['cp',*args])
if name=='observer':
    root=pathlib.Path(os.environ['FAKE_WORK'])
    work=pathlib.Path(os.environ.get('TMPDIR','/tmp'))
    if not work.is_relative_to(root) or work==root or not work.is_dir():
        print('unsafe inherited TMPDIR',file=sys.stderr);sys.exit(8)
    key='witness' if '--prearm-module' in args else args[0]
    rows=json.loads((root/'rows.json').read_text())[key]
    if os.environ.get('FAKE_OBSERVER_REFUSAL') and args[0]=='inventory':
        rows[0].update(loaded=False,errno=13,returned_fd=-1,program_id=0,returned_program_type=0)
    for row in rows: os.write(9,(json.dumps(row)+'\n').encode())
    os.write(9,(json.dumps({'record':'probe-summary','pid':111,'records':len(rows),'write_failures':0,'overflow':False})+'\n').encode())
    if args[0]=='doctor': print('host program preflight ........ ok available')
    sys.exit(1 if os.environ.get('FAKE_OBSERVER_REFUSAL') and args[0]=='inventory' else 0)
raise SystemExit('unknown owned tool '+name)
''')
        tool.chmod(0o700)
        for name in ("vng", "mkfs.ext4", "id", "uname", "stat", "losetup", "mount", "umount", "mktemp", "cp", "observer"):
            (self.bin / name).symlink_to(tool)
        self.probe = self.work / "probe.so"
        shutil.copyfile("/lib/x86_64-linux-gnu/libc.so.6", self.probe)

    def run_driver(self, *, extra=None, long_path=False):
        out = self.work / "out ' quoted"
        if long_path:
            out = self.work.joinpath(*(["long" * 45] * 6))
        out.mkdir(parents=True)
        env = os.environ.copy()
        env.update(PATH=str(self.bin) + os.pathsep + env["PATH"], XDG_CACHE_HOME=str(self.cache),
                   FAKE_EVENTS=str(self.events), FAKE_WORK=str(self.work),
                   TMPDIR="/tmp/forbidden-inherited")
        env.update(extra or {})
        result = subprocess.run(["sh", str(DRIVER), "--budgets", str(self.budgets),
                                 "--counter-budgets", str(self.counter_budgets),
                                 str(self.bin / "observer"), str(self.probe), str(out), "v7.0.14"],
                                env=env, capture_output=True, text=True, timeout=30)
        events = [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []
        return result, events

    def test_driver_runs_six_disk_scoped_guests_and_cleans_each(self):
        result, events = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observers = [row["args"] for row in events if row["tool"] == "observer"]
        self.assertEqual([args[0] for args in observers], ["doctor", "inventory", "profile", "profile", "profile", "profile"])
        self.assertEqual([args[args.index("--counter-mode")+1] for args in observers[2:5]], list(_COUNTER_MODES))
        self.assertIn("--prearm-module", observers[5])
        guests = [row for row in events if row["tool"] == "vng"]
        self.assertEqual(len(guests), 6)
        self.assertTrue(all(len(row["args"][row["args"].index("--exec")+1]) <= 950 for row in guests))
        self.assertEqual(sum(row["tool"] == "umount" for row in events), 6)
        self.assertEqual(sum(row["tool"] == "losetup" and "-d" in row["args"] for row in events), 6)
        self.assertFalse(list(self.work.glob("guest-work-*")))
        self.assertIn("# OVERALL: PASS", result.stdout)

    def test_failed_disk_setup_never_runs_observer_and_releases_loop(self):
        result, events = self.run_driver(extra={"FAKE_FAIL_MOUNT": "1"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(any(row["tool"] == "observer" for row in events))
        self.assertEqual(sum(row["tool"] == "losetup" and "-d" in row["args"] for row in events), 1)
        self.assertFalse(any(row["tool"] == "umount" for row in events))

    def test_missing_helper_never_runs_observer(self):
        result, events = self.run_driver(extra={"FAKE_BAD_HELPER": "missing"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(any(row["tool"] == "observer" for row in events))

    def test_successful_but_incomplete_helper_never_runs_observer(self):
        result, events = self.run_driver(extra={"FAKE_BAD_HELPER": "bad"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(any(row["tool"] == "observer" for row in events))

    def test_refused_inventory_still_scores_and_cleans_all_six_guests(self):
        result, events = self.run_driver(extra={"FAKE_OBSERVER_REFUSAL": "1"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("inventory --system exited rc=1", result.stdout)
        self.assertIn("# OVERALL: FAIL", result.stdout)
        self.assertEqual(sum(row["tool"] == "vng" for row in events), 6)
        self.assertEqual(sum(row["tool"] == "umount" for row in events), 6)
        self.assertEqual(sum(row["tool"] == "losetup" and "-d" in row["args"] for row in events), 6)

    def test_command_line_limit_refuses_before_any_guest(self):
        result, events = self.run_driver(long_path=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("guest command exceeds the kernel-cmdline budget", result.stdout)
        self.assertFalse(any(row["tool"] in {"vng", "observer"} for row in events))


RECORDER = ROOT / "scripts/record-verifier-budgets.py"


class RecorderTests(unittest.TestCase):
    """The budget recorder pins measured-plus-margin, never raw counts.

    New kernel cells must carry the same 15% margin as the existing
    ones (ceil(measured * 115 / 100) in integer arithmetic); a pin past
    75% of the limit is refused (BUD-1: growth past 75% needs
    restructuring, which also keeps every recorded pin inside the
    file's 95% headroom cap). Drives
    scripts/record-verifier-budgets.py through its real CLI on owned
    fixtures: a budgets file plus report tables in the
    scripts/bpf-load-report.py output format.
    """

    def setUp(self):
        self.assertTrue(RECORDER.is_file(),
                        "scripts/record-verifier-budgets.py is missing")
        self.temporary = tempfile.TemporaryDirectory(prefix="record-budgets-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write_budgets_file(self, programs, limit=1000000, headroom=5):
        path = self.root / "budgets.json"
        document = {"limit": limit, "min_headroom_percent": headroom,
                    "programs": programs}
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        return path

    def write_table(self, name, rows):
        path = self.root / name
        lines = ["# kernel=v7.4-rc1 observer-sha256=" + "ab" * 32
                 + " result=PASS",
                 "kernel program processed limit headroom_pct budget status detail",
                 *rows]
        path.write_text("\n".join(lines) + "\n", encoding="ascii")
        return path

    def run_recorder(self, *args):
        return subprocess.run([sys.executable, "-I", str(RECORDER), *args],
                              capture_output=True, text=True, timeout=30)

    def read_cells(self, path):
        return json.loads(path.read_text(encoding="ascii"))

    def test_records_measured_plus_15_percent_margin(self):
        budgets = self.write_budgets_file(
            {"detailed/p11_entry": {"v7.3.1": 263440},
             "detailed/p11_return": {"v7.3.1": 117404}})
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 202358 1000000 79.76 263440 PASS -",
            "v7.4-rc1 detailed/p11_return 152013 1000000 84.80 117404 "
            "FAIL processed 152013 over budget 117404",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.read_cells(budgets)
        # Integer ceil: 202358 * 115 / 100 = 232711.7 -> 232712, and an
        # over-budget FAIL row is still a measurement worth recording.
        self.assertEqual(document["programs"]["detailed/p11_entry"]["v7.4-rc1"],
                         232712)
        self.assertEqual(document["programs"]["detailed/p11_return"]["v7.4-rc1"],
                         174815)
        # The old kernel column is untouched.
        self.assertEqual(document["programs"]["detailed/p11_entry"]["v7.3.1"],
                         263440)

    def test_exact_multiples_stay_exact(self):
        # Float 2000 * 1.15 can exceed 2300 by an ulp, which ceil would
        # round to 2301; integer arithmetic pins exactly 2300.
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 2000 1000000 99.80 - PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.read_cells(budgets)
        self.assertEqual(document["programs"]["detailed/p11_entry"]["v7.4-rc1"],
                         2300)

    def test_refuses_pins_past_75_percent_of_the_limit(self):
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        before = budgets.read_text(encoding="ascii")
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 700000 1000000 30.00 - PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detailed/p11_entry", result.stderr)
        self.assertEqual(budgets.read_text(encoding="ascii"), before)

    def test_refuses_to_overwrite_an_existing_kernel_column(self):
        budgets = self.write_budgets_file(
            {"detailed/p11_entry": {"v7.4-rc1": 202358}})
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 202358 1000000 79.76 202358 PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v7.4-rc1", result.stderr)
        self.assertEqual(
            self.read_cells(budgets)["programs"]["detailed/p11_entry"]["v7.4-rc1"],
            202358)
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--update",
                                   "--measured", str(table))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.read_cells(budgets)["programs"]["detailed/p11_entry"]["v7.4-rc1"],
            232712)

    def test_skips_expected_probe_rows(self):
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 202358 1000000 79.76 - PASS -",
            "v7.4-rc1 detailed/unresolved 1 1000000 100.00 - EXPECTED "
            "expected bpf_loop probe refusal errno=13",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.read_cells(budgets)
        self.assertNotIn("detailed/unresolved", document["programs"])
        self.assertEqual(document["programs"]["detailed/p11_entry"]["v7.4-rc1"],
                         232712)

    def test_refuses_refused_loads(self):
        budgets = self.write_budgets_file(
            {"detailed/p11_entry": {}, "detailed/p11_return": {}})
        before = budgets.read_text(encoding="ascii")
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 202358 1000000 79.76 - PASS -",
            "v7.4-rc1 detailed/p11_return 0 1000000 100.00 - FAIL refused errno=7",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detailed/p11_return", result.stderr)
        self.assertEqual(budgets.read_text(encoding="ascii"), before)

    def test_rejects_programs_missing_from_the_budgets_file(self):
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        before = budgets.read_text(encoding="ascii")
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 202358 1000000 79.76 - PASS -",
            "v7.4-rc1 detailed/p11_typo 100 1000000 99.99 - PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detailed/p11_typo", result.stderr)
        self.assertEqual(budgets.read_text(encoding="ascii"), before)

    def test_rejects_rows_for_another_kernel(self):
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        before = budgets.read_text(encoding="ascii")
        table = self.write_table("probe.txt", [
            "v7.3.1 detailed/p11_entry 202358 1000000 79.76 - PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v7.3.1", result.stderr)
        self.assertEqual(budgets.read_text(encoding="ascii"), before)

    def test_rejects_a_zero_count(self):
        # A zero processed count is not a measurement; recording it
        # would pin a zero budget, which the positivity check rejects.
        budgets = self.write_budgets_file({"detailed/p11_entry": {}})
        before = budgets.read_text(encoding="ascii")
        table = self.write_table("probe.txt", [
            "v7.4-rc1 detailed/p11_entry 0 1000000 100.00 - PASS -",
        ])
        result = self.run_recorder("--budgets", str(budgets),
                                   "--kernel", "v7.4-rc1",
                                   "--measured", str(table))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("detailed/p11_entry", result.stderr)
        self.assertEqual(budgets.read_text(encoding="ascii"), before)


if __name__ == "__main__":
    unittest.main()
