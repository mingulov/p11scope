#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-kernel BPF load report: every root loaded, stats present, headroom kept.

Drives scripts/bpf-load-report.py through its real CLI on small owned JSONL
fixtures in the verifier-stats probe record format. Exit 0 only when every
root passes; the processed count of every root is printed either way.
"""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/bpf-load-report.py"
DRIVER = ROOT / "scripts/check-bpf-load-kernels.sh"
BUDGETS_FILE = ROOT / "tests/bpf-verifier-budgets.json"
COUNTER_BUDGETS_FILE = ROOT / "tests/counter-bpf-verifier-budgets.json"
KERNEL = "v6.1.188-test"
OBSERVER = "ab" * 32
# The driver's default kernel list (scripts/check-bpf-load-kernels.sh)
# plus the 7.0 guest the budgets also cover.
EXPECTED_BUDGET_KERNELS = frozenset({
    "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14",
})
# Counter objects load only where the verifier accepts them (6.6+); the
# old kernels keep the specified refusal, so the counter file pins its
# own kernel set. Each counter object loads 15 programs (the 13 defaults
# plus the 2 bank roots, including the sched lifecycle pair that every
# counter profile run loads); the probe file's 16th load is the lone
# Detailed return, which BTF grouping ignores when scoring counter
# modes. Every loaded counter program has a cell for each 6.6+ kernel
# and nothing else.
EXPECTED_COUNTER_BUDGET_KERNELS = frozenset({
    "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14",
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
    """Every budgeted program carries the same kernel set; a missing cell fails.

    The report's budgeted-but-missing FAIL only fires for roots carrying a
    cell for the requested kernel, so a root silently dropped from one
    kernel's column would pass with no rows at all. This pin fails such a
    file. Raises AssertionError naming the mismatch.
    """
    document = json.loads(Path(path).read_text(encoding="ascii"))
    programs = document["programs"]
    assert programs, "budgets file names no programs"
    kernel_sets = {name: frozenset(cells) for name, cells in programs.items()}
    first, *rest = sorted(kernel_sets)
    for name in rest:
        assert kernel_sets[name] == kernel_sets[first], (
            f"{name} kernels {sorted(kernel_sets[name])} differ from "
            f"{first} {sorted(kernel_sets[first])}")
    assert kernel_sets[first] == EXPECTED_BUDGET_KERNELS, (
        f"budget kernels {sorted(kernel_sets[first])} differ from "
        f"{sorted(EXPECTED_BUDGET_KERNELS)}")


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

    def test_driver_anchors_guest_release_on_version_boundary(self):
        # The release check must accept the exact version or a `-`-suffixed
        # release only; a bare prefix also matches a different kernel
        # (6.1.1880 for 6.1.188). Real guest runs prove the behavior; this
        # pins the anchored pattern against revert.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn('"${KERNEL#v}"|"${KERNEL#v}-"*)', text)

    def test_driver_scores_inventory_side_against_budgets(self):
        # The 72 inventory budget cells exist (pinned by the budgets-shape
        # test above); the driver must pass them on the inventory side so
        # an inventory regression fails the gate. Real guest runs prove
        # the scoring; this pins the wiring against revert.
        self.assertTrue(DRIVER.is_file(),
                        "scripts/check-bpf-load-kernels.sh is missing")
        text = DRIVER.read_text(encoding="ascii")
        self.assertIn('--budgets "$BUDGETS" --object inventory', text)

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
        self.assertIn("uprobe-multi-required", text)
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


# The FNV-1a 64 of `call 181; exit` (BPF_LOOP_PROBE_INSNS), cross-checked
# against src/attach.rs by the fingerprint test above.
EXPECTED_BPF_LOOP_PROBE_FNV = "27ef27a73ecc6270"


if __name__ == "__main__":
    unittest.main()
