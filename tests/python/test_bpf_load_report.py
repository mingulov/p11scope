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
KERNEL = "v6.1.188-test"
OBSERVER = "ab" * 32
# The driver's default kernel list (scripts/check-bpf-load-kernels.sh)
# plus the 7.0 guest the budgets also cover.
EXPECTED_BUDGET_KERNELS = frozenset({
    "v5.15.221", "v6.1.188", "v6.6.157", "v6.12.111", "v6.18.58", "v7.0.14",
})


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

next_program_id = 100


def load_row(root, *, loaded=True, errno=0, stats_present=True,
             processed=1000, limit=1000000, auxiliary=None, pid=111):
    global next_program_id
    next_program_id += 1
    return {
        "record": "load", "pid": pid, "root": root,
        "btf_resolved": auxiliary is None and root != "unresolved",
        "btf_fd": 4, "btf_id": 77, "returned_btf_id": 77, "root_type_id": 1,
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

    def run_report(self, *jsonl, budgets=None, object_name=None):
        command = [sys.executable, "-I", str(SCRIPT), "--kernel", KERNEL,
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
        # exit`, kprobe type, refused (5.15 EINVAL, 6.1 EACCES).
        row = load_row("unresolved", loaded=False, errno=errno,
                       stats_present=False, processed=0)
        row.update({"program_type": 2, "insn_count": 2,
                    "relocated_fnv1a64": EXPECTED_BPF_LOOP_PROBE_FNV})
        return row

    def test_expected_bpf_loop_probe_refusal_passes(self):
        for errno in (22, 13):
            loads = [self.bpf_loop_probe_row(errno),
                     load_row("p11_entry", processed=472892)]
            result = self.run_report(self.write_loads("probe.jsonl", loads))
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("result=PASS", result.stdout)
            self.assertIn("EXPECTED", result.stdout)
            self.assertIn("expected bpf_loop probe refusal", result.stdout)
            self.assertIn(f"errno={errno}", result.stdout)

    def test_expected_bpf_loop_probe_refusal_passes_namespaced(self):
        loads = [self.bpf_loop_probe_row(22),
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
        base = self.bpf_loop_probe_row(22)
        variants = []
        for key, value in (("relocated_fnv1a64", "27ef27a73ecc6271"),
                           ("relocated_fnv1a64", "0" * 16),
                           ("program_type", 5),
                           ("insn_count", 3),
                           ("errno", 7),
                           ("errno", 1)):
            variant = dict(base)
            variant[key] = value
            variants.append(variant)
        for variant in variants:
            loads = [variant, load_row("p11_entry", processed=472892)]
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


# The FNV-1a 64 of `call 181; exit` (BPF_LOOP_PROBE_INSNS), cross-checked
# against src/attach.rs by the fingerprint test above.
EXPECTED_BPF_LOOP_PROBE_FNV = "27ef27a73ecc6270"


if __name__ == "__main__":
    unittest.main()
