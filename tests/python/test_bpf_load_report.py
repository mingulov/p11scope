#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-kernel BPF load report: every root loaded, stats present, headroom kept.

Drives scripts/bpf-load-report.py through its real CLI on small owned JSONL
fixtures in the verifier-stats probe record format. Exit 0 only when every
root passes; the processed count of every root is printed either way.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/bpf-load-report.py"
KERNEL = "v6.1.188-test"
OBSERVER = "ab" * 32

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

    def run_report(self, *jsonl, budgets=None):
        command = [sys.executable, "-I", str(SCRIPT), "--kernel", KERNEL,
                   "--observer-sha256", OBSERVER]
        if budgets is not None:
            command += ["--budgets", str(budgets)]
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


if __name__ == "__main__":
    unittest.main()
