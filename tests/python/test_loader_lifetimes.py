#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent lifetime workload and oracle controls for G16/G17.

Synthetic rows exercise the parser/judge boundaries (including full 300
and 16,385 populations without launching 16,385 processes). Real C
fixtures prove short topology/ledger runs unprivileged. Installed judging
must FAIL on contradiction and BLOCK on the missing native seams; it must
never manufacture a positive from ledger numbers alone.

Run via the registered runner:
  python3 -I scripts/run-python-suites.py test_loader_lifetimes.py
"""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import _loader  # noqa: E402

ORACLE = _loader.load_path(ROOT / "scripts" / "qualify-loader-lifetimes.py",
                           "qualify_loader_lifetimes")

PIN = {"dev": [8, 1], "ino": 71, "sha256": "a" * 64,
       "mapping": {"dev": [8, 1], "ino": 71, "file_offset": 0,
                   "length": 4096, "permissions": "r--p"},
       "file_identity": {"dev": [8, 1], "ino": 71, "size": 8192,
                         "mtime_ns": 123, "ctime_ns": 456}}
FOREIGN_PIN = {"dev": [8, 1], "ino": 72, "sha256": "b" * 64,
               "mapping": {"dev": [8, 1], "ino": 72, "file_offset": 0,
                           "length": 4096, "permissions": "r--p"},
               "file_identity": {"dev": [8, 1], "ino": 72, "size": 8192,
                                 "mtime_ns": 123, "ctime_ns": 456}}


def make_header(cell, expected, pin=None):
    return {"seq": 1, "kind": "header", "version": 1, "cell": cell,
            "expected_lifetimes": expected, "calls_per_lifetime": 2,
            "max_live": 1, "provider": copy.deepcopy(pin or PIN)}


def make_lifetime(label, seq, *, pid=None, start=None, pin=None,
                  surfaces=None, calls=None):
    row = {"seq": seq, "kind": "lifetime", "label": label,
           "pid": 1000 + label if pid is None else pid,
           "starttime": 5000 + label if start is None else start,
           "provider_dev": list((pin or PIN)["file_identity"]["dev"]),
           "provider_ino": (pin or PIN)["file_identity"]["ino"],
           "surfaces": {"function_list": 0, "interface_list": 0,
                        "interface": 0, "interface_count": 1}
           if surfaces is None else surfaces,
           "calls": [{"fn": "C_GetInfo", "rv": 0},
                     {"fn": "C_GetSlotList", "rv": 0}] if calls is None else calls}
    return row


def make_done(lifetimes, seq):
    return {"seq": seq, "kind": "done", "lifetimes": lifetimes,
            "api_calls": lifetimes * 2,
            "calls_by_function": {"C_GetInfo": lifetimes,
                                  "C_GetSlotList": lifetimes}}


def valid_ledger(cell, count):
    rows = [make_header(cell, count)]
    for label in range(1, count + 1):
        rows.append(make_lifetime(label, label + 1))
    rows.append(make_done(count, count + 2))
    return rows


def valid_report(expected, pin=None):
    owned = dict((pin or PIN), path="/owned.so", tables=[{}])
    module = {"dev": list((pin or PIN)["dev"]), "ino": (pin or PIN)["ino"],
              "sha256": (pin or PIN)["sha256"]}
    target = dict(module)
    rows = []
    for index, name in enumerate(("C_GetInfo", "C_GetSlotList")):
        rows.append({"names": [name], "aliased": False, "calls": expected,
                     "errors": 0, "in_flight": 0, "pending_returns": 0,
                     "module": dict(module), "module_ambiguous": False,
                     "module_unresolved": False,
                     "target": {"object": dict(target),
                                "file_offset": 0x1000 + index * 0x40},
                     "ordinals": [{"table_file_offset": 0, "ordinal": 2 + index * 2}],
                     "latency_ns": {"total": 0, "max": 0},
                     "rv_counts": {"0000000000000000": expected}})
    return {"schema": "p11scope/observed-profile/v3", "lane": "profile",
            "capture": {"scope": "system", "mode": "profile",
                        "modules": [dict(module, path="/owned.so",
                                         build_id=None)]},
            "functions": rows,
            "evidence": {
                "completeness": "COMPLETE", "verdict_detail": "clean_proven",
                "drain_proven": True,
                "stop_quiescence": {"state": "proven", "post_q_events": False,
                                    "post_q_discovery": False},
                "gap_classes": {
                    "observation": {"status": "exact", "causes": []},
                    "attribution": {"status": "attested", "causes": []},
                    "semantics": {"status": "complete", "causes": []},
                    "open_calls": 0, "settlement": "proven",
                    "stdout_data_sink": False},
                "kernel_control": {
                    "capture_halted": False, "owner_poison": [],
                    "owner_admission_failures": 0, "identity_unavailable": 0,
                    "identity_budget_exhausted": False,
                    "root_affiliation_failures": []},
                "discovery": [owned],
                "in_flight_at_end": 0, "event_loss": 0}}


def valid_trace(expected):
    lines = ["Trace — completed call events in arrival order",
             "CAPTURE privacy=allowlisted"]
    pid = 2000
    for _ in range(expected):
        for fn in ("C_GetInfo", "C_GetSlotList"):
            lines.append(f"12:00:00.000001 \"driver\" (PID {pid}, TID {pid}) "
                         f"exe=\"/d\" {fn} → CKR_OK 1µs")
        pid += 1
    evidence = {"completeness": "COMPLETE", "verdict_detail": "clean_proven",
                "drain_proven": True, "trace_truncated": False,
                "gap_classes": {
                    "observation": {"status": "exact", "causes": []}},
                "kernel_control": {
                    "capture_halted": False, "owner_poison": [],
                    "owner_admission_failures": 0, "identity_unavailable": 0,
                    "identity_budget_exhausted": False,
                    "root_affiliation_failures": []}}
    lines.append("COUNT_EVIDENCE " + json.dumps({"calls": expected * 2}))
    lines.append("EVIDENCE " + json.dumps(evidence))
    return "\n".join(lines) + "\n"


class LedgerValidationTests(unittest.TestCase):
    def assert_refused(self, rows, cell, expected):
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.validate_ledger(rows, cell, expected)

    def test_g16_short_valid(self):
        summary = ORACLE.validate_ledger(valid_ledger("g16", 3), "g16", 3)
        self.assertEqual((summary["lifetimes"], summary["api_calls"]), (3, 6))
        self.assertEqual(summary["calls_by_function"],
                         {"C_GetInfo": 3, "C_GetSlotList": 3})

    def test_g17_short_valid(self):
        summary = ORACLE.validate_ledger(valid_ledger("g17", 3), "g17", 3)
        self.assertEqual((summary["lifetimes"], summary["api_calls"]), (3, 6))

    def test_g16_full_300_valid(self):
        summary = ORACLE.validate_ledger(valid_ledger("g16", 300), "g16", 300)
        self.assertEqual((summary["lifetimes"], summary["api_calls"]), (300, 600))

    def test_g17_full_16385_valid(self):
        summary = ORACLE.validate_ledger(valid_ledger("g17", 16385), "g17", 16385)
        self.assertEqual(summary["api_calls"], 32770)

    def test_g16_256_is_not_positive(self):
        self.assert_refused(valid_ledger("g16", 256), "g16", 300)

    def test_g17_16384_is_not_positive(self):
        self.assert_refused(valid_ledger("g17", 16384), "g17", 16385)

    def test_repeated_context_is_not_positive(self):
        for cell in ("g16", "g17"):
            with self.subTest(cell=cell):
                rows = valid_ledger(cell, 3)
                rows[2]["pid"] = rows[1]["pid"]
                rows[2]["starttime"] = rows[1]["starttime"]
                self.assert_refused(rows, cell, 3)

    def test_same_task_exec_is_not_distinct_leaders(self):
        rows = valid_ledger("g17", 5)
        for row in rows[1:6]:
            row["pid"] = 4242
            row["starttime"] = 777
        self.assert_refused(rows, "g17", 5)

    def test_duplicate_label_is_not_positive(self):
        rows = valid_ledger("g16", 3)
        rows[2]["label"] = 1
        self.assert_refused(rows, "g16", 3)

    def test_label_gap_is_not_positive(self):
        rows = valid_ledger("g16", 3)
        rows[3]["label"] = 4
        self.assert_refused(rows, "g16", 3)

    def test_omitted_final44_is_not_positive(self):
        rows = valid_ledger("g16", 300)
        # Relabel the final 44 as repeated early labels: duplicates, and
        # 257..300 vanish. A bare count of 300 rows must not pass.
        for index in range(257, 301):
            rows[index]["label"] = index - 256
        self.assert_refused(rows, "g16", 300)

    def test_missing_last_leader_is_not_positive(self):
        rows = valid_ledger("g17", 16385)
        rows[-2]["label"] = 1
        self.assert_refused(rows, "g17", 16385)

    def test_broken_surface_fails_g16_but_not_g17(self):
        broken = valid_ledger("g16", 3)
        broken[1]["surfaces"]["interface"] = 5
        self.assert_refused(broken, "g16", 3)
        independent = valid_ledger("g17", 3)
        independent[1]["surfaces"]["interface"] = 5
        summary = ORACLE.validate_ledger(independent, "g17", 3)
        self.assertEqual(summary["lifetimes"], 3)

    def test_wrong_call_population_fails(self):
        for cell in ("g16", "g17"):
            with self.subTest(cell=cell):
                rows = valid_ledger(cell, 3)
                rows[1]["calls"] = [{"fn": "C_GetInfo", "rv": 0}]
                self.assert_refused(rows, cell, 3)
                rows = valid_ledger(cell, 3)
                rows[1]["calls"] = [{"fn": "C_GetSlotList", "rv": 0},
                                    {"fn": "C_GetInfo", "rv": 0}]
                self.assert_refused(rows, cell, 3)
                rows = valid_ledger(cell, 3)
                rows[1]["calls"][0]["rv"] = 5
                self.assert_refused(rows, cell, 3)

    def test_wrong_provider_is_not_positive(self):
        rows = valid_ledger("g16", 3)
        rows[2]["provider_ino"] = FOREIGN_PIN["ino"]
        self.assert_refused(rows, "g16", 3)

    def test_invalid_birth_is_refused(self):
        for pid, start in ((0, 5001), (1001, 0), (True, 5001), (1001, False),
                           ("1001", 5001), (1001, None), (-1, 5001)):
            with self.subTest(pid=pid, start=start):
                rows = valid_ledger("g16", 3)
                rows[1]["pid"] = pid
                rows[1]["starttime"] = start
                self.assert_refused(rows, "g16", 3)

    def test_done_summary_cannot_repair_calls(self):
        rows = valid_ledger("g16", 3)
        rows[-1]["api_calls"] = 7
        self.assert_refused(rows, "g16", 3)
        rows = valid_ledger("g16", 3)
        rows[-1]["calls_by_function"]["C_GetInfo"] = 4
        self.assert_refused(rows, "g16", 3)

    def test_held_return_keeps_charge_as_separate_control(self):
        # A lifetime whose calls never completed is a held control, never
        # a positive completion.
        rows = valid_ledger("g16", 3)
        rows[1]["calls"] = []
        self.assert_refused(rows, "g16", 3)

    def test_delayed_old_record_blocks_positive(self):
        rows = valid_ledger("g16", 3)
        rows[1], rows[2] = rows[2], rows[1]
        self.assert_refused(rows, "g16", 3)

    def test_ledger_mutations_cannot_preserve_acceptance(self):
        mutations = {
            "empty": lambda r: r.clear(),
            "missing_done": lambda r: r.pop(),
            "duplicate_seq": lambda r: r[1].update(seq=1),
            "wrong_version": lambda r: r[0].update(version=2),
            "bool_version": lambda r: r[0].update(version=True),
            "wrong_cell": lambda r: r[0].update(cell="g17"),
            "wrong_expected": lambda r: r[0].update(expected_lifetimes=4),
            "live_bound": lambda r: r[0].update(max_live=5),
            "extra_header": lambda r: r[0].update(marker=1),
            "bad_hash": lambda r: r[0]["provider"].update(sha256="z" * 64),
            "wrong_mapping": lambda r: r[0]["provider"]["mapping"].update(ino=99),
            "extra_lifetime": lambda r: r[1].update(marker=1),
            "missing_label": lambda r: r[1].pop("label"),
            "bool_pid": lambda r: r[1].update(pid=True),
            "overflow_pid": lambda r: r[1].update(pid=2**64),
            "unknown_function": lambda r: r[1]["calls"][0].update(fn="C_Fabricated"),
            "boolean_rv": lambda r: r[1]["calls"][0].update(rv=False),
            "extra_call_field": lambda r: r[1]["calls"][0].update(handle=1),
            "trailing_row": lambda r: r.append(copy.deepcopy(r[-1])),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                rows = valid_ledger("g16", 3)
                mutate(rows)
                self.assert_refused(rows, "g16", 3)

    def test_parser_rejects_malformed_and_unbounded_input(self):
        for content in ('{"seq":1,"seq":1}\n', '[]\n', '\n', '{"seq":NaN}\n',
                        '{"x":"' + 'x' * 4096 + '"}\n'):
            with self.subTest(content=content[:24]):
                with self.assertRaises(ORACLE.LedgerError):
                    ORACLE.read_jsonl(io.StringIO(content))

    def test_parser_enforces_row_and_byte_limits(self):
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.read_jsonl(io.StringIO('{"x":0}\n' * 20001))
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.read_jsonl(io.StringIO(('{"x":"' + 'x' * 4000 + '"}\n') * 5000))

    def test_jsonl_roundtrip(self):
        text = "".join(json.dumps(r) + "\n" for r in valid_ledger("g16", 3))
        summary = ORACLE.validate_ledger(ORACLE.read_jsonl(io.StringIO(text)),
                                         "g16", 3)
        self.assertEqual(summary["api_calls"], 6)

    def test_cli_validate_accepts_and_redacts(self):
        ledger = "".join(json.dumps(r) + "\n" for r in valid_ledger("g16", 2))
        command = [os.sys.executable, str(ROOT / "scripts/qualify-loader-lifetimes.py"),
                   "validate", "--cell", "g16", "--expected", "2"]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                         delete=False) as stream:
            stream.write(ledger)
            name = stream.name
        try:
            result = subprocess.run([*command, name], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["api_calls"], 4)
        finally:
            os.unlink(name)
        result = subprocess.run(
            [*command[:-1], "3", "/nonexistent-ledger.jsonl"],
            capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class InstalledJudgeTests(unittest.TestCase):
    def ledger_text(self, cell, count):
        return "".join(json.dumps(r) + "\n" for r in valid_ledger(cell, count))

    def write(self, directory, name, text):
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def judge_cli(self, cell, ledger, report=None, trace=None):
        command = [os.sys.executable,
                   str(ROOT / "scripts/qualify-loader-lifetimes.py"),
                   "judge", "--cell", cell, "--ledger", ledger]
        if report:
            command += ["--report", report]
        if trace:
            command += ["--trace", trace]
        return subprocess.run(command, capture_output=True, text=True, timeout=30)

    def test_g16_valid_public_output_is_blocked_not_pass(self):
        rows = valid_ledger("g16", 300)
        report = json.dumps(valid_report(300))
        with self.assertRaises(ORACLE.Blocked) as raised:
            ORACLE.judge("g16", rows, report_text=report)
        self.assertIn("arming", str(raised.exception))

    def test_g17_valid_profile_is_blocked_not_pass(self):
        rows = valid_ledger("g17", 16385)
        report = json.dumps(valid_report(16385))
        with self.assertRaises(ORACLE.Blocked) as raised:
            ORACLE.judge("g17", rows, report_text=report)
        self.assertIn("ticket", str(raised.exception))

    def test_g17_valid_trace_is_blocked_not_pass(self):
        # Full 32,770-row trace (~5 MB); well within the 256 MiB bound.
        with self.assertRaises(ORACLE.Blocked):
            ORACLE.judge("g17", valid_ledger("g17", 16385),
                         trace_text=valid_trace(16385))
        # Short-trace sanity: exact per-function delivery is checked before
        # the seam blocks.
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", valid_ledger("g16", 3), trace_text=valid_trace(2))

    def test_wrong_mode_is_fail_not_blocked(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["lane"] = "metrics"
        report["schema"] = "p11scope/observed-profile/v3-metrics"
        report["capture"]["mode"] = "metrics"
        with self.assertRaises(ORACLE.JudgeFail) as raised:
            ORACLE.judge("g16", rows, report_text=json.dumps(report))
        self.assertIn("metrics", str(raised.exception))

    def test_partial_output_is_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["evidence"]["completeness"] = "PARTIAL"
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_kernel_loss_is_fail(self):
        rows = valid_ledger("g17", 16385)
        report = valid_report(16385)
        report["evidence"]["kernel_control"]["identity_unavailable"] = 7
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g17", rows, report_text=json.dumps(report))

    def test_g16_ticket_exhaustion_is_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["evidence"]["kernel_control"]["identity_budget_exhausted"] = True
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_wrong_counts_are_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["functions"][0]["calls"] = 299
        report["functions"][0]["rv_counts"] = {"0000000000000000": 299}
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_doubled_early_calls_are_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["functions"][0]["calls"] = 301
        report["functions"][0]["rv_counts"] = {"0000000000000000": 301}
        report["functions"][1]["calls"] = 299
        report["functions"][1]["rv_counts"] = {"0000000000000000": 299}
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_foreign_or_ambient_rows_are_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        extra = copy.deepcopy(report["functions"][0])
        extra["target"]["file_offset"] = 0x9999
        report["functions"].append(extra)
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_unowned_module_is_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300)
        report["functions"][0]["module"] = None
        report["functions"][0]["module_ambiguous"] = False
        report["functions"][0]["module_unresolved"] = True
        report["evidence"]["completeness"] = "PARTIAL"
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_wrong_provider_report_is_fail(self):
        rows = valid_ledger("g16", 300)
        report = valid_report(300, pin=FOREIGN_PIN)
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=json.dumps(report))

    def test_trace_foreign_call_is_fail(self):
        trace = valid_trace(3).replace("C_GetInfo", "C_Encrypt", 1)
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", valid_ledger("g16", 3), trace_text=trace)

    def test_trace_truncation_is_fail(self):
        trace = valid_trace(3).replace('"trace_truncated": false',
                                       '"trace_truncated": true')
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", valid_ledger("g16", 3), trace_text=trace)

    def test_single_pid_trace_is_not_sequential_leaders(self):
        single = re.sub(r"PID \d+, TID \d+", "PID 4242, TID 4242", valid_trace(3))
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", valid_ledger("g16", 3), trace_text=single)

    def test_one_capture_is_required(self):
        rows = valid_ledger("g16", 300)
        report = json.dumps(valid_report(300))
        trace = valid_trace(300)
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows, report_text=report, trace_text=trace)
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", rows)

    def test_short_ledger_cannot_pass_full_gate(self):
        with self.assertRaises(ORACLE.JudgeFail) as raised:
            ORACLE.judge("g16", valid_ledger("g16", 3),
                         report_text=json.dumps(valid_report(3)))
        self.assertIn("full population", str(raised.exception))

    def test_judge_independence_g16_needs_surfaces(self):
        broken = valid_ledger("g16", 300)
        broken[1]["surfaces"]["interface"] = 5
        with self.assertRaises(ORACLE.JudgeFail):
            ORACLE.judge("g16", broken,
                         report_text=json.dumps(valid_report(300)))
        independent = valid_ledger("g17", 16385)
        independent[1]["surfaces"]["interface"] = 5
        with self.assertRaises(ORACLE.Blocked):
            ORACLE.judge("g17", independent,
                         report_text=json.dumps(valid_report(16385)))

    def test_cli_judge_reports_blocked_and_fail_distinctly(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-loader-judge-") as raw:
            ledger = self.write(raw, "ledger.jsonl",
                                self.ledger_text("g16", 300))
            report = self.write(raw, "report.json",
                                json.dumps(valid_report(300)))
            result = self.judge_cli("g16", ledger, report=report)
            self.assertEqual(result.returncode, 2, result.stderr)
            verdict = json.loads(result.stdout)
            self.assertEqual(
                (verdict["pass"], verdict["qualification"]), (False, "blocked"))
            bad = valid_report(300)
            bad["evidence"]["completeness"] = "PARTIAL"
            partial = self.write(raw, "partial.json", json.dumps(bad))
            result = self.judge_cli("g16", ledger, report=partial)
            self.assertEqual(result.returncode, 1)
            verdict = json.loads(result.stdout)
            self.assertEqual(
                (verdict["pass"], verdict["qualification"]), (False, "failed"))


class BoundedTextTests(unittest.TestCase):
    def test_stale_stat_growth_is_refused(self):
        # Regression: a stale size-1 stat for a 1 KiB file with limit 16
        # must refuse; the helper reads the held FD with limit+1, never a
        # stale stat plus unbounded read.
        with tempfile.TemporaryDirectory(
                prefix="p11scope-loader-bounded-") as raw:
            path = Path(raw) / "evidence.txt"
            path.write_text("A" * 1024, encoding="utf-8")
            original = Path.stat

            def stale_stat(self, *args, **kwargs):
                info = original(self, *args, **kwargs)
                if str(self) == str(path):
                    class Stale:
                        st_mode = info.st_mode
                        st_size = 1
                    return Stale()
                return info

            Path.stat = stale_stat
            try:
                with self.assertRaises(ORACLE.JudgeFail):
                    ORACLE.read_bounded_text(str(path), 16)
            finally:
                Path.stat = original

    def test_actual_overflow_is_refused_without_stale_stat(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-loader-bounded-") as raw:
            path = Path(raw) / "big.txt"
            path.write_text("B" * 1024, encoding="utf-8")
            with self.assertRaises(ORACLE.JudgeFail):
                ORACLE.read_bounded_text(str(path), 16)

    def test_bounded_utf8_succeeds(self):
        # Healthy twin: bounded UTF-8 (including multibyte) within limit.
        with tempfile.TemporaryDirectory(
                prefix="p11scope-loader-bounded-") as raw:
            path = Path(raw) / "healthy.txt"
            text = "hello héllo 🌐"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(
                ORACLE.read_bounded_text(str(path), 64), text)
            exact = Path(raw) / "exact.txt"
            exact.write_bytes(b"x" * 16)
            self.assertEqual(
                ORACLE.read_bounded_text(str(exact), 16), "x" * 16)
            over = Path(raw) / "over.txt"
            over.write_bytes(b"y" * 17)
            with self.assertRaises(ORACLE.JudgeFail):
                ORACLE.read_bounded_text(str(over), 16)

    def test_nonregular_is_refused(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-loader-bounded-") as raw:
            with self.assertRaises(ORACLE.JudgeFail):
                ORACLE.read_bounded_text(raw, 16)


class FixtureWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("gcc"):
            raise unittest.SkipTest("gcc is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="p11scope-loader-fixture-")
        cls.directory = Path(cls.temporary.name)
        cls.provider = cls.directory / "provider.so"
        cls.driver = cls.directory / "lifetime-driver"
        fixture = ROOT / "tests/fixtures/loader-lifetimes"
        provider = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC",
             "-shared", "-Wl,-z,defs", "-o", str(cls.provider),
             str(fixture / "provider.c")],
            capture_output=True, text=True, timeout=60)
        if provider.returncode:
            cls.temporary.cleanup()
            raise AssertionError("provider compilation failed: " + provider.stderr)
        driver = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-o", str(cls.driver), str(fixture / "lifetime-driver.c"), "-ldl"],
            capture_output=True, text=True, timeout=60)
        if driver.returncode:
            cls.temporary.cleanup()
            raise AssertionError("driver compilation failed: " + driver.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_single_lifetime_emits_one_valid_row(self):
        child = subprocess.run([str(self.driver), str(self.provider), "1"],
                               capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stderr, "")
        lines = child.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["label"], 1)
        self.assertGreater(row["pid"], 0)
        self.assertGreater(row["starttime"], 0)
        self.assertEqual(row["surfaces"],
                         {"function_list": 0, "interface_list": 0,
                          "interface": 0, "interface_count": 1})
        self.assertEqual(row["calls"], [{"fn": "C_GetInfo", "rv": 0},
                                        {"fn": "C_GetSlotList", "rv": 0}])
        info = self.provider.stat()
        self.assertEqual(row["provider_ino"], info.st_ino)

    def test_driver_refuses_bad_label_and_missing_provider(self):
        for args in (["0"], ["16386"], ["abc"], []):
            with self.subTest(args=args):
                child = subprocess.run(
                    [str(self.driver), str(self.provider), *args],
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(child.returncode, 0)
                self.assertEqual(child.stdout, "")
        child = subprocess.run(
            [str(self.driver), str(self.directory / "absent.so"), "1"],
            capture_output=True, text=True, timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(child.stdout, "")

    def test_run_three_sequential_lifetimes_g16(self):
        output = self.directory / "g16-3.jsonl"
        summary = ORACLE.run_lifetimes(
            cell="g16", lifetimes=3, provider=str(self.provider),
            driver=str(self.driver), output=str(output))
        self.assertEqual((summary["lifetimes"], summary["api_calls"]), (3, 6))
        rows = ORACLE.read_jsonl(io.StringIO(output.read_text(encoding="utf-8")))
        check = ORACLE.validate_ledger(rows, "g16", 3)
        self.assertEqual(check["lifetimes"], 3)
        births = {(row["pid"], row["starttime"]) for row in rows[1:4]}
        self.assertEqual(len(births), 3)
        self.assertEqual(rows[0]["max_live"], 1)

    def test_run_three_sequential_lifetimes_g17(self):
        output = self.directory / "g17-3.jsonl"
        summary = ORACLE.run_lifetimes(
            cell="g17", lifetimes=3, provider=str(self.provider),
            driver=str(self.driver), output=str(output))
        self.assertEqual(summary["lifetimes"], 3)

    def test_run_eight_proves_distinct_births(self):
        output = self.directory / "g16-8.jsonl"
        ORACLE.run_lifetimes(cell="g16", lifetimes=8,
                             provider=str(self.provider),
                             driver=str(self.driver), output=str(output))
        rows = ORACLE.read_jsonl(io.StringIO(output.read_text(encoding="utf-8")))
        ORACLE.validate_ledger(rows, "g16", 8)
        births = {(row["pid"], row["starttime"]) for row in rows[1:9]}
        self.assertEqual(len(births), 8)

    def test_run_failure_is_honest_and_leaves_no_done(self):
        output = self.directory / "failed.jsonl"
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.run_lifetimes(
                cell="g16", lifetimes=2, provider=str(self.provider),
                driver="/bin/false", output=str(output))
        self.assertFalse(output.exists())
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.run_lifetimes(
                cell="g16", lifetimes=0, provider=str(self.provider),
                driver=str(self.driver), output=str(output))
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.run_lifetimes(
                cell="g16", lifetimes=1, provider=str(self.provider),
                driver=str(self.driver),
                output=str(self.directory / "absent-dir" / "x.jsonl"))

    def test_hung_lifetime_is_reaped_through_held_handle(self):
        # A hanging driver hits the absolute per-lifetime deadline; the
        # harness kills and reaps it through its held Popen handle (never
        # kill-by-PID) and reports an honest deadline failure.
        sleeper = self.directory / "hang.sh"
        sleeper.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
        sleeper.chmod(0o755)
        output = self.directory / "hung.jsonl"
        previous = ORACLE.PER_LIFETIME_SECONDS
        ORACLE.PER_LIFETIME_SECONDS = 1
        try:
            with self.assertRaises(ORACLE.LedgerError) as raised:
                ORACLE.run_lifetimes(
                    cell="g16", lifetimes=1, provider=str(self.provider),
                    driver=str(sleeper), output=str(output))
            self.assertIn("deadline", str(raised.exception))
        finally:
            ORACLE.PER_LIFETIME_SECONDS = previous
        self.assertFalse(output.exists())

    def test_cli_run_writes_validated_ledger(self):
        output = self.directory / "cli.jsonl"
        result = subprocess.run(
            [os.sys.executable,
             str(ROOT / "scripts/qualify-loader-lifetimes.py"), "run",
             "--cell", "g16", "--lifetimes", "2",
             "--provider", str(self.provider), "--driver", str(self.driver),
             "--output", str(output)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["lifetimes"], 2)
        rows = ORACLE.read_jsonl(io.StringIO(output.read_text(encoding="utf-8")))
        ORACLE.validate_ledger(rows, "g16", 2)

    def test_ledger_contains_no_secrets(self):
        output = self.directory / "secrets.jsonl"
        ORACLE.run_lifetimes(cell="g16", lifetimes=2,
                             provider=str(self.provider),
                             driver=str(self.driver), output=str(output))
        text = output.read_text(encoding="utf-8")
        for forbidden in ('"pin"', '"PIN"', '"handle"', '"pValue"',
                          '"signature"', '"payload"', '"secret"',
                          "fixture-secret"):
            self.assertNotIn(forbidden, text)

    def test_same_inode_append_is_refused(self):
        # Regression: a wrapper appends one NUL byte (same inode) before
        # exec of the real driver. Held-FD revalidation must refuse; an
        # accepted ledger with a stale SHA is the bug.
        work = self.directory / "mutate-append"
        work.mkdir(exist_ok=True)
        provider = work / "provider.so"
        shutil.copy2(self.provider, provider)
        before = provider.stat()
        wrapper = work / "append.sh"
        wrapper.write_text(
            f'#!/bin/sh\nprintf "\\0" >> "$1"\n'
            f'exec "{self.driver}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        output = work / "ledger.jsonl"
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.run_lifetimes(
                cell="g16", lifetimes=1, provider=str(provider),
                driver=str(wrapper), output=str(output))
        self.assertFalse(output.exists())
        after = provider.stat()
        self.assertEqual(after.st_ino, before.st_ino)
        self.assertEqual(after.st_size, before.st_size + 1)

    def test_passthrough_wrapper_succeeds_with_fd(self):
        # Healthy twin: the same wrapper seam without mutation succeeds,
        # and the ledger hash matches the current provider bytes.
        work = self.directory / "passthrough-fd"
        work.mkdir(exist_ok=True)
        provider = work / "provider.so"
        shutil.copy2(self.provider, provider)
        wrapper = work / "pass.sh"
        wrapper.write_text(f'#!/bin/sh\nexec "{self.driver}" "$@"\n',
                           encoding="utf-8")
        wrapper.chmod(0o755)
        output = work / "ledger.jsonl"
        summary = ORACLE.run_lifetimes(
            cell="g16", lifetimes=1, provider=str(provider),
            driver=str(wrapper), output=str(output))
        self.assertEqual(summary["lifetimes"], 1)
        current = hashlib.sha256(provider.read_bytes()).hexdigest()
        self.assertEqual(summary["provider"]["sha256"], current)
        rows = ORACLE.read_jsonl(io.StringIO(output.read_text(encoding="utf-8")))
        ORACLE.validate_ledger(rows, "g16", 1)
        self.assertEqual(rows[1]["provider_ino"], provider.stat().st_ino)

    def test_same_inode_content_restore_is_refused(self):
        # Same bytes at the end do not erase an in-place change while the
        # driver was loading the provider. Its mtime remains a refusal witness.
        work = self.directory / "mutate-restore"
        work.mkdir(exist_ok=True)
        provider = work / "provider.so"
        shutil.copy2(self.provider, provider)
        before = provider.stat()
        original = provider.read_bytes()
        wrapper = work / "restore.sh"
        wrapper.write_text(
            f'#!/bin/sh\nprintf "\\0" >> "$1"\n'
            f'truncate -s {before.st_size} "$1"\n'
            f'exec "{self.driver}" "$@"\n',
            encoding="utf-8")
        wrapper.chmod(0o755)
        output = work / "ledger.jsonl"
        with self.assertRaisesRegex(ORACLE.LedgerError, "provider changed"):
            ORACLE.run_lifetimes(
                cell="g16", lifetimes=1, provider=str(provider),
                driver=str(wrapper), output=str(output))
        self.assertEqual(provider.read_bytes(), original)
        self.assertEqual(provider.stat().st_ino, before.st_ino)
        self.assertNotEqual(provider.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertFalse(output.exists())

    def test_path_replacement_retains_fd_authority(self):
        # Coverage: the wrapper replaces the provider pathname (different
        # inode, invalid bytes) before exec. FD-backed exec must still run
        # the held bytes; the ledger matches the original hash, never the
        # replacement. Reopening the pathname would accept new bytes.
        work = self.directory / "replace-path"
        work.mkdir(exist_ok=True)
        provider = work / "provider.so"
        shutil.copy2(self.provider, provider)
        orig_sha = hashlib.sha256(provider.read_bytes()).hexdigest()
        orig_ino = provider.stat().st_ino
        replacement = work / "replacement.so"
        replacement.write_bytes(b"not-an-elf" * 100)
        repl_sha = hashlib.sha256(replacement.read_bytes()).hexdigest()
        self.assertNotEqual(orig_sha, repl_sha)
        wrapper = work / "replace.sh"
        wrapper.write_text(
            f'#!/bin/sh\ncp "{replacement}" "{provider}.tmp-new"\n'
            f'mv "{provider}.tmp-new" "{provider}"\n'
            f'exec "{self.driver}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        output = work / "ledger.jsonl"
        summary = ORACLE.run_lifetimes(
            cell="g16", lifetimes=1, provider=str(provider),
            driver=str(wrapper), output=str(output))
        self.assertEqual(summary["provider"]["sha256"], orig_sha)
        rows = ORACLE.read_jsonl(io.StringIO(output.read_text(encoding="utf-8")))
        ORACLE.validate_ledger(rows, "g16", 1)
        self.assertEqual(rows[1]["provider_ino"], orig_ino)
        self.assertNotEqual(provider.stat().st_ino, orig_ino)


if __name__ == "__main__":
    unittest.main()
