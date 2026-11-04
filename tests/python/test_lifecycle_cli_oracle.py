# SPDX-License-Identifier: GPL-3.0-or-later
"""Lifecycle CLI oracle unit tests (WP-10, S9/S10).

Exercises tests/fixtures/lifecycle-cli/oracle.py on synthetic reports,
ledgers and receipts: each judge passes on a healthy input and fails on
a mutated one (non-vacuity). Live privileged runs prove the same judges
against real captures; these pin the logic.

Run: python3 -I tests/python/test_lifecycle_cli_oracle.py -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "tests/fixtures/lifecycle-cli/oracle.py"


def run_oracle(tmp, *, cell, report, ledger, receipt, stderr=""):
    report_path = tmp / "report.json"
    ledger_path = tmp / "ledger.txt"
    receipt_path = tmp / "receipt.json"
    stderr_path = tmp / "stderr.txt"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    ledger_path.write_text(ledger, encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "-I", str(ORACLE), "--cell", cell,
         "--report", str(report_path), "--ledger", str(ledger_path),
         "--receipt", str(receipt_path), "--stderr", str(stderr_path)],
        capture_output=True, text=True, timeout=30)
    row = json.loads(completed.stdout.strip().splitlines()[-1])
    return completed.returncode, row


def provider():
    return {"dev": [8, 1], "ino": 11, "sha256": "aa",
            "path": "/w/owned.so"}


def profile_report(*, calls, scope="pid", exact=True, hints=None,
                   loop_end="expiry", causes=None, surfaces=None,
                   observation_status=None):
    functions = []
    for name, count in calls.items():
        functions.append({
            "names": [name], "calls": count, "errors": 0,
            "in_flight": 0, "pending_returns": 0,
            "target": {"file_offset": 1234, "object": dict(provider())},
        })
    if causes is None:
        causes = [] if exact else ["late_load"]
    if observation_status is None:
        observation_status = "exact" if exact else "partial"
    evidence = {
        "event_loss": 0, "semantic_capture_failures": 0,
        "gap_classes": {"observation": {
            "status": observation_status,
            "causes": causes}},
        "scheduling": {"phase_mono_ns": {"loop_end_reason": loop_end}},
        "discovery": [],
    }
    if surfaces is not None:
        evidence["surfaces"] = surfaces
    if hints is not None:
        evidence["gap_exe_hints"] = hints
    return {"schema": "p11scope/observed-profile/v3",
            "capture": {"scope": scope, "mode": "profile"},
            "functions": functions, "evidence": evidence}


def known_prefix_surfaces():
    return [{"walk": "known_prefix", "functions": 68,
             "acquisition": "ok", "source": "legacy_function_list"}]


def full_surfaces():
    return [{"walk": "full", "functions": 68,
             "acquisition": "ok", "source": "legacy_function_list"}]


def cli_ledger(calls):
    functions = ",".join(
        f'{{"name":"{name}","attempts":{count},"successful":{count}}}'
        for name, count in calls.items())
    return (f'LEDGER {{"schema":"p11scope/public-cli-ledger/v1","pid":4242,'
            f'"complete":true,"functions":[{functions}]}}\n')


def receipt_for(cell, scope="pid", **extra):
    receipt = {
        "cell": cell, "scope": scope, "workload_ready": True,
        "capture_ready": True, "gate_released": True,
        "observer_exit": 0, "workload_exit": 0,
        "ledger_complete": True,
        "provider_before": provider(), "provider_after": provider(),
    }
    receipt.update(extra)
    return receipt


class ReloadTests(unittest.TestCase):
    def test_exact_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(calls={"C_GenerateRandom": 100}),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 0)
        self.assertTrue(row["pass"])

    def test_doubled_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(calls={"C_GenerateRandom": 200}),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])

    def test_surfaces_known_prefix_passes_with_label(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(
                    calls={"C_GenerateRandom": 100},
                    causes=["surfaces"],
                    observation_status="lossy",
                    surfaces=known_prefix_surfaces()),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 0)
        self.assertTrue(row["pass"])
        self.assertIn("SoftHSM 2.7 table shape; exec-scan-legacy32",
                      row["detail"])

    def test_surfaces_full_only_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(
                    calls={"C_GenerateRandom": 100},
                    causes=["surfaces"],
                    observation_status="lossy",
                    surfaces=full_surfaces()),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])

    def test_surfaces_acquisition_error_fails(self):
        bad = [{"walk": "known_prefix", "functions": 68,
                "acquisition": "error: boom",
                "source": "legacy_function_list"}]
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(
                    calls={"C_GenerateRandom": 100},
                    causes=["surfaces"],
                    observation_status="lossy",
                    surfaces=bad),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])

    def test_surfaces_missing_surfaces_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reload",
                report=profile_report(
                    calls={"C_GenerateRandom": 100},
                    causes=["surfaces"],
                    observation_status="lossy",
                    surfaces=None),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reload"))
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])


class ReuseTests(unittest.TestCase):
    def test_target_exact_reuser_excluded(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reuse",
                report=profile_report(calls={"C_GenerateRandom": 100},
                                      loop_end="target_exit"),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reuse", reuser_calls=200),
                stderr="p11scope: capture ended: target exited after 9 ticks\n")
        self.assertEqual(rc, 0)
        self.assertTrue(row["pass"])

    def test_reuser_calls_included_fails(self):
        # Non-vacuity: if the reuser's 200 calls leaked into the report
        # (300 observed vs 100 ledgered), the cell must fail.
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reuse",
                report=profile_report(calls={"C_GenerateRandom": 300},
                                      loop_end="target_exit"),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reuse", reuser_calls=200),
                stderr="p11scope: capture ended: target exited after 9 ticks\n")
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])

    def test_vacuous_reuser_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="profile-pid-reuse",
                report=profile_report(calls={"C_GenerateRandom": 100},
                                      loop_end="target_exit"),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("profile-pid-reuse", reuser_calls=0),
                stderr="p11scope: capture ended: target exited after 9 ticks\n")
        self.assertEqual(rc, 1)
        self.assertIn("vacuous", row["detail"])


class ShortLivedTests(unittest.TestCase):
    def test_cgroup_hints_match(self):
        ledger = "".join(cli_ledger({"C_GenerateRandom": 5})
                         for _ in range(20))
        hints = {"links_provider": 20, "links_pkcs11_loader": 0,
                 "no_static_link_within_scope": 0, "unknown": 0}
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="track-short-lived-cgroup",
                report=profile_report(calls={}, scope="cgroup", hints=hints),
                ledger=ledger,
                receipt=receipt_for("track-short-lived-cgroup",
                                    scope="cgroup"))
        self.assertEqual(rc, 0)
        self.assertTrue(row["pass"])

    def test_cgroup_hint_shortfall_fails(self):
        ledger = "".join(cli_ledger({"C_GenerateRandom": 5})
                         for _ in range(20))
        hints = {"links_provider": 19, "links_pkcs11_loader": 0,
                 "no_static_link_within_scope": 0, "unknown": 0}
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="track-short-lived-cgroup",
                report=profile_report(calls={}, scope="cgroup", hints=hints),
                ledger=ledger,
                receipt=receipt_for("track-short-lived-cgroup",
                                    scope="cgroup"))
        self.assertEqual(rc, 1)
        self.assertFalse(row["pass"])

    def test_pid_records_nothing(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="track-short-lived-pid",
                report=profile_report(calls={"C_GenerateRandom": 100},
                                      hints=None),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("track-short-lived-pid"))
        self.assertEqual(rc, 0)
        self.assertTrue(row["pass"])

    def test_pid_with_hints_fails(self):
        hints = {"links_provider": 1, "links_pkcs11_loader": 0,
                 "no_static_link_within_scope": 0, "unknown": 0}
        with tempfile.TemporaryDirectory() as raw:
            rc, row = run_oracle(
                Path(raw), cell="track-short-lived-pid",
                report=profile_report(calls={"C_GenerateRandom": 100},
                                      hints=hints),
                ledger=cli_ledger({"C_GenerateRandom": 100}),
                receipt=receipt_for("track-short-lived-pid"))
        self.assertEqual(rc, 1)
        self.assertIn("exe hints", row["detail"])


LIFECYCLE_CELLS = [
    "profile-pid-reload", "run-exec-chain", "profile-system-exec-churn",
    "profile-pid-reuse", "prearm-late-dlopen", "prearm-late-dlopen-noflag",
    "track-short-lived-cgroup", "track-short-lived-refused",
    "track-short-lived-pid",
]


def extract_python_block(path, marker):
    text = Path(path).read_text(encoding="utf-8")
    start = text.index(marker)
    heredoc = text.index("<<'PY'", start) + len("<<'PY'")
    code_start = text.index("\n", heredoc) + 1
    code_end = text.index("\nPY", code_start)
    return text[code_start:code_end]


def write_results(tmp, *, nonqualifying_cell=None):
    path = Path(tmp) / "results.jsonl"
    with open(path, "w", encoding="utf-8") as handle:
        for cell in LIFECYCLE_CELLS:
            if cell == nonqualifying_cell:
                row = {"cell": cell, "pass": False,
                       "qualification": "nonqualifying",
                       "detail": "smoke; not a qualifying proof"}
            elif cell == "prearm-late-dlopen":
                row = {"cell": cell, "pass": False,
                       "qualification": "expected-failure",
                       "detail": "lossy observation [WU-13]"}
            else:
                row = {"cell": cell, "pass": True,
                       "qualification": "qualified",
                       "detail": "ok"}
            handle.write(json.dumps(row) + "\n")
    return path


class WrapperTests(unittest.TestCase):
    def test_ci_wrapper_rejects_unlisted_nonqualifying(self):
        code = extract_python_block(
            ROOT / "scripts/ci/lifecycle-cli.sh", "python3 - ")
        with tempfile.TemporaryDirectory() as raw:
            bad = write_results(
                raw, nonqualifying_cell="profile-pid-reload")
            completed = subprocess.run(
                [sys.executable, "-I", "-", str(bad)],
                input=code, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(
                completed.returncode, 0,
                f"unlisted nonqualifying accepted: {completed.stdout}")
            good = write_results(raw, nonqualifying_cell=None)
            completed = subprocess.run(
                [sys.executable, "-I", "-", str(good)],
                input=code, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0,
                             f"qualified rows rejected: {completed.stdout}")

    def test_qualify_summary_rejects_unlisted_nonqualifying(self):
        code = extract_python_block(
            ROOT / "scripts/qualify-lifecycle-cli.sh", 'python3 - "$@"')
        with tempfile.TemporaryDirectory() as raw:
            write_results(raw, nonqualifying_cell="profile-pid-reload")
            # The summary block reads results.jsonl from its cwd, which
            # write_results already populates.
            completed = subprocess.run(
                [sys.executable, "-I", "-", *LIFECYCLE_CELLS],
                input=code, capture_output=True, text=True, timeout=30,
                cwd=raw)
            self.assertNotEqual(
                completed.returncode, 0,
                f"unlisted nonqualifying accepted: {completed.stdout}")
            write_results(raw, nonqualifying_cell=None)
            completed = subprocess.run(
                [sys.executable, "-I", "-", *LIFECYCLE_CELLS],
                input=code, capture_output=True, text=True, timeout=30,
                cwd=raw)
            self.assertEqual(completed.returncode, 0,
                             f"qualified rows rejected: {completed.stdout}")


if __name__ == "__main__":
    unittest.main()
