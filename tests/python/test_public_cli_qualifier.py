# SPDX-License-Identifier: GPL-3.0-or-later
"""Public CLI qualifier harness: expected-failure, summary, startup, ia32, cgroup.

Tests the shell qualifier's handling of known product gaps (expected-failure
with named reasons, unexpected-pass fails), the summary contract, the startup
bound default, ia32 split modes and cgroup force cleanup. Functions are
extracted from scripts/qualify-public-cli.sh (not copied) so the tests track
the real code.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUAL = ROOT / "scripts/qualify-public-cli.sh"


def extract_functions(*names):
    """Extract named shell functions plus REASON_* lines from the qualifier."""
    parts = []
    for name in names:
        proc = subprocess.run(
            ["sed", "-n", f"/^{name}()/,/^}}/p", str(QUAL)],
            capture_output=True, text=True, timeout=5)
        parts.append(proc.stdout)
    proc = subprocess.run(
        ["grep", "^REASON_", str(QUAL)],
        capture_output=True, text=True, timeout=5)
    parts.append(proc.stdout)
    return "\n".join(parts)


def run_shell(body, *, cwd):
    """Run body with extracted qualifier functions sourced, return CompletedProcess."""
    funcs = extract_functions("result", "summary", "emit_judged")
    script = funcs + "\n" + body
    return subprocess.run(
        ["bash", "-u", "-c", script],
        capture_output=True, text=True, timeout=10, cwd=str(cwd))


def write_results(tmp, rows):
    path = tmp / "results.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return path


class SummaryTests(unittest.TestCase):
    def test_expected_failures_do_not_fail_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "trace-pid", "pass": False, "detail": "smoke",
             "qualification": "nonqualifying"},
            {"cell": "run-short", "pass": False,
             "detail": "run exact loss; product fix lane: [failed] loss or unknown discovery_truncated",
             "qualification": "expected-failure"},
            {"cell": "profile-cgroup", "pass": False,
             "detail": "cgroup fork gaps; product fix lane: [failed] lossy",
             "qualification": "expected-failure"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell(
                "summary doctor trace-pid run-short profile-cgroup; echo EXIT=$?",
                cwd=tmp)
        self.assertIn("EXIT=2", proc.stdout,
                      f"summary must exit 2 (valid with smoke/expected), got: {proc.stdout}\n{proc.stderr}")
        # tmp is cleaned with its summary.txt; check via stdout (tee prints too).
        self.assertIn("terminal_rows_valid=True", proc.stdout)

    def test_unexpected_pass_fails_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "run-short", "pass": True,
             "detail": "UNEXPECTED PASS (reason may have landed)",
             "qualification": "expected-failure"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell("summary doctor run-short; echo EXIT=$?", cwd=tmp)
        self.assertIn("EXIT=1", proc.stdout,
                      f"unexpected pass must fail summary with exit 1, got: {proc.stdout}\n{proc.stderr}")

    def test_qualified_failure_still_fails_summary(self):
        rows = [
            {"cell": "doctor", "pass": True, "detail": "rc=0",
             "qualification": "command-contract"},
            {"cell": "system", "pass": False, "detail": "loss",
             "qualification": "failed"},
        ]
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            write_results(tmp, rows)
            proc = run_shell("summary doctor system; echo EXIT=$?", cwd=tmp)
        self.assertIn("EXIT=1", proc.stdout,
                      f"qualified fail must exit 1, got: {proc.stdout}\n{proc.stderr}")


class EmitJudgedTests(unittest.TestCase):
    def test_known_gap_becomes_expected_failure(self):
        oracle_row = json.dumps({
            "cell": "run-short", "pass": False,
            "detail": "loss or unknown discovery_truncated",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged run-short 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        self.assertIn("EMIT_RC=0", proc.stdout,
                      f"known gap must emit expected with rc 0, got: {proc.stdout}\n{proc.stderr}")
        # Last line should be the emitted row.
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}")
        row = json.loads(lines[-1])
        self.assertEqual(row["cell"], "run-short")
        self.assertFalse(row["pass"])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertIn("product fix lane", row["detail"])

    def test_qualified_pass_becomes_unexpected_pass(self):
        oracle_row = json.dumps({
            "cell": "run-short", "pass": True,
            "detail": "owned physical-provider counts match",
            "qualification": "owned-provider-counts"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged run-short 0 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertTrue(row["pass"])
        self.assertIn("UNEXPECTED PASS", row["detail"])

    def test_unknown_failure_sig_stays_failed(self):
        oracle_row = json.dumps({
            "cell": "run-short", "pass": False,
            "detail": "some brand new failure mode never seen before",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged run-short 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "failed")
        self.assertFalse(row["pass"])

    def test_trace_cgroup_smoke_becomes_unexpected_pass(self):
        oracle_row = json.dumps({
            "cell": "trace-cgroup", "pass": False,
            "detail": "trace delivery/count checked with loss identity",
            "qualification": "nonqualifying"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged trace-cgroup 2 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertTrue(row["pass"])
        self.assertIn("UNEXPECTED PASS", row["detail"])

    def test_trace_cgroup_known_loss_becomes_expected(self):
        oracle_row = json.dumps({
            "cell": "trace-cgroup", "pass": False,
            "detail": "trace lossy or unknown observation gap class",
            "qualification": "failed"})
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "results.jsonl").write_text("")
            body = f"emit_judged trace-cgroup 1 '{oracle_row}'; echo EMIT_RC=$?; cat results.jsonl"
            proc = run_shell(body, cwd=tmp)
        lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, f"no emitted row in: {proc.stdout}\n{proc.stderr}")
        row = json.loads(lines[-1])
        self.assertEqual(row["qualification"], "expected-failure")
        self.assertFalse(row["pass"])


class ScriptTextTests(unittest.TestCase):
    def test_startup_bound_default_is_45(self):
        text = QUAL.read_text()
        self.assertIn("STARTUP_BOUND_S:-45", text,
                      "startup bound default must be 45s (7.2 measured 22-24s, 30s gives <20% margin)")
        self.assertNotIn("STARTUP_BOUND_S:-30", text,
                         "old 30s default must be gone")

    def test_expected_reasons_present(self):
        text = QUAL.read_text()
        for name in ("REASON_RUN", "REASON_CGROUP", "REASON_TRACE_CGROUP",
                     "REASON_INVENTORY_7X", "REASON_IA32"):
            self.assertIn(name, text, f"missing {name} with named product-gap reason")
        self.assertIn("product fix lane", text)

    def test_ia32_prereq_missing_is_expected(self):
        text = QUAL.read_text()
        # Default-mode prereq-missing branch must emit expected-failure, not failed.
        self.assertIn("REASON_IA32", text)
        # The old failed prereq message must be gone from the default branch
        # (ONLY mode still uses failed for missing prereq as a harness error).
        self.assertIn("P11SCOPE_PUBLIC_CLI_ONLY_IA32", text,
                      "ia32-only job mode must exist")
        self.assertIn("summary profile-pid-ia32 run-ia32", text,
                      "ia32-only mode must summarize exactly the two ia32 cells")

    def test_ia32_module_override_allowed(self):
        text = QUAL.read_text()
        self.assertIn("IA32_MODULE=${IA32_MODULE:-", text,
                      "IA32_MODULE must allow override for unpacked i386 copies")

    def test_cgroup_force_cleanup_present(self):
        text = QUAL.read_text()
        self.assertIn("cgroup.procs", text)
        self.assertIn("kill -KILL", text,
                      "cgroup cleanup must KILL leftover procs before retrying rmdir")
        self.assertIn("CGROUPS", text,
                      "owned cgroups must be tracked for EXIT cleanup")

    def test_inventory_conditional_expected(self):
        text = QUAL.read_text()
        self.assertIn("inventory gaps about owned module", text)
        self.assertIn("REASON_INVENTORY_7X", text,
                      "inventory 7.x gap must map to expected-failure with named reason")


if __name__ == "__main__":
    unittest.main()
