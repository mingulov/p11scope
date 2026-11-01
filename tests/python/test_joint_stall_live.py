#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Joint stall live cell twins: driver and script oracle.

The live cell (scripts/ci/joint-stall-live.sh) proves the Joint finish
neither stalls nor abandons under route pressure, refresh churn and fault
bursts. This suite pins its two owned parts without privileges:

- the refresh-churn driver (tests/fixtures/joint-stall/refresh-churn.c)
  builds warning-free, its --help/--dry-run need no provider, its
  --short mode fails closed on a missing provider, and its long mode
  alternates exec/reload with accumulated totals and an absolute
  deadline, driven against an in-suite stub provider;
- the script oracle (--check-run) accepts a healthy run and rejects a
  no-progress trip (with h0_below/staged_max/floor), an abandon, a slow
  run, a live-publication stderr line and a disposition error, plus
  malformed inputs; --self-test passes.

Healthy and mutation twins run unignored; no SoftHSM install is needed.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVER_SRC = ROOT / "tests" / "fixtures" / "joint-stall" / "refresh-churn.c"
SCRIPT = ROOT / "scripts" / "ci" / "joint-stall-live.sh"

STUB_PROVIDER_C = r"""
/* Test-only stub PKCS#11 provider: immediate OK returns, no state. */
typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef struct { unsigned long mechanism; void *p; unsigned long len; } CK_MECHANISM;
CK_RV C_Initialize(void *a) { (void)a; return 0; }
CK_RV C_Finalize(void *a) { (void)a; return 0; }
CK_RV C_GetSlotList(int token, CK_SLOT_ID *slots, CK_ULONG *n) {
    (void)token;
    if (slots == 0 || n == 0 || *n < 1) return 1;
    slots[0] = 1; *n = 1; return 0;
}
CK_RV C_OpenSession(CK_SLOT_ID s, CK_FLAGS f, void *a, void *b, CK_SESSION_HANDLE *h) {
    (void)s; (void)f; (void)a; (void)b; *h = 42; return 0;
}
CK_RV C_CloseSession(CK_SESSION_HANDLE h) { (void)h; return 0; }
CK_RV C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM *m) { (void)h; (void)m; return 0; }
CK_RV C_Digest(CK_SESSION_HANDLE h, CK_BYTE *in, CK_ULONG in_len, CK_BYTE *out, CK_ULONG *out_len) {
    (void)h; (void)in; (void)in_len; (void)out;
    if (out_len != 0) {
        *out_len = 32;
    }
    return 0;
}
"""


def run_ok(argv, **kwargs):
    proc = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    return proc


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DRIVER_SRC.exists():
            raise unittest.SkipTest(f"driver source missing: {DRIVER_SRC}")
        if shutil.which("gcc") is None:
            raise unittest.SkipTest("gcc required")
        cls.work = Path(tempfile.mkdtemp(prefix="joint-stall-driver-"))
        cls.exe = cls.work / "refresh-churn"
        proc = run_ok(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-o", str(cls.exe), str(DRIVER_SRC), "-ldl"])
        if proc.returncode != 0:
            raise AssertionError(f"driver build failed: {proc.stderr}")
        stub_c = cls.work / "stub.c"
        stub_c.write_text(STUB_PROVIDER_C, encoding="utf-8")
        cls.stub = cls.work / "stub.so"
        proc = run_ok(["gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
                       "-Werror", "-o", str(cls.stub), str(stub_c)])
        if proc.returncode != 0:
            raise AssertionError(f"stub build failed: {proc.stderr}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_help_needs_no_provider(self):
        proc = run_ok([str(self.exe), "--help"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PROVIDER", proc.stdout)

    def test_dry_run_needs_no_provider(self):
        proc = run_ok([str(self.exe), "--dry-run", "/nonexistent/x.so",
                       "5", "10", "60"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("total_ops=50", proc.stdout)
        self.assertIn("exec,reload,exec,reload", proc.stdout)

    def test_dry_run_rejects_bad_numbers(self):
        proc = run_ok([str(self.exe), "--dry-run", "/nonexistent/x.so",
                       "0", "10", "60"])
        self.assertEqual(proc.returncode, 2)

    def test_short_fails_closed_on_missing_provider(self):
        proc = run_ok([str(self.exe), "--short", "/nonexistent/x.so"])
        self.assertEqual(proc.returncode, 2)

    def test_short_ok_on_stub(self):
        proc = run_ok([str(self.exe), "--short", str(self.stub)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout, r"LEDGER mode=short calls=2 ok=2 pid=\d+")

    def test_long_exec_reload_chain_accumulates(self):
        proc = run_ok([str(self.exe), str(self.stub), "4", "3", "30"],
                      timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        ledgers = [line for line in lines if line.startswith("LEDGER ")]
        dones = [line for line in lines if line.startswith("DONE ")]
        self.assertEqual(len(ledgers), 4, proc.stdout)
        self.assertEqual(len(dones), 1, proc.stdout)
        # Alternation: exec, reload, exec.
        self.assertIn("next=exec", ledgers[0])
        self.assertIn("next=reload", ledgers[1])
        self.assertIn("next=exec", ledgers[2])
        self.assertIn("next=done", ledgers[3])
        # Totals accumulate across the two exec images: 4 rounds x 3 ops.
        self.assertRegex(dones[0], r"rounds=4 ops=12 calls=24 ok=24")

    def test_long_deadline_cuts_with_rc1(self):
        proc = run_ok([str(self.exe), str(self.stub), "100000", "1000", "1"],
                      timeout=30)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("DONE ", proc.stdout)


class ScriptOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SCRIPT.exists():
            raise unittest.SkipTest(f"script missing: {SCRIPT}")
        if not os.access(SCRIPT, os.X_OK):
            raise AssertionError("script is not executable")

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="joint-stall-oracle-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def write(self, name, text):
        path = self.work / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def check(self, run_json, stderr_text, duration=30, wall=35,
              exit_code=0, slack=60):
        run_path = self.write("run.json", run_json)
        err_path = self.write("run.stderr", stderr_text)
        proc = run_ok([str(SCRIPT), "--check-run", run_path, err_path,
                       str(duration), str(wall), str(exit_code), str(slack)])
        try:
            payload = json.loads(proc.stdout)
        except ValueError:
            self.fail(f"oracle printed no JSON: {proc.stdout!r} {proc.stderr!r}")
        return proc.returncode, payload

    def test_help(self):
        proc = run_ok([str(SCRIPT), "--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("P11SCOPE OUTDIR", proc.stdout)

    def test_self_test_passes(self):
        proc = run_ok([str(SCRIPT), "--self-test"], timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("fail=0", proc.stdout)

    def test_script_lists_apt_prerequisites(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for token in ("gcc", "python3", "softhsm2"):
            self.assertIn(token, text)

    def test_healthy_run_passes(self):
        rc, payload = self.check(
            '{"gaps": [], "observation": {"lifecycle": {"records": 5, "ring_loss": 0}}}',
            "")
        self.assertEqual(rc, 0, payload)
        self.assertTrue(payload["stall_ok"])
        self.assertTrue(payload["wedge_ok"])

    def test_trip_fails_with_watermarks(self):
        rc, payload = self.check(
            '{"gaps": [{"subject": "joint finish made no progress", '
            '"reason": "6s without progress across 10 polls in Audited; x; '
            'h0_below=Some(11), staged_max=None, floor=Some(7)"}]}',
            "joint finish made no progress for 6s across 10 polls")
        self.assertEqual(rc, 1, payload)
        self.assertFalse(payload["stall_ok"])
        self.assertFalse(payload["wedge_ok"])
        self.assertTrue(payload["no_progress"])
        trip = payload["trips"][0]
        self.assertEqual(trip["h0_below"], "11")
        self.assertIsNone(trip["staged_max"])
        self.assertEqual(trip["floor"], "7")

    def test_audit_trip_fails(self):
        rc, payload = self.check(
            '{"gaps": [{"subject": "joint audit made no progress", "reason": "x"}]}',
            "")
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload["no_progress"])

    def test_abandon_fails_wedge_only(self):
        rc, payload = self.check(
            '{"gaps": [{"subject": "joint finish abandoned for exit", "reason": "r"}]}',
            "")
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload["stall_ok"])
        self.assertFalse(payload["wedge_ok"])
        self.assertEqual(payload["abandons"], 1)

    def test_mutation_wrong_subject_passes(self):
        # A renamed subject must not trip the oracle: only the exact
        # production subjects fail.
        rc, payload = self.check(
            '{"gaps": [{"subject": "joint finish made progress", "reason": "x"}]}',
            "")
        self.assertEqual(rc, 0, payload)
        self.assertFalse(payload["no_progress"])

    def test_slow_run_fails_stall(self):
        rc, payload = self.check('{"gaps": []}', "", duration=30, wall=200)
        self.assertEqual(rc, 1, payload)
        self.assertFalse(payload["time_ok"])
        self.assertFalse(payload["stall_ok"])

    def test_live_publication_stderr_fails_wedge(self):
        rc, payload = self.check(
            '{"gaps": []}',
            "p11scope: live publication made no progress for 6 s; abandoned it")
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload["stderr_no_progress"])
        self.assertFalse(payload["wedge_ok"])

    def test_disposition_stderr_fails_wedge(self):
        rc, payload = self.check('{"gaps": []}',
                                 "joint finish disposition required",
                                 exit_code=1)
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload["stderr_disposition"])
        self.assertFalse(payload["wedge_ok"])

    def test_bad_json_fails(self):
        rc, _ = self.check("not json", "")
        self.assertEqual(rc, 1)

    def test_missing_run_json_fails(self):
        err_path = self.write("run.stderr", "")
        proc = run_ok([str(SCRIPT), "--check-run", str(self.work / "nope.json"),
                       err_path, "30", "35", "0", "60"])
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
