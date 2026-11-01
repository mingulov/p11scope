#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gated fixture driver: protocol, barriers, reaping (self-test).

Drives scripts/ci/key_operations_fixture.py against a fake fixture
(a shell stub honoring the bare-byte G/F barriers behind gate files)
through the happy path and every failure mode: early exit, non-JSON
rows, gate timeouts, bad exits. No SoftHSM, no observer, no privilege.
Run as a script:

    python3 -I tests/python/test_key_operations_fixture.py -v
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "scripts/ci/key_operations_fixture.py"

sys.path.insert(0, str(ROOT / "scripts/ci"))
import key_operations_fixture as driver_mod  # noqa: E402


FAKE_FIXTURE = """#!/bin/sh
# Fake rsa-ledger: bare-byte G/F barriers, canned JSONL rows.
# Env: FAKE_MODE (rows|early|nonjson|silent|eof-hold), FAKE_EXIT, FAKE_SLEEP.
mode=${FAKE_MODE:-rows}
if [ "$mode" = early ]; then
    echo "application call C_Initialize returned unexpected CK_RV 0x5" >&2
    exit 1
fi
echo '{"seq":1,"kind":"header","time_ns":1}'
echo '{"seq":2,"kind":"ready","time_ns":2}'
go=$(dd bs=1 count=1 2>/dev/null)
[ "$go" = G ] || exit 3
if [ "$mode" = nonjson ]; then
    echo "NOT JSON"
    exit 0
fi
if [ "$mode" = silent ]; then
    sleep 120
    exit 0
fi
if [ "$mode" = eof-hold ]; then
    exec >&-
    sleep 120
    exit 1
fi
[ -n "${FAKE_SLEEP:-}" ] && sleep "$FAKE_SLEEP"
echo '{"seq":3,"kind":"sign","time_ns":3}'
echo '{"seq":4,"kind":"done","time_ns":4}'
fin=$(dd bs=1 count=1 2>/dev/null)
[ "$fin" = F ] || exit 3
exit "${FAKE_EXIT:-0}"
"""


class FixtureDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-keyops-fixture-")
        self.directory = Path(self.temporary.name)
        self.fixture = self.directory / "fake-fixture"
        self.fixture.write_text(FAKE_FIXTURE)
        self.fixture.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def gates(self):
        paths = {}
        for name in ("ledger.jsonl", "gofile", "donefile", "stopfile"):
            paths[name] = str(self.directory / name)
        return paths

    def run_driver(self, timeout_s="20", env=None):
        paths = self.gates()
        full_env = dict(os.environ)
        full_env.update(env or {})
        proc = subprocess.Popen(
            [sys.executable, "-I", str(DRIVER), str(self.fixture),
             "/nonexistent-provider.so", paths["ledger.jsonl"],
             paths["gofile"], paths["donefile"], paths["stopfile"],
             timeout_s],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=full_env)
        return proc, paths

    def test_happy_path(self):
        proc, paths = self.run_driver(env={"FAKE_EXIT": "0"})
        try:
            Path(paths["gofile"]).touch()
            deadline = time.monotonic() + 15
            while not os.path.exists(paths["donefile"]):
                self.assertLess(time.monotonic(), deadline, "no donefile")
                self.assertIsNone(proc.poll(), proc.stderr.read()[:300]
                                  if proc.poll() is not None else "")
                time.sleep(0.05)
            Path(paths["stopfile"]).touch()
            out, err = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 0, err)
        self.assertRegex(out, r"pid=\d+")
        self.assertIn("exit=0 kinds=4", out)
        ledger = Path(paths["ledger.jsonl"]).read_text().splitlines()
        self.assertEqual(len(ledger), 4)
        self.assertIn('"done"', ledger[-1])

    def test_fixture_early_exit_is_failure(self):
        proc, paths = self.run_driver(env={"FAKE_MODE": "early"})
        try:
            out, err = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("before ready", err)
        # The ledger still lands (partial here: nothing was emitted).
        self.assertTrue(Path(paths["ledger.jsonl"]).exists())

    def test_non_json_row_is_failure(self):
        proc, paths = self.run_driver(env={"FAKE_MODE": "nonjson"})
        try:
            Path(paths["gofile"]).touch()
            out, err = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("non-JSON", err)
        ledger = Path(paths["ledger.jsonl"]).read_text()
        self.assertIn('"ready"', ledger)

    def test_go_gate_timeout_is_failure(self):
        proc, paths = self.run_driver(timeout_s="2")
        try:
            out, err = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("go gate", err)

    def test_silent_fixture_trips_the_row_deadline(self):
        # The driver blocks in read_row while the fixture holds its
        # stdout open and silent for 120 s; the 3 s deadline must trip
        # instead of wedging the wait.
        proc, paths = self.run_driver(
            timeout_s="3", env={"FAKE_MODE": "silent"})
        try:
            Path(paths["gofile"]).touch()
            start = time.monotonic()
            out, err = proc.communicate(timeout=60)
            elapsed = time.monotonic() - start
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("timeout waiting for done", err)
        self.assertLess(elapsed, 60, "deadline not honored in read")

    def test_stdout_eof_with_live_stderr_fails_fast(self):
        # The fixture closes stdout but holds stderr open for 120 s;
        # the EOF diagnostic drain must not block on the live child.
        proc, paths = self.run_driver(
            timeout_s="30", env={"FAKE_MODE": "eof-hold"})
        try:
            Path(paths["gofile"]).touch()
            start = time.monotonic()
            out, err = proc.communicate(timeout=60)
            elapsed = time.monotonic() - start
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("before done", err)
        self.assertLess(elapsed, 60, "stderr drain blocked")

    def test_bad_exit_after_f_is_failure(self):
        proc, paths = self.run_driver(env={"FAKE_EXIT": "7"})
        try:
            Path(paths["gofile"]).touch()
            deadline = time.monotonic() + 15
            while not os.path.exists(paths["donefile"]):
                self.assertLess(time.monotonic(), deadline, "no donefile")
                self.assertIsNone(proc.poll())
                time.sleep(0.05)
            Path(paths["stopfile"]).touch()
            out, err = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("exit 7", err)

    def test_usage_error(self):
        proc = subprocess.run(
            [sys.executable, "-I", str(DRIVER), "only-one-arg"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 2)

    def test_imported_run_reports_pid_and_reaps(self):
        paths = self.gates()
        Path(paths["gofile"]).touch()
        Path(paths["stopfile"]).touch()
        seen = []
        result = driver_mod.run_gated_fixture(
            str(self.fixture), "/nonexistent-provider.so",
            paths["ledger.jsonl"], paths["gofile"], paths["donefile"],
            paths["stopfile"], 20, dict(os.environ),
            on_spawn=seen.append)
        self.assertEqual(result["exit"], 0)
        self.assertEqual(result["kinds"], 4)
        self.assertEqual(seen, [result["pid"]])
        self.assertFalse(Path(f"/proc/{result['pid']}").exists(),
                         "fixture child was not reaped")


if __name__ == "__main__":
    unittest.main()
