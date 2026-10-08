#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real-child regressions for the dashboard PTY driver's cleanup custody."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "dashboard_pty_drive", ROOT / "tests/fixtures/dashboard-pty-drive.py"
)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
REAL_KILL = os.kill


class DashboardPtyCleanupTests(unittest.TestCase):
    def setUp(self):
        self.children = []
        self.signals = []

    def tearDown(self):
        # Only signal an unreaped child of this test; never trust a stale PID.
        for pid in self.children:
            try:
                state = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                continue
            if state is None:
                REAL_KILL(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    def safe_kill(self, pid, sig):
        self.signals.append((pid, sig))
        try:
            state = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            self.fail("cleanup attempted to signal a PID after the child was reaped")
        self.assertIsNone(state, "cleanup signaled an already exited child")
        return REAL_KILL(pid, sig)

    def launch(self, *, exited=False):
        ready_read, ready_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.write(ready_write, b"1")
            os.close(ready_write)
            if not exited:
                time.sleep(30)
            os._exit(0)
        self.children.append(pid)
        os.close(ready_write)
        try:
            self.assertTrue(select.select([ready_read], [], [], 2)[0], "child launch deadline")
            self.assertEqual(os.read(ready_read, 1), b"1")
        finally:
            os.close(ready_read)
        if exited:
            deadline = time.monotonic() + 2
            while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                self.assertLess(time.monotonic(), deadline, "child exit deadline")
                time.sleep(0.005)
        return pid

    def owner(self, pid):
        self.assertTrue(hasattr(driver, "PtyChild"), "missing PTY child custody helper")
        return driver.PtyChild(pid)

    def run_main(self, script, budget):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "dashboard"
            binary.write_text(f"#!{sys.executable}\n" + script)
            binary.chmod(0o700)
            original_fork = driver.pty.fork

            def fork():
                pid, master = original_fork()
                if pid:
                    self.children.append(pid)
                return pid, master

            with patch.object(driver.pty, "fork", side_effect=fork), \
                    patch.object(driver.os, "kill", side_effect=self.safe_kill), \
                    patch.object(sys, "argv", ["driver", str(binary), "1", "60", str(budget)]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                result = driver.main()
            return result, output.getvalue()

    def test_successful_dashboard_reap_does_not_signal_in_finally(self):
        result, output = self.run_main(
            "import os,select,tty\n"
            "tty.setraw(0)\n"
            "os.write(1,b'\\x1b[?1049hp11scope inventory coverage:')\n"
            "while not select.select([0],[],[],0.02)[0]:\n"
            "    os.write(1,b'scroll 0/1')\n"
            "assert os.read(0,1)==b'j'\n"
            "while not select.select([0],[],[],0.02)[0]:\n"
            "    os.write(1,b'scroll 1/1')\n"
            "assert os.read(0,1)==b'q'\n"
            "os.write(1,b'\\x1b[?25h\\x1b[?1049ldashboard frames:')\n", 3
        )
        self.assertEqual(result, 0, output)
        self.assertIn("pty-dashboard: PASS", output)
        self.assertEqual(self.signals, [])

    def test_timeout_kills_live_dashboard_once_across_fail_and_finally(self):
        result, output = self.run_main("import time\ntime.sleep(30)\n", 0.05)
        self.assertEqual(result, 1)
        self.assertIn("timed out waiting for the first dashboard frame", output)
        self.assertEqual(self.signals, [(self.children[0], signal.SIGKILL)])
        with self.assertRaises(ChildProcessError):
            os.waitpid(self.children[0], os.WNOHANG)

    def test_successful_wait_keeps_cleanup_idempotent(self):
        pid = self.launch(exited=True)
        child = self.owner(pid)
        done, status = child.wait(0)
        self.assertEqual(done, pid)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        with patch.object(driver.os, "kill", side_effect=self.safe_kill):
            child.cleanup()
            child.cleanup()
        self.assertEqual(self.signals, [])

    def test_already_reaped_child_is_never_signaled(self):
        pid = self.launch(exited=True)
        child = self.owner(pid)
        os.waitpid(pid, 0)
        with patch.object(driver.os, "kill", side_effect=self.safe_kill):
            child.cleanup()
            child.cleanup()
        self.assertEqual(self.signals, [])

    def test_exited_unreaped_child_is_reaped_without_a_signal(self):
        pid = self.launch(exited=True)
        child = self.owner(pid)
        with patch.object(driver.os, "kill", side_effect=self.safe_kill):
            child.cleanup()
            child.cleanup()
        self.assertEqual(self.signals, [])
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_error_cleanup_kills_and_reaps_live_child_once(self):
        pid = self.launch()
        child = self.owner(pid)
        with patch.object(driver.os, "kill", side_effect=self.safe_kill), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = driver.fail("owned error", bytearray(b"last frame"), child)
            child.cleanup()
            child.cleanup()
        self.assertEqual(result, 1)
        self.assertIn("pty-dashboard FAILED: owned error\nlast frame", output.getvalue())
        self.assertEqual(self.signals, [(pid, signal.SIGKILL)])
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


if __name__ == "__main__":
    unittest.main()
