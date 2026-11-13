#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The vng boot watchdog: KVM pre-flight, silent-hang trip, passthrough.

Drives scripts/ci/vng-boot-watch.sh directly with stub children (no KVM,
no vng, no root): the KVM probe failure arms use fake device nodes, the
watchdog arms use sleep/print stubs, and VNG_BOOT_WATCH_TEST=1 skips the
live probe where the probe itself is not under test. The probe SUCCESS
arm needs an openable /dev/kvm, which CI script lanes lack, so it is
proven by live vng runs instead of a self-skipping test here.

Run: python3 -I tests/python/test_vng_boot_watch.py -v
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/ci/vng-boot-watch.sh"


class BootWatchTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "scripts/ci/vng-boot-watch.sh is missing")
        self.assertTrue(os.access(HELPER, os.X_OK), "vng-boot-watch.sh is not executable")
        self.temp = tempfile.TemporaryDirectory(prefix="vng-boot-watch-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def run_helper(self, *child, extra_env=None, timeout=60):
        marker = self.work / "marker"
        console = self.work / "console.log"
        diag = self.work / "diag.log"
        env = dict(os.environ, VNG_BOOT_WATCH_TEST="1")
        if extra_env:
            env.update(extra_env)
        command = [str(HELPER), "--marker", str(marker),
                   "--console", str(console), "--diag", str(diag),
                   "--", *child]
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, env=env)
        return result, time.monotonic() - start, marker, console, diag

    def test_passthrough_keeps_the_child_exit_and_console(self):
        result, _, _, console, diag = self.run_helper(
            "sh", "-c", "echo guest-bytes; exit 7")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(console.read_text(encoding="utf-8"), "guest-bytes\n")
        body = diag.read_text(encoding="utf-8")
        self.assertIn("result=passthrough rc=7 booted=1", body)
        self.assertIn("kvm_probe=skipped(test)", body)

    def test_console_bytes_cancel_the_trip(self):
        # A child that prints but exits nonzero is a guest failure, not
        # a boot hang: no trip, exit passes through.
        result, _, _, _, diag = self.run_helper(
            "sh", "-c", "echo cells-done; exit 3")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("VNG_BOOT_TIMEOUT", result.stderr)
        self.assertIn("booted=1", diag.read_text(encoding="utf-8"))

    def test_marker_cancels_the_trip(self):
        # The marker is the first file the guest script writes through
        # the 9p rwdir; its appearance proves the guest runs even when
        # the console is still empty.
        marker = self.work / "marker"
        result, _, _, _, diag = self.run_helper(
            "sh", "-c", f"echo 6.6.157 > {marker}; exit 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("VNG_BOOT_TIMEOUT", result.stderr)
        self.assertIn("marker=present-nonempty", diag.read_text(encoding="utf-8"))

    def test_silent_hang_trips_fast_with_diagnostics(self):
        # The CI zero-byte signature: nothing on the console, no marker.
        # The stub sleeps 30s; the deadline here is 3s.
        result, elapsed, _, console, diag = self.run_helper(
            "sleep", "30", extra_env={"VNG_BOOT_TIMEOUT_S": "3"})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("VNG_BOOT_TIMEOUT", result.stderr)
        self.assertEqual(console.read_bytes(), b"")
        body = diag.read_text(encoding="utf-8")
        for pin in ("vng_boot_watch=1", "boot_timeout_s=3",
                    "result=VNG_BOOT_TIMEOUT", "console_bytes=0",
                    "marker=missing", "child_pid=", "--- group ---",
                    "--- qemu ---", "--- kvm ---", "--- load ---"):
            with self.subTest(pin=pin):
                self.assertIn(pin, body)
        self.assertLess(elapsed, 25, f"watchdog did not trip fast: {elapsed:.1f}s")

    def test_missing_kvm_node_fails_without_starting_the_child(self):
        env = {"VNG_BOOT_WATCH_TEST": "0",
               "VNG_KVM_NODE": str(self.work / "no-such-kvm")}
        result, _, _, console, diag = self.run_helper("echo", "no", extra_env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("VNG_KVM_UNUSABLE", result.stderr)
        self.assertIn("reason=node-missing-or-not-char", result.stderr)
        self.assertFalse(console.exists(), "the child must not start without KVM")
        body = diag.read_text(encoding="utf-8")
        self.assertIn("result=VNG_KVM_UNUSABLE", body)

    def test_wrong_kvm_node_fails_on_the_ioctl(self):
        # /dev/null opens but is not KVM: the API ioctl must refuse it.
        env = {"VNG_BOOT_WATCH_TEST": "0", "VNG_KVM_NODE": "/dev/null"}
        result, _, _, console, _ = self.run_helper("echo", "no", extra_env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("VNG_KVM_UNUSABLE", result.stderr)
        self.assertIn("reason=api:", result.stderr)
        self.assertFalse(console.exists(), "the child must not start without KVM")

    def test_test_mode_skips_the_probe(self):
        env = {"VNG_KVM_NODE": str(self.work / "no-such-kvm")}
        result, _, _, console, diag = self.run_helper(
            "sh", "-c", "echo ok", extra_env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(console.read_text(encoding="utf-8"), "ok\n")
        self.assertIn("kvm_probe=skipped(test)", diag.read_text(encoding="utf-8"))

    def test_bad_usage_exits_two(self):
        env = dict(os.environ)
        for argv in ([], ["--marker", "m"],
                    ["--marker", "m", "--console", "c", "--diag", "d"],
                    ["--marker", "m", "--console", "c", "--diag", "d",
                     "--"]):
            with self.subTest(argv=argv):
                result = subprocess.run([str(HELPER), *argv],
                                        capture_output=True, text=True,
                                        timeout=30, env=env)
                self.assertEqual(result.returncode, 2, result.stderr)
        env["VNG_BOOT_TIMEOUT_S"] = "soon"
        result = subprocess.run(
            [str(HELPER), "--marker", "m", "--console", "c",
             "--diag", str(self.work / "d"), "--", "echo", "hi"],
            capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("VNG_BOOT_TIMEOUT_S", result.stderr)


if __name__ == "__main__":
    unittest.main()
