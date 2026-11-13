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

    def test_missing_kvm_node_warns_and_still_runs_the_child(self):
        # A missing node means TCG, not a refusal: vng boots without
        # /dev/kvm (virtme can_use_kvm falls back), so the watch must
        # record the failure and run the child.
        env = {"VNG_BOOT_WATCH_TEST": "0",
               "VNG_KVM_NODE": str(self.work / "no-such-kvm")}
        result, _, _, console, diag = self.run_helper(
            "sh", "-c", "echo guest-bytes; exit 0", extra_env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(console.read_text(encoding="utf-8"), "guest-bytes\n")
        self.assertNotIn("VNG_KVM_UNUSABLE", result.stderr)
        body = diag.read_text(encoding="utf-8")
        self.assertIn("reason=node-missing-or-not-char", body)
        self.assertIn("kvm_expected_accel=tcg-fallback", body)
        self.assertIn("result=passthrough rc=0 booted=1", body)

    def test_wrong_kvm_node_warns_and_still_runs_the_child(self):
        # /dev/null opens but is not KVM: the API ioctl fails, which
        # selects TCG instead of refusing the boot.
        env = {"VNG_BOOT_WATCH_TEST": "0", "VNG_KVM_NODE": "/dev/null"}
        result, _, _, console, diag = self.run_helper(
            "sh", "-c", "echo guest-bytes; exit 0", extra_env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(console.read_text(encoding="utf-8"), "guest-bytes\n")
        self.assertNotIn("VNG_KVM_UNUSABLE", result.stderr)
        body = diag.read_text(encoding="utf-8")
        self.assertIn("reason=api:", body)
        self.assertIn("kvm_expected_accel=tcg-fallback", body)
        self.assertIn("result=passthrough rc=0 booted=1", body)

    def test_permission_denied_kvm_node_still_boots_with_tcg_fallback(self):
        # CI run 43460470603: the qemu install re-applied udev perms
        # (0660 root:kvm) after the workflow's chmod 0666, so the
        # probe's open got EACCES while vng boots anyway (virtme
        # can_use_kvm treats a denied open as "use TCG"). /dev/mem is
        # a char node that denies non-root O_RDWR and whose ioctls can
        # never satisfy KVM: the probe must record the failure and
        # still start the child.
        try:
            fd = os.open("/dev/mem", os.O_RDWR)
        except PermissionError:
            denied = True
        except OSError:
            denied = False  # missing node or other error: still unusable KVM
        else:
            os.close(fd)
            denied = False  # root: the open works, the KVM ioctl refuses
        marker = self.work / "marker"
        result, _, _, console, diag = self.run_helper(
            "sh", "-c", f"echo guest-bytes; echo 6.6.157 > {marker}; exit 0",
            extra_env={"VNG_BOOT_WATCH_TEST": "0",
                       "VNG_KVM_NODE": "/dev/mem"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(console.read_text(encoding="utf-8"), "guest-bytes\n")
        self.assertNotIn("VNG_KVM_UNUSABLE", result.stderr)
        body = diag.read_text(encoding="utf-8")
        self.assertIn("kvm_probe=fail", body)
        if denied:
            self.assertIn("reason=open:", body)
        self.assertIn("kvm_expected_accel=tcg-fallback", body)
        self.assertIn("result=passthrough rc=0 booted=1", body)

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
