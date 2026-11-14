#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""mem-churn.py driver contract: docs accuracy, workdir hygiene, forked split.

The v0.8.0 memory-soak churn driver (scripts/mem-churn.py) initializes one
throwaway token in a private dir, must leave no workdir behind on a clean
exit, and must count forked iterations only in `forked` (the `done` line
partitions: ok + fail + forked == iterations). Run as a script:

    python3 -I tests/python/test_mem_churn.py -v
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHURN = ROOT / "scripts" / "mem-churn.py"

CANDIDATE_LIBS = [
    os.environ.get("SOFTHSM_LIB", ""),
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Debian/Ubuntu
    "/usr/lib64/pkcs11/libsofthsm2.so",  # Fedora
]

DONE_RE = re.compile(
    r"mem-churn: done t=\S+s iterations=(\d+) ok=(\d+) fail=(\d+) "
    r"forked=(\d+) rate=\S+/s"
)


def probe_lib():
    for path in CANDIDATE_LIBS:
        if path and os.access(path, os.R_OK):
            return path
    return None


class DriverDocs(unittest.TestCase):
    def test_docstring_states_throwaway_token_init(self):
        source = CHURN.read_text(encoding="utf-8")
        # The driver initializes slot 0 in its private conf, so the
        # docstring must say so instead of claiming no init happens.
        self.assertIn("--init-token", source)
        self.assertNotIn("never initializes a token", source)
        self.assertIn("throwaway token", source)


class DriverRun(unittest.TestCase):
    def run_churn(self, tmpdir, *args):
        env = dict(os.environ, TMPDIR=str(tmpdir))
        proc = subprocess.run(
            [sys.executable, "-I", str(CHURN), *args],
            env=env, capture_output=True, text=True, timeout=120,
        )
        return proc

    def test_workdir_removed_after_clean_exit(self):
        if probe_lib() is None:
            self.skipTest("requires existing SoftHSM; installs nothing")
        with tempfile.TemporaryDirectory(prefix="churn-workdir-") as work:
            tmpdir = Path(work)
            proc = self.run_churn(
                tmpdir, "--rate", "20", "--fail-share", "0.2",
                "--fork-every", "0", "--duration", "2",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            self.assertRegex(proc.stdout + proc.stderr, r"mem-churn: done ")
            leftovers = list(tmpdir.glob("mem-churn-*"))
            self.assertEqual(leftovers, [])

    def test_keep_workdir_preserves_the_token_dir(self):
        if probe_lib() is None:
            self.skipTest("requires existing SoftHSM; installs nothing")
        with tempfile.TemporaryDirectory(prefix="churn-keep-") as work:
            tmpdir = Path(work)
            proc = self.run_churn(
                tmpdir, "--rate", "20", "--fail-share", "0",
                "--fork-every", "0", "--duration", "1", "--keep-workdir",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            kept = list(tmpdir.glob("mem-churn-*"))
            self.assertEqual(len(kept), 1)
            self.assertTrue((kept[0] / "softhsm2.conf").is_file())

    def test_forked_iterations_counted_outside_ok(self):
        if probe_lib() is None:
            self.skipTest("requires existing SoftHSM; installs nothing")
        with tempfile.TemporaryDirectory(prefix="churn-fork-") as work:
            proc = self.run_churn(
                Path(work), "--rate", "50", "--fail-share", "0",
                "--fork-every", "2", "--duration", "2",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            match = DONE_RE.search(proc.stdout)
            self.assertIsNotNone(match, proc.stdout[-2000:])
            iterations, ok, fail, forked = (int(g) for g in match.groups())
            self.assertGreater(forked, 0)
            self.assertEqual(ok + fail + forked, iterations)


if __name__ == "__main__":
    unittest.main()
