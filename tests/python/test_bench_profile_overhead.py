#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Profile-overhead bench: harness self-test wiring.

Runs scripts/bench-profile-overhead.sh --self-test (unprivileged) and
checks its usage refusal. The self-test itself covers the SAMPLE/MEM
parsing, the memory-line key checks, and the refuse-path trap. Run as
a script:

    python3 -I tests/python/test_bench_profile_overhead.py -v
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "scripts/bench-profile-overhead.sh"


class BenchHarnessTests(unittest.TestCase):
    def test_bench_self_test(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-profileoverhead-suite-") as work:
            env = dict(os.environ, TMPDIR=work)
            proc = subprocess.run(
                ["sh", str(BENCH), "--self-test"],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("self-test OK", proc.stdout)

    def test_usage_refuses_extra_args(self):
        proc = subprocess.run(
            ["sh", str(BENCH), "--bogus"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("usage", proc.stderr)


if __name__ == "__main__":
    unittest.main()
