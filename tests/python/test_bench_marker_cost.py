#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Marker-cost bench: harness self-tests and analyzer checks.

Runs scripts/bench-marker-cost.sh --self-test and --dry-run (both
unprivileged), verifies the rotation plan, and checks
scripts/bench-marker-cost-analyze.py on an independent hand-written
campaign (exact medians and deltas) plus a truncated-log must-fail
(non-vacuity). The analyzer's own --self-test covers the remaining
failure modes. Run as a script:

    python3 -I tests/python/test_bench_marker_cost.py -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "scripts/bench-marker-cost.sh"
ANALYZE = ROOT / "scripts/bench-marker-cost-analyze.py"

sys.path.insert(0, str(ROOT / "scripts"))
import importlib.util  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "bench_marker_cost_analyze", str(ANALYZE))
ANALYZER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ANALYZER)


def campaign_fixture(directory, rounds=1, drop=(), mutate=None, done=True):
    """Write a hand-computed campaign: fixed 10% armed call-latency cost."""
    manifest = {
        "cells": {"exec-storm": {"rounds": rounds, "ops": 100},
                  "call-rate": {"rounds": rounds, "rate": "1k",
                                "duration_s": 2}},
        "arms": ["none", "off-profile", "on-profile", "on-armed"],
        "rotation": "ABBA: odd rounds forward, even rounds reversed",
        "completion": {"marker": "DONE"},
    }
    man_path = directory / "manifest.json"
    man_path.write_text(__import__("json").dumps(manifest))
    lines = ["MACHINE kernel=test"]
    for cell in ("exec-storm", "call-rate"):
        for rnd in range(1, rounds + 1):
            order = ANALYZER.expected_order(manifest["arms"], rounds)[rnd]
            for arm in order:
                if (cell, rnd, arm) in drop:
                    continue
                ops = 100 if cell == "exec-storm" else 2000
                wall = 200_000 if cell == "exec-storm" else 2_000_000_000
                lat = 1100 if (cell == "call-rate" and arm == "on-armed") else 1000
                extra = "" if cell == "exec-storm" else (
                    f" rate_per_s=1000.0 lat_med_ns={lat} "
                    f"lat_p90_ns={lat + 50} unhealthy=0")
                prog = ("sched_process_exec" if cell == "exec-storm"
                        else "p11_entry")
                bpf = ("bpf_prog=" + prog + " bpf_ns=30000 bpf_cnt=100"
                       if arm != "none" else
                       "bpf_prog=" + prog + " bpf_ns=none bpf_cnt=none")
                lines.append(f"SAMPLE cell={cell} arm={arm} round={rnd} "
                             f"ops={ops} wall_ns={wall}{extra} {bpf}")
    if mutate is not None:
        lines = mutate(lines)
    if done:
        lines.append("DONE samples=8" if not drop else
                     f"DONE samples={8 - len(drop)}")
    log_path = directory / "campaign.log"
    log_path.write_text("\n".join(lines) + "\n")
    return log_path, man_path


class BenchHarnessTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gcc"), "gcc required")
    def test_bench_self_test(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-suite-") as work:
            env = dict(os.environ, TMPDIR=work)
            proc = subprocess.run(
                ["sh", str(BENCH), "--self-test"],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("self-test: OK", proc.stdout)

    def test_dry_run_rotation(self):
        proc = subprocess.run(
            ["sh", str(BENCH), "--dry-run"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), env=dict(os.environ, ROUNDS="3",
                                    CELLS="exec-storm call-rate"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("round 1: none off-profile on-profile on-armed",
                      proc.stdout)
        self.assertIn("round 2: on-armed on-profile off-profile none",
                      proc.stdout)
        self.assertIn("round 3: none off-profile on-profile on-armed",
                      proc.stdout)
        self.assertIn("samples: 24", proc.stdout)

    def test_dry_run_single_cell(self):
        proc = subprocess.run(
            ["sh", str(BENCH), "--dry-run"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), env=dict(os.environ, ROUNDS="1",
                                    CELLS="exec-storm", EXEC_OPS="50"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("samples: 4", proc.stdout)
        self.assertIn("50 execs", proc.stdout)

    def test_usage_errors(self):
        proc = subprocess.run(["sh", str(BENCH)],
                              capture_output=True, text=True, timeout=30,
                              cwd=str(ROOT))
        self.assertEqual(proc.returncode, 2)
        proc = subprocess.run(
            ["sh", str(BENCH), "--dry-run", "extra"],
            capture_output=True, text=True, timeout=30, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 2)


class AnalyzerTests(unittest.TestCase):
    def test_analyzer_self_test(self):
        proc = subprocess.run(
            [sys.executable, "-I", str(ANALYZE), "--self-test"],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("self-test: OK", proc.stdout)

    def test_hand_computed_campaign(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-campaign-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(directory)
            manifest, samples = ANALYZER.verify(str(log_path), str(man_path))
            table = ANALYZER.render(manifest, samples)
        self.assertEqual(len(samples), 8)
        # exec-storm: 200000 ns / 100 ops on every arm; deltas zero.
        self.assertIn("ns/exec median=2,000", table)
        self.assertIn("0 ns/exec (+0.00%, within 2%)", table)
        # call-rate: on-armed latency 1100 vs 1000 elsewhere.
        self.assertIn("delta armed    (on-armed - on-profile): "
                      "100 lat_ns (+10.00%, exceeds 2%)", table)
        self.assertIn("delta disarmed (on-profile - off-profile): "
                      "0 lat_ns (+0.00%, within 2%)", table)
        self.assertIn("recorded, not gated", table)
        # Health renders per arm: p90 beside the median, unhealthy beside
        # the rate. The fixture runs clean.
        self.assertIn("lat_p90_ns median=1,050", table)
        self.assertIn("lat_p90_ns median=1,150", table)
        self.assertIn("unhealthy median=0", table)
        self.assertIn("total=0", table)

    def test_armed_arm_labeled_gated_read_only(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-armed-note-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(directory)
            manifest, samples = ANALYZER.verify(str(log_path), str(man_path))
            table = ANALYZER.render(manifest, samples)
        self.assertIn("gated read only", table)
        self.assertIn("lane journal-ready", table)
        self.assertIn("no production session writes READY", table)

    def test_truncated_log_fails(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-truncated-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(
                directory, drop={("call-rate", 1, "on-armed")})
            with self.assertRaises(ANALYZER.CampaignError):
                ANALYZER.verify(str(log_path), str(man_path))
            proc = subprocess.run(
                [sys.executable, "-I", str(ANALYZE), str(log_path),
                 "--manifest", str(man_path)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("arm order", proc.stderr)

    def test_missing_done_fails(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-nodone-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(directory, done=False)
            with self.assertRaises(ANALYZER.CampaignError):
                ANALYZER.verify(str(log_path), str(man_path))

    def test_done_count_mismatch_fails(self):
        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-count-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(directory)
            log_path.write_text(
                log_path.read_text().replace("DONE samples=8",
                                              "DONE samples=7"))
            with self.assertRaises(ANALYZER.CampaignError):
                ANALYZER.verify(str(log_path), str(man_path))

    def test_all_unhealthy_campaign_fails(self):
        def sicken(lines):
            return [line.replace("unhealthy=0", "unhealthy=2000")
                    if line.startswith("SAMPLE cell=call-rate") else line
                    for line in lines]

        with tempfile.TemporaryDirectory(
                prefix="p11scope-markercost-sick-") as work:
            directory = Path(work)
            log_path, man_path = campaign_fixture(directory, mutate=sicken)
            with self.assertRaises(ANALYZER.CampaignError):
                ANALYZER.verify(str(log_path), str(man_path))

    def test_analyzer_usage(self):
        proc = subprocess.run([sys.executable, "-I", str(ANALYZE)],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
