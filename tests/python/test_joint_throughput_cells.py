#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Twins for scripts/ci/joint-throughput.sh (the WU-7a cells).

The privileged capture core cannot run here; this suite covers what it
can without privilege: the CLI surface (help, usage errors, parameter
validation), the emitter build with the pinned warnings, provider
probing, the verdict mapping (pass/fail/nonqualifying/expected), and
the results.jsonl row shape. Library functions are reached by
sourcing the script with JOINT_TP_SOURCED=1 (the file's own guard
keeps main from running); live cell flows are exercised by the
script's own runs, never by this suite.
"""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/joint-throughput.sh"


def run_script(argv, env=None, timeout=60):
    base = {key: value for key, value in os.environ.items()
            if key not in ("RATE", "DURATION", "MIN_RATE", "CELLS",
                           "SOFTHSM_LIB", "OBS_MARGIN")}
    if env:
        base.update(env)
    return subprocess.run([str(SCRIPT), *argv], capture_output=True,
                          text=True, timeout=timeout, env=base, cwd=ROOT)


def run_sourced(shell, env=None, timeout=60):
    """Run sh code with the cell script sourced (main guarded off).

    The script path travels as $0 so its ROOT resolution works.
    """
    base = {key: value for key, value in os.environ.items()
            if key not in ("RATE", "DURATION", "MIN_RATE", "CELLS",
                           "SOFTHSM_LIB", "OBS_MARGIN")}
    if env:
        base.update(env)
    base["JOINT_TP_SOURCED"] = "1"
    return subprocess.run(["sh", "-c", f'. "$0"; {shell}', str(SCRIPT)],
                          capture_output=True, text=True, timeout=timeout,
                          env=base, cwd=ROOT)


class CellScriptCLI(unittest.TestCase):
    def test_help_is_exit_0(self):
        proc = run_script(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("usage: joint-throughput.sh P11SCOPE OUTDIR",
                      proc.stderr)

    def test_missing_args_are_exit_2(self):
        for argv in ([], ["/bin/true"], ["/bin/true", "a", "b"]):
            proc = run_script(argv)
            self.assertEqual(proc.returncode, 2, argv)
            self.assertIn("usage: joint-throughput.sh", proc.stderr)

    def test_missing_observer_is_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="jtp-cli-") as tmp:
            proc = run_script(["/nonexistent-p11scope", tmp])
            self.assertEqual(proc.returncode, 2)
            self.assertIn("not executable", proc.stderr)

    def test_min_rate_above_rate_is_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="jtp-cli-") as tmp:
            proc = run_script(["/bin/true", tmp],
                              env={"RATE": "1k", "MIN_RATE": "10000"})
            self.assertEqual(proc.returncode, 2)
            self.assertIn("exceeds RATE", proc.stderr)

    def test_bad_params_are_exit_2(self):
        cases = ({"RATE": "2k"}, {"DURATION": "0"}, {"DURATION": "soon"},
                 {"MIN_RATE": "-1"}, {"CELLS": "joint-10k-single nope"})
        with tempfile.TemporaryDirectory(prefix="jtp-cli-") as tmp:
            for env in cases:
                proc = run_script(["/bin/true", tmp], env=env)
                self.assertEqual(proc.returncode, 2, env)


class CellScriptLibrary(unittest.TestCase):
    def test_script_is_executable_sh(self):
        mode = SCRIPT.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR, "script must be executable")
        with open(SCRIPT, encoding="utf-8") as stream:
            head = stream.readline().rstrip("\n")
        self.assertEqual(head, "#!/bin/sh")

    def test_rate_hz_maps_labels(self):
        proc = run_sourced('rate_hz 1k; rate_hz 10k; rate_hz 100k; '
                           'rate_hz 2k; echo "rc=$?"')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["1000", "10000", "100000",
                                               "rc=0"])

    def test_validate_params_matrix(self):
        good = ({"RATE": "10k", "DURATION": "20", "MIN_RATE": "10000"},
                {"RATE": "1k", "DURATION": "5", "MIN_RATE": "1000",
                 "CELLS": "s1-10k-twin"},
                {"RATE": "100k", "DURATION": "2", "MIN_RATE": "0"})
        for env in good:
            proc = run_sourced('validate_params', env=env)
            self.assertEqual(proc.returncode, 0, env)
        bad = ({"RATE": "2k"}, {"DURATION": "0"}, {"DURATION": "3601"},
               {"DURATION": "x"}, {"MIN_RATE": "10001", "RATE": "10k"},
               {"MIN_RATE": "-1"}, {"CELLS": "s1-10k-twin bogus"})
        for env in bad:
            proc = run_sourced('validate_params', env=env)
            self.assertNotEqual(proc.returncode, 0, env)

    def test_select_provider_honors_the_override(self):
        proc = run_sourced('select_provider',
                           env={"SOFTHSM_LIB": "/override/lib.so"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "/override/lib.so")

    def test_select_provider_finds_a_live_library(self):
        proc = run_sourced('select_provider')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        path = proc.stdout.strip()
        self.assertTrue(path.endswith("libsofthsm2.so"), path)
        self.assertTrue(Path(path).is_file(), path)

    def test_build_emitter_compiles_with_pinned_warnings(self):
        with tempfile.TemporaryDirectory(prefix="jtp-build-") as tmp:
            proc = run_sourced(f'build_emitter "{tmp}/bin"', timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            binary = Path(tmp) / "bin" / "gen-calls"
            self.assertTrue(binary.is_file())
            glfw = subprocess.run([str(binary), "--help"],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(glfw.returncode, 0)
            self.assertIn("keyed / keyed-churn", glfw.stdout)

    def test_load_and_nproc_are_sane(self):
        proc = run_sourced('load1; nproc_')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        load, cpus = proc.stdout.split()
        self.assertGreater(float(load), -0.01)
        self.assertGreaterEqual(int(cpus), 1)


class VerdictMapping(unittest.TestCase):
    def map_verdict(self, rc, reason, load="2.0", cpus="8"):
        with tempfile.TemporaryDirectory(prefix="jtp-map-") as tmp:
            oracle = Path(tmp) / "oracle.json"
            if reason is None:
                oracle.write_text("not json\n", encoding="utf-8")
            else:
                oracle.write_text(json.dumps({"verdict": "fail",
                                              "reason": reason}),
                                  encoding="utf-8")
            proc = run_sourced(
                f'map_verdict {rc} "{oracle}" "{load}" "{cpus}"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return proc.stdout.strip()

    def test_pass_maps(self):
        with tempfile.TemporaryDirectory(prefix="jtp-map-") as tmp:
            oracle = Path(tmp) / "oracle.json"
            oracle.write_text(json.dumps({"verdict": "pass"}),
                              encoding="utf-8")
            proc = run_sourced(f'map_verdict 0 "{oracle}" "99.0" "8"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "pass|")

    def test_rate_miss_on_a_loaded_host_is_nonqualifying(self):
        got = self.map_verdict(
            1, "window 0: 5 calls/s below minimum 10 [0, 1)", load="12.5",
            cpus="8")
        self.assertEqual(got, "nonqualifying|")

    def test_rate_miss_on_a_quiet_host_is_failed(self):
        got = self.map_verdict(
            1, "window 0: 5 calls/s below minimum 10 [0, 1)", load="2.0",
            cpus="8")
        self.assertEqual(got, "fail|")

    def test_unlinked_joint_marker_is_expected(self):
        got = self.map_verdict(
            1, "object_observations status unavailable reason "
               "journal_unavailable, not the Joint marker populated/none")
        self.assertEqual(got, "fail|Session-loop seal wire pending (WU-2)")

    def test_other_joint_reasons_stay_unexpected(self):
        got = self.map_verdict(1, "per-key operations [5] != ledgered [6]")
        self.assertEqual(got, "fail|")

    def test_conservation_miss_is_failed_at_any_load(self):
        got = self.map_verdict(1, "operations.calls 65 != issued 20006",
                               load="99.0", cpus="8")
        self.assertEqual(got, "fail|")

    def test_unparsable_oracle_output_is_failed(self):
        self.assertEqual(self.map_verdict(1, None), "fail|")
        with tempfile.TemporaryDirectory(prefix="jtp-map-") as tmp:
            oracle = Path(tmp) / "oracle.json"
            oracle.write_text(json.dumps({"verdict": "pass"}),
                              encoding="utf-8")
            proc = run_sourced(f'map_verdict 2 "{oracle}" "1.0" "8"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "fail|")


class ResultsRows(unittest.TestCase):
    def test_write_row_shape_and_expected(self):
        with tempfile.TemporaryDirectory(prefix="jtp-row-") as tmp:
            results = Path(tmp) / "results.jsonl"
            env = {"RESULTS_JSONL": str(results)}
            first = run_sourced(
                'RESULTS_JSONL="$RESULTS_JSONL"; '
                'write_row joint-10k-single pass "host=h load1=1.0" ""',
                env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run_sourced(
                'RESULTS_JSONL="$RESULTS_JSONL"; write_row joint-10k-churn '
                'fail "host=h load1=1.0" "Session-loop seal wire pending (WU-2)"',
                env=env)
            self.assertEqual(second.returncode, 0, second.stderr)
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0],
                             {"cell": "joint-10k-single", "result": "pass",
                              "detail": "host=h load1=1.0"})
            self.assertNotIn("expected", rows[0])
            self.assertEqual(rows[1]["cell"], "joint-10k-churn")
            self.assertEqual(rows[1]["result"], "fail")
            self.assertEqual(rows[1]["expected"],
                             "Session-loop seal wire pending (WU-2)")


if __name__ == "__main__":
    unittest.main()
