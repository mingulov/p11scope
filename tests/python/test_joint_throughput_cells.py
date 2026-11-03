#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Twins for scripts/ci/joint-throughput.sh (the WU-7a cells).

The privileged capture core cannot run here; this suite covers what it
can without privilege: the CLI surface (help, usage errors, parameter
validation), the emitter build with the pinned warnings, provider
probing, the verdict mapping (pass plus the qualified,
nonqualifying, expected-failure and failed qualifications), the
event assembly and flow helpers, and the results.jsonl row shape.
Library functions are reached by
sourcing the script with JOINT_TP_SOURCED=1 (the file's own guard
keeps main from running); live cell flows are exercised by the
script's own runs, never by this suite.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/joint-throughput.sh"


def run_script(argv, env=None, timeout=60):
    base = {key: value for key, value in os.environ.items()
            if key not in ("RATE", "DURATION", "MIN_RATE", "CELLS",
                           "SOFTHSM_LIB", "OBS_MARGIN", "SETTLEMENT_LAT", "STAGE_TIMINGS")}
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
                           "SOFTHSM_LIB", "OBS_MARGIN", "SETTLEMENT_LAT", "STAGE_TIMINGS")}
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
        self.assertIn("SETTLEMENT_LAT", proc.stderr)

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

    def test_observer_env_passes_the_settlement_toggle(self):
        proc = run_sourced('observer_env', env={"SETTLEMENT_LAT": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(),
                         "P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY=1")
        for env in ({}, {"SETTLEMENT_LAT": "0"},
                    {"SETTLEMENT_LAT": "yes"}):
            proc = run_sourced('observer_env', env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "", env)

    def test_observer_env_passes_the_stage_timings_toggle(self):
        proc = run_sourced('observer_env', env={"STAGE_TIMINGS": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "P11SCOPE_STAGE_TIMINGS=1")
        proc = run_sourced('observer_env',
                           env={"SETTLEMENT_LAT": "1", "STAGE_TIMINGS": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines(),
                         ["P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY=1",
                          "P11SCOPE_STAGE_TIMINGS=1"])

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

    def test_pass_wait_counts_observer_passes(self):
        with tempfile.TemporaryDirectory(prefix="jtp-pass-") as tmp:
            log = Path(tmp) / "observer.out"
            log.write_text("p11scope: pass 0: 1 scanned\n"
                           "p11scope: pass 1: 2 scanned\n", encoding="utf-8")
            first = run_sourced(f'wait_for_pass "{log}" 1 5')
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run_sourced(f'wait_for_pass "{log}" 5 1')
            self.assertEqual(second.returncode, 1)

    def test_load_and_nproc_are_sane(self):
        proc = run_sourced('load1; nproc_')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        load, cpus = proc.stdout.split()
        self.assertGreater(float(load), -0.01)
        self.assertGreaterEqual(int(cpus), 1)

    def test_loaded_host_compares_against_nproc(self):
        for load, cpus, expected in (("12.5", "8", 0), ("8.0", "8", 1),
                                    ("2.0", "8", 1), ("0.5", "1", 1)):
            proc = run_sourced(f'loaded_host "{load}" "{cpus}"')
            self.assertEqual(proc.returncode, expected, (load, cpus))

    def test_event_args_lists_every_part_oldest_first(self):
        with tempfile.TemporaryDirectory(prefix="jtp-ev-") as tmp:
            workdir = Path(tmp) / "out.dir"
            workdir.mkdir()
            (workdir / "events.jsonl").write_text("{}\n", encoding="utf-8")
            proc = run_sourced(f'event_args "{workdir}"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.split(),
                             ["--events", str(workdir / "events.jsonl")])
            (workdir / "events.jsonl.1").write_text("{}\n", encoding="utf-8")
            (workdir / "events.jsonl.2").write_text("{}\n", encoding="utf-8")
            (workdir / "events.jsonl.10").write_text("{}\n", encoding="utf-8")
            proc = run_sourced(f'event_args "{workdir}"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                proc.stdout.split(),
                ["--events", str(workdir / "events.jsonl.10"),
                 "--events", str(workdir / "events.jsonl.2"),
                 "--events", str(workdir / "events.jsonl.1"),
                 "--events", str(workdir / "events.jsonl")])

    def test_fail_flow_records_rc_and_reason(self):
        with tempfile.TemporaryDirectory(prefix="jtp-flow-") as tmp:
            proc = run_sourced(
                f'ORACLE_RC=0; ORACLE_REASON=""; fail_flow "{tmp}" '
                '"pass 0 never published"; '
                'echo "rc=$ORACLE_RC reason=$ORACLE_REASON"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("rc=2 reason=pass 0 never published",
                          proc.stdout)
            payload = json.loads(
                (Path(tmp) / "oracle.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "fail")
            self.assertEqual(payload["reason"], "pass 0 never published")


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

    def test_pass_maps_to_qualified(self):
        with tempfile.TemporaryDirectory(prefix="jtp-map-") as tmp:
            oracle = Path(tmp) / "oracle.json"
            oracle.write_text(json.dumps({"verdict": "pass"}),
                              encoding="utf-8")
            proc = run_sourced(f'map_verdict 0 "{oracle}" "99.0" "8"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "true|qualified|")

    def test_rate_miss_on_a_loaded_host_is_nonqualifying(self):
        got = self.map_verdict(
            1, "window 0: 5 calls/s below minimum 10 [0, 1)", load="12.5",
            cpus="8")
        self.assertEqual(got, "false|nonqualifying|")

    def test_rate_miss_on_a_quiet_host_is_failed(self):
        got = self.map_verdict(
            1, "window 0: 5 calls/s below minimum 10 [0, 1)", load="2.0",
            cpus="8")
        self.assertEqual(got, "false|failed|")

    def test_unlinked_joint_marker_is_expected(self):
        for reason in (
                "object_observations status unavailable reason "
                "journal_unavailable, not the Joint marker populated/none",
                "unlinked lane disclosure present: "
                "joint_journal_unavailable"):
            with self.subTest(reason=reason):
                got = self.map_verdict(1, reason)
                self.assertEqual(
                    got, "false|expected-failure|"
                         "Session-loop seal wire pending (WU-2)")

    def test_other_joint_reasons_stay_failed(self):
        for reason in ("per-key operations [5] != ledgered [6]",
                       "object_observations without key rows",
                       "unknown-key operations persist: 2 rows"):
            with self.subTest(reason=reason):
                self.assertEqual(self.map_verdict(1, reason, load="99.0"),
                                 "false|failed|")

    def test_conservation_miss_is_failed_at_any_load(self):
        got = self.map_verdict(1, "operations.calls 65 != issued 20006",
                               load="99.0", cpus="8")
        self.assertEqual(got, "false|failed|")

    def test_loss_miss_is_failed_at_any_load(self):
        got = self.map_verdict(
            1, "stop did not prove a full drain (final_drain=None, "
               "stop_quiescence=not_requested)", load="99.0", cpus="8")
        self.assertEqual(got, "false|failed|")

    def test_r59_and_counted_loss_are_failed_at_any_load(self):
        reasons = (
            "semantic coverage is not the exact R59 stopped disclosure",
            "loss gap: published capture loss or retirement",
            "loss gap: semantic input refused beyond count-only setup",
            "ring_loss 1 (observation.lifecycle.ring_loss)",
            "events_lost 1 "
            "(observation.semantic_capture.unrouted_returns)",
            "unrouted_returns 1 "
            "(observation.semantic_capture.unrouted_returns)",
            "events_lost 1 (observation.semantic_capture.events_lost)",
            "semantic_capture events_lost missing or out of range",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.map_verdict(1, reason, load="99.0", cpus="8"),
                    "false|failed|")

    def test_foreign_joint_marker_status_is_failed(self):
        reasons = (
            "object_observations status unavailable reason "
            "bootstrap_unavailable, not the Joint marker populated/none",
            "object_observations status populated reason stale, not the "
            "Joint marker populated/none",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.map_verdict(1, reason, load="99.0", cpus="8"),
                    "false|failed|")

    def test_driver_topology_failures_are_failed(self):
        reasons = (
            "no single caller for driver pid 4242: 0 rows",
            "no single edge for driver pid 4242: 2 rows",
            "driver module row is not unique",
            "driver instance row is not unique",
            "driver semantic row is not unique",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.map_verdict(1, reason, load="99.0", cpus="8"),
                    "false|failed|")

    def test_rotation_marker_wording_stays_load_judged(self):
        reason = ("event stream incomplete: ended marker is not unique "
                  "and last")
        self.assertEqual(self.map_verdict(1, reason, load="12.5", cpus="8"),
                         "false|nonqualifying|")
        self.assertEqual(self.map_verdict(1, reason, load="2.0", cpus="8"),
                         "false|failed|")

    def test_shapeless_evidence_is_load_judged(self):
        reasons = (
            "unreadable events /tmp/x/events.jsonl.1",
            "unreadable ledger /tmp/x/hot.jsonl",
            "unreadable inventory /tmp/x/report.json",
            "event stream incomplete: missing or duplicate sequence",
            "event stream incomplete: started marker is not unique "
            "and first",
            "current parent is not the exact withheld semantic summary",
            "physical entries are not complete observed counts",
            "no ledgers emitted",
            "pass 0 never published",
            "MAPPED never printed",
            "DONE never printed",
            "generator never became ready",
            "no admission pass after mapping",
            "no binding pass after setup",
            "target not held through drain",
            "observer rc=1",
            "generator rc=1",
            "evidence chmod failed",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.map_verdict(1, reason, load="12.5", cpus="8"),
                    "false|nonqualifying|")
                self.assertEqual(
                    self.map_verdict(1, reason, load="2.0", cpus="8"),
                    "false|failed|")

    def test_unparsable_oracle_output_is_failed(self):
        self.assertEqual(self.map_verdict(1, None), "false|failed|")
        self.assertEqual(self.map_verdict(1, "oracle output unparsable",
                                           load="99.0"),
                         "false|failed|")
        with tempfile.TemporaryDirectory(prefix="jtp-map-") as tmp:
            oracle = Path(tmp) / "oracle.json"
            oracle.write_text(json.dumps({"verdict": "pass"}),
                              encoding="utf-8")
            proc = run_sourced(f'map_verdict 2 "{oracle}" "1.0" "8"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "false|failed|")


class ResultsRows(unittest.TestCase):
    def test_write_row_uses_the_contract_shape(self):
        with tempfile.TemporaryDirectory(prefix="jtp-row-") as tmp:
            results = Path(tmp) / "results.jsonl"
            env = {"RESULTS_JSONL": str(results)}
            first = run_sourced(
                'write_row joint-10k-single true qualified '
                '"host=h load1=1.0"',
                env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run_sourced(
                'write_row joint-10k-churn false expected-failure '
                '"host=h load1=1.0 expected-failure: '
                'Session-loop seal wire pending (WU-2)"',
                env=env)
            self.assertEqual(second.returncode, 0, second.stderr)
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0],
                             {"cell": "joint-10k-single", "pass": True,
                              "qualification": "qualified",
                              "detail": "host=h load1=1.0"})
            self.assertIs(rows[0]["pass"], True)
            self.assertEqual(rows[1]["cell"], "joint-10k-churn")
            self.assertIs(rows[1]["pass"], False)
            self.assertEqual(rows[1]["qualification"], "expected-failure")
            self.assertIn("Session-loop seal wire pending (WU-2)",
                          rows[1]["detail"])

    def test_skip_all_is_nonqualifying_with_the_prerequisite(self):
        with tempfile.TemporaryDirectory(prefix="jtp-skip-") as tmp:
            results = Path(tmp) / "results.jsonl"
            env = {"RESULTS_JSONL": str(results),
                   "CELLS": "joint-10k-single s1-10k-twin"}
            proc = run_sourced('skip_all "no gcc"', env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertIs(row["pass"], False)
                self.assertEqual(row["qualification"], "nonqualifying")
                self.assertIn("no gcc", row["detail"])


class EmitterLedgerCeiling(unittest.TestCase):
    """The 10k/60s run needs 600k calls; the toolchain must allow it."""

    NEEDED = 10_000 * 60

    def _read_define(self, path, name):
        text = (ROOT / path).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith(f"#define {name} "):
                return int(line.split()[2].rstrip("ulUL"))
        raise AssertionError(f"{name} not found in {path}")

    def _read_py_const(self, path, name):
        text = (ROOT / path).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith(f"{name} = "):
                return int(line.split("=")[1].strip())
        raise AssertionError(f"{name} not found in {path}")

    def test_ceilings_cover_10k_60s(self):
        emitter = self._read_define(
            "tests/fixtures/joint-throughput/gen-calls.c",
            "MAX_CALLS_PER_LEDGER")
        per_call = self._read_define(
            "tests/fixtures/joint-ledger/per-call-ledger.c", "MAX_CALLS")
        oracle = self._read_py_const(
            "scripts/joint-ledger-oracle.py", "MAX_CALLS")
        events = self._read_py_const(
            "scripts/s1-throughput-compare.py", "MAX_EVENT_ROWS")
        self.assertGreaterEqual(emitter, self.NEEDED)
        self.assertGreaterEqual(per_call, self.NEEDED)
        self.assertGreaterEqual(oracle, self.NEEDED)
        self.assertGreaterEqual(events, self.NEEDED)
        self.assertEqual(emitter, oracle)
        self.assertEqual(per_call, oracle)

    def test_dry_run_accepts_10k_60s(self):
        with tempfile.TemporaryDirectory(prefix="jtp-ceil-") as tmp:
            proc = run_sourced(f'build_emitter "{tmp}/bin"', timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            binary = Path(tmp) / "bin" / "gen-calls"
            for mode in ("keyed", "keyed-churn"):
                dry = subprocess.run(
                    [str(binary), "--dry-run", "/nonexistent-provider.so",
                     mode, "10k", "60", f"{tmp}/ledger.jsonl"],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(dry.returncode, 0, dry.stderr)
                self.assertIn("600000 calls", dry.stdout)


class BpfEvidenceSum(unittest.TestCase):
    """Sum EVIDENCE[0] (ring loss) over CPUs and maps from bpftool JSON."""

    HELPER = ROOT / "scripts/bpf-evidence-sum.py"

    def _run_helper(self, show_json, dumps, timeout=30):
        with tempfile.TemporaryDirectory(prefix="bpf-ev-") as tmp:
            show = Path(tmp) / "show.json"
            show.write_text(show_json, encoding="utf-8")
            args = [sys.executable, "-I", str(self.HELPER), "--show", str(show)]
            for map_id, dump_json in dumps.items():
                dump = Path(tmp) / f"dump-{map_id}.json"
                dump.write_text(dump_json, encoding="utf-8")
                args += ["--dump", f"{map_id}={dump}"]
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=timeout)

    def test_sums_key_zero_over_cpus_and_maps(self):
        show = json.dumps([
            {"id": 11, "name": "EVIDENCE", "max_entries": 9},
            {"id": 12, "name": "EVIDENCE", "max_entries": 9},
            {"id": 13, "name": "EVENTS", "max_entries": 4},
        ])
        dumps = {
            11: json.dumps([
                {"key": [0, 0, 0, 0], "values": [3, 0, 7, 0]},
                {"key": [1, 0, 0, 0], "values": [99, 99, 99, 99]},
            ]),
            12: json.dumps([
                {"key": [0, 0, 0, 0], "values": [1, 1, 1, 1]},
            ]),
        }
        proc = self._run_helper(show, dumps)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["maps"], [
            {"id": 11, "ring_loss_sum": 10, "cpus": 4},
            {"id": 12, "ring_loss_sum": 4, "cpus": 4},
        ])
        self.assertEqual(summary["total_ring_loss_sum"], 14)

    def test_empty_show_is_empty_summary(self):
        proc = self._run_helper("[]", {})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["maps"], [])
        self.assertEqual(summary["total_ring_loss_sum"], 0)

    def test_missing_key_zero_is_zero_not_an_error(self):
        show = json.dumps([{"id": 21, "name": "EVIDENCE", "max_entries": 9}])
        dumps = {21: json.dumps([
            {"key": [5, 0, 0, 0], "values": [1, 2]},
        ])}
        proc = self._run_helper(show, dumps)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["maps"],
                         [{"id": 21, "ring_loss_sum": 0, "cpus": 0}])
        self.assertEqual(summary["total_ring_loss_sum"], 0)

    def test_scalar_zero_key_counts(self):
        show = json.dumps([{"id": 31, "name": "EVIDENCE", "max_entries": 9}])
        dumps = {31: json.dumps([
            {"key": 0, "values": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
        ])}
        proc = self._run_helper(show, dumps)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["maps"],
                         [{"id": 31, "ring_loss_sum": 0, "cpus": 12}])
        self.assertEqual(summary["total_ring_loss_sum"], 0)

    def test_real_bpftool_hex_format_decodes(self):
        show = json.dumps([{"id": 41, "name": "EVIDENCE", "max_entries": 9}])
        zero8 = ["0x00"] * 8
        dumps = {41: json.dumps([
            {"key": ["0x00", "0x00", "0x00", "0x00"], "values": [
                {"cpu": 0, "value": ["0x03"] + zero8[1:]},
                {"cpu": 1, "value": ["0x07"] + zero8[1:]},
            ]},
            {"key": ["0x01", "0x00", "0x00", "0x00"], "values": [
                {"cpu": 0, "value": ["0x63"] + zero8[1:]},
            ]},
        ])}
        proc = self._run_helper(show, dumps)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["maps"],
                         [{"id": 41, "ring_loss_sum": 10, "cpus": 2}])
        self.assertEqual(summary["total_ring_loss_sum"], 10)


if __name__ == "__main__":
    unittest.main()
