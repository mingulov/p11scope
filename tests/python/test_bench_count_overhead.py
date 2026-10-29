#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""M2 counting-overhead analyzer: strict shape and exactness gates (G34).

A reduced log, a None==None count re-check, scrambled ABBA order or a
missing independent BPF corroboration must fail loudly; only a complete
campaign with integer-exact counts renders a verdict. Run as a script:

    python3 -I tests/python/test_bench_count_overhead.py -v
"""
import io
import os
import re
import runpy
import shlex
import signal
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYZE = runpy.run_path(str(ROOT / "scripts/bench-count-overhead-analyze.py"))

M2_CELLS = ("relevant-call-t1", "relevant-call-t4", "relevant-call-t12",
            "relevant-call-t12-nolock", "unrelated-mmap")


class ObserverReadiness(unittest.TestCase):
    def run_gate(self, function, mode, *, kill_zero_fails=False):
        source = (ROOT / "scripts/bench-count-overhead.sh").read_text()
        # Source only the actual definitions: sourcing the full script would
        # launch the privileged campaign before these functions are defined.
        names = ("cleanup", "reap_observer_if_gone", "wait_for_lane_active", "wait_for_passes")
        definitions = []
        for name in names:
            matches = re.findall(r"^" + name + r"\(\) \{\n.*?^\}\n", source, re.M | re.S)
            self.assertLessEqual(len(matches), 1, name)
            if name != "reap_observer_if_gone":
                self.assertEqual(len(matches), 1, name)
            definitions.extend(matches)
        marker = re.search(r"^LANE_MARKER=.*$", source, re.M).group()
        with tempfile.TemporaryDirectory(prefix="count-readiness-") as work:
            root = Path(work)
            log, operations = root / "observer.stderr", root / "operations"
            log.touch()
            driver = root / "driver.sh"
            command = (f'{function} "$OBSERVER_LOG" 1' if function == "wait_for_lane_active"
                       else f'{function} "$OBSERVER_LOG" 2 1')
            driver.write_text("set -eu\n" + "\n".join(definitions) + "\n" + marker + "\n"
                + f"OBSERVER_LOG={shlex.quote(str(log))}\nOPERATIONS={shlex.quote(str(operations))}\n"
                + f"KILL_ZERO_FAILS={int(kill_zero_fails)}\n"
                + '''WPID= APID= SPID= BPF_STATS_BEFORE= KIND_PAUSED=0
kill() {
    printf 'KILL %s\n' "$*" >> "$OPERATIONS"
    if [ "$1" = -0 ] && [ "$KILL_ZERO_FAILS" = 1 ]; then return 1; fi
    command kill "$@"
}
wait() {
    printf 'WAIT %s\n' "$*" >> "$OPERATIONS"
    command wait "$@"
}
'''
                + f". {shlex.quote(str(ROOT / 'scripts/cleanup-traps.sh'))}\n"
                + ({"exit0": "sh -c 'exit 0' &\n", "exit7": "sh -c 'exit 7' &\n",
                    "signal": "sh -c 'kill -TERM $$' &\n",
                    "ready": '''sh -c 'printf "%s\\n" "$2 multi" "p11scope: pass 1: 1 scanned" "p11scope: pass 2: 1 scanned" > "$1"; exec sleep 60' observer "$OBSERVER_LOG" "$LANE_MARKER" &
''', "live": "sleep 60 &\n"}[mode])
                + "SPID=$!\nORIGINAL_SPID=$SPID\n"
                + ("while [ -e \"/proc/$SPID\" ]; do sleep 0.01; done\n"
                   if mode in ("exit0", "exit7", "signal") else "")
                + f"if {command}; then ready_status=0; else ready_status=$?; fi\n"
                + '''printf 'RESULT status=%s spid=%s original=%s\n' "$ready_status" "${SPID:-cleared}" "$ORIGINAL_SPID"
if [ -e "/proc/$ORIGINAL_SPID" ]; then echo CHILD_PRESENT; else echo CHILD_GONE; fi
exit "$ready_status"
''')
            foreign = subprocess.Popen(["sleep", "60"])
            process = subprocess.Popen(["sh", str(driver)], cwd=ROOT, start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    self.fail("actual readiness shell exceeded the 5s fixture bound")
                self.assertIsNone(foreign.poll(), "readiness or cleanup touched foreign work")
                row = next(line for line in stdout.splitlines() if line.startswith("RESULT "))
                fields = dict(part.split("=", 1) for part in row.split()[1:])
                original = fields["original"]
                calls = operations.read_text().splitlines()
                self.assertEqual([line for line in calls if line.startswith("WAIT ")],
                                 [f"WAIT {original}"], "original child must be reaped once")
                self.assertFalse(any(str(foreign.pid) in line.split() for line in calls))
                self.assertFalse(Path(f"/proc/{original}").exists())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)
                return process.returncode, fields, stdout, stderr, calls
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                foreign.terminate()
                foreign.wait(timeout=3)

    def test_early_observer_exit_reports_exact_status_and_stays_failure(self):
        for function in ("wait_for_lane_active", "wait_for_passes"):
            for mode, status in (("exit0", 0), ("exit7", 7), ("signal", 143)):
                with self.subTest(function=function, mode=mode):
                    rc, fields, stdout, stderr, calls = self.run_gate(function, mode)
                    self.assertEqual(rc, 1)
                    self.assertEqual(fields["status"], "1")
                    self.assertEqual(fields["spid"], "cleared")
                    self.assertIn(f"status={status}", stderr)
                    self.assertIn("CHILD_GONE", stdout)
                    self.assertFalse(any(line.startswith("KILL ") and not line.startswith("KILL -0 ")
                                         for line in calls))

    def test_ready_observer_keeps_original_child_until_cleanup(self):
        for function in ("wait_for_lane_active", "wait_for_passes"):
            with self.subTest(function=function):
                rc, fields, stdout, stderr, _ = self.run_gate(function, "ready")
                self.assertEqual(rc, 0, stderr)
                self.assertEqual(fields["spid"], fields["original"])
                self.assertIn("CHILD_PRESENT", stdout)
                self.assertNotIn("observer exited", stderr)

    def test_live_observer_reaches_timeout_even_if_kill_zero_fails(self):
        for function, message in (("wait_for_lane_active", "lane never went active within 1s"),
                                  ("wait_for_passes", "only 0/2 passes committed within 1s")):
            for permission_failure in (False, True):
                with self.subTest(function=function, permission_failure=permission_failure):
                    rc, fields, stdout, stderr, _ = self.run_gate(
                        function, "live", kill_zero_fails=permission_failure)
                    self.assertEqual(rc, 1)
                    self.assertEqual(fields["spid"], fields["original"])
                    self.assertIn("CHILD_PRESENT", stdout)
                    self.assertIn(message, stderr)
                    self.assertNotIn("observer exited", stderr)


def sample(cell, arm, rnd, threads, ops, wall, **kw):
    base = {"pad": 0, "mode": "call", "parallel": 1, "lane": "multi",
            "edge_count": "none", "edge_expected": "none", "edge_state": "none",
            "bpf_ns": "none", "bpf_cnt": "none"}
    base.update(kw)
    return (
        f"SAMPLE cell={cell} arm={arm} round={rnd} threads={threads} "
        f"ops={ops} wall_ns={wall} pad={base['pad']} mode={base['mode']} "
        f"parallel={base['parallel']} lane={base['lane']} "
        f"edge_count={base['edge_count']} edge_expected={base['edge_expected']} "
        f"edge_state={base['edge_state']} bpf_ns={base['bpf_ns']} "
        f"bpf_cnt={base['bpf_cnt']}\n"
    )


def counted(threads, ops):
    return {"edge_count": ops + 2 * threads + 1,
            "edge_expected": ops + 2 * threads + 1, "edge_state": "counted"}


def witnessed():
    return {"edge_count": "none", "edge_expected": "none", "edge_state": "witnessed"}


def bpf(ns=200000, cnt=1000):
    return {"bpf_ns": ns, "bpf_cnt": cnt}


# Registered workload per cell name (threads, pad), mirroring
# scripts/bench-count-overhead.sh run_call_sample/run_map_sample.
WORKLOADS = {
    "relevant-call-t1": (1, 0),
    "relevant-call-t4": (4, 0),
    "relevant-call-t12": (12, 0),
    "relevant-call-t12-nolock": (12, 1),
    "unrelated-mmap": (1, 0),
}


def campaign_log(cells=("relevant-call-t1",), rounds=10, wall_on=1010000,
                 wall_off=1000000, ops=1000):
    """One exact ABBA/BAAB campaign: odd rounds on/off/off/on, even off/on/on/off.

    Every cell runs its registered workload; ops stay measured per sample.
    """
    log = "MACHINE kernel=7.0 test-cpu nproc=12\n"
    for cell in cells:
        threads, pad = WORKLOADS[cell]
        mode = "mmap" if cell == "unrelated-mmap" else "call"
        for rnd in range(1, rounds + 1):
            arms = ("on", "off", "off", "on") if rnd % 2 else ("off", "on", "on", "off")
            for arm in arms:
                if mode == "call":
                    edge = counted(threads, ops) if arm == "on" else witnessed()
                    log += sample(cell, arm, rnd, threads, ops,
                                  wall_on if arm == "on" else wall_off,
                                  pad=pad, **edge, **bpf())
                else:
                    log += sample(cell, arm, rnd, threads, ops,
                                  wall_on if arm == "on" else wall_off,
                                  pad=pad, mode="mmap", bpf_ns=0, bpf_cnt=0)
            if mode == "call":
                log += sample(cell, "unobserved", rnd, threads, ops, 900000,
                              pad=pad, lane="none")
            else:
                log += sample(cell, "unobserved", rnd, threads, ops, 900000,
                              pad=pad, lane="none", mode="mmap")
    return log


def analyze_text(log, **kwargs):
    with tempfile.TemporaryDirectory(prefix="count-analyze-") as work:
        path = Path(work) / "campaign.log"
        path.write_text(log)
        _, samples, errors = ANALYZE["parse_log"](str(path))
        assert not errors, errors
        return ANALYZE["analyze"](samples, 5.0, 10.0, **kwargs)


class CountOverheadOracle(unittest.TestCase):
    def test_count_overhead_rejects_missing_counts_and_rounds(self):
        # None == None is not count exactness on a relevant on-arm sample.
        log = campaign_log(rounds=10)
        log = log.replace("edge_count=1003", "edge_count=none", 1).replace(
            "edge_expected=1003", "edge_expected=none", 1)
        _, problems = analyze_text(log, required_cells=("relevant-call-t1",))
        self.assertTrue(any("count" in problem for problem in problems), problems)
        # A reduced log (2 rounds) renders no verdict.
        _, problems = analyze_text(campaign_log(rounds=2),
                                   required_cells=("relevant-call-t1",))
        self.assertTrue(any("round" in problem for problem in problems), problems)
        # Scrambled ABBA order within a round breaks pairing discipline.
        lines = campaign_log(rounds=10).splitlines(keepends=True)
        head = [line for line in lines
                if "round=1 " in line and " arm=" in line and "cell=relevant" in line]
        on_first = next(line for line in head if " arm=on " in line)
        off_first = next(line for line in head if " arm=off " in line)
        i, j = lines.index(on_first), lines.index(off_first)
        lines[i], lines[j] = lines[j], lines[i]
        _, problems = analyze_text("".join(lines), required_cells=("relevant-call-t1",))
        self.assertTrue(any("ABBA" in problem or "order" in problem for problem in problems),
                        problems)
        # Missing independent BPF corroboration on an observed arm.
        log = campaign_log(rounds=10).replace("bpf_ns=200000 bpf_cnt=1000",
                                              "bpf_ns=none bpf_cnt=none", 1)
        _, problems = analyze_text(log, required_cells=("relevant-call-t1",))
        self.assertTrue(any("bpf" in problem.lower() for problem in problems), problems)

    def test_count_overhead_requires_expected_cells(self):
        # A missing expected cell and an unexpected extra cell both fail.
        _, problems = analyze_text(campaign_log(cells=("relevant-call-t1",)))
        self.assertTrue(any("relevant-call-t4" in problem for problem in problems), problems)
        log = campaign_log(cells=("relevant-call-t1",)) + sample(
            "rogue-cell", "on", 1, 1, 100, 100000, **counted(1, 100), **bpf())
        _, problems = analyze_text(log, required_cells=("relevant-call-t1",))
        self.assertTrue(any("rogue-cell" in problem for problem in problems), problems)

    def test_count_overhead_accepts_exact_ten_round_abba_campaign(self):
        rows, problems = analyze_text(campaign_log(rounds=10),
                                      required_cells=("relevant-call-t1",))
        self.assertEqual(problems, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pairs"], 20)
        self.assertFalse(rows[0]["material"], "1% must read immaterial")
        log = campaign_log(cells=M2_CELLS)
        # The positive fixture carries each cell's registered workload.
        for pin in ("cell=relevant-call-t4 arm=on round=1 threads=4",
                    "cell=relevant-call-t12 arm=on round=1 threads=12",
                    "cell=relevant-call-t12-nolock arm=on round=1 threads=12",
                    "pad=1 mode=call"):
            self.assertIn(pin, log)
        rows, problems = analyze_text(log)
        self.assertEqual(problems, [])
        self.assertEqual({row["cell"] for row in rows}, set(M2_CELLS))

    def test_count_overhead_binds_cell_names_to_workloads(self):
        log = campaign_log(cells=M2_CELLS)
        # Every call cell relabeled to the map workload proves nothing:
        # zero counted samples must not pass the M2 gate.
        _, problems = analyze_text(log.replace("mode=call", "mode=mmap"))
        self.assertTrue(any("workload" in problem for problem in problems), problems)
        # Wrong thread counts or padding for the cell name.
        _, problems = analyze_text(log.replace("threads=4", "threads=1", 1))
        self.assertTrue(any("workload" in problem for problem in problems), problems)
        _, problems = analyze_text(log.replace("pad=1", "pad=0", 1))
        self.assertTrue(any("workload" in problem for problem in problems), problems)
        # The binding covers the unobserved baseline arm too.
        bad_bare = log.replace("arm=unobserved round=1 threads=1",
                               "arm=unobserved round=1 threads=2", 1)
        _, problems = analyze_text(bad_bare)
        self.assertTrue(any("workload" in problem for problem in problems), problems)

    def test_count_overhead_recomputes_counts_from_the_workload(self):
        log = campaign_log(rounds=10)
        # Two agreeing log fields off the ops+2*threads+1 denominator fail.
        for lie in ("edge_count=1 edge_expected=1",
                    "edge_count=1002 edge_expected=1002"):
            bad = log.replace("edge_count=1003 edge_expected=1003", lie, 1)
            _, problems = analyze_text(bad, required_cells=("relevant-call-t1",))
            self.assertTrue(any("workload denominator 1003" in problem
                                for problem in problems), problems)

    def test_count_overhead_keeps_existing_failure_modes(self):
        log = campaign_log(rounds=10, cells=("relevant-call-t1",))
        # Unpaired round, mixed lane, wrong count still fail.
        bad_pair = log + sample("relevant-call-t1", "on", 11, 1, 1000, 1010000,
                                **counted(1, 1000), **bpf())
        _, problems = analyze_text(bad_pair, required_cells=("relevant-call-t1",))
        self.assertTrue(any("do not pair" in problem or "order" in problem
                            for problem in problems), problems)
        bad_lane = log.replace("lane=multi", "lane=singles", 1)
        _, problems = analyze_text(bad_lane, required_cells=("relevant-call-t1",))
        self.assertTrue(any("mixed lane" in problem for problem in problems), problems)
        bad_count = log.replace("edge_count=1003", "edge_count=1002", 1)
        _, problems = analyze_text(bad_count, required_cells=("relevant-call-t1",))
        self.assertTrue(any("workload denominator" in problem for problem in problems),
                        problems)


DEN_CELLS = ("relevant-call-t1", "relevant-call-t4")


def dencampaign_log(cells=DEN_CELLS, rounds=5):
    """One exact denominator campaign: on/unobserved ABBA per round.

    Odd rounds run on/unobserved/unobserved/on, even rounds the
    mirror. t1 diffs run 100..190 over alternating bare walls (the
    subtraction is per pair, not against a median); t4 is flat 75 ns
    per total completed call (300 under M2's per-thread normalization).
    """
    log = "MACHINE kernel=7.2.9 test-cpu nproc=5\n"
    log += "BINARY role=candidate path=/tmp/c sha256=aaa commit=c0ffee\n"
    for cell in cells:
        threads, pad = WORKLOADS[cell]
        pair = 0
        for rnd in range(1, rounds + 1):
            arms = ("on", "unobserved", "unobserved", "on") if rnd % 2 else (
                "unobserved", "on", "on", "unobserved")
            on_queue, bare_queue = [], []
            for _ in range(2):
                if cell == "relevant-call-t1":
                    bare = 1000000 + (pair % 2) * 10000
                    diff = 100 + 10 * pair
                else:
                    bare = 1000000
                    diff = 300
                on_queue.append(bare + diff * 1000 // threads)
                bare_queue.append(bare)
                pair += 1
            for arm in arms:
                if arm == "on":
                    log += sample(cell, arm, rnd, threads, 1000, on_queue.pop(0),
                                  pad=pad, **counted(threads, 1000), **bpf())
                else:
                    log += sample(cell, arm, rnd, threads, 1000, bare_queue.pop(0),
                                  pad=pad, lane="none")
    return log


def den_analyze_text(log, cells=DEN_CELLS, rounds=5):
    with tempfile.TemporaryDirectory(prefix="count-denominator-") as work:
        path = Path(work) / "campaign.log"
        path.write_text(log)
        _, samples, errors = ANALYZE["parse_log"](str(path))
        assert not errors, errors
        return ANALYZE["analyze_traced"](samples, cells, rounds)


class TracedCostOracle(unittest.TestCase):
    def test_traced_cost_four_thread_units_are_completed_calls(self):
        rows, problems = den_analyze_text(dencampaign_log())
        self.assertEqual(problems, [])
        t1 = next(row for row in rows if row["cell"] == "relevant-call-t1")
        self.assertEqual(t1["median_ns"], 145.0)
        t4 = next(row for row in rows if row["cell"] == "relevant-call-t4")
        # Each four-thread on arm takes 75,000 ns more for 1,000
        # total completed calls: 75 ns/call, without multiplying by four.
        self.assertEqual(t4["median_ns"], 75.0)

    def test_traced_cost_relative_budget_uses_completed_call_units(self):
        log = "MACHINE kernel=7.2.9 test-cpu nproc=5\n"
        for cell, threads in (("relevant-call-t1", 1), ("relevant-call-t4", 4)):
            for rnd in range(1, 6):
                arms = ("on", "unobserved", "unobserved", "on") if rnd % 2 else (
                    "unobserved", "on", "on", "unobserved")
                for arm in arms:
                    if arm == "on":
                        log += sample(cell, arm, rnd, threads, 1000, 1250000,
                                      **counted(threads, 1000), **bpf())
                    else:
                        log += sample(cell, arm, rnd, threads, 1000, 1000000,
                                      lane="none")
        rows, problems = den_analyze_text(log)
        self.assertEqual(problems, [])
        for line in ANALYZE["traced_cost_lines"](rows):
            fields = dict(token.split("=", 1) for token in line.split()[1:])
            self.assertEqual(fields["unit"], "ns/completed_call")
            self.assertEqual(int(fields["threads"]),
                             1 if fields["cell"] == "relevant-call-t1" else 4)
            self.assertEqual(int(fields["on_total_calls"]), 10000)
            self.assertEqual(int(fields["unobserved_total_calls"]), 10000)
            production_ns = float(fields["median_ns"])
            self.assertEqual(production_ns, 250.0, fields["cell"])
            # An 80 ns/call dispatcher addition is 32%, above the
            # 15% gate, even though it meets the independent 250 ns gate.
            self.assertEqual(80.0 * 100.0 / production_ns, 32.0)
            self.assertGreater(80.0 * 100.0 / production_ns, 15.0)
            # The inclusive relative boundary remains healthy.
            self.assertEqual(37.5 * 100.0 / production_ns, 15.0)
            self.assertGreater(37.5001 * 100.0 / production_ns, 15.0)

    def test_traced_cost_machine_denominator_round_trips_at_budget_boundary(self):
        cell = "relevant-call-t4"
        for wall_ns, added_ns, expected_pass in (
                (1249960, 37.5, False), (1250040, 37.501, True)):
            log = "MACHINE kernel=7.2.9 test-cpu nproc=5\n"
            for rnd in range(1, 6):
                arms = ("on", "unobserved", "unobserved", "on") if rnd % 2 else (
                    "unobserved", "on", "on", "unobserved")
                for arm in arms:
                    if arm == "on":
                        log += sample(cell, arm, rnd, 4, 1000, wall_ns,
                                      **counted(4, 1000), **bpf())
                    else:
                        log += sample(cell, arm, rnd, 4, 1000, 1000000,
                                      lane="none")
            rows, problems = den_analyze_text(log, cells=(cell,))
            self.assertEqual(problems, [])
            self.assertEqual(len(rows), 1)
            raw = rows[0]["median_ns"]
            line, = ANALYZE["traced_cost_lines"](rows)
            fields = dict(token.split("=", 1) for token in line.split()[1:])
            exported = float(fields["median_ns"])
            self.assertEqual(exported, raw, "machine denominator must round-trip")
            self.assertEqual(added_ns * 100.0 / raw <= 15.0, expected_pass)
            self.assertEqual(added_ns * 100.0 / exported <= 15.0, expected_pass)

    def test_traced_cost_accepts_exact_denominator_campaign(self):
        rows, problems = den_analyze_text(dencampaign_log())
        self.assertEqual(problems, [])
        self.assertEqual(len(rows), 2)
        t1 = next(row for row in rows if row["cell"] == "relevant-call-t1")
        self.assertEqual(t1["median_ns"], 145.0)
        # Interpolated percentiles are float-exact to 1e-9 only.
        self.assertAlmostEqual(t1["p10_ns"], 109.0, places=9)
        self.assertAlmostEqual(t1["p90_ns"], 181.0, places=9)
        self.assertEqual(t1["samples"], 10)
        t4 = next(row for row in rows if row["cell"] == "relevant-call-t4")
        self.assertEqual(
            (t4["median_ns"], t4["p10_ns"], t4["p90_ns"], t4["samples"]),
            (75.0, 75.0, 75.0, 10))
        self.assertEqual(
            ANALYZE["traced_cost_lines"](rows),
            ["TRACED_COST cell=relevant-call-t1 median_ns=145.0 "
             "p10_ns=109.0 p90_ns=181.0 samples=10 unit=ns/completed_call threads=1 "
             "on_total_calls=10000 unobserved_total_calls=10000",
             "TRACED_COST cell=relevant-call-t4 median_ns=75.0 "
             "p10_ns=75.0 p90_ns=75.0 samples=10 unit=ns/completed_call threads=4 "
             "on_total_calls=10000 unobserved_total_calls=10000"])

    def test_traced_cost_subtracts_the_unobserved_baseline(self):
        # The pinned median is the per-pair observed-minus-unobserved
        # cost (145.0), not the raw observed on-arm median (1150.0):
        # dropping the subtraction fails this test.
        rows, problems = den_analyze_text(dencampaign_log())
        self.assertEqual(problems, [])
        t1 = next(row for row in rows if row["cell"] == "relevant-call-t1")
        self.assertEqual(t1["median_ns"], 145.0)
        with tempfile.TemporaryDirectory(prefix="count-denominator-") as work:
            path = Path(work) / "campaign.log"
            path.write_text(dencampaign_log())
            _, samples, _ = ANALYZE["parse_log"](str(path))
        on_units = sorted(
            ANALYZE["unit_ns"](s) for s in samples
            if s["cell"] == "relevant-call-t1" and s["arm"] == "on")
        self.assertEqual(len(on_units), 10)
        on_median = (on_units[4] + on_units[5]) / 2
        self.assertEqual(on_median, 1150.0)
        self.assertNotEqual(t1["median_ns"], on_median)

    def test_traced_cost_reports_parseable_lines_end_to_end(self):
        with tempfile.TemporaryDirectory(prefix="count-denominator-") as work:
            path = Path(work) / "campaign.log"
            path.write_text(dencampaign_log())
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                rc = ANALYZE["main"](["--traced-cost", "--cells",
                                      "relevant-call-t1,relevant-call-t4",
                                      "--rounds", "5", str(path)])
        self.assertEqual(rc, 0)
        self.assertEqual(
            buffer.getvalue().splitlines(),
            ["TRACED_COST cell=relevant-call-t1 median_ns=145.0 "
             "p10_ns=109.0 p90_ns=181.0 samples=10 unit=ns/completed_call threads=1 "
             "on_total_calls=10000 unobserved_total_calls=10000",
             "TRACED_COST cell=relevant-call-t4 median_ns=75.0 "
             "p10_ns=75.0 p90_ns=75.0 samples=10 unit=ns/completed_call threads=4 "
             "on_total_calls=10000 unobserved_total_calls=10000"])

    def test_traced_cost_rejects_bad_shapes(self):
        log = dencampaign_log()
        # An off arm or a scrambled order breaks the round shape.
        bad_off = log.replace("cell=relevant-call-t1 arm=on round=1",
                              "cell=relevant-call-t1 arm=off round=1", 1)
        _, problems = den_analyze_text(bad_off)
        self.assertTrue(any("order" in problem for problem in problems), problems)
        bad_order = log.replace("cell=relevant-call-t1 arm=on round=2",
                                "cell=relevant-call-t1 arm=unobserved round=2", 1)
        _, problems = den_analyze_text(bad_order)
        self.assertTrue(any("order" in problem for problem in problems), problems)
        # Missing on-arm BPF corroboration or an evidenced baseline.
        bad_bpf = log.replace("bpf_ns=200000 bpf_cnt=1000",
                              "bpf_ns=none bpf_cnt=none", 1)
        _, problems = den_analyze_text(bad_bpf)
        self.assertTrue(any("BPF" in problem for problem in problems), problems)
        bad_bare = log.replace("lane=none", "lane=multi", 1)
        _, problems = den_analyze_text(bad_bare)
        self.assertTrue(any("unobserved" in problem for problem in problems),
                        problems)
        # The on-arm count re-verifies against the workload denominator.
        bad_count = log.replace("edge_count=1003", "edge_count=1002", 1)
        _, problems = den_analyze_text(bad_count)
        self.assertTrue(any("denominator" in problem for problem in problems),
                        problems)
        # Missing or extra cells, short rounds, mixed lanes, rebinding.
        _, problems = den_analyze_text(dencampaign_log(cells=DEN_CELLS[:1]))
        self.assertTrue(any("relevant-call-t4" in problem for problem in problems),
                        problems)
        extra = log + sample("rogue", "on", 1, 1, 100, 100000,
                             **counted(1, 100), **bpf())
        _, problems = den_analyze_text(extra)
        self.assertTrue(any("rogue" in problem for problem in problems), problems)
        _, problems = den_analyze_text(dencampaign_log(rounds=2))
        self.assertTrue(any("rounds" in problem for problem in problems), problems)
        bad_lane = log.replace("lane=multi", "lane=singles", 1)
        _, problems = den_analyze_text(bad_lane)
        self.assertTrue(any("mixed lane" in problem for problem in problems),
                        problems)
        bad_threads = log.replace("threads=4", "threads=1", 1)
        _, problems = den_analyze_text(bad_threads)
        self.assertTrue(any("workload" in problem for problem in problems),
                        problems)
        # The modes do not leak into each other.
        with tempfile.TemporaryDirectory(prefix="count-denominator-") as work:
            path = Path(work) / "campaign.log"
            path.write_text(log)
            _, samples, _ = ANALYZE["parse_log"](str(path))
        _, problems = ANALYZE["analyze"](samples, 5.0, 10.0, DEN_CELLS, 5)
        self.assertTrue(problems, "an on/unobserved log is not an M2 campaign")


if __name__ == "__main__":
    unittest.main()
