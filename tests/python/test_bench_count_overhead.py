#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""M2 counting-overhead analyzer: strict shape and exactness gates (G34).

A reduced log, a None==None count re-check, scrambled ABBA order or a
missing independent BPF corroboration must fail loudly; only a complete
campaign with integer-exact counts renders a verdict. Run as a script:

    python3 -I tests/python/test_bench_count_overhead.py -v
"""
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYZE = runpy.run_path(str(ROOT / "scripts/bench-count-overhead-analyze.py"))

M2_CELLS = ("relevant-call-t1", "relevant-call-t4", "relevant-call-t12",
            "relevant-call-t12-nolock", "unrelated-mmap")


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


if __name__ == "__main__":
    unittest.main()
