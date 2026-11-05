# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for scripts/matched-cost-run.py (no root, no binaries).

Covers the parsers (stage timings, readiness lines, GNU time RSS),
percentiles, ABBA/BAAB order, pairing, the comparison summary, and
every input refusal (missing/non-executable binaries, old==new by
path or by bytes, bad duration, bad rounds, unknown cells).

Run: python3 -I scripts/run-python-suites.py test_matched_cost_run.py
"""

import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "scripts" / "matched-cost-run.py"
MOD = runpy.run_path(str(DRIVER))

MatchedCostError = MOD["MatchedCostError"]
parse_stage_timings = MOD["parse_stage_timings"]
first_qualifying_pass = MOD["first_qualifying_pass"]
steady_pass_total = MOD["steady_pass_total"]
parse_time_rss = MOD["parse_time_rss"]
parse_readiness = MOD["parse_readiness"]
round_order = MOD["round_order"]
wait_for_quiet = MOD["wait_for_quiet"]
paired_deltas = MOD["paired_deltas"]
summarize = MOD["summarize"]
render_table = MOD["render_table"]
validate_args = MOD["validate_args"]
p50 = MOD["p50"]
p95 = MOD["p95"]

STDERR = """p11scope: enumerating processes...
p11scope: pass 0: stage timings: sweep 81.5ms select 4.7ms deep_scan 286.8ms assemble 36.6ms confirm 168.5ms absorb 0.1ms reconcile 50.3ms project 5.2ms
p11scope: pass 1: stage timings: sweep 70.0ms select 4.0ms deep_scan 200.0ms assemble 30.0ms confirm 120.0ms absorb 0.1ms reconcile 6.5ms project 5.0ms
p11scope: pass 2: stage timings: sweep 71.0ms select 4.1ms deep_scan 201.0ms assemble 31.0ms confirm 121.0ms absorb 0.1ms reconcile 6.6ms project 5.1ms
"""

TIME_V = """Command exited with non-zero status 0
Maximum resident set size (kbytes): 123456
"""


def make_args(**overrides):
    params = {
        "old": "/bin/true",
        "new": "/bin/false",
        "out": tempfile.mkdtemp(prefix="matched-cost-"),
        "rounds": 1,
        "duration": "20s",
        "max_scan_pids": 8,
        "cells": "counts-system,detailed-pid,inventory-system",
    }
    params.update(overrides)
    return SimpleNamespace(**params)


class ParserTests(unittest.TestCase):
    def test_stage_timings_parse_units(self):
        passes = parse_stage_timings(STDERR)
        self.assertEqual([number for number, _ in passes], [0, 1, 2])
        ops = passes[0][1]
        self.assertAlmostEqual(ops["sweep"], 81.5e6)
        self.assertAlmostEqual(ops["confirm"], 168.5e6)
        self.assertAlmostEqual(sum(ops.values()), 633.7e6)

    def test_first_qualifying_pass_needs_confirm(self):
        bare = "p11scope: pass 0: stage timings: sweep 1ms select 1ms confirm 0ms\n"
        with self.assertRaises(MatchedCostError):
            first_qualifying_pass(parse_stage_timings(bare))
        number, ops = first_qualifying_pass(parse_stage_timings(STDERR))
        self.assertEqual(number, 0)
        self.assertIn("confirm", ops)

    def test_steady_pass_is_median_of_later(self):
        passes = parse_stage_timings(STDERR)
        first_total = sum(passes[0][1].values())
        later = sorted(sum(ops.values()) for _, ops in passes[1:])
        self.assertEqual(steady_pass_total(passes), later[0])
        self.assertNotEqual(steady_pass_total(passes), first_total)

    def test_steady_pass_refuses_single_pass(self):
        one = parse_stage_timings(STDERR.splitlines()[1])
        with self.assertRaises(MatchedCostError):
            steady_pass_total(one)

    def test_time_rss_parses(self):
        self.assertEqual(parse_time_rss(TIME_V), 123456)

    def test_time_rss_refuses_blank(self):
        with self.assertRaises(MatchedCostError):
            parse_time_rss("no rss here\n")

    def test_readiness_detailed_pid(self):
        lines = ["noise", "p11scope: capturing: 136 probe(s) attached; stop with Ctrl-C"]
        index, probes = parse_readiness(lines, "detailed-pid")
        self.assertEqual((index, probes), (1, 136))

    def test_readiness_counts_system(self):
        lines = ["p11scope: native usage lane active (Inventory capture activated, 3 links)"]
        index, probes = parse_readiness(lines, "counts-system")
        self.assertEqual((index, probes), (0, None))

    def test_readiness_inventory_system_uses_first_pass(self):
        lines = STDERR.splitlines()
        index, probes = parse_readiness(lines, "inventory-system")
        self.assertEqual(index, 1)
        self.assertIsNone(probes)

    def test_readiness_refuses_silent_stderr(self):
        with self.assertRaises(MatchedCostError):
            parse_readiness(["nothing here"], "detailed-pid")


class StatsTests(unittest.TestCase):
    def test_p95_index_is_ceil(self):
        values = list(range(1, 21))
        self.assertEqual(p95(values), 19)
        self.assertEqual(p50(values), 10)

    def test_p95_single_sample(self):
        self.assertEqual(p95([7.0]), 7.0)

    def test_p95_refuses_empty(self):
        with self.assertRaises(MatchedCostError):
            p95([])

    def test_round_order_is_abba_baab(self):
        self.assertEqual(round_order(1), ("new", "old", "old", "new"))
        self.assertEqual(round_order(2), ("old", "new", "new", "old"))
        self.assertEqual(round_order(3), ("new", "old", "old", "new"))

    def test_paired_deltas_pair_in_order(self):
        self.assertEqual(paired_deltas([1.0, 2.0], [1.5, 1.0]), [0.5, -1.0])

    def test_paired_deltas_refuses_uneven(self):
        with self.assertRaises(MatchedCostError):
            paired_deltas([1.0], [1.0, 2.0])

    def test_summarize_computes_paired_median_pct(self):
        samples = []
        for arm, base in (("old", 100.0), ("new", 110.0)):
            for trial in range(4):
                samples.append({
                    "cell": "inventory-system",
                    "tag": f"{arm}-inventory-system-r01-{trial}",
                    "startup_ns": base,
                    "wall_ns": base * 10,
                    "peak_rss_kb": 1024.0,
                })
        table = summarize(samples)["inventory-system"]["startup_ns"]
        self.assertEqual(table["old_p50"], 100.0)
        self.assertEqual(table["new_p50"], 110.0)
        self.assertEqual(table["paired_median_delta"], 10.0)
        self.assertAlmostEqual(table["paired_median_delta_pct"], 10.0)
        self.assertEqual((table["old_n"], table["new_n"]), (4, 4))

    def test_summarize_skips_missing_metric(self):
        samples = [
            {"cell": "detailed-pid", "tag": "old-x", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0},
            {"cell": "detailed-pid", "tag": "new-x", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0},
        ]
        table = summarize(samples)["detailed-pid"]
        self.assertNotIn("firstpass_ns", table)
        self.assertIn("startup_ns", table)

    def test_render_table_names_cells_and_metrics(self):
        samples = [
            {"cell": "detailed-pid", "tag": "old-x", "startup_ns": 1e9,
             "wall_ns": 2e9, "peak_rss_kb": 2048.0},
            {"cell": "detailed-pid", "tag": "new-x", "startup_ns": 1e9,
             "wall_ns": 2e9, "peak_rss_kb": 2048.0},
        ]
        text = render_table(summarize(samples))
        self.assertIn("detailed-pid", text)
        self.assertIn("startup_ns", text)
        self.assertIn("peak_rss_kb", text)


def patch_main_globals(test, **overrides):
    """Patch main()'s live globals (runpy returns a snapshot, not these)."""
    live = MOD["main"].__globals__
    saved = {name: live[name] for name in overrides if name in live}
    missing = [name for name in overrides if name not in live]
    live.update(overrides)
    def restore():
        for name in overrides:
            if name in saved:
                live[name] = saved[name]
            else:
                del live[name]
    test.addCleanup(restore)
    assert not missing, f"no driver global(s): {missing}"


class UnevenPairingTests(unittest.TestCase):
    """summarize() must survive arm gaps (round/pair keying, never raise)."""

    def test_uneven_steady_pairs_matched_pair_only(self):
        # Round 1 ABBA: new@0, old@1, old@2, new@3; new@3 lost steady.
        samples = [
            {"cell": "c", "tag": "new-c-r01-0", "steady_ns": 110.0},
            {"cell": "c", "tag": "old-c-r01-1", "steady_ns": 100.0},
            {"cell": "c", "tag": "old-c-r01-2", "steady_ns": 200.0},
            {"cell": "c", "tag": "new-c-r01-3", "steady_ns": None},
        ]
        row = summarize(samples)["c"]["steady_ns"]
        self.assertEqual(row["paired_median_delta"], 10.0)
        self.assertEqual(row["paired_n"], 1)
        self.assertEqual((row["old_n"], row["new_n"]), (2, 1))

    def test_no_matched_pair_skips_metric(self):
        samples = [
            {"cell": "c", "tag": "new-c-r01-0", "steady_ns": 110.0},
            {"cell": "c", "tag": "old-c-r01-1", "steady_ns": None},
            {"cell": "c", "tag": "old-c-r02-2", "steady_ns": 200.0},
            {"cell": "c", "tag": "new-c-r02-3", "steady_ns": None},
        ]
        table = summarize(samples)["c"]
        self.assertNotIn("steady_ns", table)

    def test_uneven_unkeyed_tags_skip_metric(self):
        samples = [
            {"cell": "c", "tag": "old-x", "steady_ns": 100.0},
            {"cell": "c", "tag": "old-y", "steady_ns": 200.0},
            {"cell": "c", "tag": "new-x", "steady_ns": 110.0},
        ]
        table = summarize(samples)["c"]
        self.assertNotIn("steady_ns", table)

    def test_main_survives_uneven_samples(self):
        main = MOD["main"]
        samples = [
            {"cell": "c", "tag": "old-c-r01-1", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0, "steady_ns": 100.0},
            {"cell": "c", "tag": "old-c-r01-2", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0, "steady_ns": 200.0},
            {"cell": "c", "tag": "new-c-r01-0", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0, "steady_ns": 110.0},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old"
            new = Path(tmp) / "new"
            old.write_bytes(b"old-bytes")
            new.write_bytes(b"new-bytes")
            out = Path(tmp) / "out"
            out.mkdir()
            patch_main_globals(self, run_campaign=lambda args: samples)
            code = main(["--old", str(old), "--new", str(new),
                         "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertTrue((out / "comparison.json").is_file())

    def test_main_converts_summarize_refusal_to_exit_1(self):
        main = MOD["main"]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            patch_main_globals(
                self,
                run_campaign=lambda args: [],
                summarize=lambda samples: (_ for _ in ()).throw(
                    MatchedCostError("boom")),
            )
            code = main(["--old", "/bin/true", "--new", "/bin/false",
                         "--out", str(out)])
            self.assertEqual(code, 1)


class ProvenanceTests(unittest.TestCase):
    """comparison.json must identify the compared binaries and campaign."""

    def test_binary_provenance_records_digests_and_campaign(self):
        import hashlib
        provenance = MOD["binary_provenance"]
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old"
            new = Path(tmp) / "new"
            old.write_bytes(b"old-bytes")
            new.write_bytes(b"new-bytes")
            meta = provenance(str(old), str(new), "30s", 40)
        self.assertEqual(meta["old_path"], str(old))
        self.assertEqual(meta["new_path"], str(new))
        self.assertEqual(meta["old_sha256"], hashlib.sha256(b"old-bytes").hexdigest())
        self.assertEqual(meta["new_sha256"], hashlib.sha256(b"new-bytes").hexdigest())
        self.assertTrue(meta["kernel"])
        self.assertEqual(meta["duration"], "30s")
        self.assertEqual(meta["max_scan_pids"], 40)

    def test_binary_provenance_refuses_unreadable(self):
        provenance = MOD["binary_provenance"]
        with self.assertRaisesRegex(MatchedCostError, "cannot hash"):
            provenance("/nonexistent/old", "/nonexistent/new", "30s", 40)

    def test_comparison_json_carries_meta(self):
        import json
        main = MOD["main"]
        samples = [
            {"cell": "c", "tag": "old-x", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0},
            {"cell": "c", "tag": "new-x", "startup_ns": 1.0,
             "wall_ns": 2.0, "peak_rss_kb": 3.0},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old"
            new = Path(tmp) / "new"
            old.write_bytes(b"old-bytes")
            new.write_bytes(b"new-bytes")
            out = Path(tmp) / "out"
            out.mkdir()
            patch_main_globals(self, run_campaign=lambda args: samples)
            code = main(["--old", str(old), "--new", str(new),
                         "--out", str(out), "--duration", "30s",
                         "--max-scan-pids", "40"])
            self.assertEqual(code, 0)
            doc = json.loads((out / "comparison.json").read_text(encoding="utf-8"))
        self.assertIn("meta", doc)
        self.assertEqual(doc["meta"]["duration"], "30s")
        self.assertEqual(doc["meta"]["max_scan_pids"], 40)
        self.assertTrue(doc["meta"]["old_sha256"])
        self.assertTrue(doc["meta"]["new_sha256"])

    def test_render_table_echoes_provenance(self):
        render = MOD["render_table"]
        meta = {
            "old_path": "/b/old", "new_path": "/b/new",
            "old_sha256": "a" * 64, "new_sha256": "b" * 64,
            "kernel": "7.0.0-test", "duration": "30s", "max_scan_pids": 40,
        }
        samples = [
            {"cell": "c", "tag": "old-x", "startup_ns": 1e9,
             "wall_ns": 2e9, "peak_rss_kb": 2048.0},
            {"cell": "c", "tag": "new-x", "startup_ns": 1e9,
             "wall_ns": 2e9, "peak_rss_kb": 2048.0},
        ]
        text = render(summarize(samples), meta)
        self.assertIn("/b/old", text)
        self.assertIn("/b/new", text)
        self.assertIn("7.0.0-test", text)
        self.assertIn("30s", text)


class RefusalTests(unittest.TestCase):
    def check(self, args, pattern):
        """validate_args as root must refuse with a message naming the cause."""
        with self.assertRaisesRegex(MatchedCostError, pattern):
            validate_args(args, euid=0)

    def test_non_root_refused(self):
        with self.assertRaisesRegex(MatchedCostError, "needs root"):
            validate_args(make_args(), euid=1000)

    def test_missing_old_refused(self):
        self.check(make_args(old="/nonexistent/binary"), "not a file")

    def test_non_executable_new_refused(self):
        with tempfile.NamedTemporaryFile() as handle:
            self.check(make_args(new=handle.name), "not executable")

    def test_same_path_refused(self):
        self.check(make_args(old="/bin/true", new="/bin/true"), "same file")

    def test_same_file_by_link_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link"
            link.symlink_to("/bin/true")
            self.check(make_args(old="/bin/true", new=str(link)), "same file")

    def test_identical_bytes_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a"
            second = Path(tmp) / "b"
            first.write_bytes(b"same-bytes")
            second.write_bytes(b"same-bytes")
            first.chmod(0o755)
            second.chmod(0o755)
            self.check(make_args(old=str(first), new=str(second)), "identical bytes")

    def test_distinct_bytes_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a"
            second = Path(tmp) / "b"
            first.write_bytes(b"bytes-a")
            second.write_bytes(b"bytes-b")
            first.chmod(0o755)
            second.chmod(0o755)
            seconds = validate_args(
                make_args(old=str(first), new=str(second)), euid=0
            )
            self.assertEqual(seconds, 20)

    def test_bad_duration_refused(self):
        for bad in ("20", "xs", "20m", "4s", "301s"):
            with self.assertRaises(MatchedCostError, msg=bad):
                validate_args(make_args(duration=bad), euid=0)

    def test_bad_rounds_refused(self):
        self.check(make_args(rounds=0), "--rounds")

    def test_bad_scan_cap_refused(self):
        self.check(make_args(max_scan_pids=0), "--max-scan-pids")

    def test_unknown_cell_refused(self):
        self.check(make_args(cells="counts-system,nope"), "unknown cell")

    def test_quiet_wait_refuses_impossible_gates(self):
        with self.assertRaisesRegex(MatchedCostError, "never settled"):
            wait_for_quiet(0.0, 0.0, 0, "test-label")

    def test_quiet_wait_allow_builders_keeps_load_gate(self):
        with self.assertRaisesRegex(MatchedCostError, "never settled"):
            wait_for_quiet(0.0, 0.0, 0, "test-label", allow_builders=True)

    def test_quiet_wait_accepts_satisfied_gates(self):
        load1, _ = wait_for_quiet(1000.0, 1000.0, 0, "test-label",
                                  allow_builders=True)
        self.assertGreaterEqual(load1, 0.0)


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    unittest.main(verbosity=2)
