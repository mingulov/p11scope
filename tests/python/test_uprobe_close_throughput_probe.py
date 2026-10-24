#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for scripts/uprobe-close-throughput-probe.py (A2.0).

Only the pure logic (argument parsing, offset planning, spec building,
timing math, JSON rendering) is tested here; the privileged kernel path
(tracefs + perf_event_open + threaded close) runs under sudo by the
controller and is never executed by this suite.
Run: python3 -I tests/python/test_uprobe_close_throughput_probe.py -v
"""

import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = runpy.run_path(str(ROOT / "scripts/uprobe-close-throughput-probe.py"))


class WidthParsingTests(unittest.TestCase):
    def test_default_widths_are_1_4_16(self):
        args = PROBE["parse_args"]([])
        self.assertEqual(args.widths, [1, 4, 16])

    def test_default_event_count_is_1026(self):
        args = PROBE["parse_args"]([])
        self.assertEqual(args.events, 1026)

    def test_widths_accept_comma_list(self):
        self.assertEqual(PROBE["parse_widths"]("1,4,16"), [1, 4, 16])
        self.assertEqual(PROBE["parse_widths"](" 8 "), [8])

    def test_widths_reject_empty_zero_and_non_integer(self):
        for bad in ("", "1,,4", "0", "-2", "1.5", "x", "1,0"):
            with self.assertRaises(ValueError, msg=bad):
                PROBE["parse_widths"](bad)

    def test_events_override_parses(self):
        args = PROBE["parse_args"](["--events", "513"])
        self.assertEqual(args.events, 513)

    def test_events_reject_non_positive(self):
        for bad in ("0", "-5"):
            with self.assertRaises(SystemExit, msg=bad):
                PROBE["parse_args"](["--events", bad])


class OffsetPlanningTests(unittest.TestCase):
    def test_offsets_are_distinct_and_in_range(self):
        offsets = PROBE["plan_offsets"](28672, 0x1000, 1026)
        self.assertEqual(len(offsets), 1026)
        self.assertEqual(len(set(offsets)), 1026)
        self.assertTrue(all(0x1000 <= o < 28672 for o in offsets))

    def test_offsets_reject_impossible_layouts(self):
        with self.assertRaises(ValueError):
            PROBE["plan_offsets"](4096, 0x1000, 0)
        with self.assertRaises(ValueError):
            PROBE["plan_offsets"](4096, 4096, 8)
        with self.assertRaises(ValueError):
            PROBE["plan_offsets"](4096, 5000, 8)

    def test_uprobe_spec_and_delete_name_exact_probe(self):
        self.assertEqual(
            PROBE["build_uprobe_spec"]("g", "n", "/bin/true", 0x1000),
            "p:g/n /bin/true:0x1000")
        self.assertEqual(PROBE["build_uprobe_delete"]("g", "n"), "-:g/n")


class TimingMathTests(unittest.TestCase):
    def test_per_close_divides_wall_by_count(self):
        self.assertAlmostEqual(PROBE["per_close_ms"](28.0, 1000), 28.0)
        self.assertAlmostEqual(PROBE["per_close_ms"](10.26, 1026), 10.0)

    def test_per_close_fails_closed_on_empty_or_negative(self):
        with self.assertRaises(ValueError):
            PROBE["per_close_ms"](1.0, 0)
        with self.assertRaises(ValueError):
            PROBE["per_close_ms"](-1.0, 1026)

    def test_required_fds_covers_events_plus_headroom(self):
        self.assertEqual(PROBE["required_fds"](1026), 1026 + 64)

    def test_result_line_is_single_json_object_with_required_keys(self):
        line = PROBE["format_result_line"](4, 1026, 28.412, "/bin/true",
                                           "6.6.1", "/sys/kernel/debug/tracing")
        self.assertNotIn("\n", line)
        record = json.loads(line)
        self.assertEqual(record["probe"], "uprobe-close-throughput")
        self.assertEqual(record["width"], 4)
        self.assertEqual(record["events"], 1026)
        self.assertAlmostEqual(record["total_s"], 28.412)
        self.assertAlmostEqual(record["per_close_ms"], 28412.0 / 1026, places=3)
        self.assertEqual(record["binary"], "/bin/true")


if __name__ == "__main__":
    unittest.main()
