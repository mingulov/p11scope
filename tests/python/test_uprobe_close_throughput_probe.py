#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for scripts/uprobe-close-throughput-probe.py (A2.0).

Only the pure logic (argument parsing, offset planning, spec building,
timing math, JSON rendering) is tested here; the privileged kernel path
(tracefs + perf_event_open + threaded close) runs under sudo by the
controller and is never executed by this suite.
Run: python3 -I tests/python/test_uprobe_close_throughput_probe.py -v
"""

import builtins
import ctypes
import json
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class PerfFlagTests(unittest.TestCase):
    def test_perf_flag_fd_cloexec_is_kernel_value(self):
        self.assertEqual(PROBE["PERF_FLAG_FD_CLOEXEC"], 8)
        self.assertEqual(PROBE["PERF_FLAG_FD_CLOEXEC"], 1 << 3)

    def test_perf_event_open_passes_cloexec_flag_to_syscall(self):
        capture = {}
        Attr = PROBE["PerfEventAttr"]

        def fake_cdll(name, use_errno=False):
            self.assertEqual(name, "libc.so.6")
            handle = mock.Mock()

            def fake_syscall(nr, attr_ptr, pid, cpu, group_fd, flags):
                capture["nr"] = nr
                capture["flags"] = flags
                attr = ctypes.cast(attr_ptr, ctypes.POINTER(Attr)).contents
                capture["type"] = attr.type
                capture["config"] = attr.config
                return 99

            handle.syscall = fake_syscall
            return handle

        with mock.patch.object(ctypes, "CDLL", side_effect=fake_cdll):
            fd = PROBE["perf_event_open"](2, 12345)
        self.assertEqual(fd, 99)
        self.assertEqual(capture["nr"], PROBE["NR_PERF_EVENT_OPEN"])
        self.assertEqual(capture["flags"], 8)
        self.assertEqual(capture["type"], 2)
        self.assertEqual(capture["config"], 12345)


class TracepointTypeTests(unittest.TestCase):
    def test_create_events_without_uprobes_type_file_uses_tracepoint_type(self):
        group = "p11close_test"
        with tempfile.TemporaryDirectory() as tmp:
            tracefs = Path(tmp) / "tracing"
            (tracefs / "events" / group).mkdir(parents=True)
            (tracefs / "uprobe_events").write_text("pre-existing\n")
            pid = os.getpid()
            for i in range(2):
                name = "w%d_%d" % (pid, i)
                event = tracefs / "events" / group / name
                event.mkdir(parents=True)
                (event / "id").write_text("42\n")
            self.assertFalse((tracefs / "events/uprobes/type").exists())
            seen = []
            live = PROBE["create_events"].__globals__
            orig = live["perf_event_open"]

            def stub(uprobe_type, config):
                seen.append((uprobe_type, config))
                return 100 + len(seen)

            live["perf_event_open"] = stub
            try:
                fds, names = PROBE["create_events"](
                    str(tracefs), group, "/bin/true", [0x1000, 0x1001])
            finally:
                live["perf_event_open"] = orig
            self.assertEqual([kind for kind, _ in seen], [2, 2])
            self.assertEqual([config for _, config in seen], [42, 42])
            self.assertEqual(len(fds), 2)
            self.assertEqual(len(names), 2)


class UprobeEventsAppendTests(unittest.TestCase):
    def test_uprobe_events_writes_use_append_without_truncate(self):
        group = "p11close_append"
        with tempfile.TemporaryDirectory() as tmp:
            tracefs = Path(tmp) / "tracing"
            (tracefs / "events" / group).mkdir(parents=True)
            (tracefs / "events" / "uprobes").mkdir(parents=True, exist_ok=True)
            (tracefs / "events" / "uprobes" / "type").write_text("999\n")
            uprobe_events = tracefs / "uprobe_events"
            uprobe_events.write_text("pre-existing-line\n")
            pid = os.getpid()
            for i in range(2):
                name = "w%d_%d" % (pid, i)
                event = tracefs / "events" / group / name
                event.mkdir(parents=True)
                (event / "id").write_text("7\n")
            live = PROBE["create_events"].__globals__
            orig_perf = live["perf_event_open"]
            counter = {"n": 0}

            def stub_perf(uprobe_type, config):
                counter["n"] += 1
                return 200 + counter["n"]

            live["perf_event_open"] = stub_perf
            real_os_open = os.open
            calls = []

            def recording_open(path, flags, *args, **kwargs):
                try:
                    text = os.fspath(path)
                except TypeError:
                    text = str(path)
                if str(text).endswith("uprobe_events"):
                    calls.append(flags)
                    if flags & os.O_TRUNC:
                        raise AssertionError("uprobe_events opened with O_TRUNC")
                    if not (flags & os.O_APPEND):
                        raise AssertionError("uprobe_events opened without O_APPEND")
                return real_os_open(path, flags, *args, **kwargs)

            real_open = builtins.open

            def guard_open(file, mode="r", *args, **kwargs):
                try:
                    text = os.fspath(file)
                except TypeError:
                    text = str(file)
                if str(text).endswith("uprobe_events") and "w" in str(mode):
                    raise AssertionError(
                        "uprobe_events must not use mode %r (truncates)" % (mode,))
                return real_open(file, mode, *args, **kwargs)

            try:
                with mock.patch.object(os, "open", side_effect=recording_open):
                    with mock.patch.object(builtins, "open", side_effect=guard_open):
                        fds, names = PROBE["create_events"](
                            str(tracefs), group, "/bin/true", [0x1000, 0x1001])
                        PROBE["delete_probes"](str(tracefs), group, names)
            finally:
                live["perf_event_open"] = orig_perf
            self.assertEqual(len(calls), 4)
            for flags in calls:
                self.assertFalse(flags & os.O_TRUNC)
                self.assertTrue(flags & os.O_APPEND)
                self.assertTrue(flags & os.O_CLOEXEC)
            self.assertIn("pre-existing-line", uprobe_events.read_text())


if __name__ == "__main__":
    unittest.main()
