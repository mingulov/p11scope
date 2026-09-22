# SPDX-License-Identifier: GPL-3.0-or-later
"""Loss-share measurement oracle (Task 3.1): trace-stream, burst-timing,
event-path arithmetic, window-validity, and loadavg helpers imported from
scripts/system-scope-measure.py, never copied.

Run: python3 -I tests/python/test_loss_share_measure.py -v
"""

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEASURE = runpy.run_path(str(ROOT / "scripts/system-scope-measure.py"))


def trace_fixture(*, lost_values=(), truncated=False, functions=(),
                  qualifier=False, mechanism=False):
    """A complete synthetic trace stream with exact expected tallies."""
    lines = ["CAPTURE privacy=allowlisted"]
    for function in functions:
        label = function
        if qualifier:
            label += " [semantics unverified]"
        if mechanism:
            label += " CKM_RSA_PKCS_PSS(hash=CKM_SHA256 mgf=CKG_MGF1_SHA256 salt=32)"
        lines.append(
            f"03:15:44.123456 pid 111 tid 111 {label} \u2192 CKR_OK 1.23\u00b5s")
    for value in lost_values:
        lines.append(f"LOST {value} events")
    if truncated:
        lines.append("TRUNCATED at 100 events (--max-events)")
    stats_returned = 20006 if functions else 0
    lines.append(
        'COUNT_EVIDENCE {"stats_entered": %d, "stats_returned": %d, '
        '"raw_calls": %d}' % (stats_returned, stats_returned, len(functions)))
    lines.append(
        'EVIDENCE {"schema": "p11scope/capture-evidence/v1", '
        '"completeness": "PARTIAL", "attached_probes": 136, "slots": 68, '
        '"event_loss": %d}' % (lost_values[-1] if lost_values else 0))
    return "\n".join(lines) + "\n"


class TraceStreamTests(unittest.TestCase):
    def parse(self, text):
        return MEASURE["parse_trace_stream"](text.splitlines(keepends=True))

    def test_call_lines_count_exactly_with_sess_and_plain_shapes(self):
        text = trace_fixture(functions=["C_GenerateRandom"] * 3)
        # One sess-tagged twin exercises the optional sess#n prefix.
        text = text.replace("pid 111 tid 111 C_GenerateRandom",
                            "pid 111 tid 111 sess#7 C_GenerateRandom", 1)
        parsed = self.parse(text)
        self.assertEqual(parsed["call_lines_total"], 3)
        self.assertEqual(parsed["per_function"], {"C_GenerateRandom": 3})
        self.assertEqual(parsed["lost_total"], 0)
        self.assertFalse(parsed["truncated"])

    def test_function_token_survives_qualifier_and_mechanism_suffixes(self):
        text = trace_fixture(functions=["C_Sign", "unknown"],
                             qualifier=True, mechanism=True)
        parsed = self.parse(text)
        self.assertEqual(parsed["per_function"], {"C_Sign": 1, "unknown": 1})
        self.assertEqual(parsed["qualified_lines"], 2)
        self.assertEqual(parsed["mechanism_lines"], 2)

    def test_plain_lines_carry_no_qualifier_or_mechanism_flags(self):
        parsed = self.parse(trace_fixture(functions=["C_GenerateRandom"]))
        self.assertEqual(parsed["qualified_lines"], 0)
        self.assertEqual(parsed["mechanism_lines"], 0)

    def test_lost_lines_are_cumulative_last_value_wins(self):
        parsed = self.parse(trace_fixture(lost_values=(101, 2620)))
        self.assertEqual(parsed["lost_values"], [101, 2620])
        self.assertEqual(parsed["lost_total"], 2620)

    def test_lost_line_drop_changes_the_total(self):
        # Mutation guard: the parser must read every LOST line, so removing
        # one from the fixture changes the attributed loss.
        full = self.parse(trace_fixture(lost_values=(101, 2620)))
        dropped = self.parse(trace_fixture(lost_values=(101,)))
        self.assertNotEqual(full["lost_total"], dropped["lost_total"])

    def test_decreasing_lost_series_fails_closed(self):
        text = trace_fixture(lost_values=(2620, 101))
        with self.assertRaises(ValueError):
            self.parse(text)

    def test_count_evidence_fields_are_exact(self):
        parsed = self.parse(trace_fixture(functions=["C_GenerateRandom"] * 5))
        self.assertEqual(parsed["count_evidence"]["stats_returned"], 20006)
        self.assertEqual(parsed["count_evidence"]["raw_calls"], 5)

    def test_evidence_json_is_exposed_verbatim(self):
        parsed = self.parse(trace_fixture(lost_values=(7,)))
        self.assertEqual(parsed["evidence"]["event_loss"], 7)
        self.assertEqual(parsed["evidence"]["attached_probes"], 136)

    def test_truncated_flag_survives(self):
        parsed = self.parse(trace_fixture(truncated=True))
        self.assertTrue(parsed["truncated"])

    def test_garbage_line_fails_closed(self):
        text = trace_fixture(functions=["C_GenerateRandom"])
        text += "something the observer never prints\n"
        with self.assertRaises(ValueError):
            self.parse(text)

    def test_missing_evidence_fails_closed(self):
        lines = [line for line in trace_fixture().splitlines(keepends=True)
                 if not line.startswith("EVIDENCE ")]
        with self.assertRaises(ValueError):
            MEASURE["parse_trace_stream"](lines)

    def test_missing_count_evidence_fails_closed(self):
        lines = [line for line in trace_fixture().splitlines(keepends=True)
                 if not line.startswith("COUNT_EVIDENCE ")]
        with self.assertRaises(ValueError):
            MEASURE["parse_trace_stream"](lines)

    def test_missing_capture_header_fails_closed(self):
        lines = [line for line in trace_fixture().splitlines(keepends=True)
                 if not line.startswith("CAPTURE ")]
        with self.assertRaises(ValueError):
            MEASURE["parse_trace_stream"](lines)

    def test_empty_lines_are_skipped(self):
        text = "\n" + trace_fixture(functions=["C_GenerateRandom"]) + "\n"
        parsed = self.parse(text)
        self.assertEqual(parsed["call_lines_total"], 1)


class BurstParseTests(unittest.TestCase):
    LOG = ("TRUTH_PREGO {}\n"
           "BURST go_ns=1000000000 end_ns=1500000000\n"
           "TRUTH {\"C_GenerateRandom\": 20000}\n")

    def test_burst_bounds_are_exact(self):
        go_ns, end_ns = MEASURE["parse_burst"](self.LOG.splitlines())
        self.assertEqual((go_ns, end_ns), (1000000000, 1500000000))

    def test_missing_burst_fails_closed(self):
        with self.assertRaises(SystemExit):
            MEASURE["parse_burst"](["TRUTH {}\n"])

    def test_reversed_burst_fails_closed(self):
        log = self.LOG.replace("go_ns=1000000000 end_ns=1500000000",
                               "go_ns=1500000000 end_ns=1000000000")
        with self.assertRaises(SystemExit):
            MEASURE["parse_burst"](log.splitlines())

    def test_burst_rate_math_is_exact(self):
        rate = MEASURE["burst_rate_per_s"](20000, 1000000000, 1500000000)
        self.assertAlmostEqual(rate, 40000.0)
        self.assertIsNone(MEASURE["burst_rate_per_s"](0, 1, 1))


class EventPathTests(unittest.TestCase):
    def test_ring_capacity_pins_336_byte_records(self):
        capacity = MEASURE["ring_capacity_records"]
        self.assertEqual(capacity(256 * 1024), 780)
        self.assertEqual(capacity(64 * 1024), 195)
        self.assertEqual(capacity(1024 * 1024), 3120)
        self.assertEqual(capacity(4 * 1024 * 1024), 12483)
        self.assertIsNone(capacity(None))

    def test_predicted_burst_loss_is_floor_at_zero(self):
        predicted = MEASURE["predicted_burst_loss"]
        self.assertEqual(predicted(20006, 780), 19226)
        self.assertEqual(predicted(100, 780), 0)
        self.assertIsNone(predicted(20006, None))

    def test_profile_derives_delivered_only_with_zero_pre_reserve_failures(self):
        build = MEASURE["build_event_path"]
        exact = build(mode="profile", generated=20006, kernel_observed=20006,
                      event_loss=19226, semantic_capture_failures=0,
                      call_lines=None, raw_calls=None,
                      ring_bytes=256 * 1024, burst_wall_s=0.5)
        self.assertEqual(exact["delivered_derived"], 780)
        self.assertIsNone(exact["delivery_gap"])
        gapped = build(mode="profile", generated=20006, kernel_observed=20006,
                       event_loss=19226, semantic_capture_failures=3,
                       call_lines=None, raw_calls=None,
                       ring_bytes=256 * 1024, burst_wall_s=0.5)
        self.assertIsNone(gapped["delivered_derived"])
        self.assertIn("semantic_capture_failures=3", gapped["delivery_gap"])

    def test_trace_cross_checks_lines_against_raw_calls(self):
        build = MEASURE["build_event_path"]
        exact = build(mode="trace", generated=7, kernel_observed=7,
                      event_loss=0, semantic_capture_failures=0,
                      call_lines=7, raw_calls=7,
                      ring_bytes=256 * 1024, burst_wall_s=0.01)
        self.assertTrue(exact["lines_vs_raw_calls_match"])
        self.assertIsNone(exact["delivery_gap"])
        gapped = build(mode="trace", generated=7, kernel_observed=7,
                       event_loss=0, semantic_capture_failures=0,
                       call_lines=5, raw_calls=7,
                       ring_bytes=256 * 1024, burst_wall_s=0.01)
        self.assertFalse(gapped["lines_vs_raw_calls_match"])
        self.assertIn("raw_calls=7", gapped["delivery_gap"])

    def test_metrics_has_no_ring_traffic(self):
        build = MEASURE["build_event_path"]
        path = build(mode="metrics", generated=20006, kernel_observed=20006,
                     event_loss=0, semantic_capture_failures=0,
                     call_lines=None, raw_calls=None,
                     ring_bytes=256 * 1024, burst_wall_s=0.5)
        self.assertIsNone(path["delivered_derived"])
        self.assertIn("no ring traffic", path["delivery_gap"])

    def test_event_path_carries_rate_and_model(self):
        build = MEASURE["build_event_path"]
        path = build(mode="profile", generated=20006, kernel_observed=20006,
                     event_loss=19226, semantic_capture_failures=0,
                     call_lines=None, raw_calls=None,
                     ring_bytes=256 * 1024, burst_wall_s=0.5)
        self.assertEqual(path["ring_capacity_records"], 780)
        self.assertEqual(path["predicted_burst_loss"], 19226)
        self.assertAlmostEqual(path["burst_rate_per_s"], 40012.0)


class WindowValidityTests(unittest.TestCase):
    def assess(self, **overrides):
        kwargs = {"gate": "frame", "scope": "pid", "counts_match": True,
                  "burst_outside_window": False, "attached_probes": 136,
                  "trace_crosscheck": True}
        kwargs.update(overrides)
        return MEASURE["assess_window"](**kwargs)

    def test_frame_gate_is_strong(self):
        window = self.assess()
        self.assertEqual(window["gate_strength"], "strong")
        self.assertTrue(window["window_valid"])

    def test_weak_gate_pid_valid_only_on_exact_counts(self):
        self.assertTrue(self.assess(gate="marker+settle:10s")["window_valid"])
        invalid = self.assess(gate="marker+settle:10s", counts_match=False)
        self.assertFalse(invalid["window_valid"])
        self.assertIn("counts_match=False", invalid["window_note"])

    def test_weak_gate_system_needs_probes_and_no_burst_escape(self):
        valid = self.assess(gate="marker+plateau+settle:20s", scope="system")
        self.assertTrue(valid["window_valid"])
        escaped = self.assess(gate="marker+plateau+settle:20s",
                              scope="system", burst_outside_window=True)
        self.assertFalse(escaped["window_valid"])
        self.assertIn("BURST OUTSIDE WINDOW", escaped["window_note"])
        unattached = self.assess(gate="marker+plateau+settle:20s",
                                 scope="system", attached_probes=0)
        self.assertFalse(unattached["window_valid"])

    def test_failed_trace_crosscheck_invalidates(self):
        window = self.assess(gate="marker+settle:10s", trace_crosscheck=False)
        self.assertFalse(window["window_valid"])


class RingBytesTests(unittest.TestCase):
    def test_default_is_4mib(self):
        resolve = MEASURE["resolve_ring_bytes"]
        self.assertEqual(resolve("default"), 4 * 1024 * 1024)
        self.assertEqual(resolve(None), 4 * 1024 * 1024)

    def test_suffixes_and_bare_ints(self):
        resolve = MEASURE["resolve_ring_bytes"]
        self.assertEqual(resolve("64K"), 64 * 1024)
        self.assertEqual(resolve("1M"), 1024 * 1024)
        self.assertEqual(resolve(65536), 65536)
        self.assertEqual(resolve("262144"), 262144)

    def test_garbage_fails_closed(self):
        with self.assertRaises(ValueError):
            MEASURE["resolve_ring_bytes"]("huge")


class TraceMatchTests(unittest.TestCase):
    def test_pid_requires_exact_kernel_total(self):
        match, note = MEASURE["trace_counts_match"](
            "pid", {"C_GenerateRandom": 20000}, 20000)
        self.assertTrue(match)
        match, _ = MEASURE["trace_counts_match"](
            "pid", {"C_GenerateRandom": 20000}, 19999)
        self.assertFalse(match)

    def test_system_requires_covering_kernel_total(self):
        match, _ = MEASURE["trace_counts_match"](
            "system", {"C_GenerateRandom": 20000}, 20010)
        self.assertTrue(match)
        match, _ = MEASURE["trace_counts_match"](
            "system", {"C_GenerateRandom": 20000}, 19999)
        self.assertFalse(match)

    def test_crosscheck_pins_loss_identity(self):
        holds, _ = MEASURE["trace_crosscheck"](
            lost_total=2620, event_loss=2620, stats_returned=20006,
            raw_calls=17386, semantic_failures=0, truncated=False)
        self.assertTrue(holds)
        # Dropped LOST lines (stale last value) must not cross-check.
        holds, detail = MEASURE["trace_crosscheck"](
            lost_total=101, event_loss=2620, stats_returned=20006,
            raw_calls=17386, semantic_failures=0, truncated=False)
        self.assertFalse(holds)
        self.assertIn("LOST", detail)
        # Truncation suppresses lines after the limit: no identity claimed.
        holds, detail = MEASURE["trace_crosscheck"](
            lost_total=0, event_loss=0, stats_returned=20006,
            raw_calls=20006, semantic_failures=0, truncated=True)
        self.assertFalse(holds)
        self.assertIn("truncated", detail)


class LoadavgTests(unittest.TestCase):
    def test_loadavg_triple_parses(self):
        self.assertEqual(
            MEASURE["parse_loadavg"]("3.20 3.53 4.19 7/1919 3126663"),
            (3.20, 3.53, 4.19))

    def test_missing_or_malformed_loadavg_is_none(self):
        self.assertIsNone(MEASURE["parse_loadavg"](None))
        self.assertIsNone(MEASURE["parse_loadavg"]("bogus"))


def scheduling_fixture(**overrides):
    """A valid scheduling sub-object, idle unless overridden."""
    fixture = {
        "drain_repolls": 0,
        "drain_budget_exhaustions": 0,
        "capture_event_loss": 0,
        "detach_event_loss": 0,
        "capture_discovery_loss": 0,
        "detach_discovery_loss": 0,
        "terminal_drain_bound": 65536,
        "terminal_drain_truncated": False,
        "sink_policy": "bounded-wait-drop",
        "sink_stall_ms": 0,
        "sink_timeouts": 0,
        "sink_dropped_bytes": 0,
        "phase_ms": {
            "discovery": 0, "discovery_terminal": 0, "drain": 0,
            "maps": 0, "render": 0, "detach": 0,
        },
        "max_inter_drain_gap_ms": 0,
    }
    fixture.update(overrides)
    return fixture


class SchedulingEvidenceCheckTests(unittest.TestCase):
    def test_valid_scheduling_passes(self):
        evidence = {"event_loss": 10, "discovery_ring_loss": 0,
                    "scheduling": scheduling_fixture(
                        capture_event_loss=6, detach_event_loss=4)}
        ok, _ = MEASURE["check_scheduling_evidence"](evidence)
        self.assertTrue(ok)

    def test_missing_scheduling_fails_closed(self):
        ok, detail = MEASURE["check_scheduling_evidence"](
            {"event_loss": 0, "discovery_ring_loss": 0})
        self.assertFalse(ok)
        self.assertIn("missing", detail)

    def test_split_mismatch_fails(self):
        evidence = {"event_loss": 10, "discovery_ring_loss": 0,
                    "scheduling": scheduling_fixture(
                        capture_event_loss=6, detach_event_loss=5)}
        ok, detail = MEASURE["check_scheduling_evidence"](evidence)
        self.assertFalse(ok)
        self.assertIn("split", detail)

    def test_wrong_policy_fails(self):
        evidence = {"event_loss": 0, "discovery_ring_loss": 0,
                    "scheduling": scheduling_fixture(sink_policy="drop-all")}
        ok, _ = MEASURE["check_scheduling_evidence"](evidence)
        self.assertFalse(ok)


class LossAttributionTests(unittest.TestCase):
    def test_zero_loss_is_lossless(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=0,
            semantic_failures=0, scheduling=scheduling_fixture())
        self.assertEqual(result["status"], "lossless")

    def test_unthrottled_small_loss_is_capacity(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=700,
            semantic_failures=0, scheduling=scheduling_fixture())
        self.assertEqual(result["status"], "attributed")
        self.assertIn("ring-capacity-vs-production", result["bounds"])

    def test_budget_exhaustion_names_the_tick_budget(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=700,
            semantic_failures=0,
            scheduling=scheduling_fixture(drain_budget_exhaustions=3))
        self.assertEqual(result["status"], "attributed")
        self.assertIn("drain-tick-budget", result["bounds"])
        self.assertNotIn("ring-capacity-vs-production", result["bounds"])

    def test_detach_share_names_the_detach_window(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=700,
            semantic_failures=0,
            scheduling=scheduling_fixture(
                capture_event_loss=690, detach_event_loss=10))
        self.assertEqual(result["status"], "attributed")
        self.assertIn("detach-window", result["bounds"])

    def test_terminal_truncation_names_the_terminal_bound(self):
        result = MEASURE["attribute_loss"](
            truth_calls=100000, ring_capacity=780, event_loss=65000,
            semantic_failures=0,
            scheduling=scheduling_fixture(terminal_drain_truncated=True))
        self.assertEqual(result["status"], "attributed")
        self.assertIn("terminal-drain-bound", result["bounds"])

    def test_sink_drops_name_the_slow_sink(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=3,
            semantic_failures=0,
            scheduling=scheduling_fixture(
                sink_timeouts=2, sink_dropped_bytes=4096))
        self.assertEqual(result["status"], "attributed")
        self.assertIn("slow-sink", result["bounds"])

    def test_semantic_skips_guard_attribution(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=5,
            semantic_failures=1, scheduling=scheduling_fixture())
        self.assertEqual(result["status"], "guarded")

    def test_unexplained_loss_fails_closed(self):
        # Loss past burst physics with no bound fired: unattributed,
        # never silently absorbed.
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=19900,
            semantic_failures=0, scheduling=scheduling_fixture())
        self.assertEqual(result["status"], "UNATTRIBUTED")

    def test_missing_scheduling_cannot_claim_repair_credit(self):
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=0,
            semantic_failures=0, scheduling=None)
        self.assertEqual(result["status"], "lossless-unverified")
        result = MEASURE["attribute_loss"](
            truth_calls=20000, ring_capacity=780, event_loss=5,
            semantic_failures=0, scheduling=None)
        self.assertEqual(result["status"], "UNATTRIBUTED")


class CancelProbeTests(unittest.TestCase):
    MARKER = ("p11scope: cancel: loop exited on signal 2 "
              "after 137 ticks")

    def test_marker_parses(self):
        row = {"ts_ns": 1720000000000000000, "stream": "stderr",
               "line": self.MARKER}
        found = MEASURE["find_cancel_marker"]([row])
        self.assertEqual(
            found, (1720000000000000000, 2, 137))

    def test_garbage_and_missing_markers_are_none(self):
        self.assertIsNone(MEASURE["find_cancel_marker"]([]))
        self.assertIsNone(MEASURE["find_cancel_marker"](
            [{"ts_ns": 1, "stream": "stderr", "line": "noise"}]))
        self.assertIsNone(MEASURE["find_cancel_marker"](
            [{"ts_ns": 1, "stream": "stdout", "line": self.MARKER}]))

    def test_latency_verdict_edges(self):
        verdict = MEASURE["cancel_probe_verdict"]
        self.assertTrue(verdict(0, 99_999_999)["pass"])
        self.assertFalse(verdict(0, 100_000_001)["pass"])
        missed = MEASURE["cancel_probe_verdict"](0, None)
        self.assertFalse(missed["pass"])
        self.assertIn("marker", missed["detail"])


if __name__ == "__main__":
    unittest.main()
