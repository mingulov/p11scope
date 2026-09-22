# SPDX-License-Identifier: GPL-3.0-or-later
"""E03 measurement-contract regressions (audit F-74, Package A).

The system-scope harness must derive phases from actual monotonic
boundaries, never from a setup-vs-duration heuristic; it must match
the owned workload by physical identity from its own mapping/pin
receipt, never by pathname; and a derived delivered count must never
pose as an independently observed consumer count. These tests feed
synthetic sampler/marker records straight into the parsing functions
of scripts/system-scope-measure.py, per SYSTEM-EXPERIMENTS.md E03:
60 s setup + 8 s post-attach capture, early target exit, reordered
per-class diagnostic summaries, same pathname on different inodes,
and alternate paths to the same inode.

Run: python3 -I tests/python/test_measure_e03.py -v
"""

import contextlib
import io
import json
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEASURE = runpy.run_path(str(ROOT / "scripts/system-scope-measure.py"))
CHECKER = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))

COMPLETION = ("p11scope: discovery: 2 module(s), 136 attach slot(s), "
              "scan 41ms, conflicts 0, uncorroborated 0")
TARGET_EXIT = "p11scope: capture ended: target exited after 12 ticks"


def ramp_samples(*, attach_s, end_s, detach_s=None, step_s=1.0,
                 baseline=30, plateau=180):
    """Fd trace: baseline, one attach ramp, plateau, optional taper."""
    rows = []
    moment = 0.0
    while moment <= end_s + 1e-9:
        if moment < attach_s:
            fds = baseline
        elif detach_s is not None and moment >= detach_s:
            span = max(end_s - detach_s, step_s)
            fds = baseline + int(
                (plateau - baseline) * max(0.0, 1 - (moment - detach_s) / span)
            )
        else:
            fds = plateau
        rows.append({
            "t_mono_ns": int(moment * 1e9), "fds": fds,
            "utime_ticks": int(moment * 10),
            "stime_ticks": int(moment * 5),
            "rss_bytes": 4096, "threads": 1, "clk_tck": 100,
        })
        moment += step_s
    return rows


def complete_target_receipt(pid, starttime, *, endpoint="0x1800"):
    """Synthetic complete mapping receipt plus its validated report join."""
    sha = "aa" * 32
    mapping = {"dev": [8, 1], "ino": 11}
    opened_mapping = {**mapping, "mount_id": 5}
    opened_file = {"dev": [8, 1], "ino": 11, "sha256": sha,
                   "size": 100, "path": "/w/owned.so"}
    report_bridge = {
        "schema": "p11scope/map-files-mountinfo-bridge/v1",
        "kind": "map_files_fdinfo_target_mountinfo",
        "mapping_identity": mapping,
        "opened_mapping_identity": opened_mapping,
        "opened_file_identity": {"dev": [8, 1], "ino": 11,
                                 "sha256": sha},
    }
    namespace = {"dev": [0, 5], "ino": 99}
    receipt = {
        "schema": "p11scope/workload-mapping-receipt/v1",
        "pid": pid, "starttime": starttime,
        "endpoint_address": endpoint,
        "mapping": {**mapping, "start": "0x1000", "end": "0x2000",
                    "offset": "0x0", "perms": "r-xp",
                    "path": "/w/owned.so"},
        "mapping_identity": mapping,
        "opened_mapping_identity": opened_mapping,
        "opened_file_identity": opened_file,
        "pinned": opened_file,
        "expected": opened_file,
        "source": {**opened_file, "ino": 12, "path": "/usr/lib/source.so"},
        "mount_namespace_identity_before": namespace,
        "mount_namespace_identity_after": namespace,
        "maps_before_sha256": "bb" * 32,
        "maps_after_sha256": "cc" * 32,
        "mapping_bridge": {
            "schema": "p11scope/map-files-mountinfo-bridge/v1",
            "kind": "map_files_fdinfo_target_mountinfo",
            "range": "1000-2000",
            "mount_namespace_identity": namespace,
            "mountinfo_sha256": "dd" * 32,
            "report_identity_bridge": report_bridge,
        },
    }
    module_identity = [{
        **mapping, "sha256": sha, "path": "/w/owned.so",
        "report_identity_associated": True,
        "report_identity_bridge": report_bridge,
    }]
    return receipt, module_identity


def run_measure(tmp, *, scope="pid", mode="profile", workload_argv,
                report_text, stderr_lines=(), truth, truth_prego=None,
                duration_s=8, samples=(), t_spawn_ns=0, t_go_ns=1_000_000_000,
                t_exit_ns=12_000_000_000, burst_go_ns=1_000_000_000,
                burst_end_ns=1_100_000_000, receipt=None, observer_exit=0,
                observer_timed_out=False, observer_signal=None, gate="frame",
                target_receipt=None, observer_pid=None, mapped_pid=None,
                mapped_starttime=None, mapped_endpoint="0x1800"):
    """Run the real measurement main() on synthetic inputs.

    Returns (record, summary). `receipt` becomes the workload mapping/pin
    receipt when given; omitted means the harness supplied none.
    """
    condition = {
        "scope": scope, "mode": mode, "duration_s": duration_s,
        "gate": gate,
        "observer_argv": (["p11scope", mode, "--pid", str(observer_pid)]
                          if observer_pid is not None else
                          ["p11scope", mode, "--system"]),
        "binary": "synthetic", "build_profile": "synthetic",
        "ring_bytes": "default", "drain_interval_ms": "default",
        "manifest": None, "workload_argv": workload_argv,
        "seed": 1, "n_calls": sum(truth.values()), "pace_us": 0,
    }
    if receipt is not None:
        condition["workload_module_identity"] = receipt
    if target_receipt is not None:
        condition["workload_mapping_receipt"] = target_receipt
    meta = {
        "condition": condition,
        "timing": {"t_spawn_mono_ns": t_spawn_ns,
                   "t_exit_mono_ns": t_exit_ns,
                   "t_go_mono_ns": t_go_ns},
        "harness": {"git_rev": "synthetic", "git_clean": True,
                    "observer_exit": observer_exit,
                    "observer_timed_out": observer_timed_out,
                    "observer_signal": observer_signal},
        "host": {"kernel": "synthetic", "cpu": "synthetic", "ncpu": 1,
                 "loadavg": "0 0 0"},
        "artifacts": {},
    }
    paths = {}
    for name, text in (
        ("meta", json.dumps(meta)),
        ("report", report_text),
        ("samples", "".join(json.dumps(row) + "\n" for row in samples)),
        ("stderr-ts", "".join(
            json.dumps({"t_mono_ns": ts, "line": line}) + "\n"
            for ts, line in stderr_lines)),
        ("workload-log",
         f"TRUTH_PREGO {json.dumps(truth_prego or {})}\n"
         + (f"workload: MAPPED pid={mapped_pid} "
            f"starttime={mapped_starttime} endpoint={mapped_endpoint}\n"
            if mapped_pid is not None and mapped_starttime is not None else "")
         + f"BURST go_ns={burst_go_ns} end_ns={burst_end_ns}\n"
         f"TRUTH {json.dumps(truth)}\n"),
    ):
        path = tmp / f"{name}.input"
        path.write_text(text, encoding="utf-8")
        paths[name] = str(path)
    out, summary = str(tmp / "record.json"), str(tmp / "summary.txt")
    argv = ["--meta", paths["meta"], "--report", paths["report"],
           "--samples", paths["samples"], "--stderr-ts", paths["stderr-ts"],
           "--workload-log", paths["workload-log"],
           "--out", out, "--summary", summary]
    quiet = io.StringIO()
    with contextlib.redirect_stdout(quiet):
        MEASURE["main"](argv)
    record = json.loads(Path(out).read_text(encoding="utf-8"))
    return record, Path(summary).read_text(encoding="utf-8")


def profile_report(*, functions, discovery, skipped=(), probes=2, slots=1):
    evidence = {name: 0 for name in CHECKER["COUNTERS"]}
    evidence.update(attached_probes=probes, slots=slots,
                    completeness="PARTIAL", discovery=discovery,
                    modules_skipped=list(skipped))
    return json.dumps({"schema": "synthetic", "capture": {},
                       "functions": functions, "evidence": evidence})


def owned_receipt(*, associated=True):
    receipt = {"dev": [8, 1], "ino": 11, "sha256": "aa",
               "path": "/w/owned.so",
               "report_identity_associated": associated}
    if associated:
        receipt["report_identity_bridge"] = {
            "schema": "p11scope/map-files-mountinfo-bridge/v1",
            "kind": "map_files_fdinfo_target_mountinfo",
            "mapping_identity": {"dev": [8, 1], "ino": 11},
            "opened_mapping_identity": {
                "mount_id": 17, "dev": [8, 1], "ino": 11},
            "opened_file_identity": {
                "dev": [0, 44], "ino": 11, "sha256": "aa"},
        }
    return [receipt]


def trace_report(*, stats_returned, raw_calls, discovery, probes=2):
    evidence = {name: 0 for name in CHECKER["COUNTERS"]}
    evidence.update(schema="p11scope/capture-evidence/v1",
                    completeness="PARTIAL", attached_probes=probes,
                    slots=1, discovery=discovery, modules_skipped=[])
    return "\n".join([
        "CAPTURE privacy=allowlisted",
        "COUNT_EVIDENCE " + json.dumps({
            "stats_entered": stats_returned,
            "stats_returned": stats_returned,
            "raw_calls": raw_calls,
        }),
        "EVIDENCE " + json.dumps(evidence),
        "",
    ])


class CollapseInferenceTests(unittest.TestCase):
    def test_long_setup_with_burst_inside_window_is_not_a_collapse(self):
        # 60 s setup, 8 s capture, burst inside [60, 68]: the old
        # setup-vs-duration heuristic cried COLLAPSED WINDOW here, but the
        # observer's duration clock starts after attach, so setup never
        # consumes it. Actual boundaries show a healthy window.
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=60, end_s=75, detach_s=70),
            [], 8.0, 0, 80_000_000_000, 60_500_000_000,
            burst_go_ns=61_000_000_000, burst_end_ns=62_000_000_000)
        warnings = phases["method_warnings"]
        self.assertFalse(
            [warning for warning in warnings
             if "COLLAPSED" in warning or "OUTSIDE WINDOW" in warning],
            warnings)
        self.assertEqual(phases["capture_measured_s"], 8.0)
        self.assertEqual(phases["t_expiry_mono_ns"], 68_000_000_000)
        self.assertFalse(phases["burst_outside_window"])

    def test_burst_outliving_expiry_escapes_the_window(self):
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=12), [], 8.0, 0,
            12_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=11_000_000_000)
        self.assertTrue(phases["burst_outside_window"])
        self.assertTrue(any("BURST OUTLIVED WINDOW" in warning
                            for warning in phases["method_warnings"]),
                        phases["method_warnings"])

    def test_burst_predating_attach_escapes_the_window(self):
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=5, end_s=16), [], 8.0, 0,
            16_000_000_000, 1_000_000_000,
            burst_go_ns=1_000_000_000, burst_end_ns=6_000_000_000)
        self.assertTrue(phases["burst_outside_window"])
        self.assertTrue(any("BURST PREDATED ATTACH" in warning
                            for warning in phases["method_warnings"]),
                        phases["method_warnings"])

    def test_missing_burst_bounds_leave_overlap_unchecked(self):
        # Callers without a workload log (lane-a) skip the overlap check
        # instead of inventing bounds.
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=12), [], 8.0, 0,
            12_000_000_000, 1_500_000_000)
        self.assertIsNone(phases["burst_outside_window"])
        self.assertFalse(
            [warning for warning in phases["method_warnings"]
             if "BURST" in warning], phases["method_warnings"])

    def test_burst_escape_invalidates_the_window(self):
        window = MEASURE["assess_window"](
            gate="frame", scope="pid", counts_match=True,
            burst_outside_window=True, attached_probes=136,
            trace_crosscheck=True)
        self.assertFalse(window["window_valid"])
        self.assertIn("BURST OUTSIDE WINDOW", window["window_note"])

    def test_unchecked_overlap_does_not_invalidate_a_match(self):
        window = MEASURE["assess_window"](
            gate="frame", scope="pid", counts_match=True,
            burst_outside_window=None, attached_probes=136,
            trace_crosscheck=True)
        self.assertTrue(window["window_valid"])


class FrameBoundaryTests(unittest.TestCase):
    def derive(self, *, burst_go_ns, burst_end_ns, marker_ns=None,
               duration_s=8.0, marker_line=TARGET_EXIT,
               owned_target_exit_causal=True):
        rows = ([] if marker_ns is None else
                [{"t_mono_ns": marker_ns, "line": marker_line}])
        rows.insert(0, {"t_mono_ns": 2_000_000_000,
                        "line": COMPLETION})
        return MEASURE["derive_phases"](
            ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                         step_s=0.5, baseline=30, plateau=60),
            rows, duration_s, 1_000_000_000, 7_000_000_000, 3_000_000_000,
            burst_go_ns=burst_go_ns, burst_end_ns=burst_end_ns,
            gate="frame",
            owned_target_exit_causal=owned_target_exit_causal)[0]

    def test_delayed_fd_max_does_not_reject_frame_gated_burst(self):
        phases = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
            marker_ns=5_000_000_000)
        self.assertIsNone(phases["t_attached_mono_ns"])
        self.assertEqual(phases["t_attached_fd_estimate_mono_ns"],
                         4_000_000_000)
        self.assertIsNone(phases["t_expiry_mono_ns"])
        self.assertAlmostEqual(phases["capture_proven_lower_bound_s"], 1.4)
        self.assertFalse(phases["burst_outside_window"])
        self.assertFalse(any("PREDATED ATTACH" in warning
                             for warning in phases["method_warnings"]))

    def test_frame_gate_preserves_provable_early_and_late_negatives(self):
        early = self.derive(
            burst_go_ns=100_000_000, burst_end_ns=500_000_000,
            marker_ns=5_000_000_000)
        late_marker = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=5_500_000_000,
            marker_ns=5_000_000_000, owned_target_exit_causal=False)
        late_duration_bound = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=5_500_000_000,
            duration_s=2.0)
        self.assertTrue(early["burst_outside_window"])
        self.assertTrue(late_marker["burst_outside_window"])
        self.assertTrue(late_duration_bound["burst_outside_window"])

    def test_delayed_frame_receipt_never_invents_expiry(self):
        phases = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=4_000_000_000)
        self.assertIsNone(phases["t_expiry_mono_ns"])
        self.assertIsNone(phases["capture_measured_s"])
        self.assertIsNone(phases["burst_outside_window"])
        self.assertTrue(any("unknown" in warning.lower()
                            for warning in phases["method_warnings"]))

    def test_delayed_cancel_observation_cannot_prove_burst_preceded_stop(self):
        phases = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=5_000_000_000,
            marker_ns=6_000_000_000,
            marker_line="p11scope: cancel: loop exited on signal 2 after 9 ticks",
            owned_target_exit_causal=False)
        self.assertEqual(phases["burst_window_relation"], "unknown")
        window = MEASURE["assess_window"](
            gate="frame", scope="pid", counts_match=True,
            burst_outside_window=phases["burst_outside_window"],
            burst_window_relation=phases["burst_window_relation"],
            attached_probes=136, trace_crosscheck=True)
        self.assertFalse(window["window_valid"])
        self.assertIn("BURST WINDOW UNKNOWN", window["window_note"])

    def test_generic_target_exit_observation_is_not_causal_owned_proof(self):
        phases = self.derive(
            burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
            marker_ns=5_000_000_000, owned_target_exit_causal=False)
        self.assertEqual(phases["burst_window_relation"], "unknown")
        self.assertIsNone(phases["burst_outside_window"])

    def test_raw_main_uses_frame_bounds_not_late_fd_max(self):
        with tempfile.TemporaryDirectory() as raw:
            target, module = complete_target_receipt(4242, 99)
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                stderr_lines=[(2_000_000_000, COMPLETION),
                              (5_000_000_000, TARGET_EXIT)],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                receipt=module, observer_pid=4242, target_receipt=target,
                mapped_pid=4242, mapped_starttime=99)
        self.assertTrue(record["truth_vs_observed"]["counts_match"])
        self.assertTrue(record["window"]["window_valid"])
        self.assertFalse(record["phases"]["burst_outside_window"])
        self.assertEqual(record["phases"]["t_attached_fd_estimate_mono_ns"],
                         4_000_000_000)

    def test_raw_main_delayed_cancel_stays_temporally_unknown(self):
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                stderr_lines=[
                    (2_000_000_000, COMPLETION),
                    (6_000_000_000, "p11scope: cancel: loop exited on "
                     "signal 2 after 9 ticks"),
                ],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=6.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=5_000_000_000)
        self.assertTrue(record["truth_vs_observed"]["counts_match"])
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_raw_main_requires_exact_owned_generation_for_target_exit(self):
        with tempfile.TemporaryDirectory() as raw:
            target, module = complete_target_receipt(4242, 99)
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                stderr_lines=[(2_000_000_000, COMPLETION),
                              (5_000_000_000, TARGET_EXIT)],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                receipt=module, observer_pid=4243, target_receipt=target,
                mapped_pid=4242, mapped_starttime=99)
        self.assertTrue(record["truth_vs_observed"]["counts_match"])
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_raw_main_without_loop_end_cannot_accept_unknown_expiry(self):
        with tempfile.TemporaryDirectory() as raw:
            target, module = complete_target_receipt(4242, 99)
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7}],
                    discovery=[]),
                stderr_lines=[(2_000_000_000, COMPLETION)],
                truth={"C_GenerateRandom": 7}, duration_s=2,
                samples=ramp_samples(attach_s=4, end_s=6, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_spawn_ns=1_000_000_000, t_go_ns=3_000_000_000,
                t_exit_ns=6_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                receipt=module, observer_pid=4242, target_receipt=target,
                mapped_pid=4242, mapped_starttime=99)
        self.assertTrue(record["truth_vs_observed"]["counts_match"])
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_raw_main_receipt_birth_must_match_mapped_generation(self):
        with tempfile.TemporaryDirectory() as raw:
            target, module = complete_target_receipt(4242, 100)
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7}],
                    discovery=[]),
                stderr_lines=[(2_000_000_000, COMPLETION),
                              (5_000_000_000, TARGET_EXIT)],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                receipt=module, observer_pid=4242, target_receipt=target,
                mapped_pid=4242, mapped_starttime=99)
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_raw_main_mapped_birth_must_match_complete_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            target, module = complete_target_receipt(4242, 99)
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7}],
                    discovery=[]),
                stderr_lines=[(2_000_000_000, COMPLETION),
                              (5_000_000_000, TARGET_EXIT)],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                receipt=module, observer_pid=4242, target_receipt=target,
                mapped_pid=4242, mapped_starttime=100)
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_raw_main_incomplete_receipt_cannot_prove_target_exit_order(self):
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="pid", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7}],
                    discovery=[]),
                stderr_lines=[(2_000_000_000, COMPLETION),
                              (5_000_000_000, TARGET_EXIT)],
                truth={"C_GenerateRandom": 7},
                samples=ramp_samples(attach_s=4, end_s=7, detach_s=5.5,
                                     step_s=0.5, baseline=30, plateau=60),
                t_go_ns=3_000_000_000, t_exit_ns=7_000_000_000,
                burst_go_ns=3_100_000_000, burst_end_ns=4_400_000_000,
                observer_pid=4242,
                target_receipt={"pid": 4242, "starttime": 99},
                mapped_pid=4242, mapped_starttime=99)
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])


class EarlyExitTests(unittest.TestCase):
    def test_early_target_exit_is_not_a_full_window(self):
        # PID target exits 2 s into an 8 s capture: the measured window is
        # attach-to-marker, and detach/drain anchor at the marker, not at
        # the estimated expiry the loop never reached.
        rows = [{"t_mono_ns": 3_000_000_000, "line": TARGET_EXIT}]
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=6, detach_s=3.5), rows, 8.0, 0,
            6_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=2_500_000_000)
        self.assertAlmostEqual(phases["capture_measured_s"], 2.0)
        self.assertEqual(phases["t_loop_end_mono_ns"], 3_000_000_000)
        self.assertEqual(phases["loop_end_reason"], "target-exit")
        self.assertGreater(phases["detach_s"], 0.0)

    def test_exit_before_expiry_without_a_marker_is_unknown(self):
        # The observer is gone 5 s before the estimated expiry and no
        # loop-end marker names the cause: claiming the full 8 s window
        # would invent coverage.
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=4, detach_s=3.5), [], 8.0, 0,
            4_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=2_500_000_000)
        self.assertIsNone(phases["capture_measured_s"])
        self.assertEqual(phases["loop_end_reason"], "unknown-early-exit")
        self.assertTrue(any("unknown" in warning.lower()
                            for warning in phases["method_warnings"]),
                        phases["method_warnings"])

    def test_cancel_marker_bounds_the_measured_window(self):
        rows = [{"t_mono_ns": 4_000_000_000, "line": "p11scope: cancel: "
                 "loop exited on signal 2 after 9 ticks"}]
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=7, detach_s=4.5), rows, 8.0, 0,
            7_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=2_500_000_000)
        self.assertAlmostEqual(phases["capture_measured_s"], 3.0)
        self.assertEqual(phases["loop_end_reason"], "cancel")

    def test_marker_before_estimated_attach_is_unknown(self):
        # Contradictory boundaries (coarse fd sampling dated attach after
        # the loop provably ended): unknown, never a negative window.
        rows = [{"t_mono_ns": 2_000_000_000, "line": TARGET_EXIT}]
        phases, _ = MEASURE["derive_phases"](
            ramp_samples(attach_s=5, end_s=10), rows, 8.0, 0,
            10_000_000_000, 1_000_000_000,
            burst_go_ns=1_000_000_000, burst_end_ns=1_500_000_000)
        self.assertIsNone(phases["capture_measured_s"])
        self.assertTrue(any("precedes estimated attach" in warning
                            for warning in phases["method_warnings"]),
                        phases["method_warnings"])


class DiscoveryMarkerTests(unittest.TestCase):
    def test_summaries_before_completion_do_not_move_discovery(self):
        rows = [
            {"t_mono_ns": 100, "line": "p11scope: discovery: stale-view ×12: "
             "view 3 went stale … ×12"},
            {"t_mono_ns": 200, "line": "p11scope: discovery: broad "
             "fixed-family: /lib/x.so: 2 table(s) added, 0 already covered, "
             "0 refused at [] (first reason: unknown)"},
            {"t_mono_ns": 300, "line": COMPLETION},
            {"t_mono_ns": 400, "line": "p11scope: discovery: process-view: "
             "one sample"},
        ]
        phases, line = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=12), rows, 8.0, 0,
            12_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=2_500_000_000)
        self.assertEqual(phases["t_discovery_mono_ns"], 300)
        self.assertEqual(line, COMPLETION)
        self.assertAlmostEqual(phases["discovery_s"], 300 / 1e9)

    def test_summaries_alone_leave_the_split_unknown(self):
        rows = [
            {"t_mono_ns": 100, "line": "p11scope: discovery: stale-view: x"},
            {"t_mono_ns": 200, "line": "p11scope: discovery: 3 matching "
             "overlay mapping(s) were collapsed: y"},
        ]
        phases, line = MEASURE["derive_phases"](
            ramp_samples(attach_s=1, end_s=12), rows, 8.0, 0,
            12_000_000_000, 1_500_000_000,
            burst_go_ns=1_500_000_000, burst_end_ns=2_500_000_000)
        self.assertIsNone(phases["t_discovery_mono_ns"])
        self.assertIsNone(line)
        self.assertIsNone(phases["discovery_s"])
        self.assertIsNone(phases["attach_s"])
        self.assertTrue(any("completion marker" in warning
                            for warning in phases["method_warnings"]),
                        phases["method_warnings"])


class IdentityTests(unittest.TestCase):
    def assess(self, functions, discovery, refused=(), labels=("/w/owned.so",),
               receipts="owned"):
        if receipts == "owned":
            receipts = owned_receipt()
        return MEASURE["assess_owned_coverage"](
            functions, discovery, list(refused), list(labels), receipts)

    def test_same_pathname_on_other_inodes_is_not_owned(self):
        # The owned pathname at an unattested inode, with calls behind it:
        # pathname equality is not physical identity.
        result = self.assess(
            [{"names": ["unknown"], "calls": 7,
              "module": {"dev": [8, 1], "ino": 22, "sha256": "bb"}}],
            [{"path": "/w/owned.so", "dev": [8, 1], "ino": 22,
              "sha256": "bb", "tables": [{}]}])
        self.assertFalse(result["owned_admitted"])
        self.assertEqual(result["owned_calls"], 0)
        self.assertIn("not admitted", result["note"])

    def test_foreign_host_calls_cannot_satisfy_private_copy_truth(self):
        result = self.assess(
            [{"names": ["unknown"], "calls": 5000,
              "module": {"dev": [8, 1], "ino": 22, "sha256": "bb"}}],
            [{"path": "/usr/lib/softhsm/libsofthsm2.so", "dev": [8, 1],
              "ino": 22, "sha256": "bb", "tables": [{}]}])
        self.assertFalse(result["owned_admitted"])
        self.assertEqual(result["owned_calls"], 0)
        self.assertEqual(result["total_calls"], 5000)

    def test_device_domain_mismatch_cannot_match_coincident_report_key(self):
        result = self.assess(
            [{"names": ["unknown"], "calls": 7,
              "module": {"dev": [0, 35], "ino": 11, "sha256": "aa"}}],
            [{"path": "/foreign/subvolume.so", "dev": [0, 35],
              "ino": 11, "sha256": "aa", "tables": [{}]}],
            receipts=owned_receipt(associated=False))
        self.assertIsNone(result["owned_admitted"])
        self.assertIsNone(result["owned_calls"])
        self.assertIn("opened-object association", result["note"])
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=profile_report(
                    functions=[{"names": ["unknown"], "calls": 7,
                                "module": {"dev": [0, 35], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/foreign/subvolume.so",
                                "dev": [0, 35], "ino": 11,
                                "sha256": "aa", "tables": [{}]}]),
                truth={"C_GenerateRandom": 7},
                receipt=owned_receipt(associated=False))
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertFalse(record["window"]["window_valid"])
        self.assertIn("opened-object association",
                      record["truth_vs_observed"]["match_note"])

    def test_missing_or_forged_bridge_cannot_authorize_report_rows(self):
        matching_functions = [{"names": ["unknown"], "calls": 7,
                               "module": {"dev": [8, 1], "ino": 11,
                                          "sha256": "aa"}}]
        matching_discovery = [{"path": "/w/owned.so", "dev": [8, 1],
                               "ino": 11, "sha256": "aa", "tables": [{}]}]
        missing = owned_receipt()[0]
        del missing["report_identity_bridge"]
        forged = owned_receipt()[0]
        forged["report_identity_bridge"]["opened_mapping_identity"]["dev"] = [8, 2]
        for name, receipt in (("missing", missing), ("forged", forged)):
            with self.subTest(name=name):
                result = self.assess(matching_functions, matching_discovery,
                                     receipts=[receipt])
                self.assertIsNone(result["owned_admitted"])
                self.assertIsNone(result["owned_calls"])
                self.assertIn("opened-object association", result["note"])

    def test_alternate_path_to_the_same_inode_is_owned(self):
        result = self.assess(
            [{"names": ["unknown"], "calls": 7,
              "module": {"dev": [8, 1], "ino": 11, "sha256": "aa"}}],
            [{"path": "/alias/renamed.so", "dev": [8, 1], "ino": 11,
              "sha256": "aa", "tables": [{}]}])
        self.assertTrue(result["owned_admitted"])
        self.assertEqual(result["owned_calls"], 7)

    def test_missing_receipt_is_unknown(self):
        result = self.assess(
            [{"names": ["unknown"], "calls": 7,
              "module": {"dev": [8, 1], "ino": 11, "sha256": "aa"}}],
            [{"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
              "sha256": "aa", "tables": [{}]}],
            receipts=None)
        self.assertIsNone(result["owned_admitted"])
        self.assertIsNone(result["owned_calls"])
        self.assertIn("receipt", result["note"])

    def test_entries_without_identity_leave_matching_unresolved(self):
        result = self.assess(
            [{"names": ["unknown"], "calls": 7,
              "module": {"path": "/w/owned.so"}}],
            [{"path": "/w/owned.so", "tables": [{}]}])
        self.assertIsNone(result["owned_admitted"])
        self.assertIsNone(result["owned_calls"])
        self.assertIn("unresolved", result["note"])

    def test_conflicting_build_identity_is_not_a_match(self):
        # Same device and inode, different bytes: the file changed under
        # the receipt, so the receipt no longer identifies the entry.
        result = self.assess(
            [], [{"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                  "sha256": "bb", "tables": [{}]}])
        self.assertFalse(result["owned_admitted"])
        self.assertIn("not admitted", result["note"])

    def test_refusal_of_the_owned_label_vetoes_admission(self):
        result = self.assess(
            [], [{"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                  "sha256": "aa", "tables": [{}]}],
            refused=[{"path": "/w/owned.so", "reason": "capacity"}])
        self.assertFalse(result["owned_admitted"])
        self.assertIn("refused", result["note"])

    def test_unknown_matching_fails_system_coverage_openly(self):
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["unknown"], "calls": 7,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                truth={"C_GenerateRandom": 7})
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("receipt", tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_receipt_backed_coverage_does_not_replace_temporal_proof(self):
        with tempfile.TemporaryDirectory() as raw:
            record, summary = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["unknown"], "calls": 7,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                truth={"C_GenerateRandom": 7}, receipt=owned_receipt())
        tvo = record["truth_vs_observed"]
        self.assertTrue(tvo["counts_match"])
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])
        self.assertIn("not an independently observed consumer count", summary)

    def test_named_foreign_rows_cannot_satisfy_owned_truth_in_raw_main(self):
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=profile_report(
                    functions=[
                        {"names": ["C_GenerateRandom"], "calls": 0,
                         "module": {"dev": [8, 1], "ino": 11,
                                    "sha256": "aa"}},
                        {"names": ["C_GenerateRandom"], "calls": 7,
                         "module": {"dev": [8, 1], "ino": 22,
                                    "sha256": "bb"}},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1],
                         "ino": 11, "sha256": "aa", "tables": [{}]},
                        {"path": "/usr/lib/foreign.so", "dev": [8, 1],
                         "ino": 22, "sha256": "bb", "tables": [{}]},
                    ]),
                truth={"C_GenerateRandom": 7}, receipt=owned_receipt())
        self.assertEqual(record["truth_vs_observed"]["observed"],
                         {"C_GenerateRandom": 7})
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertIn("owned-attributed", record["truth_vs_observed"]["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_system_trace_global_total_is_unknown_without_owned_rows(self):
        with tempfile.TemporaryDirectory() as raw:
            record, _ = run_measure(
                Path(raw), scope="system", mode="trace",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=trace_report(
                    stats_returned=7007, raw_calls=7007,
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                truth={"C_GenerateRandom": 7}, receipt=owned_receipt())
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertIn("lacks per-module attribution",
                      record["truth_vs_observed"]["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_each_observer_failure_invalidates_correct_pid_counts(self):
        failures = [
            ({"observer_exit": 7}, "observer exit=7"),
            ({"observer_timed_out": True}, "observer timed out"),
            ({"observer_signal": "SIGKILL"}, "observer terminated by SIGKILL"),
        ]
        for kwargs, expected in failures:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as raw:
                record, _ = run_measure(
                    Path(raw), scope="pid", mode="profile",
                    workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                    report_text=profile_report(
                        functions=[{"names": ["C_GenerateRandom"], "calls": 7,
                                    "module": {"dev": [8, 1], "ino": 11,
                                               "sha256": "aa"}}],
                        discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                    "ino": 11, "sha256": "aa",
                                    "tables": [{}]}]),
                    truth={"C_GenerateRandom": 7}, receipt=owned_receipt(),
                    **kwargs)
            self.assertTrue(record["truth_vs_observed"]["counts_match"])
            self.assertFalse(record["window"]["window_valid"])
            self.assertIn(expected, record["window"]["window_note"])


class DeliveredNoteTests(unittest.TestCase):
    def test_profile_derivation_names_its_non_oracle_status(self):
        path = MEASURE["build_event_path"](
            mode="profile", generated=20006, kernel_observed=20006,
            event_loss=19226, semantic_capture_failures=0,
            call_lines=None, raw_calls=None,
            ring_bytes=256 * 1024, burst_wall_s=0.5)
        self.assertEqual(path["delivered_derived"], 780)
        self.assertIn("not an independently observed consumer count",
                      path["delivered_note"])


if __name__ == "__main__":
    unittest.main()
