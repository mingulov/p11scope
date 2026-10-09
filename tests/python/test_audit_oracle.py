# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit-oracle regressions (system-scale audit 2026-09-20: F2, F9).

F2 pins owned-attribution for system-scope coverage at the artifact level:
the tests invoke scripts/system-scope-measure.py main() on synthetic inputs
shaped exactly like the audit PoC (owned workload refused, foreign-only
traffic observed, TRUTH = owned count) and require the coverage assertion
to fail with the window invalid — foreign/unknown sums must never certify
owned coverage. A healthy owned-attributed control proves coverage while
keeping its unauthenticated temporal window unknown, and a zero-observed
case pins the honest G1-style zeros.

F6's regression (all proxy calls zeroed must not accept) lives in
scripts/check-capture-evidence.py self_test(), next to the lane's other
mutations; F9 pins derive_phases' in-observer detach preference here.

Run: python3 -I tests/python/test_audit_oracle.py -v
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


def run_measure(tmp, *, scope, mode, workload_argv, report_text,
                stderr_lines=(), truth, truth_prego=None, duration_s=8,
                receipt=None):
    """Run the real measurement main() on synthetic inputs; return record.

    `receipt` is the workload mapping/pin receipt (Package A: owned
    matching needs one; omitted means the harness supplied none).
    """
    condition = {
        "scope": scope, "mode": mode, "duration_s": duration_s,
        "gate": "frame",
        "observer_argv": ["p11scope", mode, "--system"],
        "binary": "synthetic", "build_profile": "synthetic",
        "ring_bytes": "default", "drain_interval_ms": "default",
        "manifest": None, "workload_argv": workload_argv,
        "seed": 1, "n_calls": sum(truth.values()), "pace_us": 0,
    }
    if receipt is not None:
        identities = []
        for entry in receipt:
            value = {**entry, "report_identity_associated":
                     entry.get("report_identity_associated", True)}
            if value["report_identity_associated"] is True:
                value.setdefault("report_identity_bridge", {
                    "schema": "p11scope/map-files-mountinfo-bridge/v1",
                    "kind": "map_files_fdinfo_target_mountinfo",
                    "mapping_identity": {
                        "dev": value["dev"], "ino": value["ino"]},
                    "opened_mapping_identity": {
                        "mount_id": 17, "dev": value["dev"],
                        "ino": value["ino"]},
                    "opened_file_identity": {
                        "dev": [0, 44], "ino": value["ino"],
                        "sha256": value["sha256"]},
                })
            identities.append(value)
        condition["workload_module_identity"] = identities
    meta = {
        "condition": condition,
        "timing": {"t_spawn_mono_ns": 0, "t_exit_mono_ns": 12_000_000_000,
                   "t_go_mono_ns": 1_000_000_000},
        "harness": {"git_rev": "synthetic", "git_clean": True,
                    "observer_exit": 0, "observer_timed_out": False,
                    "observer_signal": None},
        "host": {"kernel": "synthetic", "cpu": "synthetic", "ncpu": 1,
                 "loadavg": "0 0 0"},
        "artifacts": {},
    }
    paths = {}
    for name, text in (
        ("meta", json.dumps(meta)),
        ("report", report_text),
        ("samples", ""),
        ("stderr-ts", "".join(
            json.dumps({"t_mono_ns": 100, "line": line}) + "\n"
            for line in stderr_lines)),
        ("workload-log",
         f"TRUTH_PREGO {json.dumps(truth_prego or {})}\n"
         "BURST go_ns=1000000000 end_ns=1100000000\n"
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
    return json.loads(Path(out).read_text(encoding="utf-8"))


def profile_report(*, functions, discovery, skipped=(), probes=2, slots=1):
    evidence = {name: 0 for name in CHECKER["COUNTERS"]}
    evidence.update(attached_probes=probes, slots=slots,
                    completeness="PARTIAL", discovery=discovery,
                    modules_skipped=list(skipped))
    return json.dumps({"schema": "synthetic", "capture": {},
                       "functions": functions, "evidence": evidence})


def trace_stream(*, lines, stats_returned, raw_calls, lost=0, evidence):
    text = ["CAPTURE privacy=allowlisted"] + list(lines)
    if lost:
        text.append(f"LOST {lost} events")
    text.append(json.dumps({"stats_entered": stats_returned,
                            "stats_returned": stats_returned,
                            "raw_calls": raw_calls}).join(
        ["COUNT_EVIDENCE ", ""]))
    text.append("EVIDENCE " + json.dumps(evidence))
    return "\n".join(text) + "\n"


class OwnedCoverageTests(unittest.TestCase):
    def test_foreign_only_refused_owned_does_not_validate(self):
        # Exact audit F2 PoC shape: owned.so refused, only foreign.so
        # observed, seven foreign unknown-name calls, owned TRUTH=7.
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["controlled-owned.so"],
                report_text=profile_report(
                    functions=[{"names": ["unknown"], "calls": 7,
                                "module": {"path": "foreign.so"}}],
                    discovery=[{"path": "foreign.so", "dev": [8, 1],
                                "ino": 12, "sha256": "bb", "tables": [{}]}],
                    skipped=[{"name": "owned.so",
                              "reason": "capacity: controlled workload refused"}]),
                stderr_lines=["p11scope: module refused: owned.so — capacity"],
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "controlled-owned.so"}])
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("not admitted", tvo["match_note"])
        self.assertIn("total coverage unprovable", tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])
        self.assertIn("counts_match=False", record["window"]["window_note"])
        self.assertIn("not admitted", record["window"]["window_note"])
        # The refusal itself stays visible; only the false coverage
        # certification is gone.
        self.assertEqual(record["verdict"], "PARTIAL")
        self.assertEqual(record["evidence"]["refused_modules"],
                         [{"path": "owned.so", "reason": "capacity"}])

    def test_owned_attributed_coverage_does_not_supply_temporal_proof(self):
        # Healthy control with real identity shapes: owned calls cover
        # truth while foreign unknown-name traffic is also present. This
        # system fixture has no authenticated loop-end bound, so coverage
        # remains separate from temporal window validity.
        owned = {"dev": [8, 1], "ino": 11, "sha256": "aa"}
        foreign = {"dev": [8, 1], "ino": 12, "sha256": "bb"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[
                        {"names": ["unknown"], "calls": 7,
                         "module": dict(owned)},
                        {"names": ["unknown"], "calls": 50,
                         "module": dict(foreign)},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                        {"path": "/w/foreign.so", "dev": [8, 1], "ino": 12,
                         "sha256": "bb", "tables": [{}]},
                    ],
                    probes=4, slots=2),
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "/w/owned.so"}])
        tvo = record["truth_vs_observed"]
        self.assertTrue(tvo["counts_match"])
        self.assertIn("owned-attributed coverage 7 vs truth 7",
                      tvo["match_note"])
        self.assertEqual(record["phases"]["burst_window_relation"], "unknown")
        self.assertFalse(record["window"]["window_valid"])

    def test_foreign_calls_cannot_cover_without_owned_attribution(self):
        # Admission alone is not coverage: the owned module is admitted
        # but every observed call is foreign-attributed or unattributable
        # (null module), so a large foreign total must still fail.
        foreign = {"dev": [8, 1], "ino": 12, "sha256": "bb"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[
                        {"names": ["unknown"], "calls": 700,
                         "module": dict(foreign)},
                        {"names": ["unknown"], "calls": 5, "module": None},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                        {"path": "/w/foreign.so", "dev": [8, 1], "ino": 12,
                         "sha256": "bb", "tables": [{}]},
                    ],
                    probes=4, slots=2),
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "/w/owned.so"}])
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("owned-attributed coverage 0 vs truth 7",
                      tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_zero_observed_stays_unmatched(self):
        # Honest G1-style zeros: nothing observed is still no coverage,
        # even with the owned module admitted.
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[{"names": ["unknown"], "calls": 0,
                                "module": {"dev": [8, 1], "ino": 11,
                                           "sha256": "aa"}}],
                    discovery=[{"path": "/w/owned.so", "dev": [8, 1],
                                "ino": 11, "sha256": "aa", "tables": [{}]}]),
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "/w/owned.so"}])
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertFalse(record["window"]["window_valid"])

    def test_system_named_scope_requires_owned_admission(self):
        # Named per-name coverage still needs the owned module: foreign
        # same-name calls must not certify a refused owned workload.
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["controlled-owned.so"],
                report_text=profile_report(
                    functions=[{"names": ["C_GenerateRandom"], "calls": 7,
                                "module": {"path": "foreign.so"}}],
                    discovery=[{"path": "foreign.so", "dev": [8, 1],
                                "ino": 12, "sha256": "bb", "tables": [{}]}],
                    skipped=[{"name": "owned.so", "reason": "capacity"}]),
                stderr_lines=["p11scope: module refused: owned.so — capacity"],
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "controlled-owned.so"}])
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("requires the owned workload module",
                      tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_trace_system_refused_owned_does_not_validate(self):
        # The trace half of F2: the kernel aggregate cannot attribute
        # calls, so a refused owned workload fails even with covering,
        # cross-checked totals.
        lines = ["03:15:44.123456 pid 111 tid 111 C_GenerateRandom "
                 "→ CKR_OK 1.23µs"] * 7
        evidence = {name: 0 for name in CHECKER["COUNTERS"]}
        evidence.update(schema="p11scope/capture-evidence/v1",
                        completeness="PARTIAL", attached_probes=136,
                        slots=68, discovery=[{"path": "foreign.so",
                                              "dev": [8, 1], "ino": 12,
                                              "sha256": "bb"}],
                        modules_skipped=[{"name": "owned.so",
                                          "reason": "capacity"}])
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="trace",
                workload_argv=["controlled-owned.so"],
                report_text=trace_stream(
                    lines=lines, stats_returned=7, raw_calls=7,
                    evidence=evidence),
                stderr_lines=["p11scope: module refused: owned.so — capacity"],
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "controlled-owned.so"}])
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("not admitted", tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])
        self.assertTrue(record["trace_stream"]["crosscheck_holds"])

    def test_trace_system_admission_does_not_attribute_global_totals(self):
        lines = ["03:15:44.123456 pid 111 tid 111 C_GenerateRandom "
                 "→ CKR_OK 1.23µs"] * 7
        evidence = {name: 0 for name in CHECKER["COUNTERS"]}
        evidence.update(schema="p11scope/capture-evidence/v1",
                        completeness="PARTIAL", attached_probes=136,
                        slots=68,
                        discovery=[{"path": "controlled-owned.so",
                                    "dev": [8, 1], "ino": 11,
                                    "sha256": "aa"}])
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="trace",
                workload_argv=["controlled-owned.so"],
                report_text=trace_stream(
                    lines=lines, stats_returned=7, raw_calls=7,
                    evidence=evidence),
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "controlled-owned.so"}])
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertIn("lacks per-module attribution",
                      record["truth_vs_observed"]["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_unknown_executable_trace_preserves_aggregate_attribution_limits(self):
        lines = ["03:15:44.123456 Unknown executable (PID 111, TID 111) "
                 "C_GenerateRandom → CKR_OK 1.23µs"] * 7
        evidence = {name: 0 for name in CHECKER["COUNTERS"]}
        evidence.update(schema="p11scope/capture-evidence/v1", completeness="PARTIAL",
                        attached_probes=136, slots=68,
                        discovery=[{"path": "controlled-owned.so", "dev": [8, 1],
                                    "ino": 11, "sha256": "aa"}])
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="trace",
                workload_argv=["controlled-owned.so"],
                report_text=trace_stream(lines=lines, stats_returned=7,
                                        raw_calls=7, evidence=evidence),
                truth={"C_GenerateRandom": 7},
                receipt=[{"dev": [8, 1], "ino": 11, "sha256": "aa",
                          "path": "controlled-owned.so"}])
        self.assertEqual(record["trace_stream"]["call_lines_total"], 7)
        self.assertTrue(record["trace_stream"]["crosscheck_holds"])
        self.assertFalse(record["truth_vs_observed"]["counts_match"])
        self.assertIn("lacks per-module attribution",
                      record["truth_vs_observed"]["match_note"])
        self.assertFalse(record["window"]["window_valid"])


def early_exit_samples():
    """Fd trace whose target is gone before the computed expiry: a ramp
    to a plateau that never tapers, so the estimator falls back."""
    samples = []
    for index in range(51):
        samples.append({"t_mono_ns": index * 500_000_000,
                        "fds": 30 if index < 5 else 180})
    return samples


def taper_samples():
    """Fd trace with a genuine post-expiry taper back to baseline."""
    fds = [30] * 5 + [180] * 10 + [170, 150, 120, 80, 40, 30, 30, 30]
    return [{"t_mono_ns": index * 1_000_000_000, "fds": value}
            for index, value in enumerate(fds)]


class PhaseTimerTests(unittest.TestCase):
    def derive(self, samples, duration_s, t_exit_ns, phase_ms):
        return MEASURE["derive_phases"](
            samples, [], duration_s, 0, t_exit_ns, 1_000_000_000,
            phase_ms=phase_ms)

    def test_in_observer_detach_overrides_zero_estimate(self):
        phases, _ = self.derive(early_exit_samples(), 30.0, 25_500_000_000,
                                {"detach": 11826, "drain": 7})
        self.assertAlmostEqual(phases["detach_s"], 11.826)
        self.assertTrue(any("contradicts the in-observer detach timer" in w
                            for w in phases["method_warnings"]))

    def test_zero_estimate_without_timer_warns(self):
        phases, _ = self.derive(early_exit_samples(), 30.0, 25_500_000_000,
                                None)
        self.assertEqual(phases["detach_s"], 0.0)
        self.assertTrue(any("no in-observer timer" in w
                            for w in phases["method_warnings"]))

    def test_observer_zero_confirms_zero_silently(self):
        phases, _ = self.derive(early_exit_samples(), 30.0, 25_500_000_000,
                                {"detach": 0})
        self.assertEqual(phases["detach_s"], 0.0)
        self.assertFalse(any("contradicts the in-observer" in w
                             or "no in-observer timer" in w
                             for w in phases["method_warnings"]))

    def test_genuine_taper_keeps_estimate(self):
        phases, _ = self.derive(taper_samples(), 8.0, 30_000_000_000,
                                {"detach": 11826})
        self.assertAlmostEqual(phases["detach_s"], 4.0)
        self.assertFalse(any("in-observer" in w
                             for w in phases["method_warnings"]))

    def test_malformed_timer_is_ignored(self):
        for bad in ("junk", {"detach": -5}, {"detach": "x"},
                    {"detach": True}, {"drain": 7}):
            with self.subTest(phase_ms=bad):
                phases, _ = self.derive(early_exit_samples(), 30.0,
                                        25_500_000_000, bad)
                self.assertEqual(phases["detach_s"], 0.0)
                self.assertTrue(any("no in-observer timer" in w
                                    for w in phases["method_warnings"]))


if __name__ == "__main__":
    unittest.main()
