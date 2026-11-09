# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""System-scope exact-equality regressions (WP-10, gap §3 item 4).

The harness always runs the workload against a private provider inode
(system-scope-measure.sh copies the module into $WORK/provider), so only
the owned workload maps it. Owned-attributed counts must therefore equal
the workload truth exactly: overcounting (doubled or phantom calls) fails,
just as undercounting does. The `>=` coverage check would pass a doubled
count; `==` rejects it.

Run: python3 -I tests/python/test_system_scope_equality.py -v
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
                stderr_lines=(), truth, duration_s=8, receipt=None):
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
         "TRUTH_PREGO {}\n"
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


def owned_receipt():
    return [{"dev": [8, 1], "ino": 11, "sha256": "aa",
             "path": "/w/owned.so"}]


class SystemExactEqualityTests(unittest.TestCase):
    def test_scan_only_doubled_count_fails(self):
        # Non-vacuity: 14 owned-attributed unknown-name calls against
        # truth 7 must fail. Under `>=` this passed.
        owned = {"dev": [8, 1], "ino": 11, "sha256": "aa"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "0"],
                report_text=profile_report(
                    functions=[
                        {"names": ["unknown"], "calls": 14,
                         "module": dict(owned)},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                    ],
                    probes=2, slots=1),
                truth={"C_GenerateRandom": 7},
                receipt=owned_receipt())
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertIn("14 vs truth 7", tvo["match_note"])
        self.assertFalse(record["window"]["window_valid"])

    def test_named_doubled_count_fails(self):
        # Per-name: owned 14 vs truth 7 must fail.
        owned = {"dev": [8, 1], "ino": 11, "sha256": "aa"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=profile_report(
                    functions=[
                        {"names": ["C_GenerateRandom"], "calls": 14,
                         "module": dict(owned)},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                    ],
                    probes=2, slots=1),
                truth={"C_GenerateRandom": 7},
                receipt=owned_receipt())
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertFalse(record["window"]["window_valid"])

    def test_named_exact_count_passes(self):
        # Control: owned 7 vs truth 7 passes (coverage; the window stays
        # invalid without temporal proof, as in the audit control).
        owned = {"dev": [8, 1], "ino": 11, "sha256": "aa"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=profile_report(
                    functions=[
                        {"names": ["C_GenerateRandom"], "calls": 7,
                         "module": dict(owned)},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                    ],
                    probes=2, slots=1),
                truth={"C_GenerateRandom": 7},
                receipt=owned_receipt())
        tvo = record["truth_vs_observed"]
        self.assertTrue(tvo["counts_match"])

    def test_named_phantom_extra_name_fails(self):
        # An owned-attributed call for a function outside the truth is a
        # phantom: the private copy is mapped only by the workload, whose
        # post-go ledger is complete.
        owned = {"dev": [8, 1], "ino": 11, "sha256": "aa"}
        with tempfile.TemporaryDirectory() as raw:
            record = run_measure(
                Path(raw), scope="system", mode="profile",
                workload_argv=["/w/workload", "/w/owned.so", "7", "0", "1"],
                report_text=profile_report(
                    functions=[
                        {"names": ["C_GenerateRandom"], "calls": 7,
                         "module": dict(owned)},
                        {"names": ["C_Initialize"], "calls": 1,
                         "module": dict(owned)},
                    ],
                    discovery=[
                        {"path": "/w/owned.so", "dev": [8, 1], "ino": 11,
                         "sha256": "aa", "tables": [{}]},
                    ],
                    probes=2, slots=1),
                truth={"C_GenerateRandom": 7},
                receipt=owned_receipt())
        tvo = record["truth_vs_observed"]
        self.assertFalse(tvo["counts_match"])
        self.assertFalse(record["window"]["window_valid"])


if __name__ == "__main__":
    unittest.main()
