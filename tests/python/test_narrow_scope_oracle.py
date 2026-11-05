#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Narrow-scope discovery oracle twins.

The oracle (scripts/check-narrow-scope.py) checks strace evidence from::

    strace -f -y -e trace=openat,open,getdents64 -s 128 -o <ev> p11scope ...

for the absence of a global census under PID, run and cgroup scopes, and
validates canned per-cell coverage, residency, numbering, replacement and
partial-walk records. The scope-matrix process tree
(tests/fixtures/scope-matrix/tree.sh) provides the root/descendant/outside
sibling population the installed cells scope onto. Healthy and mutation
twins run unignored; every mutation names the refused field or comparison.
"""

import importlib.util
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "check-narrow-scope.py"
TREE_SRC = ROOT / "tests" / "fixtures" / "scope-matrix" / "tree.sh"

try:
    _SPEC = importlib.util.spec_from_file_location(
        "check_narrow_scope", ORACLE_PATH
    )
    ORACLE = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(ORACLE)
except OSError:
    ORACLE = None


def require_oracle(test):
    """Fail naming the missing production file or return the oracle."""
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


PID = 5000
SCOPED = 4242
CGROUP = "/sys/fs/cgroup/scopetest"


def healthy_pid_trace(scoped=SCOPED):
    return "\n".join([
        f"{PID} openat(AT_FDCWD, \"/proc/self/stat\", O_RDONLY) = 3",
        f"{PID} openat(AT_FDCWD, \"/proc/{scoped}/maps\", O_RDONLY) = 4",
        f"{PID} openat(AT_FDCWD, \"/proc/{scoped}/task\", "
        "O_RDONLY|O_DIRECTORY) = 5",
        f"{PID} getdents64(5</proc/{scoped}/task>, 0x7f00, 1024) = 48",
        f"{PID} openat(AT_FDCWD, \"/opt/vendor/lib/pkcs11.so\", "
        "O_RDONLY) = 6",
    ]) + "\n"


def healthy_cgroup_trace(cgroup=CGROUP, members=(4242, 4243)):
    lines = [
        f"{PID} openat(AT_FDCWD, \"{cgroup}\", O_RDONLY|O_DIRECTORY) = 3",
        f"{PID} getdents64(3<{cgroup}>, 0x7f00, 32768) = 120",
        f"{PID} openat(AT_FDCWD, \"{cgroup}/cgroup.procs\", O_RDONLY) = 4",
        f"{PID} openat(AT_FDCWD, \"{cgroup}/child\", "
        "O_RDONLY|O_DIRECTORY) = 5",
        f"{PID} getdents64(5<{cgroup}/child>, 0x7f00, 32768) = 64",
        f"{PID} openat(AT_FDCWD, \"{cgroup}/child/cgroup.procs\", "
        "O_RDONLY) = 6",
        f"{PID} openat(AT_FDCWD, \"/proc/self/fd/3/cgroup.procs\", "
        "O_RDONLY) = 7",
    ]
    for index, member in enumerate(members):
        lines.append(f"{PID} openat(AT_FDCWD, \"/proc/{member}/maps\", "
                     f"O_RDONLY) = {8 + index}")
    return "\n".join(lines) + "\n"


def coverage_record(coverage, exit_code=0, gaps=None, refusal=None,
                    cell="pid-scan"):
    return {"cell": cell, "coverage": coverage, "exit": exit_code,
            "gaps": gaps if gaps is not None else [], "refusal": refusal}


class CensusCheckTests(unittest.TestCase):
    def test_scoped_pid_evidence_passes_with_counts(self):
        oracle = require_oracle(self)
        events = oracle.parse_strace(healthy_pid_trace())
        verdict = oracle.check_census(events, "pid", scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["scope"], "pid")
        self.assertEqual(verdict["events"], 5)
        self.assertEqual(verdict["counts"]["allowed"], 4)
        self.assertEqual(verdict["counts"]["outside-proc"], 1)

    def test_run_scope_follows_pid_rules_for_the_owned_child(self):
        oracle = require_oracle(self)
        events = oracle.parse_strace(healthy_pid_trace())
        verdict = oracle.check_census(events, "run", scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["scope"], "run")

    def test_scoped_cgroup_evidence_passes(self):
        oracle = require_oracle(self)
        events = oracle.parse_strace(healthy_cgroup_trace())
        verdict = oracle.check_census(events, "cgroup",
                                      scoped_pids=[4242, 4243], cgroup=CGROUP)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["counts"]["cgroup"], 6)
        self.assertEqual(verdict["counts"]["allowed"], 3)

    def test_system_scope_passes_a_full_proc_walk(self):
        oracle = require_oracle(self)
        trace = (f"{PID} openat(AT_FDCWD, \"/proc\", "
                 "O_RDONLY|O_DIRECTORY) = 3\n"
                 f"{PID} getdents64(3</proc>, 0x7f00, 32768) = 2048\n")
        verdict = oracle.check_census(oracle.parse_strace(trace), "system")
        self.assertEqual(verdict["verdict"], "pass")

    def test_empty_pid_evidence_passes_with_zero_events(self):
        oracle = require_oracle(self)
        verdict = oracle.check_census(oracle.parse_strace(""), "pid",
                                      scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["events"], 0)

    def test_bare_proc_open_under_pid_scope_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} openat(AT_FDCWD, \"/proc\", "
                 "O_RDONLY|O_DIRECTORY) = 9\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "bare /proc"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_bare_proc_enumeration_fails_even_without_its_open(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} getdents64(9</proc>, 0x7f00, 32768) = 2048\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "bare-/proc enumeration"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_unscoped_pid_open_fails_naming_the_pid(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} openat(AT_FDCWD, \"/proc/9999/maps\", "
                 "O_RDONLY) = 9\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "/proc/9999"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_root_enumeration_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} getdents64(9</>, 0x7f00, 32768) = 100\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "enumerates /"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_out_of_scope_cgroup_procs_read_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_cgroup_trace() +
                 f"{PID} openat(AT_FDCWD, \"/sys/fs/cgroup/other/"
                 "cgroup.procs\", O_RDONLY) = 20\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "out-of-scope cgroup.procs"):
            oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                scoped_pids=[4242, 4243], cgroup=CGROUP)

    def test_enumeration_above_the_scoped_cgroup_fails(self):
        oracle = require_oracle(self)
        nested = CGROUP + "/nested"
        trace = (healthy_cgroup_trace(cgroup=nested) +
                 f"{PID} getdents64(20<{CGROUP}>, 0x7f00, 32768) = 60\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "above the scoped cgroup"):
            oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                scoped_pids=[4242, 4243], cgroup=nested)

    def test_non_procs_file_inside_the_cgroup_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_cgroup_trace() +
                 f"{PID} openat(AT_FDCWD, \"{CGROUP}/cgroup.controllers\", "
                 "O_RDONLY) = 20\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "outside the cgroup.procs set"):
            oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                scoped_pids=[4242, 4243], cgroup=CGROUP)

    def test_split_unfinished_call_still_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} getdents64(9</proc>, 0x7f00 <unfinished ...>\n"
                 f"{PID} <... getdents64 resumed> , 32768) = 2048\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "bare-/proc enumeration"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_getdents_on_unattributable_fd_fails_closed(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} getdents64(9, 0x7f00, 32768) = 10\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "unresolved fd 9"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_fd_table_resolves_unannotated_getdents(self):
        oracle = require_oracle(self)
        trace = (
            f"{PID} openat(AT_FDCWD, \"{CGROUP}/child\", "
            "O_RDONLY|O_DIRECTORY) = 5\n"
            f"{PID} getdents64(5, 0x7f00, 32768) = 64\n")
        verdict = oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                      scoped_pids=[], cgroup=CGROUP)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["counts"]["cgroup"], 2)

    def test_dirfd_relative_procs_resolves_inside_the_cgroup(self):
        oracle = require_oracle(self)
        trace = (
            f"{PID} openat(AT_FDCWD, \"{CGROUP}/child\", "
            "O_RDONLY|O_DIRECTORY) = 5\n"
            f"{PID} openat(5, \"cgroup.procs\", O_RDONLY) = 6\n")
        verdict = oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                      scoped_pids=[], cgroup=CGROUP)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["counts"]["cgroup"], 2)

    def test_dotdot_escape_to_unscoped_pid_fails(self):
        oracle = require_oracle(self)
        trace = (healthy_pid_trace() +
                 f"{PID} openat(AT_FDCWD, \"/proc/self/../9999/maps\", "
                 "O_RDONLY) = 9\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "/proc/9999"):
            oracle.check_census(oracle.parse_strace(trace), "pid",
                                scoped_pids=[SCOPED])

    def test_hostile_path_bytes_are_not_echoed(self):
        oracle = require_oracle(self)
        trace = (f"{PID} openat(AT_FDCWD, \"/x/\\007ad/cgroup.procs\", "
                 "O_RDONLY) = 9\n")
        with self.assertRaises(oracle.EvidenceError) as raised:
            oracle.check_census(oracle.parse_strace(trace), "cgroup",
                                scoped_pids=[], cgroup=CGROUP)
        self.assertIn("unprintable path", str(raised.exception))
        self.assertNotIn("\x07", str(raised.exception))

    def test_unknown_scope_and_missing_cgroup_fail(self):
        oracle = require_oracle(self)
        events = oracle.parse_strace(healthy_pid_trace())
        with self.assertRaisesRegex(oracle.EvidenceError, "unknown scope"):
            oracle.check_census(events, "planet", scoped_pids=[SCOPED])
        with self.assertRaisesRegex(oracle.EvidenceError, "absolute cgroup"):
            oracle.check_census(events, "cgroup", scoped_pids=[SCOPED])
        with self.assertRaisesRegex(oracle.EvidenceError, "scoped pid"):
            oracle.check_census(events, "pid", scoped_pids=[0])

    def test_cli_passes_healthy_and_refuses_a_walk(self):
        require_oracle(self)
        work = tempfile.TemporaryDirectory(prefix="p11scope-narrow-cli-")
        self.addCleanup(work.cleanup)
        healthy = Path(work.name) / "healthy.strace"
        healthy.write_text(healthy_pid_trace())
        census = Path(work.name) / "census.strace"
        census.write_text(healthy_pid_trace() +
                          f"{PID} getdents64(9</proc>, 0x7f00, 8) = 8\n")
        code, out, _ = self.run_cli(["--scope", "pid", "--pid",
                                         str(SCOPED), str(healthy)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "pass")
        code, _, err = self.run_cli(["--scope", "pid", "--pid",
                                     str(SCOPED), str(census)])
        self.assertEqual(code, 1)
        self.assertIn("narrow scope refused", err)

    def run_cli(self, argv):
        oracle = require_oracle(self)
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = oracle.main(argv)
        return code, out.getvalue(), err.getvalue()


class CoverageCheckTests(unittest.TestCase):
    def test_full_clean_coverage_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_coverage(coverage_record("full"))
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["coverage"], "full")

    def test_full_coverage_with_gaps_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("full", gaps=[{"reason": "x"}])
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "full coverage carries gaps"):
            oracle.check_coverage(record)

    def test_full_coverage_with_refusal_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("full", exit_code=1, refusal="denied")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "full coverage carries a refusal"):
            oracle.check_coverage(record)

    def test_partial_coverage_with_gap_marker_passes(self):
        oracle = require_oracle(self)
        record = coverage_record(
            "partial", gaps=[{"reason": "PARTIAL: walk stopped at boundary",
                              "subject": "sub"}])
        verdict = oracle.check_coverage(record)
        self.assertEqual(verdict["coverage"], "partial")

    def test_partial_coverage_with_refusal_marker_passes(self):
        oracle = require_oracle(self)
        record = coverage_record(
            "partial", exit_code=1,
            gaps=[{"reason": "walk stopped", "subject": "sub"}],
            refusal="PARTIAL: one subtree unreadable")
        verdict = oracle.check_coverage(record)
        self.assertEqual(verdict["coverage"], "partial")

    def test_silently_narrowed_partial_fails(self):
        oracle = require_oracle(self)
        record = coverage_record(
            "partial", gaps=[{"reason": "walk stopped"}])
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without explicit PARTIAL"):
            oracle.check_coverage(record)

    def test_partial_without_boundary_gap_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("partial", refusal="PARTIAL: nothing?")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without a boundary gap"):
            oracle.check_coverage(record)

    def test_refused_coverage_with_text_and_exit_passes(self):
        oracle = require_oracle(self)
        record = coverage_record("refused", exit_code=1,
                                 refusal="scope is not supported here")
        verdict = oracle.check_coverage(record)
        self.assertEqual(verdict["coverage"], "refused")

    def test_refused_coverage_without_text_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("refused", exit_code=1)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without refusal text"):
            oracle.check_coverage(record)

    def test_refused_coverage_with_exit_zero_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("refused", refusal="denied")
        with self.assertRaisesRegex(oracle.EvidenceError, "with exit 0"):
            oracle.check_coverage(record)

    def test_unknown_coverage_and_merged_record_fail(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError, "unknown coverage"):
            oracle.check_coverage(coverage_record("mostly"))
        merged = {"cell": "x", "coverage": "full", "exit": 0, "gaps": []}
        with self.assertRaisesRegex(oracle.EvidenceError, "exactly"):
            oracle.check_coverage(merged)


class ResidencyCheckTests(unittest.TestCase):
    def test_sampled_claim_inside_the_window_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_residency(
            [100, 150, 200], {"kind": "sampled", "start": 90, "end": 210})
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["samples"], 3)

    def test_continuous_claim_from_samples_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "cannot prove continuous residency"):
            oracle.check_residency(
                [100, 200], {"kind": "continuous", "start": 90, "end": 210})

    def test_empty_samples_fail(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError, "non-empty"):
            oracle.check_residency(
                [], {"kind": "sampled", "start": 0, "end": 10})

    def test_sample_outside_the_window_fails_naming_it(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "sample 500 lies outside"):
            oracle.check_residency(
                [100, 500], {"kind": "sampled", "start": 90, "end": 210})

    def test_inverted_window_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError, "window"):
            oracle.check_residency(
                [100], {"kind": "sampled", "start": 200, "end": 100})


class NumberingCheckTests(unittest.TestCase):
    def test_matching_numbering_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_numbering([
            {"caller_pid": 4242, "observer_pid": 4242},
            {"caller_pid": 4243, "observer_pid": 4243}])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["rows"], 2)

    def test_renumbered_caller_fails_naming_both(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError, "pid 7 is not"):
            oracle.check_numbering([
                {"caller_pid": 4242, "observer_pid": 4242},
                {"caller_pid": 7, "observer_pid": 4243}])

    def test_empty_numbering_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError, "caller rows"):
            oracle.check_numbering([])


class ReplacementCheckTests(unittest.TestCase):
    def test_refused_root_replacement_with_gap_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_replacement({
            "event": "root-replacement", "exit": 1,
            "gaps": [{"reason": "root changed during scan"}],
            "refusal": "scan root was replaced"})
        self.assertEqual(verdict["verdict"], "pass")

    def test_refused_mount_replacement_with_gap_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_replacement({
            "event": "mount-replacement", "exit": 0,
            "gaps": [{"reason": "mount changed during scan"}],
            "refusal": "mount was replaced"})
        self.assertEqual(verdict["verdict"], "pass")

    def test_unrefused_replacement_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without a refusal"):
            oracle.check_replacement({
                "event": "root-replacement", "exit": 0, "gaps": [],
                "refusal": None})

    def test_refused_replacement_without_gap_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without a recorded gap"):
            oracle.check_replacement({
                "event": "mount-replacement", "exit": 1, "gaps": [],
                "refusal": "mount was replaced"})

    def test_unknown_replacement_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "unknown replacement"):
            oracle.check_replacement({
                "event": "time-replacement", "exit": 1,
                "gaps": [{"reason": "x"}], "refusal": "y"})


class PartialWalkCheckTests(unittest.TestCase):
    BOUNDARY = "/sys/fs/cgroup/scopetest/hidden"

    def walk_trace(self):
        return "\n".join([
            f"{PID} openat(AT_FDCWD, \"{CGROUP}\", O_RDONLY|O_DIRECTORY) = 3",
            f"{PID} getdents64(3<{CGROUP}>, 0x7f00, 32768) = 120",
            f"{PID} openat(AT_FDCWD, \"{CGROUP}/cgroup.procs\", "
            "O_RDONLY) = 4",
        ]) + "\n"

    def partial_record(self):
        return coverage_record(
            "partial", gaps=[{"reason": "PARTIAL: hidden subtree withheld",
                              "subject": "hidden"}])

    def test_walk_stopping_at_the_boundary_passes(self):
        oracle = require_oracle(self)
        verdict = oracle.check_partial_walk(
            self.walk_trace(), self.BOUNDARY, self.partial_record(),
            scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["events"], 3)

    def test_partial_walk_counts_relative_opens(self):
        oracle = require_oracle(self)
        trace = "\n".join([
            f"{PID} openat(AT_FDCWD, \"rel/sub\", O_RDONLY|O_DIRECTORY) = 3",
            f"{PID} getdents64(3, 0x7f00, 32768) = 120",
        ]) + "\n"
        verdict = oracle.check_partial_walk(
            trace, self.BOUNDARY, self.partial_record(),
            scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["events"], 2)
        self.assertEqual(verdict["counts"],
                         {"unresolved-open": 0, "relative-unresolved": 2})

    def test_partial_walk_counts_unresolvable_open(self):
        oracle = require_oracle(self)
        events = [{"pid": PID, "call": "openat", "path": None, "fd": None,
                   "result": 3, "directory_open": False, "lineno": 1}]
        verdict = oracle.check_partial_walk(
            events, self.BOUNDARY, self.partial_record(),
            scoped_pids=[SCOPED])
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["counts"],
                         {"unresolved-open": 1, "relative-unresolved": 0})

    def test_partial_walk_getdents_on_unknown_fd_fails(self):
        oracle = require_oracle(self)
        trace = (f"{PID} getdents64(9, 0x7f00, 32768) = 120\n")
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "getdents64 on unresolved fd"):
            oracle.check_partial_walk(trace, self.BOUNDARY,
                                      self.partial_record(),
                                      scoped_pids=[SCOPED])

    def test_walk_crossing_the_boundary_fails_naming_it(self):
        oracle = require_oracle(self)
        trace = (self.walk_trace() +
                 f"{PID} openat(AT_FDCWD, \"{self.BOUNDARY}/cgroup.procs\", "
                 "O_RDONLY) = 9\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "crosses .*hidden"):
            oracle.check_partial_walk(trace, self.BOUNDARY,
                                      self.partial_record(),
                                      scoped_pids=[SCOPED])

    def test_proc_walk_inside_a_partial_cell_fails(self):
        oracle = require_oracle(self)
        trace = (self.walk_trace() +
                 f"{PID} getdents64(9</proc>, 0x7f00, 32768) = 100\n")
        with self.assertRaisesRegex(oracle.EvidenceError, "bare /proc"):
            oracle.check_partial_walk(trace, self.BOUNDARY,
                                      self.partial_record(),
                                      scoped_pids=[SCOPED])

    def test_partial_walk_without_partial_declaration_fails(self):
        oracle = require_oracle(self)
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without a partial coverage"):
            oracle.check_partial_walk(self.walk_trace(), self.BOUNDARY,
                                      coverage_record("full"),
                                      scoped_pids=[SCOPED])

    def test_partial_walk_with_silent_record_fails(self):
        oracle = require_oracle(self)
        record = coverage_record("partial",
                                 gaps=[{"reason": "walk stopped"}])
        with self.assertRaisesRegex(oracle.EvidenceError,
                                    "without explicit PARTIAL"):
            oracle.check_partial_walk(self.walk_trace(), self.BOUNDARY,
                                      record, scoped_pids=[SCOPED])


class ScopeTreeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-scope-tree-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.go = self.work / "go"
        self.child = None

    def tearDown(self):
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.communicate(timeout=5)

    def start(self):
        self.assertTrue(TREE_SRC.exists(), f"fixture missing: {TREE_SRC}")
        self.child = subprocess.Popen(
            ["sh", str(TREE_SRC), str(self.work), str(self.go)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return self.child

    def read_ready(self, child):
        line = child.stdout.readline()
        self.assertTrue(line, f"no READY line: {child.poll()}")
        self.assertTrue(line.startswith("READY pid="), line)
        fields = dict(part.split("=", 1) for part in line.split()[1:])
        return {key: int(value) for key, value in fields.items()}

    def ledger_rows(self):
        path = self.work / "tree.jsonl"
        self.assertTrue(path.exists(), "ledger missing")
        return [json.loads(line) for line in
                path.read_text().splitlines() if line.strip()]

    def wait_rows(self, count, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            path = self.work / "tree.jsonl"
            if path.exists():
                rows = [json.loads(line) for line in
                        path.read_text().splitlines() if line.strip()]
                if len(rows) >= count:
                    return rows
            time.sleep(0.02)
        self.fail(f"ledger did not reach {count} rows")

    def assert_reaped(self, pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                break
            time.sleep(0.02)
        self.fail(f"pid {pid} unexpectedly survives")

    def test_ready_tree_go_cycle_and_stop(self):
        child = self.start()
        self.wait_rows(3)
        ready = self.read_ready(child)
        rows = self.wait_rows(3)
        spawns = {row["role"]: row for row in rows
                  if row["event"] == "spawn"}
        self.assertEqual(set(spawns), {"root", "descendant", "sibling"})
        self.assertEqual(spawns["root"]["pid"], ready["root"])
        self.assertEqual(spawns["root"]["ppid"], ready["pid"])
        self.assertEqual(spawns["descendant"]["pid"], ready["descendant"])
        self.assertEqual(spawns["descendant"]["ppid"], ready["root"])
        self.assertEqual(spawns["sibling"]["pid"], ready["sibling"])
        self.assertEqual(spawns["sibling"]["ppid"], ready["pid"])
        with self.assertRaises(subprocess.TimeoutExpired):
            child.wait(timeout=0.2)
        self.go.touch()
        rows = self.wait_rows(5)
        leave = [row for row in rows if row["event"] == "leave"]
        self.assertEqual(len(leave), 1)
        self.assertEqual(leave[0]["pid"], ready["descendant"])
        gen2 = [row for row in rows if row["event"] == "spawn"
                and row.get("generation") == 2]
        self.assertEqual(len(gen2), 1)
        self.assertEqual(gen2[0]["ppid"], ready["root"])
        self.assertNotEqual(gen2[0]["pid"], ready["descendant"])
        cycle = child.stdout.readline()
        self.assertIn(f"reenter={gen2[0]['pid']}", cycle)
        child.terminate()
        _, error = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, error)
        self.assertEqual(error, "")
        for pid in (ready["root"], gen2[0]["pid"], ready["sibling"]):
            self.assert_reaped(pid)

    def test_stop_before_go_exits_cleanly(self):
        child = self.start()
        self.wait_rows(3)
        self.read_ready(child)
        child.terminate()
        _, error = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, error)
        rows = self.ledger_rows()
        self.assertFalse(any(row["event"] == "leave" for row in rows))

    def test_usage_and_stale_rendezvous_fail(self):
        self.assertTrue(TREE_SRC.exists(), f"fixture missing: {TREE_SRC}")
        result = subprocess.run(["sh", str(TREE_SRC)], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage", result.stderr)
        result = subprocess.run(
            ["sh", str(TREE_SRC), str(self.work / "absent"), str(self.go)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.go.touch()
        result = subprocess.run(
            ["sh", str(TREE_SRC), str(self.work), str(self.go)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("go file already exists", result.stderr)
        self.go.unlink()
        (self.work / "tree.jsonl").write_text("preserve\n")
        result = subprocess.run(
            ["sh", str(TREE_SRC), str(self.work), str(self.go)],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.work / "tree.jsonl").read_text(), "preserve\n")


if __name__ == "__main__":
    unittest.main()
