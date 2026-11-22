# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Table-driven qualification suite for scripts/ci/joint_stop_verdict.py.

One row per accepted shape and per malformed or contradictory input
class of the Joint linked-stop cell log. Each row names the exact
qualification and reason the fail-closed validator must return. The
mutation test disables every named check in turn and requires at
least one row to turn red, so no check is dead weight; the coverage
test requires every check to be the refusing reason of some row.

Run: python3 -I tests/python/test_joint_stop_verdict.py -v
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "tests/python"))
import joint_stop_verdict as jv  # noqa: E402
from joint_stop_logs import (  # noqa: E402
    BACKTRACE, CELL, FAILED_SUMMARY, OK_SUMMARY, PREAMBLE, S1_ERROR,
    UNATTRIBUTED_ERROR, case_head, case_lines, case_outcome, frame,
    matrix_body, offset_of, passing, precluded, s1_body, unattributed_body,
    wedge_body, wedge_error,
)

Q, X, P, F = "qualified", "expected-failure", "environment-precluded", "failed"


def replace_line(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def full_with(extra_tail_body):
    """A full matrix whose body ends with extra lines."""
    return frame(matrix_body() + list(extra_tail_body), True)


def body_edit(body, old, new):
    """Replace (or drop, when new is None) the first line equal to old."""
    body = list(body)
    index = body.index(old)
    if new is None:
        del body[index]
    else:
        body[index] = new
    return body


def matrix_without(k):
    body = []
    for line in matrix_body():
        if line != "P11SCOPE_STOP_COMPLETE=wp7-stop%d" % k:
            body.append(line)
    return body


# (id, log, status, expect_wedge, qualification, reason, origin)
ROWS = [
    # ---- accepted shapes ------------------------------------------------
    ("pass-threaded", passing(), 0, False, Q, "full-matrix", "positive"),
    ("pass-single-thread", passing(threaded=False), 0, False, Q,
     "full-matrix", "positive (LONG framing)"),
    ("pass-with-timeout-warning",
     frame(matrix_body()[:3] + ["test %s has been running for over 60 "
                                "seconds" % CELL] + matrix_body()[3:], True),
     0, False, Q, "full-matrix", "positive (slow runner)"),
    ("s1-threaded", precluded(), 101, False, P, "s1-first-case", "positive"),
    ("s1-single-thread", precluded(threaded=False), 101, False, P,
     "s1-first-case", "positive (LONG framing)"),
    ("s1-with-backtrace", frame(s1_body() + BACKTRACE, False), 101, False, P,
     "s1-first-case", "positive (RUST_BACKTRACE set)"),
    ("s1-under-expect-wedge", precluded(), 101, True, P, "s1-first-case",
     "positive (preclusion holds whatever the expectation)"),
    ("wedge-under-expect", frame(wedge_body(), False), 101, True, X, "wedge",
     "positive (opt-in wedge arm)"),
    ("wedge-single-thread", frame(wedge_body(), False, threaded=False), 101,
     True, X, "wedge", "positive (LONG framing)"),

    # ---- exit status ----------------------------------------------------
    ("s1-log-signal-137", precluded(), 137, False, F, "exit-status",
     "codex r7 #1 (signal exit)"),
    ("pass-log-status-1", passing(), 1, False, F, "exit-status",
     "derived (non-libtest status)"),

    # ---- header ---------------------------------------------------------
    ("zero-tests-selected",
     "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; "
     "0 measured; 0 filtered out; finished in 0.00s\n\n", 0, False, F,
     "header", "codex r1 #3 (zero-test run)"),
    ("unframed-pass", "\n".join(matrix_body() + [OK_SUMMARY]) + "\n", 0,
     False, F, "header", "derived (stub-style unframed log)"),
    ("garbage-before-header", "warning: x\n" + passing(), 0, False, F,
     "header", "derived"),

    # ---- summary --------------------------------------------------------
    ("unfinished-transcript",
     "\n".join(["", "running 1 test"] + matrix_body()) + "\n", 0, False, F,
     "summary-missing", "codex r7 #1 (unfinished transcript)"),
    ("pass-then-failed-summary",
     passing(tail=[FAILED_SUMMARY]), 0, False, F, "summary-duplicate",
     "codex r6 #3 (earlier pass, failed terminal)"),
    ("summary-inside-body",
     full_with(["JOINT_STOP saw " + OK_SUMMARY]), 0, False, F,
     "summary-duplicate", "derived (embedded summary)"),
    ("summary-passed-suffix",
     passing(summary="test result: ok. 1 passed_suspected; 9 failed; "
             "0 ignored; 0 measured; 0 filtered out; finished in 1.00s"),
     0, False, F, "summary-malformed", "codex r6 #3 (malformed prefix)"),
    ("summary-garbage-after-ignored",
     passing(summary="test result: ok. 1 passed; 0 failed; 0 ignored; "
             "9 failed; garbage"),
     0, False, F, "summary-malformed", "codex r7 #2 (suffix after ignored)"),
    ("summary-truncated",
     passing(summary="test result: ok. 1 passed; 0 failed; 0 ignored;"),
     0, False, F, "summary-malformed", "codex r7 #2 (truncated)"),
    ("summary-suffix-after-finished",
     passing(summary=OK_SUMMARY + " garbage"), 0, False, F,
     "summary-malformed", "derived (suffix after the full summary)"),
    ("offset-diagnostic-suffixed",
     frame(body_edit(matrix_body(), case_outcome(2)[1],
                     case_outcome(2)[1] + "-late"), True),
     0, False, F, "record-malformed", "derived (suffixed diagnostic)"),
    ("linked-tag-suffixed",
     frame(body_edit(matrix_body(), "P11SCOPE_CELL_BRANCH=wp7-stop3:linked",
                     "P11SCOPE_CELL_BRANCH=wp7-stop3:linked-ish"), True),
     0, False, F, "record-malformed", "derived (suffixed linked tag)"),
    ("linked-then-other-case-s1",
     frame(case_head(0) + ["P11SCOPE_CELL_BRANCH=wp7-stop1:s1-precluded",
                           S1_ERROR.format(k=1)], False),
     101, False, F, "sequence", "codex r5 (S1 beside a linked tag)"),
    ("summary-bare-count", passing(summary="test result: ok. 1 passed"), 0,
     False, F, "summary-malformed", "derived (old short form)"),
    ("summary-leading-zero",
     passing(summary="test result: ok. 01 passed; 0 failed; 0 ignored; "
             "0 measured; 0 filtered out; finished in 1.00s"),
     0, False, F, "summary-malformed", "derived (non-canonical count)"),
    ("summary-then-error", passing(tail=["Error: joint cleanup failed"]), 0,
     False, F, "summary-not-terminal", "codex r7 #2 (later error)"),
    ("two-passed",
     passing(summary="test result: ok. 2 passed; 0 failed; 0 ignored; "
             "0 measured; 0 filtered out; finished in 1.00s"),
     0, False, F, "summary-counts", "codex r6 (two passed)"),
    ("pass-with-ignored",
     passing(summary="test result: ok. 1 passed; 0 failed; 1 ignored; "
             "0 measured; 0 filtered out; finished in 1.00s"),
     0, False, F, "summary-counts", "derived"),
    ("ok-summary-status-101", passing(), 101, False, F, "summary-status",
     "derived (summary disagrees with status)"),
    ("failed-summary-status-0", precluded(), 0, False, F, "summary-status",
     "derived (summary disagrees with status)"),

    # ---- outcome and trailer --------------------------------------------
    ("outcome-other-test",
     frame(matrix_body(), True, cell="other::test",
           trailer=[""]), 0, False, F, "outcome", "derived (foreign test)"),
    ("outcome-disagrees-with-summary",
     replace_line(passing(), "test %s ... ok" % CELL,
                  "test %s ... FAILED" % CELL), 0, False, F, "outcome",
     "derived"),
    ("failures-list-other-test",
     replace_line(precluded(), "    " + CELL, "    other::test"), 101, False,
     F, "failures-list", "derived"),
    ("failures-list-missing",
     frame(s1_body(), False, trailer=[""]), 101, False, F, "failures-list",
     "derived"),

    # ---- stray framing and records --------------------------------------
    ("stray-ok-line", full_with(["ok"]), 0, False, F, "stray-framing",
     "derived"),
    ("second-running-line", full_with(["running 1 test"]), 0, False, F,
     "stray-framing", "derived"),
    ("complete-marker-in-diagnostic",
     frame([("JOINT_STOP wp7-stop7: P11SCOPE_STOP_COMPLETE=wp7-stop7 "
             "emitted late") if line == "P11SCOPE_STOP_COMPLETE=wp7-stop7"
            else line for line in matrix_body()], True),
     0, False, F, "record-malformed", "codex r4 #2 (embedded marker)"),
    ("complete-marker-suffixed",
     frame(["P11SCOPE_STOP_COMPLETE=wp7-stop7:linked-but-not-completed"
            if line == "P11SCOPE_STOP_COMPLETE=wp7-stop7" else line
            for line in matrix_body()], True),
     0, False, F, "record-malformed", "codex r4 #2 (quoted marker)"),
    ("embedded-s1-tag",
     frame(list(matrix_body(range(0))) + [
         "JOINT_STOP wp7-stop0: P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded "
         "emitted late", S1_ERROR.format(k=0)], False),
     101, False, F, "record-malformed", "codex r5 #2 (embedded tag)"),
    ("suffixed-s1-lookalike",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded-suspected",
            S1_ERROR.format(k=0)], False),
     101, False, F, "record-malformed", "codex r5 #2 (lookalike tag)"),
    ("out-of-range-case-tag",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop12:s1-precluded",
            S1_ERROR.format(k=12)], False),
     101, False, F, "record-malformed", "codex r5 (out-of-range case)"),
    ("embedded-unattributed-tag",
     frame(["JOINT_STOP wp7-stop0: P11SCOPE_CELL_BRANCH=wp7-stop0:"
            "no-feeds-unattributed emitted late",
            UNATTRIBUTED_ERROR.format(k=0)], False),
     101, False, F, "record-malformed", "codex r5 (embedded unattributed)"),
    ("s1-receipt-in-diagnostic",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
            "JOINT_STOP wp7-stop0: diagnostic " + S1_ERROR.format(k=0)[7:]
            + " seen", "Error: wp7-stop0: q1 fixture failed"], False),
     101, False, F, "receipt-stray", "codex r6 #1 (receipt in diagnostic)"),
    ("s1-receipt-unprefixed-then-other-error",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
            S1_ERROR.format(k=0)[7:],
            "Error: wp7-stop0: joint cleanup failed"], False),
     101, False, F, "receipt-stray",
     "codex r7 #1 (earlier unprefixed receipt, later error)"),
    ("pass-with-unattributed-receipt-text",
     full_with([UNATTRIBUTED_ERROR.format(k=0)[7:]]), 0, False, F,
     "receipt-stray", "codex r7 #3 (receipt only, no tag)"),
    ("pass-with-s1-receipt-text",
     full_with([S1_ERROR.format(k=0)[7:]]), 0, False, F, "receipt-stray",
     "codex r7 #3 (receipt only, other cause)"),

    # ---- error records --------------------------------------------------
    ("pass-with-unattributed-error",
     full_with([UNATTRIBUTED_ERROR.format(k=0)]), 0, False, F, "error-count",
     "codex r7 #3 (Error receipt on a pass)"),
    ("pass-with-error-line", full_with(["Error: joint cleanup failed"]), 0,
     False, F, "error-count", "derived"),
    ("s1-then-later-error",
     frame(s1_body() + ["Error: wp7-stop0: joint cleanup failed"], False),
     101, False, F, "error-count", "codex r7 #1 (competing terminal error)"),
    ("s1-plus-unattributed-error",
     frame(s1_body() + [UNATTRIBUTED_ERROR.format(k=0)], False), 101, False,
     F, "error-count", "codex r6 #1 (conflicting receipt)"),
    ("failure-by-panic",
     frame(matrix_body(range(2)) + case_head(2) + [
         "", "thread 'x' panicked at src/inventory/x.rs:1:1:", "boom",
         "note: run with `RUST_BACKTRACE=1` environment variable to "
         "display a backtrace"], False),
     101, False, F, "error-count", "derived (panic, no terminal error)"),
    ("diagnostic-after-error",
     frame(s1_body() + ["JOINT_STOP late diagnostic"], False), 101, False, F,
     "error-not-terminal", "derived"),
    ("caused-by-after-error",
     frame(s1_body() + ["", "Caused by:", "    io error"], False), 101,
     False, F, "error-not-terminal", "derived"),

    # ---- case sequence --------------------------------------------------
    ("tags-then-markers-not-interleaved",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop%d:linked" % k for k in range(12)]
           + ["P11SCOPE_STOP_COMPLETE=wp7-stop%d" % k for k in range(12)],
           True),
     0, False, F, "sequence", "derived (old stub shape)"),
    ("linked-but-incomplete-case",
     frame(matrix_without(7), True), 0, False, F, "sequence",
     "codex r4 #2 (linked, never completed)"),
    ("duplicated-case",
     frame(matrix_body() + case_lines(11), True), 0, False, F, "sequence",
     "derived (case twice)"),
    ("case-out-of-order",
     frame(matrix_body(range(2)) + case_lines(3) + case_lines(2)
           + matrix_body(range(4, 12))[len(matrix_body(range(0))):], True),
     0, False, F, "sequence", "derived"),
    ("marker-for-other-case",
     frame([("P11SCOPE_STOP_COMPLETE=wp7-stop4"
             if line == "P11SCOPE_STOP_COMPLETE=wp7-stop3" else line)
            for line in matrix_body()], True),
     0, False, F, "sequence", "derived (mismatched marker)"),
    ("lone-later-s1",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop7:s1-precluded",
            S1_ERROR.format(k=7)], False),
     101, False, F, "sequence", "codex r6 #1 (impossible later case)"),
    ("s1-after-full-matrix",
     full_with(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded"]), 0, False, F,
     "sequence", "codex r5 (pass with S1 tag)"),
    ("s1-then-unattributed-tags",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
            "P11SCOPE_CELL_BRANCH=wp7-stop1:no-feeds-unattributed",
            UNATTRIBUTED_ERROR.format(k=1)], False),
     101, False, F, "sequence", "codex r5 (mixed no-feed tags)"),
    ("offset-diagnostic-missing",
     frame(body_edit(matrix_body(), case_outcome(2)[1], None), True),
     0, False, F, "sequence", "derived (marker without its diagnostic)"),
    ("offset-wrong-for-case",
     frame(body_edit(matrix_body(), case_outcome(2)[1],
                     case_outcome(2, offset=20)[1]), True),
     0, False, F, "offset-binding", "derived (case bound to wrong offset)"),
    ("completed-without-publish",
     frame(matrix_body(range(3)) + case_head(3)
           + case_outcome(3, "abandoned")
           + ["P11SCOPE_STOP_COMPLETE=wp7-stop3"]
           + matrix_body(range(4, 12))[2:], True),
     0, False, F, "finish-binding", "derived (completion without publish)"),
    ("one-case-pass", frame(matrix_body(range(1)), True), 0, False, F,
     "matrix-short", "codex r3 #2 (narrowed matrix)"),
    ("pass-ends-linked",
     frame(matrix_body(range(11)) + case_head(11) + case_outcome(11), True),
     0, False, F, "matrix-short", "derived (last case never completed)"),
    ("pass-with-first-case-s1-tag",
     frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded"], True), 0, False,
     F, "pass-with-no-feed", "codex r5 (a pass never precludes)"),
    ("unexpected-pass", passing(), 0, True, F, "unexpected-pass",
     "derived (pass under JOINT_EXPECTED_FAILURE=1)"),

    # ---- failure classification -----------------------------------------
    ("s1-after-seven-linked", frame(s1_body(7), False), 101, False, F,
     "s1-after-linked", "codex r5 #2 (S1 after linked matrix)"),
    ("s1-after-one-linked", frame(s1_body(1), False), 101, False, F,
     "s1-after-linked", "codex r5 (S1 with linked tags)"),
    ("unattributed-no-feed", frame(unattributed_body(4), False), 101, False,
     F, "no-feed-unattributed", "codex r3 #3 (unattributed cause)"),
    ("unattributed-first-case", frame(unattributed_body(0), False), 101,
     True, F, "no-feed-unattributed",
     "codex r6 #1 (unattributed under expectation)"),
    ("unattributed-with-wedge-diagnostic",
     frame(unattributed_body(0)[:-1] + [
         "JOINT_STOP wp7-stop0: diagnostic Published then WoundDown seen",
         UNATTRIBUTED_ERROR.format(k=0)], False),
     101, True, F, "no-feed-unattributed",
     "codex r6 #1 (mixed unattributed wedge)"),
    ("old-collapsed-s1",
     frame(s1_body(error="Error: wp7-stop0: no joint feeds from the linked "
                   "session; not attempted"), False),
     101, False, F, "receipt-mismatch", "codex r4/r5 (collapsed tag)"),
    ("s1-tag-other-case-receipt",
     frame(s1_body(error=S1_ERROR.format(k=7)), False), 101, False, F,
     "receipt-mismatch", "codex r6 #1 (mismatched case)"),
    ("s1-tag-unattributed-receipt",
     frame(s1_body(error=UNATTRIBUTED_ERROR.format(k=0)), False), 101, False,
     F, "receipt-mismatch", "derived (tag and receipt disagree)"),
    ("s1-tag-other-error",
     frame(s1_body(error="Error: wp7-stop0: q1 fixture failed"), False), 101,
     False, F, "receipt-mismatch", "codex r5 (S1 without receipt)"),
    ("receipt-without-tag",
     frame(PREAMBLE + [S1_ERROR.format(k=0)], False), 101, False, F,
     "receipt-mismatch", "derived (untagged receipt)"),
    ("receipt-after-linked",
     frame(case_head(0) + [S1_ERROR.format(k=0)], False), 101, False, F,
     "receipt-mismatch", "derived (receipt for a linked case)"),
    ("wedge-error-wrong-offset",
     frame(wedge_body()[:-1] + [wedge_error(0)], False), 101, True, F,
     "wedge-binding", "derived (wedge of another case)"),
    ("wedge-error-wrong-finish",
     frame(wedge_body()[:-1] + [wedge_error(offset_of(5), "abandoned")],
           False),
     101, True, F, "wedge-binding", "derived (wedge disagrees with finish)"),
    ("wedge-under-expect-zero", frame(wedge_body(), False), 101, False, F,
     "wedge-unexpected", "derived (wedge regression)"),
    ("wedge-diagnostic-then-unrelated-error",
     frame(matrix_body(range(0)) + case_head(0) + case_outcome(0) + [
         "JOINT_STOP wp7-stop0: diagnostic Published then WoundDown",
         "Error: wp7-stop0: q1 fixture failed"], False),
     101, True, F, "case-failed", "codex r7 #1 (wedge arm, wrong terminal)"),
    ("wedge-without-offset-diagnostic",
     frame(matrix_body(range(5)) + case_head(5)
           + [wedge_error(offset_of(5))], False),
     101, True, F, "case-failed", "derived (wedge before the outcome)"),
    ("failure-after-full-matrix",
     frame(matrix_body() + ["Error: joint cleanup failed"], False), 101,
     False, F, "case-failed", "derived (error after all cases)"),
    ("failure-before-first-case",
     frame(PREAMBLE + ["Error: cannot build the joint workload"], False),
     101, False, F, "case-failed", "derived (setup failure)"),
]


def _check_rows():
    ids = [row[0] for row in ROWS]
    assert len(ids) == len(set(ids)), "duplicate row ids"


class JointStopVerdictTableTests(unittest.TestCase):
    def run_row(self, row, disabled=frozenset()):
        _id, log, status, expect, _q, _r, _o = row
        return jv.classify(log, status, CELL, expect_wedge=expect,
                           disabled=disabled)

    def test_every_row_has_its_exact_verdict(self):
        _check_rows()
        for row in ROWS:
            with self.subTest(row=row[0], origin=row[6]):
                got = self.run_row(row)
                self.assertEqual((got["qualification"], got["reason"]),
                                 (row[4], row[5]), got["detail"])
                self.assertTrue(got["detail"])

    def test_every_check_refuses_some_row(self):
        reasons = {row[5] for row in ROWS if row[4] == F}
        self.assertEqual(sorted(set(jv.CHECKS) - reasons), [],
                         "checks with no refusing row")
        self.assertEqual(sorted(reasons - set(jv.CHECKS) - {"case-failed"}),
                         [], "rows naming an unknown reason")

    def test_removing_any_check_turns_a_row_red(self):
        # Mutation proof: with one check disabled, the validator must
        # disagree with the table on at least one row; a check whose
        # removal changes nothing is either dead or untested.
        for name in jv.CHECKS:
            with self.subTest(check=name):
                flipped = []
                for row in ROWS:
                    got = self.run_row(row, disabled=frozenset([name]))
                    if (got["qualification"], got["reason"]) != (row[4],
                                                                 row[5]):
                        flipped.append((row[0], got["qualification"]))
                self.assertTrue(flipped, "disabling %s turns no row red"
                                % name)

    def test_disabling_a_check_can_open_an_accept_path(self):
        # The checks guard accept paths: disabling each sole-guard check
        # lets some malformed row through as an acceptance, so the table
        # holds the input each gate exists to stop. exit-status and
        # record-malformed are layered (summary-status and the case
        # sequence catch their rows second); the red test covers them.
        accepts = {Q, X, P}
        for name in ("summary-duplicate", "summary-malformed",
                     "summary-not-terminal", "summary-counts",
                     "receipt-stray", "error-count",
                     "error-not-terminal", "sequence", "offset-binding",
                     "finish-binding", "matrix-short", "s1-after-linked",
                     "wedge-binding", "wedge-unexpected", "unexpected-pass"):
            with self.subTest(check=name):
                opened = [row[0] for row in ROWS
                          if row[4] == F and row[5] == name
                          and self.run_row(row, frozenset([name]))[
                              "qualification"] in accepts]
                self.assertTrue(opened, "no row of %s becomes an "
                                "acceptance when it is disabled" % name)

    def test_grammar_matches_the_rust_emitters(self):
        # The validator's grammar is the Rust cell's output: pin each
        # literal it relies on in the emitter source, so a drift in
        # the cell fails here instead of silently failing (or passing)
        # the live qualification.
        rust = (ROOT / "src/inventory/joint_stop_races_privileged_tests.rs"
                ).read_text(encoding="utf-8")
        for literal in (
                'const OFFSETS_MS: [u64; 4] = [0, 1, 5, 20];',
                'const PREPS: [Prep; 3] = [',
                'prep_index * OFFSETS_MS.len() + offset_index,',
                'let tag = format!("wp7-stop{index}");',
                'eprintln!("P11SCOPE_CELL_BRANCH={tag}:{feed_tag}");',
                'anyhow::bail!("{tag}: {reason}; not attempted");',
                'eprintln!("P11SCOPE_CELL_BRANCH={tag}:linked");',
                '"P11SCOPE_CELL_BRANCH=offset{offset_ms}:{}:{}",',
                'Ok(format!("P11SCOPE_STOP_COMPLETE=wp7-stop{index}"))',
                'JointBranch::S1 => Some("s1-precluded"),',
                'JointBranch::Unattributed => Some("no-feeds-unattributed"),',
                '"offset {offset_ms}: the finish must reach Published then '
                'WoundDown: {outcome}"',
                '"offset={} begin={} finish={} ({} polls) first_error={:?} '
                'latched={} latch={:?} \\',
                '"published".to_string()', '"abandoned".to_string()',
                '"not-begun".to_string()', '"unpublished".to_string()',
                '"latched"', '"no-latch"'):
            with self.subTest(literal=literal):
                self.assertIn(literal, rust)
        self.assertIn(jv.S1_RECEIPT.format(k=0)[len("Error: wp7-stop0: "):
                                                -len("; not attempted")],
                      rust)
        self.assertIn(jv.UNATTRIBUTED_RECEIPT.format(k=0)[
            len("Error: wp7-stop0: "):-len("; not attempted")], rust)
        self.assertEqual(jv.OFFSETS_MS, (0, 1, 5, 20))
        self.assertEqual(jv.CASES, 3 * 4)

    def test_unknown_disabled_check_is_refused(self):
        with self.assertRaises(ValueError):
            jv.classify(passing(), 0, CELL, disabled=frozenset(["nope"]))

    def test_cli_prints_the_row_verdict(self):
        import json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "joint-cell.log"
            for log, status, expect, want in (
                    (passing(), 0, "0", Q), (precluded(), 101, "0", P),
                    (frame(wedge_body(), False), 101, "1", X),
                    (precluded(), 137, "0", F)):
                path.write_text(log, encoding="utf-8")
                proc = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "scripts/ci/"
                                               "joint_stop_verdict.py"),
                     "--cell", CELL, "--status", str(status),
                     "--expect-wedge", expect, str(path)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout)["qualification"],
                                 want)
            proc = subprocess.run(
                [sys.executable, "-I", str(ROOT / "scripts/ci/"
                                           "joint_stop_verdict.py"),
                 "--cell", CELL, "--status", "abc", str(path)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
