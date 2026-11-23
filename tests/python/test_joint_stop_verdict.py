# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Table-driven qualification suite for scripts/ci/joint_stop_verdict.py.

The Joint linked-stop cell prints one verdict record built from its own
case ledger; the validator judges only that record, the exit status
and the libtest summary. One row per accepted shape and per malformed
or contradictory class, each expressed as the record (and framing) it
would produce, with the exact qualification and reason the validator
must return. Every class the reviews found against the old free-text
grammar (rounds 2 to 9) has a row here in record form. The mutation
test disables every named check in turn and requires some row to turn
red; the coverage test requires every check to be the refusing reason
of some row.

Run: python3 -I tests/python/test_joint_stop_verdict.py -v
"""

import copy
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "tests/python"))
import joint_stop_verdict as jv  # noqa: E402
from joint_stop_logs import (  # noqa: E402
    CELL, FELL_BACK_RECEIPT, JOIN_QUANTA, MARKER, OK_SUMMARY, PREAMBLE,
    S1_RECEIPT, SHED_RECEIPT, STARVED_RECEIPT, UNATTRIBUTED_RECEIPT,
    body_for, case_failed_record, case_record, frame, healthy_outcome,
    log_for, no_feed_probe, no_feed_record, offset_of, passing, precluded,
    precluded_record, qualified_record, record_line, wedge_outcome,
    wedge_record, wedged,
)

Q, X, P, F = "qualified", "expected-failure", "environment-precluded", "failed"


def edited(rec, change):
    """A deep copy of `rec` after `change(copy)`."""
    rec = copy.deepcopy(rec)
    change(rec)
    return rec


def case_set(k, **fields):
    def change(rec):
        rec["cases"][k].update(fields)
    return change


def outcome_set(k, **fields):
    def change(rec):
        rec["cases"][k]["outcome"].update(fields)
    return change


def raw_log(record_text, ok=True, rec=None):
    """A log whose record line is `record_text` verbatim."""
    rec = rec or qualified_record()
    body = body_for(rec)
    at = body.index(record_line(rec))
    body[at] = record_text
    return frame(body, ok)


def with_body(rec, before=(), after=(), ok=None, **kwargs):
    if ok is None:
        ok = rec["terminal"]["kind"] == "qualified"
    return frame(body_for(rec, before, after), ok, **kwargs)


QR = qualified_record()
PR = precluded_record()
WR = wedge_record(5)


def summary_with(text):
    return passing(summary=text)


ROWS = [
    # --- controls ---------------------------------------------------
    ("pass-threaded", passing(), 0, False, Q, "full-matrix", "control"),
    ("pass-single-thread", passing(threaded=False), 0, False, Q,
     "full-matrix", "control"),
    ("precluded-threaded", precluded(), 101, False, P, "s1-first-case",
     "control"),
    ("precluded-single-thread", precluded(threaded=False), 101, False, P,
     "s1-first-case", "control"),
    ("wedge-expected", wedged(), 101, True, X, "wedge", "control"),
    ("wedge-expected-case0", wedged(0), 101, True, X, "wedge", "control"),
    ("wedge-not-expected", wedged(), 101, False, F, "wedge-unexpected",
     "control"),
    ("pass-under-expected-wedge", passing(), 0, True, F, "unexpected-pass",
     "r2-r6: an unexpected pass under JOINT_EXPECTED_FAILURE=1"),
    ("unattributed-case0", log_for(no_feed_record(0, "no-feeds-unattributed")),
     101, False, F, "no-feed-unattributed", "r2-r6: S1 vs unattributed"),
    ("unattributed-case4", log_for(no_feed_record(4, "no-feeds-unattributed")),
     101, False, F, "no-feed-unattributed", "r2-r6: S1 vs unattributed"),
    ("s1-after-linked", log_for(no_feed_record(1)), 101, False, F,
     "s1-after-linked", "r2-r6: S1 after a linked case"),
    ("s1-after-seven-linked", log_for(no_feed_record(7)), 101, False, F,
     "s1-after-linked", "r2-r6: S1 after a linked case"),
    ("case-failed-check", log_for(case_failed_record(3)), 101, False, F,
     "case-failed", "control"),
    ("case-failed-drive", log_for(case_failed_record(2, "drive")), 101,
     False, F, "case-failed", "control"),
    ("case-failed-setup", log_for(case_failed_record(6, "setup")), 101,
     False, F, "case-failed", "control"),
    ("case-failed-before-first-case",
     log_for(case_failed_record(None, "setup", error="softhsm missing")),
     101, False, F, "case-failed", "control"),
    ("narrowed-selection", log_for(edited(QR, lambda r: r.update(
        selection={"preps": [0], "offsets": [0, 1, 2, 3]}, cases=r["cases"][:4],
        terminal={"kind": "narrowed"})), ok=True), 0, False, F, "selection",
     "r2-r6: a narrowed matrix never qualifies"),
    ("selection-refused", log_for(case_failed_record(None, "setup",
                                                     error="bad WP7_STOP_PREPS")
                                  | {"selection": None}), 101, False, F,
     "selection", "derived: refused selector"),

    # --- free text is inert: only the record counts ----------------------
    ("text-contradicting-outcome-ignored", with_body(QR, before=[
        "JOINT_STOP outcome: offset=0 begin=polling finish=unpublished",
        "P11SCOPE_CELL_BRANCH=offset0:latched:unpublished"]), 0, False, Q,
     "full-matrix", "r9-1: contradictory diagnostics are not evidence"),
    ("text-offset-2-diagnostic-ignored", with_body(QR, after=[
        "JOINT_STOP offset=2: at-Q published (api_a == a_semantic)"]), 0,
     False, Q, "full-matrix", "r9-1: misplaced diagnostics are not evidence"),
    ("text-old-completion-markers-do-not-qualify", frame(
        ["P11SCOPE_STOP_COMPLETE=wp7-stop%d" % k for k in range(12)], True),
     0, False, F, "record-missing",
     "r2-r6: completion lines alone never qualify"),
    ("text-old-s1-receipt-does-not-preclude", frame(
        ["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
         "Error: wp7-stop0: %s; not attempted" % S1_RECEIPT], False), 101,
     False, F, "record-missing", "r7: a receipt alone never precludes"),
    ("text-post-link-edge-before-preclusion-ignored", with_body(PR, before=[
        "JOINT_STOP wp7-stop0: edge_a joint=1 reduced=1 started=Some(1) "
        "completed=Some(1) mechanisms=1"]), 101, False, P, "s1-first-case",
     "r9-2: free-text edge lines are not linkage; the ledger is"),

    # --- exit status and summary ----------------------------------------
    ("signal-after-receipt", precluded(), 137, False, F, "exit-status",
     "r7: S1 receipt then a signal"),
    ("abort-on-pass", passing(), 134, False, F, "exit-status", "r2-r6"),
    ("summary-missing", frame(body_for(QR), True, summary="", trailer=[]),
     0, False, F, "summary-missing", "r7: unfinished transcript"),
    ("summary-duplicate", passing(tail=[OK_SUMMARY]), 0, False, F,
     "summary-duplicate", "r7"),
    ("summary-in-body", with_body(QR, before=[OK_SUMMARY]), 0, False, F,
     "summary-duplicate", "r7: a summary in free text"),
    ("summary-suffix", summary_with(OK_SUMMARY + " extra"), 0, False, F,
     "summary-malformed", "r7: malformed summary"),
    ("summary-prefix", summary_with("x" + OK_SUMMARY), 0, False, F,
     "summary-malformed", "r7: malformed summary"),
    ("summary-huge-count", summary_with(
        "test result: ok. " + "1" * 4301 + " passed; 0 failed; 0 ignored; "
        "0 measured; 0 filtered out; finished in 1.00s"), 0, False, F,
     "summary-malformed", "r8: oversized count"),
    ("summary-not-terminal", passing(tail=["Error: late"]), 0, False, F,
     "summary-not-terminal", "r7: output after the summary"),
    ("summary-two-passed", summary_with(OK_SUMMARY.replace(
        "1 passed", "2 passed")), 0, False, F, "summary-counts", "r7"),
    ("summary-ignored", summary_with(
        "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; "
        "0 filtered out; finished in 0.00s"), 0, False, F, "summary-counts",
     "r2-r6: an ignored cell is not a run"),
    ("summary-ok-with-failure-count", summary_with(OK_SUMMARY.replace(
        "1 passed; 0 failed", "0 passed; 1 failed")), 0, False, F,
     "summary-counts", "derived"),
    ("summary-failed-on-exit-0", log_for(QR, ok=False), 0, False, F,
     "summary-status", "r7: summary contradicts the exit"),
    ("summary-ok-on-exit-101", passing(), 101, False, F, "summary-status",
     "r7: summary contradicts the exit"),

    # --- the record line -------------------------------------------------
    ("record-missing-panic", frame(PREAMBLE + ["thread panicked"], False),
     101, False, F, "record-missing", "derived: a panic prints no record"),
    ("record-duplicate", with_body(QR, after=[record_line(QR)]), 0, False, F,
     "record-duplicate", "r2-r6: duplicated evidence"),
    ("record-duplicate-forged-precluded", with_body(QR, before=[
        record_line(PR)]), 0, False, F, "record-duplicate",
     "r8: evidence before the deciding record"),
    ("record-marker-in-free-text", with_body(QR, before=[
        "child said " + MARKER + "{}"]), 0, False, F, "record-duplicate",
     "derived: a forged marker"),
    ("record-glued", raw_log("JOINT_STOP x " + record_line(QR)), 0, False,
     F, "record-misplaced", "r8: a malformed record stem"),
    ("record-truncated", raw_log(record_line(QR)[:-7]), 0, False, F,
     "record-json", "derived: truncated record"),
    ("record-trailing-text", raw_log(record_line(QR) + " ok"), 0, False, F,
     "record-json", "r8: a malformed record suffix"),
    ("record-duplicate-key", raw_log(record_line(QR)[:-1]
                                     + ',"cell":"%s"}' % CELL), 0, False, F,
     "record-json", "derived: duplicate key"),
    ("record-float", raw_log(record_line(QR).replace(
        '"finish_polls":3', '"finish_polls":3.0', 1)), 0, False, F,
     "record-json", "derived: float"),
    ("record-nan", raw_log(record_line(QR).replace(
        '"finish_polls":3', '"finish_polls":NaN', 1)), 0, False, F,
     "record-json", "derived: NaN"),
    ("record-huge-integer", raw_log(record_line(QR).replace(
        '"finish_polls":3', '"finish_polls":' + "9" * 4301, 1)), 0, False,
     F, "record-json", "r8: oversized count"),
    ("record-extra-key", log_for(edited(QR, lambda r: r.update(extra=1))),
     0, False, F, "record-schema", "derived"),
    ("record-missing-key", log_for(edited(QR, lambda r: r.pop("selection"))),
     0, False, F, "record-schema", "derived"),
    ("record-schema-version", log_for(edited(QR, lambda r: r.update(
        schema="p11scope.joint-stop-verdict/2"))), 0, False, F,
     "record-schema", "derived"),
    ("record-bool-index", log_for(edited(QR, case_set(1, index=True))), 0,
     False, F, "record-schema", "derived: bool as int"),
    ("record-int-completed", log_for(edited(QR, case_set(0, completed=1))),
     0, False, F, "record-schema", "derived: int as bool"),
    ("record-unknown-branch", log_for(edited(QR, case_set(
        0, branch="linked="))), 0, False, F, "record-schema",
     "r8: malformed branch stem"),
    ("record-unknown-finish", log_for(edited(QR, outcome_set(
        0, finish="done"))), 0, False, F, "record-schema", "derived"),
    ("record-outcome-extra-field", log_for(edited(QR, outcome_set(
        0, verdict="ok"))), 0, False, F, "record-schema", "derived"),
    ("record-stop-counts-short", log_for(edited(QR, outcome_set(
        0, stop_counts=[2, 0]))), 0, False, F, "record-schema", "derived"),
    ("record-negative-count", log_for(edited(QR, outcome_set(
        0, api_a=-1))), 0, False, F, "record-schema", "derived"),
    ("record-unknown-terminal", log_for(edited(QR, lambda r: r.update(
        terminal={"kind": "passed"})), ok=True), 0, False, F, "record-schema",
     "derived"),
    ("record-terminal-extra-field", log_for(edited(QR, lambda r: r.update(
        terminal={"kind": "qualified", "case": 11}))), 0, False, F,
     "record-schema", "derived"),
    ("record-unknown-check", log_for(edited(case_failed_record(3), lambda r:
                                            r["terminal"].update(
                                                check="other"))), 101,
     False, F, "record-schema", "derived"),
    ("record-not-object", raw_log(MARKER + "[]"), 0, False, F,
     "record-schema", "derived"),
    ("record-other-cell", log_for(edited(QR, lambda r: r.update(
        cell=CELL + "_other"))), 0, False, F, "record-cell",
     "r8: the generic fallback judged another cell"),

    # --- cases: sequence, branch, outcome, completion ------------------
    ("matrix-short", log_for(edited(QR, lambda r: r.update(
        cases=r["cases"][:11]))), 0, False, F, "qualified-count",
     "r2-r6: short matrix"),
    ("matrix-empty", log_for(edited(QR, lambda r: r.update(cases=[]))), 0,
     False, F, "terminal-case", "r2-r6: linked tags alone"),
    ("matrix-thirteen", log_for(edited(QR, lambda r: r["cases"].append(
        case_record(12)))), 0, False, F, "case-sequence", "derived"),
    ("case-duplicated", log_for(edited(QR, lambda r: r["cases"].__setitem__(
        2, copy.deepcopy(r["cases"][1])))), 0, False, F, "case-sequence",
     "r2-r6: duplicated case"),
    ("case-out-of-order", log_for(edited(QR, lambda r: r["cases"].reverse())),
     0, False, F, "case-sequence", "r2-r6: out of order"),
    ("case-wrong-name", log_for(edited(QR, case_set(3, name="wp7-stop30"))),
     0, False, F, "case-sequence", "derived"),
    ("case-wrong-prep", log_for(edited(QR, case_set(4, prep=0))), 0, False,
     F, "case-sequence", "derived"),
    ("case-unsupported-offset", log_for(edited(QR, lambda r: (
        case_set(0, offset_ms=2)(r), outcome_set(0, offset_ms=2)(r)))), 0,
     False, F, "case-sequence", "r9-1: an unsupported offset"),
    ("case-no-feed-mid-matrix", log_for(edited(QR, case_set(
        3, branch="s1-precluded", outcome=None, completed=False))), 0, False,
     F, "case-branch", "r2-r6: pass with a no-feed case"),
    ("case-unlinked-mid-matrix", log_for(edited(QR, case_set(
        3, branch=None))), 0, False, F, "case-branch", "derived"),
    ("outcome-other-offset", log_for(edited(QR, outcome_set(
        0, offset_ms=2))), 0, False, F, "case-outcome",
     "r9-1: outcome bound to another offset"),
    ("outcome-offset-of-neighbor", log_for(edited(QR, outcome_set(
        1, offset_ms=5))), 0, False, F, "case-outcome", "r2-r6: offset"),
    ("outcome-missing-mid-matrix", log_for(edited(QR, case_set(
        2, outcome=None))), 0, False, F, "case-outcome",
     "r2-r6: completion without a stop"),
    ("completed-unpublished", log_for(edited(QR, outcome_set(
        0, finish="unpublished"))), 0, False, F, "completion",
     "r9-1: contradictory stop outcome"),
    ("completed-unwound", log_for(edited(QR, outcome_set(
        6, wound="unwound"))), 0, False, F, "completion",
     "r9-1: contradictory stop outcome"),
    ("completed-not-taken", log_for(edited(QR, outcome_set(
        11, taken=False))), 0, False, F, "completion", "r9-1"),
    ("completed-unreconciled", log_for(edited(QR, outcome_set(
        4, reconciled=False))), 0, False, F, "completion", "r2-r6"),
    ("completed-at-q-unpublished", log_for(edited(QR, outcome_set(
        2, api_a=1))), 0, False, F, "completion", "derived"),
    ("completed-latch-without-code", log_for(edited(QR, outcome_set(
        8, latched=True))), 0, False, F, "completion", "derived"),
    ("completed-error-without-latch", log_for(edited(QR, outcome_set(
        9, first_error="boom"))), 0, False, F, "completion", "derived"),
    ("completed-gap-without-abandon", log_for(edited(QR, outcome_set(
        10, abandon_gap="for lane stop: x"))), 0, False, F, "completion",
     "derived"),
    ("open-case-mid-matrix", log_for(edited(QR, case_set(
        5, completed=False))), 0, False, F, "completion", "r2-r6"),
    ("pass-with-shed-disclosed", log_for(edited(QR, outcome_set(
        3, api_a=1, lane_shed=1))), 0, False, Q, "full-matrix",
     "control: a disclosed shed passes"),
    ("pass-latched-named-twice", log_for(edited(QR, outcome_set(
        7, latched=True, latch_code="E7", abandon_gap="for exit: E7",
        first_error="E7 latched", finish="published", stash_floor=1,
        begin="abandoned-at-begin"))), 0, False, Q, "full-matrix",
     "control: a latch named in gap and error"),

    # --- terminal binding ------------------------------------------------
    ("qualified-on-exit-101", log_for(QR, ok=False), 101, False, F,
     "terminal-status", "r7: a pass record in a failed run"),
    ("precluded-on-exit-0", log_for(PR, ok=True), 0, False, F,
     "terminal-status", "r7: a receipt-only pass"),
    ("wedge-on-exit-0", log_for(WR, ok=True), 0, True, F, "terminal-status",
     "derived"),
    ("qualified-with-open-last", log_for(edited(QR, case_set(
        11, completed=False, outcome=wedge_outcome(11)))), 0, False, F,
     "terminal-case", "derived"),
    ("wedge-on-earlier-case", log_for(edited(WR, lambda r: r["terminal"]
                                             .update(case=2))), 101, True,
     F, "terminal-case", "r9-3: a wedge naming another case"),
    ("case-failed-on-other-case", log_for(edited(case_failed_record(3),
                                                 lambda r: r["terminal"]
                                                 .update(case=1))), 101,
     False, F, "terminal-case", "derived"),
    ("case-failed-null-with-cases", log_for(edited(case_failed_record(3),
                                                   lambda r: r["terminal"]
                                                   .update(case=None))),
     101, False, F, "terminal-case", "derived"),

    # --- preclusion -------------------------------------------------------
    ("precluded-with-outcome", log_for(edited(PR, case_set(
        0, outcome=healthy_outcome(0)))), 101, False, F, "case-outcome",
     "r9-2: post-link evidence before a preclusion"),
    ("precluded-linked-case", log_for(edited(PR, case_set(
        0, branch="linked", outcome=None, no_feed=None, join_feeds=1))), 101,
     False, F, "no-feed-binding", "r9-2: preclusion of a linked case"),
    ("precluded-wrong-receipt", log_for(edited(PR, lambda r: r["terminal"]
                                               .update(receipt=S1_RECEIPT
                                                       + " ok"))), 101,
     False, F, "no-feed-binding", "r7: receipt mismatch"),
    ("precluded-cause-unattributed", log_for(edited(PR, lambda r: r[
        "terminal"].update(cause="no-feeds-unattributed",
                           receipt=UNATTRIBUTED_RECEIPT))), 101, False, F,
     "no-feed-binding", "r2-r6: S1 vs unattributed"),
    ("precluded-unattributed-case", log_for(edited(no_feed_record(
        0, "no-feeds-unattributed"), lambda r: r["terminal"].update(
            kind="precluded"))), 101, False, F, "precluded-binding",
     "r2-r6: unattributed claimed environmental"),
    ("precluded-after-linked", log_for(edited(no_feed_record(1), lambda r:
                                              r["terminal"].update(
                                                  kind="precluded"))), 101,
     False, F, "precluded-binding", "r9-2: evidence before the preclusion"),
    ("no-feed-for-first-s1", log_for(edited(PR, lambda r: r["terminal"]
                                            .update(kind="no-feed"))), 101,
     False, F, "precluded-binding", "derived"),
    ("no-feed-on-wedged-case", log_for(edited(WR, lambda r: r.update(
        terminal={"kind": "no-feed", "case": 5, "cause": "s1-precluded",
                  "receipt": S1_RECEIPT}))), 101, False, F,
     "no-feed-binding", "r8: wedge before S1 mix"),

    ("no-feed-without-probe", log_for(edited(no_feed_record(
        4, "no-feeds-unattributed"), case_set(4, no_feed=None))), 101, False,
     F, "no-feed-probe", "live r10: a no-feed refusal names its evidence"),
    ("probe-on-linked-case", log_for(edited(QR, case_set(
        2, no_feed=no_feed_probe()))), 0, False, F, "no-feed-probe",
     "derived"),
    ("probe-bad-gap-count", log_for(edited(no_feed_record(
        4, "no-feeds-unattributed"), lambda r: r["cases"][4]["no_feed"][
            "gaps"][0].update(count="1"))), 101, False, F, "record-schema",
     "derived"),
    ("probe-extra-field", log_for(edited(PR, lambda r: r["cases"][0][
        "no_feed"].update(pid=7))), 101, False, F, "record-schema",
     "derived"),

    # --- join bound and typed starvation (seal r9 item 2) ------------
    ("receipt-starved-case2", log_for(no_feed_record(
        2, "no-feeds-receipt-starved")), 101, False, F,
     "no-feed-receipt-starved", "seal r9: stop2 starvation is named, "
     "never accepted"),
    ("calls-shed-case0", log_for(no_feed_record(
        0, "no-feeds-calls-shed")), 101, False, F, "no-feed-calls-shed",
     "live r12: shed fixture calls are a named cause, never accepted"),
    ("unattributed-hiding-shed", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), lambda r: r["cases"][2][
            "no_feed"].update(shed=17))), 101, False, F, "no-feed-cause",
     "live r12: a typed cause is never unattributed"),
    ("shed-without-shed", log_for(edited(no_feed_record(
        0, "no-feeds-calls-shed"), lambda r: r["cases"][0][
            "no_feed"].update(shed=0))), 101, False, F, "no-feed-cause",
     "derived"),
    ("shed-hiding-starvation", log_for(edited(no_feed_record(
        0, "no-feeds-calls-shed"), lambda r: r["cases"][0][
            "no_feed"].update(partition=1))), 101, False, F,
     "no-feed-cause", "derived: starvation outranks shed"),
    ("shed-before-the-bound", log_for(edited(no_feed_record(
        0, "no-feeds-calls-shed"), case_set(0, join_quanta=1,
                                            join_passes=0))), 101, False, F,
     "join-bound", "live r12"),
    ("receipt-starved-case0", log_for(no_feed_record(
        0, "no-feeds-receipt-starved")), 101, False, F,
     "no-feed-receipt-starved", "seal r9: never environmental"),
    ("starved-without-discovery-passes", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), case_set(2, join_passes=0))), 101,
     False, F, "join-bound", "seal r9 correction: a deferred or refused "
     "receipt retries only on a discovery pass"),
    ("unattributed-one-pass-short", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), case_set(2, join_passes=3))), 101,
     False, F, "join-bound", "seal r9 correction"),
    ("linked-pass-before-first-quantum", log_for(edited(QR, case_set(
        3, join_quanta=1, join_passes=1)), ok=True), 0, False, F,
     "join-bound", "derived"),
    ("linked-joined-after-a-pass", log_for(edited(QR, case_set(
        3, join_quanta=2, join_passes=1)), ok=True), 0, False, Q,
     "full-matrix", "control: one pass then a quantum"),
    ("passes-on-unlinked-setup", log_for(edited(case_failed_record(
        6, "setup"), case_set(6, join_passes=0))), 101, False, F,
     "join-bound", "mutation sweep: passes without a join"),
    ("probe-shed-not-an-int", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), lambda r: r["cases"][2][
            "no_feed"].update(shed="18"))), 101, False, F, "record-schema",
     "mutation sweep"),
    ("linked-missing-passes", log_for(edited(QR, case_set(
        3, join_passes=None)), ok=True), 0, False, F, "join-bound",
     "derived"),
    ("unattributed-after-one-quantum", log_for(edited(no_feed_record(
        0, "no-feeds-unattributed"), case_set(0, join_quanta=1))), 101,
     False, F, "join-bound", "seal r9: stop0/stop1 judged after one "
     "quantum"),
    ("unattributed-without-join", log_for(edited(no_feed_record(
        1, "no-feeds-unattributed"), case_set(1, join_quanta=0))), 101,
     False, F, "join-bound", "seal r9: stop0/stop1 judged after one "
     "quantum"),
    ("starved-before-the-bound", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), case_set(
            2, join_quanta=JOIN_QUANTA - 1, join_passes=4))), 101, False, F,
     "join-bound",
     "derived"),
    ("linked-past-the-bound", log_for(edited(QR, case_set(
        3, join_quanta=JOIN_QUANTA + 1, join_passes=4)), ok=True), 0, False,
     F,
     "join-bound", "derived"),
    ("join-on-unlinked-setup", log_for(edited(case_failed_record(
        6, "setup"), case_set(6, join_quanta=0))), 101, False, F,
     "join-bound", "derived"),
    ("linked-missing-join", log_for(edited(QR, case_set(
        3, join_quanta=None)), ok=True), 0, False, F, "join-bound",
     "derived"),
    ("join-not-an-int", log_for(edited(QR, case_set(
        3, join_quanta="1")), ok=True), 0, False, F, "record-schema",
     "derived"),
    ("unattributed-hiding-starvation", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), lambda r: r["cases"][2][
            "no_feed"].update(partition=1))), 101, False, F,
     "no-feed-cause", "seal r9: a typed cause is never unattributed"),
    ("unattributed-hiding-no-receipt", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), lambda r: r["cases"][2][
            "no_feed"].update(no_receipt=4))), 101, False, F,
     "no-feed-cause", "seal r9: a typed cause is never unattributed"),
    ("starved-without-cause", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), lambda r: r["cases"][2][
            "no_feed"].update(no_receipt=0, partition=0))), 101, False, F,
     "no-feed-cause", "derived"),
    ("probe-missing-shed", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), lambda r: r["cases"][2][
            "no_feed"].pop("shed"))), 101, False, F, "record-schema",
     "derived"),
    # --- bounded join arithmetic (tier-1 r12 F1) ---------------------
    ("linked-join-huge", log_for(edited(QR, case_set(
        3, join_quanta=10 ** 12)), ok=True), 0, False, F, "join-bound",
     "r12 F1: a schema-valid huge join is refused before any loop"),
    ("linked-join-u64-max", log_for(edited(QR, case_set(
        3, join_quanta=2 ** 64 - 1, join_passes=2 ** 64 - 1)), ok=True), 0,
     False, F, "join-bound", "r12 F1"),
    # --- feeds that installed, then fell back (tier-1 r12 F2) --------
    ("fell-back-case1", log_for(no_feed_record(1, "no-feeds-fell-back")),
     101, False, F, "no-feed-fell-back",
     "r12 F2: install-then-fallback is a named cause, never accepted"),
    ("fell-back-at-the-bound", log_for(edited(no_feed_record(
        1, "no-feeds-fell-back"), case_set(
            1, join_quanta=JOIN_QUANTA, join_passes=4, join_feeds=1))), 101,
     False, F, "no-feed-fell-back",
     "control: feeds on the last join quantum that fell back"),
    ("fell-back-without-feeds", log_for(edited(no_feed_record(
        1, "no-feeds-fell-back"), case_set(1, join_feeds=0))), 101, False,
     F, "join-bound", "r12 F2: an early join end needs a feed"),
    ("fell-back-spent-without-feeds", log_for(edited(no_feed_record(
        1, "no-feeds-fell-back"), case_set(
            1, join_quanta=JOIN_QUANTA, join_passes=4, join_feeds=0))), 101,
     False, F, "no-feed-cause", "r12 F2: fell-back needs the join's feeds"),
    ("unattributed-hiding-fallback", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), case_set(2, join_feeds=2))), 101, False,
     F, "join-bound", "r12 F2: feeds at the join's end are fell-back"),
    ("starved-hiding-fallback", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), case_set(2, join_feeds=1))), 101,
     False, F, "join-bound", "r12 F2"),
    ("linked-early-without-feeds", log_for(edited(QR, case_set(
        3, join_feeds=0)), ok=True), 0, False, F, "join-bound",
     "r12 F2: a join ends early only on a feed or an S1 latch"),
    ("linked-spent-without-feeds", log_for(edited(QR, case_set(
        3, join_quanta=JOIN_QUANTA, join_passes=4, join_feeds=0)), ok=True),
     0, False, Q, "full-matrix",
     "control: feeds that arrived after the join bound"),
    ("linked-missing-feeds", log_for(edited(QR, case_set(
        3, join_feeds=None)), ok=True), 0, False, F, "join-bound",
     "derived"),
    ("feeds-on-unlinked-setup", log_for(edited(case_failed_record(
        6, "setup"), case_set(6, join_feeds=0))), 101, False, F,
     "join-bound", "derived"),
    ("join-feeds-not-an-int", log_for(edited(QR, case_set(
        3, join_feeds="1")), ok=True), 0, False, F, "record-schema",
     "derived"),
    ("probe-missing-fallback", log_for(edited(no_feed_record(
        1, "no-feeds-fell-back"), lambda r: r["cases"][1][
            "no_feed"].pop("fallback"))), 101, False, F, "record-schema",
     "derived"),
    ("probe-fallback-not-an-int", log_for(edited(no_feed_record(
        1, "no-feeds-fell-back"), lambda r: r["cases"][1][
            "no_feed"].update(fallback="2"))), 101, False, F, "record-schema",
     "mutation sweep"),
    # --- shed bound to its proof (tier-1 r12 GLM 1) ------------------
    ("unattributed-with-foreign-shed", log_for(edited(no_feed_record(
        2, "no-feeds-unattributed"), lambda r: r["cases"][2][
            "no_feed"].update(foreign_shed=5))), 101, False, F,
     "no-feed-unattributed",
     "r12 GLM 1: proven-foreign shed names no fixture cause"),
    ("calls-shed-from-foreign-only", log_for(edited(no_feed_record(
        0, "no-feeds-calls-shed"), lambda r: r["cases"][0][
            "no_feed"].update(shed=0, foreign_shed=17))), 101, False, F,
     "no-feed-cause", "r12 GLM 1: foreign shed is never calls-shed"),
    ("probe-foreign-shed-not-an-int", log_for(edited(no_feed_record(
        2, "no-feeds-receipt-starved"), lambda r: r["cases"][2][
            "no_feed"].update(foreign_shed="1"))), 101, False, F,
     "record-schema", "derived"),

    # --- wedge ------------------------------------------------------------
    ("wedge-describing-success", log_for(edited(WR, case_set(
        5, outcome=healthy_outcome(offset_of(5))))), 101, True, F,
     "completion", "r8/r9-3: a success-describing wedge"),
    ("wedge-after-at-q-failure", log_for(edited(WR, outcome_set(
        5, api_a=1))), 101, True, F, "wedge-binding",
     "r9-3: a wedge the Rust check order cannot emit"),
    ("wedge-after-latch-failure", log_for(edited(WR, outcome_set(
        5, latched=True))), 101, True, F, "wedge-binding",
     "r9-3: a wedge the Rust check order cannot emit"),
    ("wedge-without-outcome", log_for(edited(WR, case_set(
        5, outcome=None))), 101, True, F, "wedge-binding",
     "r9-3: a wedge with no stop record"),
    ("wedge-on-no-feed-case", log_for(edited(WR, case_set(
        5, branch="s1-precluded", outcome=None,
        no_feed=no_feed_probe("s1-precluded")))), 101, True, F,
     "wedge-binding", "r8: wedge before S1 mix"),
    ("wedge-reconcile-only", log_for(edited(WR, outcome_set(
        5, finish="published", wound="joined", taken=True,
        reconciled=False))), 101, True, F, "wedge-binding",
     "r9-3: a reconciliation failure claimed as a wedge"),

    # --- case-failed binding ----------------------------------------------
    ("case-failed-wrong-check", log_for(edited(case_failed_record(3),
                                               lambda r: r["terminal"]
                                               .update(check="at-q"))), 101,
     False, F, "case-failed-binding", "derived"),
    ("case-failed-hiding-a-wedge", log_for(edited(WR, lambda r: r.update(
        terminal={"kind": "case-failed", "case": 5, "stage": "check",
                  "check": "terminal", "error": "x"}))), 101, False, F,
     "case-failed-binding", "derived"),
    ("case-failed-setup-on-linked", log_for(edited(case_failed_record(
        2, "drive"), lambda r: r["terminal"].update(stage="setup"))), 101,
     False, F, "case-failed-binding", "derived"),
    ("case-failed-drive-with-outcome", log_for(edited(case_failed_record(3),
                                                      lambda r: r[
                                                          "terminal"].update(
                                                          stage="drive",
                                                          check=None))),
     101, False, F, "case-failed-binding", "derived"),
    ("case-failed-check-before-cases", log_for(edited(case_failed_record(
        None, "setup", error="x"), lambda r: r["terminal"].update(
            stage="check", check="at-q"))), 101, False, F,
     "case-failed-binding", "derived"),
    ("narrowed-on-full-selection", log_for(edited(QR, lambda r: r.update(
        terminal={"kind": "narrowed"})), ok=True), 0, False, F,
     "terminal-status", "derived"),
    ("narrowed-on-exit-101", log_for(edited(QR, lambda r: r.update(
        terminal={"kind": "narrowed"})), ok=False), 101, False, F,
     "narrowed", "derived"),
]


class JointStopVerdictTableTests(unittest.TestCase):
    def run_row(self, row, disabled=frozenset()):
        _, log, status, expect, _, _, _ = row
        return jv.classify(log, status, CELL, expect_wedge=expect,
                           disabled=disabled)

    def test_row_ids_are_unique(self):
        ids = [row[0] for row in ROWS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_row_has_its_exact_verdict(self):
        for row in ROWS:
            with self.subTest(row=row[0]):
                got = self.run_row(row)
                self.assertEqual((got["qualification"], got["reason"]),
                                 (row[4], row[5]), got["detail"])

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
        # Sole-guard checks: disabling each lets some refused row through
        # as an acceptance, so the table holds the input each gate exists
        # to stop. The other checks are layered behind a later check.
        accepts = {Q, X, P}
        for name in SOLE_GUARDS:
            with self.subTest(check=name):
                opened = [row[0] for row in ROWS
                          if row[4] == F and row[5] == name
                          and self.run_row(row, frozenset([name]))[
                              "qualification"] in accepts]
                self.assertTrue(opened, "no row of %s becomes an "
                                "acceptance when it is disabled" % name)

    def test_validator_mirrors_the_rust_record(self):
        # The record's producer is the Rust ledger; pin the literals the
        # validator relies on in its source, so a drift fails here.
        rust = (ROOT / "src/inventory/joint_stop_races_privileged_tests.rs"
                ).read_text(encoding="utf-8")
        for literal in (
                'const STOP_VERDICT_MARKER: &str = "%s";' % jv.MARKER,
                'const STOP_VERDICT_SCHEMA: &str = "%s";' % jv.SCHEMA,
                'const STOP_OFFSETS_MS: [u64; 4] = [0, 1, 5, 20];',
                'const STOP_PREPS: [Prep; 3] = [',
                'let index = prep_index * STOP_OFFSETS_MS.len() + offset_index;',
                'name: format!("wp7-stop{index}"),',
                'prep: index / STOP_OFFSETS_MS.len(),',
                '#[serde(tag = "kind", rename_all = "kebab-case")]',
                'JointBranch::S1 => Some("s1-precluded"),',
                'JointBranch::FellBack => Some("no-feeds-fell-back"),',
                'JointBranch::FellBack => "fell-back",',
                'join.feeds = coordinator.registry().joint_feeds() as u64;',
                'let held = caller_of(&coordinator, process_a.pid())?;',
                'case.note_no_feed(no_feed_probe(&lane, &coordinator, held));',
                'subject == crate::inventory_present::JOINT_RETAINED_S1_SUBJECT',
                'reason.starts_with("joint_fallback_")',
                'unproven: lane_shed.saturating_sub(foreign),',
                'lane_shed_split_from(lane_shed, coordinator.registry()'
                '.foreign_unrouted_calls())',
                'JointBranch::Unattributed => Some("no-feeds-unattributed"),',
                'JointBranch::ReceiptStarved => Some("no-feeds-receipt-starved"),',
                'JointBranch::ReceiptStarved => "receipt-starved",',
                'JointBranch::CallsShed => Some("no-feeds-calls-shed"),',
                'JointBranch::CallsShed => "calls-shed",',
                'let branch = joint_branch(&coordinator, '
                'lane.shed_calls_disclosed(), held, &join);\n'
                '    case.link(&branch, join);',
                'const STOP_JOIN_QUANTA: u64 = %d;' % jv.JOIN_QUANTA,
                'const STOP_JOIN_PASS_EVERY: u64 = %d;' % jv.JOIN_PASS_EVERY,
                'quanta % STOP_JOIN_PASS_EVERY == 1',
                'let branch = match joint_branch(driver.coordinator, '
                'lane_shed, caller_a, &join) {',
                '("semantic admission deferred", '
                '"semantic_unavailable:no_receipt")\n'
                '                if caller.as_ref() == Some(&held) =>',
                '("semantic receipt refused", "partition") if '
                'caller.is_none() => {',
                'stage: "setup",', 'stage: "drive",', 'stage: "check",',
                '(StopCheck::AtQ, check_stop_at_q),',
                '(StopCheck::Latch, check_stop_latch),',
                '(StopCheck::Abandon, check_stop_abandon),',
                '(StopCheck::Terminal, check_stop_terminal),',
                '(StopCheck::Reconcile, check_stop_reconcile),',
                S1_RECEIPT, UNATTRIBUTED_RECEIPT):
            with self.subTest(literal=literal):
                self.assertIn(literal, rust)
        self.assertEqual(jv.NO_FEED, {"s1-precluded": S1_RECEIPT,
                                      "no-feeds-fell-back":
                                          FELL_BACK_RECEIPT,
                                      "no-feeds-receipt-starved":
                                          STARVED_RECEIPT,
                                      "no-feeds-calls-shed": SHED_RECEIPT,
                                      "no-feeds-unattributed":
                                          UNATTRIBUTED_RECEIPT})
        self.assertEqual(JOIN_QUANTA, jv.JOIN_QUANTA)
        # A Rust string continuation (backslash, newline, indentation)
        # joins its lines with nothing.
        self.assertIn(STARVED_RECEIPT, re.sub(r"\\\n\s*", "", rust))
        self.assertIn(SHED_RECEIPT, re.sub(r"\\\n\s*", "", rust))
        self.assertIn(FELL_BACK_RECEIPT, re.sub(r"\\\n\s*", "", rust))
        case = rust.split("struct StopCaseRecord {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(
            sorted(re.findall(r"^    (\w+):", case, re.M)) ,
            sorted(list(jv.CASE_FIELDS) + ["failed_check"]))
        self.assertEqual(jv.OFFSETS_MS, (0, 1, 5, 20))
        self.assertEqual(jv.CASES, 3 * 4)
        self.assertEqual(sorted(jv.OUTCOME_FIELDS),
                         sorted(QR["cases"][0]["outcome"]))
        probe = rust.split("struct NoFeedProbe {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(sorted(re.findall(r"^    (\w+):", probe, re.M)),
                         sorted(jv.PROBE_FIELDS))
        gap = rust.split("struct NoFeedGap {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(sorted(re.findall(r"^    (\w+):", gap, re.M)),
                         sorted(jv.GAP_FIELDS))

    def test_stop_check_mirror_matches_the_rust_twins(self):
        # The cases of the Rust twin
        # stop_check_failure_names_the_first_failing_check.
        def failing(**fields):
            outcome = healthy_outcome(5)
            outcome.update(fields)
            return jv.first_failing_check(outcome)
        self.assertIsNone(failing())
        self.assertEqual(failing(api_a=1, finish="unpublished"), "at-q")
        self.assertEqual(failing(first_error="boom"), "latch")
        self.assertEqual(failing(abandon_gap="for lane stop: x"), "abandon")
        self.assertEqual(failing(wound="unwound"), "terminal")
        self.assertEqual(failing(reconciled=False), "reconcile")
        self.assertIsNone(failing(api_a=1, lane_shed=1))

    def test_shed_detail_names_the_typed_cause(self):
        got = jv.classify(log_for(no_feed_record(0, "no-feeds-calls-shed")),
                          101, CELL)
        self.assertEqual(got["reason"], "no-feed-calls-shed")
        self.assertIn("shed=17 foreign_shed=0 after %d join quanta and 4 "
                      "discovery passes" % JOIN_QUANTA, got["detail"])
        self.assertNotIn("unexplained", got["detail"])

    def test_starved_detail_names_the_typed_cause(self):
        got = jv.classify(log_for(no_feed_record(
            2, "no-feeds-receipt-starved")), 101, CELL)
        self.assertEqual(got["qualification"], "failed")
        self.assertEqual(got["reason"], "no-feed-receipt-starved")
        self.assertIn("no_receipt=2 partition=1 shed=18 after %d join "
                      "quanta and 4 discovery passes" % JOIN_QUANTA,
                      got["detail"])
        self.assertEqual([jv.join_passes_for(n) for n in (0, 1, 2, 9, 10, 32)],
                         [0, 0, 1, 1, 2, 4])
        self.assertEqual(
            [jv.join_passes_for(n) for n in range(JOIN_QUANTA + 1)],
            [sum(1 for q in range(n) if q % jv.JOIN_PASS_EVERY == 1)
             for n in range(JOIN_QUANTA + 1)],
            "the closed form equals the schedule over the whole bound")
        self.assertIsNone(jv.join_passes_for(JOIN_QUANTA + 1))
        self.assertNotIn("unexplained", got["detail"])

    def test_fell_back_detail_names_the_typed_cause(self):
        got = jv.classify(log_for(no_feed_record(1, "no-feeds-fell-back")),
                          101, CELL)
        self.assertEqual(got["reason"], "no-feed-fell-back")
        self.assertIn("fallback=2 after 3 join quanta and 1 discovery passes "
                      "ending with 2 feeds", got["detail"])
        self.assertIn("joint_fallback_unsealable x2", got["detail"])

    def test_huge_join_is_refused_in_bounded_time(self):
        # r12 F1: the old scan took minutes on a 10**12 join; the bound
        # is checked first and the schedule is closed form.
        import time
        for join in (10 ** 12, 10 ** 19, 2 ** 64 - 1):
            with self.subTest(join=join):
                started = time.monotonic()
                got = jv.classify(log_for(edited(QR, case_set(
                    3, join_quanta=join)), ok=True), 0, CELL)
                self.assertLess(time.monotonic() - started, 2.0)
                self.assertEqual(got["reason"], "join-bound")

    def test_no_feed_detail_names_the_sampled_evidence(self):
        got = jv.classify(log_for(no_feed_record(4, "no-feeds-unattributed")),
                          101, CELL)
        self.assertEqual(got["reason"], "no-feed-unattributed")
        self.assertIn("joint_birth_original_mismatch x1", got["detail"])
        self.assertIn("feeds=0 linked=True", got["detail"])

    def test_unknown_disabled_check_is_refused(self):
        with self.assertRaises(ValueError):
            jv.classify(passing(), 0, CELL, disabled=frozenset(["nope"]))

    def test_cli_prints_the_row_verdict(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "joint-cell.log"
            for log, status, expect, want in (
                    (passing(), 0, "0", Q), (precluded(), 101, "0", P),
                    (wedged(), 101, "1", X), (precluded(), 137, "0", F),
                    (summary_with("test result: ok. " + "1" * 4301
                                  + " passed; 0 failed; 0 ignored; 0 "
                                  "measured; 0 filtered out; finished in "
                                  "1.00s"), 0, "0", F)):
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


SOLE_GUARDS = (
    "summary-not-terminal", "summary-counts",
    "summary-duplicate", "record-duplicate", "record-misplaced",
    "record-cell", "case-sequence", "join-bound",
    "case-outcome", "completion", "terminal-status", "terminal-case",
    "qualified-count", "unexpected-pass", "precluded-binding",
    "no-feed-binding", "wedge-binding", "wedge-unexpected",
)

if __name__ == "__main__":
    unittest.main()
