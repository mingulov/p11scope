#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Fail-closed qualification of the Joint linked-stop matrix cell.

One validator for both qualifying entries (the S3 suite,
scripts/ci/stop-races.sh, and the long campaign runner,
scripts/run-privileged-lib-tests.sh). The Rust cell
(src/inventory/joint_stop_races_privileged_tests.rs) owns its verdict:
on every return path it prints exactly one line

  P11SCOPE_STOP_VERDICT=<json>

built from its own case ledger, never from log text. This validator
reads only three things: the child's exit status as the shell saw it
(128+N for a signal), the strict libtest summary, and that one record.
No other log line is interpreted; free text can neither qualify nor
disqualify a run, so diagnostics placed anywhere cannot forge evidence.

Record schema (p11scope.joint-stop-verdict/1; exact keys, exact JSON
types, no floats, no duplicate keys):

  {"schema": "p11scope.joint-stop-verdict/1", "cell": NAME,
   "selection": null | {"preps": [int], "offsets": [int]},
   "cases": [{"name": "wp7-stopK", "index": K, "prep": K // 4,
              "offset_ms": (0, 1, 5, 20)[K % 4],
              "branch": null | "linked" | "s1-precluded"
                        | "no-feeds-receipt-starved"
                        | "no-feeds-unattributed",
              "join_quanta": null | int, "join_passes": null | int,
              "outcome": null | OUTCOME,
              "no_feed": null | {"joint_feeds": int, "journal_linked": bool,
                                 "backstop_routed": int,
                                 "birth_capacity": null | TEXT,
                                 "drive": TEXT,
                                 "gaps": [{"subject": TEXT, "reason": TEXT,
                                           "count": int}],
                                 "no_receipt": int, "partition": int,
                                 "shed": int},
              "completed": bool}],
   "terminal": {"kind": "qualified"} | {"kind": "narrowed"}
             | {"kind": "precluded" | "no-feed", "case": K,
                "cause": TAG, "receipt": TEXT}
             | {"kind": "wedge", "case": K}
             | {"kind": "case-failed", "case": K | null,
                "stage": "setup" | "drive" | "check",
                "check": null | CHECK, "error": TEXT}}

join_quanta is how many quanta the cell serviced after q1, with the
call still held, before its linkage decision (null exactly before a
linkage). It never exceeds JOIN_QUANTA (the cell's STOP_JOIN_QUANTA),
and a linked no-feed branch (receipt-starved or unattributed) must
have spent all of it: one quantum is never a no-feed verdict.
join_passes counts the discovery passes the join ran (a deferred or
refused receipt is retried only on a pass); it must equal the
schedule's count for join_quanta (a pass before every quantum q with
q % JOIN_PASS_EVERY == 1, so 4 over the full bound). A
linked no-feed case is receipt-starved exactly when its probe counts a
`no_receipt` deferral or a `partition` receipt refusal; that cause is
named but never accepted.

OUTCOME is the StopOutcome struct field for field. The validator
recomputes the cell's stop checks (at-q, latch, abandon, terminal,
reconcile, in the Rust order) from each outcome, so a record can only
claim what its own data shows: a completed case passes every check, a
wedge fails first at the terminal check, a check failure names the
first failing check.

Qualification is one of:
  qualified             exit 0, a `1 passed` summary, a full selection
                        and all twelve cases completed in order;
  environment-precluded exit 101, a `1 failed` summary, and only case 0,
                        unlinked and undriven, with the S1 receipt;
  expected-failure      (only with --expect-wedge 1) exit 101 and a wedge
                        terminal on the last opened case;
  failed                everything else, with a named reason (the
                        fail-closed default is `case-failed`).

Each check has a name (the reason it reports); the table-driven suite
tests/python/test_joint_stop_verdict.py disables each check in turn
and requires some row to turn red.

Usage:
  python3 -I scripts/ci/joint_stop_verdict.py --cell NAME --status RC
      [--expect-wedge 0|1] [--format json|lines] LOG
Exit 0 after printing the verdict (json: one object; lines:
qualification, reason, result line, detail); 2 on a usage or read
error.
"""

import argparse
import json
import re
import sys

SCHEMA = "p11scope.joint-stop-verdict/1"
MARKER = "P11SCOPE_STOP_VERDICT="
PREPS = 3
OFFSETS_MS = (0, 1, 5, 20)
CASES = PREPS * len(OFFSETS_MS)
COUNT = r"(0|[1-9][0-9]{0,19})"
SUMMARY_RE = re.compile(
    r"test result: (ok|FAILED)\. " + COUNT + r" passed; " + COUNT
    + r" failed; " + COUNT + r" ignored; " + COUNT + r" measured; "
    + COUNT + r" filtered out; finished in [0-9]{1,10}\.[0-9]{2}s")
NO_FEED = {
    "s1-precluded":
        "no joint feeds with S1 seal (producers unlinked, zero installs)",
    "no-feeds-receipt-starved":
        "no joint feeds from the linked session: the held caller's birth "
        "receipt was deferred (no_receipt) or refused (partition) and no "
        "later birth bound",
    "no-feeds-unattributed":
        "no joint feeds without S1 seal (producers linked, zero installs "
        "unexplained)",
}
LINKED_NO_FEED = ("no-feeds-receipt-starved", "no-feeds-unattributed")
JOIN_QUANTA = 32
JOIN_PASS_EVERY = 8


def join_passes_for(quanta):
    """Discovery passes the cell's join schedule runs over `quanta`."""
    return sum(1 for q in range(quanta) if q % JOIN_PASS_EVERY == 1)
BRANCHES = ("linked",) + tuple(NO_FEED)
STOP_CHECKS = ("at-q", "latch", "abandon", "terminal", "reconcile")
STAGES = ("setup", "drive", "check")
BEGINS = ("polling", "published-at-begin", "abandoned-at-begin", "not-begun")
FINISHES = ("published", "abandoned", "not-begun", "unpublished")
OUTCOME_BRANCHES = ("linked", "s1", "receipt-starved", "unattributed")
U64_MAX = 2 ** 64 - 1

# Every check the validator applies, by the reason it reports. The
# table suite disables each in turn (mutation proof).
CHECKS = (
    "exit-status", "summary-missing", "summary-duplicate",
    "summary-malformed", "summary-not-terminal", "summary-counts",
    "summary-status", "record-missing", "record-duplicate",
    "record-misplaced", "record-json", "record-schema", "record-cell",
    "selection", "case-sequence", "case-branch", "case-outcome",
    "no-feed-probe", "join-bound", "no-feed-cause",
    "completion", "terminal-status", "terminal-case", "qualified-count",
    "unexpected-pass",
    "precluded-binding", "no-feed-binding", "s1-after-linked",
    "no-feed-receipt-starved", "no-feed-unattributed", "wedge-binding", "wedge-unexpected",
    "case-failed-binding", "narrowed",
)


class Refusal(Exception):
    def __init__(self, reason, detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class Malformed(Exception):
    """A schema or JSON violation, with its path."""


def verdict(qualification, reason, detail, result_line=""):
    return {"qualification": qualification, "reason": reason,
            "detail": detail, "result_line": result_line}


def classify(text, status, cell, expect_wedge=False, disabled=frozenset()):
    """Classify one joint cell log; never raises for log content."""
    unknown = set(disabled) - set(CHECKS)
    if unknown:
        raise ValueError("unknown checks: %s" % sorted(unknown))
    state = {"result_line": ""}
    try:
        return _classify(text, status, cell, expect_wedge, disabled, state)
    except Refusal as refusal:
        return verdict("failed", refusal.reason, refusal.detail,
                       state["result_line"])
    except (KeyError, IndexError, TypeError) as error:
        # Reachable only with checks disabled (the mutation proof):
        # an unvalidated record still never qualifies.
        return verdict("failed", "case-failed",
                       "unjudgeable record: %r" % (error,),
                       state["result_line"])


def first_failing_check(outcome):
    """The Rust cell's stop checks in order (stop_check_failure)."""
    o = outcome
    if not (o["api_a"] == o["a_semantic"]
            or (o["reconciled"] and o["lane_shed"] > 0)):
        return "at-q"
    if o["latched"]:
        code, gap, error = o["latch_code"], o["abandon_gap"], o["first_error"]
        if code is None or gap is None or code not in gap \
                or error is None or code not in error:
            return "latch"
    elif o["first_error"] is not None:
        return "latch"
    abandoned = "abandoned" in o["finish"] or "abandoned" in o["begin"]
    if abandoned and o["stash_floor"] is not None:
        if not (o["api_a"] == o["a_semantic"]
                or o["abandon_gap"] is not None):
            return "abandon"
    elif o["abandon_gap"] is not None:
        return "abandon"
    if not reached_wound_down(o):
        return "terminal"
    if not o["reconciled"]:
        return "reconcile"
    return None


def reached_wound_down(outcome):
    return (outcome["finish"] == "published" and outcome["wound"] == "joined"
            and outcome["taken"] is True)


def _classify(text, status, cell, expect_wedge, disabled, state):
    def check(name, ok, detail):
        if not ok and name not in disabled:
            raise Refusal(name, detail)

    check("exit-status", status in (0, 101),
          "joint cell exit status %s is neither a libtest pass (0) nor a "
          "libtest failure (101): a signal, abort or harness error"
          % status)
    lines = text.split("\n")

    # The libtest summary: exactly one, full-line, terminal, one test.
    summaries = [i for i, line in enumerate(lines) if "test result:" in line]
    check("summary-missing", bool(summaries),
          "no libtest summary (unfinished transcript)")
    check("summary-duplicate", len(summaries) <= 1,
          "%d libtest summaries; exactly one terminal summary is valid"
          % len(summaries))
    at = summaries[-1] if summaries else len(lines)
    summary = lines[at] if summaries else ""
    state["result_line"] = summary
    match = SUMMARY_RE.fullmatch(summary)
    check("summary-malformed", match is not None,
          "malformed libtest summary: %r" % summary[:200])
    check("summary-not-terminal",
          all(line == "" for line in lines[at + 1:]),
          "output follows the libtest summary")
    passed = match is not None and match.group(1) == "ok"
    counts = tuple(int(group) for group in match.groups()[1:5]) \
        if match else None
    check("summary-counts",
          counts in ((1, 0, 0, 0), (0, 1, 0, 0))
          and (counts == (1, 0, 0, 0)) == passed,
          "the summary does not report exactly one run test: %r"
          % summary[:200])
    check("summary-status", passed == (status == 0),
          "summary %r disagrees with exit status %s" % (summary[:80], status))

    # The record: exactly one line carrying the marker, at its start.
    carrying = [line for line in lines if MARKER in line]
    check("record-missing", bool(carrying),
          "no verdict record (the cell panicked, was killed, or is not "
          "the record-emitting build)")
    check("record-duplicate", len(carrying) <= 1,
          "%d verdict records; the cell prints exactly one"
          % len(carrying))
    line = carrying[-1] if carrying else MARKER + "null"
    check("record-misplaced", line.startswith(MARKER),
          "the verdict marker does not open its line: %r" % line[:200])
    try:
        record = _parse(line[line.index(MARKER) + len(MARKER):])
    except Malformed as error:
        check("record-json", False, "the verdict record is not strict "
              "JSON: %s" % error)
        record = None
    try:
        _validate_schema(record)
    except Malformed as error:
        check("record-schema", False,
              "the verdict record breaks the schema: %s" % error)
        raise Refusal("case-failed", "unreadable record (schema checks "
                      "disabled)")
    check("record-cell", record["cell"] == cell,
          "the record names cell %r, not %r" % (record["cell"][:200], cell))
    result = _judge(record, status, expect_wedge, check)
    result["result_line"] = summary
    return result


def _judge(record, status, expect_wedge, check):
    selection = record["selection"]
    check("selection",
          selection == {"preps": list(range(PREPS)),
                        "offsets": list(range(len(OFFSETS_MS)))},
          "the run's selection is not the full matrix: %r" % (selection,))
    cases = record["cases"]
    terminal = record["terminal"]
    kind = terminal["kind"]
    check("case-sequence", len(cases) <= CASES and all(
        case["index"] == k and case["name"] == "wp7-stop%d" % k
        and case["prep"] == k // len(OFFSETS_MS)
        and case["offset_ms"] == OFFSETS_MS[k % len(OFFSETS_MS)]
        for k, case in enumerate(cases)),
        "the cases are not the matrix in order (index, name, prep, "
        "offset)")
    last = len(cases) - 1
    for k, case in enumerate(cases):
        check("case-branch",
              case["branch"] == "linked" or k == last,
              "wp7-stop%d: an unlinked branch %r before the last opened "
              "case" % (k, case["branch"]))
        outcome = case["outcome"]
        check("case-outcome",
              (outcome is None or (case["branch"] == "linked"
                                   and outcome["offset_ms"]
                                   == case["offset_ms"]))
              and (outcome is not None or k == last),
              "wp7-stop%d: an outcome on an unlinked case, from another "
              "offset, or missing before the last opened case" % k)
        check("no-feed-probe",
              (case["no_feed"] is not None) == (case["branch"] in NO_FEED),
              "wp7-stop%d: a no-feed probe on branch %r (the cell samples "
              "one exactly on a no-feed case)" % (k, case["branch"]))
        join = case["join_quanta"]
        passes = case["join_passes"]
        check("join-bound",
              (join is None) == (case["branch"] is None)
              and (passes is None) == (join is None)
              and (join is None or passes == join_passes_for(join))
              and (join is None or join <= JOIN_QUANTA)
              and (case["branch"] not in LINKED_NO_FEED
                   or join == JOIN_QUANTA),
              "wp7-stop%d: join_quanta %r with %r passes on branch %r (at "
              "most %d, with the scheduled passes; a linked no-feed verdict "
              "spends all %d)"
              % (k, join, passes, case["branch"], JOIN_QUANTA, JOIN_QUANTA))
        probe = case["no_feed"]
        if case["branch"] in LINKED_NO_FEED and probe is not None:
            starved = probe["no_receipt"] + probe["partition"] > 0
            check("no-feed-cause",
                  (case["branch"] == "no-feeds-receipt-starved") == starved,
                  "wp7-stop%d: branch %r contradicts its typed cause "
                  "(no_receipt=%d partition=%d)"
                  % (k, case["branch"], probe["no_receipt"],
                     probe["partition"]))
        failing = first_failing_check(outcome) if outcome else "absent"
        check("completion",
              case["completed"] == (outcome is not None and failing is None)
              and (case["completed"] or k == last),
              "wp7-stop%d: completed=%s contradicts its outcome (first "
              "failing check: %s), or an earlier case is open"
              % (k, case["completed"], failing))
    open_case = cases[last] if cases else None
    check("terminal-status", (kind == "qualified") == (status == 0),
          "terminal %r with exit status %s" % (kind, status))
    check("terminal-case",
          (kind in ("qualified", "narrowed"))
          == (open_case is not None and open_case["completed"])
          and terminal.get("case", last if cases else None)
          == (last if cases else None),
          "terminal %r does not bind the last opened case" % kind)

    if kind == "qualified":
        check("qualified-count", len(cases) == CASES,
              "a qualified terminal over %d of %d cases"
              % (len(cases), CASES))
        check("unexpected-pass", not expect_wedge,
              "joint cell unexpectedly passed under "
              "JOINT_EXPECTED_FAILURE=1; set 0 once the wedge is gone")
        return verdict("qualified", "full-matrix",
                       "all %d stop cases completed" % CASES)
    if kind == "narrowed":
        check("narrowed", False,
              "the cell reports a narrowed matrix")
    if kind in ("precluded", "no-feed"):
        branch = open_case["branch"] if open_case else None
        check("no-feed-binding",
              open_case is not None and branch in NO_FEED
              and terminal["cause"] == branch
              and terminal["receipt"] == NO_FEED[branch]
              and open_case["outcome"] is None,
              "the no-feed terminal does not match its case's branch, "
              "receipt or undriven state")
        first_s1 = len(cases) == 1 and branch == "s1-precluded"
        check("precluded-binding", (kind == "precluded") == first_s1,
              "a %s terminal where the S1 seal %s the first and only case"
              % (kind, "is" if first_s1 else "is not"))
        if kind == "precluded":
            return verdict(
                "environment-precluded", "s1-first-case",
                "wp7-stop0: %s; not attempted" % NO_FEED["s1-precluded"])
        probe = _probe_text(open_case["no_feed"])
        check("s1-after-linked", branch != "s1-precluded",
              "wp7-stop%d sealed S1 after linked cases; %s" % (last, probe))
        check("no-feed-receipt-starved",
              branch != "no-feeds-receipt-starved",
              "wp7-stop%d: %s; no_receipt=%d partition=%d shed=%d after %d "
              "join quanta and %d discovery passes; %s"
              % (last, NO_FEED["no-feeds-receipt-starved"],
                 open_case["no_feed"]["no_receipt"],
                 open_case["no_feed"]["partition"],
                 open_case["no_feed"]["shed"], open_case["join_quanta"],
                 open_case["join_passes"], probe))
        check("no-feed-unattributed", branch != "no-feeds-unattributed",
              "wp7-stop%d: %s; %s" % (last, NO_FEED["no-feeds-unattributed"],
                                      probe))
    if kind == "wedge":
        outcome = open_case["outcome"] if open_case else None
        check("wedge-binding",
              outcome is not None and open_case["branch"] == "linked"
              and first_failing_check(outcome) == "terminal",
              "the wedge terminal's case did not fail first at the "
              "Published-then-WoundDown check")
        check("wedge-unexpected", expect_wedge,
              "wp7-stop%d wedged: the finish did not reach Published "
              "then WoundDown" % last)
        return verdict("expected-failure", "wedge",
                       "wp7-stop%d wedged (expected)" % last)
    if kind == "case-failed":
        stage = terminal["stage"]
        if open_case is None:
            bound = stage == "setup" and terminal["check"] is None
        elif stage == "setup":
            bound = open_case["branch"] is None and terminal["check"] is None
        elif stage == "drive":
            bound = (open_case["branch"] == "linked"
                     and open_case["outcome"] is None
                     and terminal["check"] is None)
        else:
            outcome = open_case["outcome"]
            failing = first_failing_check(outcome) if outcome else None
            bound = (open_case["branch"] == "linked" and outcome is not None
                     and failing not in (None, "terminal")
                     and terminal["check"] == failing)
        check("case-failed-binding", bound,
              "the case-failed terminal (stage %s, check %s) contradicts "
              "its case" % (stage, terminal["check"]))
    where = "before the first case" if open_case is None \
        else "wp7-stop%d" % last
    raise Refusal("case-failed", "%s failed: %s"
                  % (where, _excerpt(terminal.get("error", kind))))


def _probe_text(probe):
    """One-line summary of a no-feed probe for the verdict detail."""
    if probe is None:
        return "no probe"
    gaps = ", ".join("%s/%s x%d" % (gap["subject"], gap["reason"],
                                    gap["count"]) for gap in probe["gaps"])
    return ("feeds=%d linked=%s backstop=%d capacity=%s no_receipt=%d "
            "partition=%d shed=%d gaps=[%s] drive=%s"
            % (probe["joint_feeds"], probe["journal_linked"],
               probe["backstop_routed"], probe["birth_capacity"],
               probe["no_receipt"], probe["partition"], probe["shed"], gaps,
               probe["drive"]))[:1500]


def _excerpt(text):
    return repr(text[:300])


def _parse(raw):
    def pairs(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise Malformed("duplicate key in %r" % sorted(keys))
        return dict(items)

    def parse_int(digits):
        if len(digits.lstrip("-")) > 20:
            raise Malformed("integer of %d digits" % len(digits))
        return int(digits)

    def refuse(token):
        raise Malformed("non-integer number %r" % token[:40])

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_int=parse_int,
                          parse_float=refuse, parse_constant=refuse)
    except Malformed:
        raise
    except (ValueError, RecursionError) as error:
        raise Malformed(str(error)[:200])


def _is_u64(value):
    return type(value) is int and 0 <= value <= U64_MAX


def _is_str(value):
    return type(value) is str


def _opt(test):
    return lambda value: value is None or test(value)


def _one_of(*allowed):
    return lambda value: _is_str(value) and value in allowed


def _keys(value, expected, path):
    if type(value) is not dict:
        raise Malformed("%s is not an object" % path)
    if set(value) != set(expected):
        raise Malformed("%s keys %r, want %r"
                        % (path, sorted(value), sorted(expected)))
    for key, test in expected.items():
        if not test(value[key]):
            raise Malformed("%s.%s has a bad value %r"
                            % (path, key, value[key]))


def _list_of(test, length=None):
    def check(value):
        return (type(value) is list and all(test(item) for item in value)
                and (length is None or len(value) == length))
    return check


def _wound(value):
    return _is_str(value) and (value in ("joined", "unwound")
                               or value.startswith("wound-refused:"))


OUTCOME_FIELDS = {
    "offset_ms": _is_u64, "begin": _one_of(*BEGINS),
    "finish_polls": _is_u64, "finish": _one_of(*FINISHES),
    "first_error": _opt(_is_str), "latched": lambda v: type(v) is bool,
    "latch_code": _opt(_is_str), "h0_stop": _is_str, "wound": _wound,
    "wound_polls": _is_u64, "taken": lambda v: type(v) is bool,
    "minted": lambda v: type(v) is bool, "stash_floor": _opt(_is_u64),
    "stop_counts": _list_of(_is_u64, 4), "api_a": _is_u64,
    "a_semantic": _is_u64, "lane_shed": _is_u64,
    "reconciled": lambda v: type(v) is bool, "reconcile_detail": _is_str,
    "abandon_gap": _opt(_is_str), "branch": _one_of(*OUTCOME_BRANCHES),
}
CASE_FIELDS = {
    "name": _is_str, "index": _is_u64, "prep": _is_u64,
    "offset_ms": _is_u64, "branch": _opt(_one_of(*BRANCHES)),
    "join_quanta": _opt(_is_u64), "join_passes": _opt(_is_u64),
    "outcome": lambda v: True, "no_feed": lambda v: True,
    "completed": lambda v: type(v) is bool,
}
GAP_FIELDS = {"subject": _is_str, "reason": _is_str, "count": _is_u64}
PROBE_FIELDS = {
    "joint_feeds": _is_u64, "journal_linked": lambda v: type(v) is bool,
    "backstop_routed": _is_u64, "birth_capacity": _opt(_is_str),
    "drive": _is_str, "gaps": lambda v: type(v) is list,
    "no_receipt": _is_u64, "partition": _is_u64, "shed": _is_u64,
}
TERMINAL_FIELDS = {
    "qualified": {}, "narrowed": {},
    "precluded": {"case": _is_u64, "cause": _is_str, "receipt": _is_str},
    "no-feed": {"case": _is_u64, "cause": _is_str, "receipt": _is_str},
    "wedge": {"case": _is_u64},
    "case-failed": {"case": _opt(_is_u64), "stage": _one_of(*STAGES),
                    "check": _opt(_one_of(*STOP_CHECKS)), "error": _is_str},
}


def _validate_schema(record):
    _keys(record, {"schema": lambda v: v == SCHEMA, "cell": _is_str,
                   "selection": lambda v: True, "cases": lambda v: True,
                   "terminal": lambda v: True}, "record")
    if record["selection"] is not None:
        _keys(record["selection"], {"preps": _list_of(_is_u64),
                                    "offsets": _list_of(_is_u64)},
              "selection")
    if type(record["cases"]) is not list:
        raise Malformed("cases is not a list")
    for k, case in enumerate(record["cases"]):
        _keys(case, CASE_FIELDS, "cases[%d]" % k)
        if case["outcome"] is not None:
            _keys(case["outcome"], OUTCOME_FIELDS, "cases[%d].outcome" % k)
        if case["no_feed"] is not None:
            _keys(case["no_feed"], PROBE_FIELDS, "cases[%d].no_feed" % k)
            for g, gap in enumerate(case["no_feed"]["gaps"]):
                _keys(gap, GAP_FIELDS, "cases[%d].no_feed.gaps[%d]" % (k, g))
    terminal = record["terminal"]
    if type(terminal) is not dict or \
            terminal.get("kind") not in TERMINAL_FIELDS:
        raise Malformed("terminal has no known kind")
    fields = dict(TERMINAL_FIELDS[terminal["kind"]])
    fields["kind"] = _is_str
    _keys(terminal, fields, "terminal")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cell", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--expect-wedge", choices=("0", "1"), default="0")
    parser.add_argument("--format", choices=("json", "lines"), default="json")
    parser.add_argument("log")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"(0|[1-9][0-9]{0,2})", args.status):
        print("bad --status: %r" % args.status, file=sys.stderr)
        return 2
    try:
        with open(args.log, encoding="utf-8", errors="replace") as stream:
            text = stream.read()
    except OSError as error:
        print("cannot read %s: %s" % (args.log, error), file=sys.stderr)
        return 2
    result = classify(text, int(args.status), args.cell,
                      expect_wedge=args.expect_wedge == "1")
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        # One field per line for shell readers; every field is a single
        # line (excerpts are repr-quoted).
        for key in ("qualification", "reason", "result_line", "detail"):
            print(result[key].replace("\n", " "))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
