#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Fail-closed qualification of the Joint linked-stop matrix cell log.

One parser and validator for both qualifying entries (the S3 suite,
scripts/ci/stop-races.sh, and the long campaign runner,
scripts/run-privileged-lib-tests.sh). The input is the cell's
`--exact NAME --ignored --nocapture` libtest log and the child's exit
status as the shell saw it (128+N for a signal). The output is one JSON
object: qualification, reason, detail and the validated summary line.

Qualification is one of:
  qualified             exit 0, a strict one-test pass summary, and the
                        twelve cases in order, each exactly once as
                        linked tag, offset diagnostic (bound to the
                        case's offset, finish=published) and completion
                        marker, with no error, no-feed or stray record;
  environment-precluded exit 101, a strict one-test failure summary, and
                        exactly the first case's S1 tag followed by its
                        own S1 receipt as the single terminal error;
  expected-failure      (only with --expect-wedge 1) exit 101 and the
                        terminal error is the Published-then-WoundDown
                        terminal check of the linked case in progress,
                        bound to that case's offset;
  failed                everything else, with a named reason (the
                        fail-closed default is `case-failed`).

Grammar of the log (pinned libtest pretty format, both the threaded
form and the --test-threads=1 form, where the first output line is
glued to the `test NAME ... ` prefix and the verdict stands alone):

  log      := blank* "running 1 test" body outcome trailer summary blank*
  outcome  := "test NAME ... ok|FAILED"   (threaded)
            | "ok|FAILED"                 (single thread)
  trailer  := blank                                           (ok)
            | blank "failures:" blank "failures:" "    NAME" blank  (FAILED)
  summary  := "test result: ok|FAILED. P passed; F failed; I ignored;
               M measured; N filtered out; finished in S.SSs"
  body     := free text, plus records:
              P11SCOPE_CELL_BRANCH=wp7-stopK:(linked|s1-precluded|
                                              no-feeds-unattributed)
              P11SCOPE_CELL_BRANCH=offsetMS:(latched|no-latch):FINISH
              P11SCOPE_STOP_COMPLETE=wp7-stopK
              Error: MESSAGE  [backtrace block]   (terminal only)

Any line carrying a record prefix that is not a full record, a no-feed
receipt outside the terminal error, a second summary, stray libtest
framing, or any content after the terminal error other than a
backtrace block fails. Each check has a name (the reason it reports);
the table-driven suite tests/python/test_joint_stop_verdict.py disables
each check in turn and requires some row to turn red.

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

CASES = 12
OFFSETS_MS = (0, 1, 5, 20)
CASE = r"(0|[1-9]|1[01])"
OFFSET = r"(0|1|5|20)"
COUNT = r"(0|[1-9][0-9]*)"

SUMMARY_RE = re.compile(
    r"test result: (ok|FAILED)\. " + COUNT + r" passed; " + COUNT
    + r" failed; " + COUNT + r" ignored; " + COUNT + r" measured; "
    + COUNT + r" filtered out; finished in [0-9]+\.[0-9]{2}s")
BRANCH_RE = re.compile(
    r"P11SCOPE_CELL_BRANCH=wp7-stop" + CASE
    + r":(linked|s1-precluded|no-feeds-unattributed)")
OFFSET_RE = re.compile(
    r"P11SCOPE_CELL_BRANCH=offset" + OFFSET
    + r":(latched|no-latch):(published|abandoned|not-begun|unpublished)")
COMPLETE_RE = re.compile(r"P11SCOPE_STOP_COMPLETE=wp7-stop" + CASE)
RECORD_PREFIXES = ("P11SCOPE_CELL_BRANCH=", "P11SCOPE_STOP_COMPLETE")
RECEIPT_TEXT = "no joint feeds"
S1_RECEIPT = ("Error: wp7-stop{k}: no joint feeds with S1 seal "
              "(producers unlinked, zero installs); not attempted")
UNATTRIBUTED_RECEIPT = ("Error: wp7-stop{k}: no joint feeds without S1 seal "
                        "(producers linked, zero installs unexplained); "
                        "not attempted")
WEDGE_RE = re.compile(
    r"Error: offset " + OFFSET
    + r": the finish must reach Published then WoundDown: offset=" + OFFSET
    + r" begin=\S+ finish=(\S+) .*")
BACKTRACE_HEAD = "Stack backtrace:"
BACKTRACE_FRAME_RE = re.compile(r" +([0-9]+: \S.*|at \S.*)")
BACKTRACE_NOTE_RE = re.compile(r"note: Some details are omitted, .*")

# Every check the validator applies, by the reason it reports. The
# table suite disables each in turn (mutation proof).
CHECKS = (
    "exit-status", "header", "summary-missing", "summary-duplicate",
    "summary-malformed", "summary-not-terminal", "summary-counts",
    "summary-status", "outcome", "failures-list", "stray-framing",
    "record-malformed", "receipt-stray", "error-count",
    "error-not-terminal", "sequence", "offset-binding", "finish-binding",
    "matrix-short", "pass-with-no-feed", "unexpected-pass",
    "s1-after-linked", "receipt-mismatch", "no-feed-unattributed",
    "wedge-binding", "wedge-unexpected",
)


class Refusal(Exception):
    def __init__(self, reason, detail):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


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


def _classify(text, status, cell, expect_wedge, disabled, state):
    def check(name, ok, detail):
        if not ok and name not in disabled:
            raise Refusal(name, detail)

    check("exit-status", status in (0, 101),
          "joint cell exit status %s is neither a libtest pass (0) nor a "
          "libtest failure (101): a signal, abort or harness error"
          % status)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    # Header: blank lines, then exactly one selected test.
    first = 0
    while first < len(lines) and lines[first] == "":
        first += 1
    check("header", first < len(lines) and lines[first] == "running 1 test",
          "the log does not open with `running 1 test` (zero or several "
          "tests selected, or unframed output)")

    # Summary: exactly one, full-line, terminal.
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
    tail = [line for line in lines[at + 1:] if line != ""]
    check("summary-not-terminal", not tail,
          "content after the libtest summary: %r" % (tail[:1] or [""])[0][:200])
    passed_run = None
    if match is not None:
        word = match.group(1)
        counts = tuple(int(match.group(i)) for i in range(2, 6))
        want = (1, 0, 0, 0) if word == "ok" else (0, 1, 0, 0)
        check("summary-counts", counts == want,
              "summary counts %s are not exactly one %s test"
              % (counts, "passing" if word == "ok" else "failing"))
        check("summary-status",
              (word == "ok" and status == 0)
              or (word == "FAILED" and status == 101),
              "summary %s disagrees with exit status %s" % (word, status))
        passed_run = word == "ok"
    if passed_run is None:
        passed_run = status == 0
    word = "ok" if passed_run else "FAILED"

    # Trailer before the summary.
    end = at
    if passed_run:
        trailer = [""]
    else:
        trailer = ["", "failures:", "", "failures:", "    " + cell, ""]
    observed = lines[max(end - len(trailer), 0):end]
    check("failures-list", observed == trailer,
          "the libtest trailer before the summary is not the %s trailer "
          "for exactly %s" % (word, cell))
    end = max(end - len(trailer), first + 1)

    # Outcome: threaded line or single-thread verdict.
    start_prefix = "test %s ... " % cell
    timeout_line = "test %s has been running for over 60 seconds" % cell
    body_start = first + 1
    outcome = lines[end - 1] if end - 1 >= body_start else ""
    body = []
    if outcome == start_prefix + word:
        body = lines[body_start:end - 1]
    elif outcome == word and body_start < end - 1 \
            and lines[body_start].startswith(start_prefix):
        body = ([lines[body_start][len(start_prefix):]]
                + lines[body_start + 1:end - 1])
    else:
        check("outcome", False,
              "no `test %s ... %s` outcome agreeing with the summary"
              % (cell, word))
        body = lines[body_start:end]
    body = [line for line in body if line != timeout_line]

    # Body records.
    events = []
    errors = []
    for index, line in enumerate(body):
        if line.startswith("Error: "):
            errors.append(index)
            continue
        check("stray-framing",
              not (line in ("ok", "FAILED") or line.startswith("test ")
                   or line.startswith("running ") or line == "failures:"),
              "stray libtest framing inside the cell output: %r" % line[:200])
        if any(prefix in line for prefix in RECORD_PREFIXES):
            branch = BRANCH_RE.fullmatch(line)
            offset = OFFSET_RE.fullmatch(line)
            complete = COMPLETE_RE.fullmatch(line)
            check("record-malformed", branch or offset or complete,
                  "malformed or embedded record: %r" % line[:200])
            if branch:
                events.append(("tag", int(branch.group(1)), branch.group(2)))
            elif offset:
                events.append(("offset", int(offset.group(1)),
                               offset.group(3)))
            elif complete:
                events.append(("complete", int(complete.group(1)), None))
        check("receipt-stray", RECEIPT_TEXT not in line,
              "no-feed receipt outside the terminal error: %r" % line[:200])

    if passed_run:
        check("error-count", not errors,
              "a passing run carries an Error record: %r"
              % (body[errors[0]][:200] if errors else ""))
        terminal = None
    else:
        check("error-count", len(errors) == 1,
              "a failing run needs exactly one terminal Error record, "
              "saw %d (panic, abort or competing errors)" % len(errors))
        terminal = body[errors[-1]] if errors else None
        if errors:
            after = body[errors[-1] + 1:]
            check("error-not-terminal", _backtrace_only(after),
                  "content after the terminal error: %r"
                  % next((line for line in after if line), "")[:200])
    for index in errors[:-1] if not passed_run else errors:
        check("receipt-stray", RECEIPT_TEXT not in body[index],
              "no-feed receipt outside the terminal error: %r"
              % body[index][:200])

    # Case sequence: linked, offset diagnostic, completion; in order.
    next_case = 0
    phase = "start"
    current = None
    nofeed = None
    finish = None
    for kind, value, extra in events:
        if phase == "start" and kind == "tag" and value == next_case:
            current = value
            if extra == "linked":
                phase = "linked"
            else:
                phase = "nofeed"
                nofeed = (value, extra)
            continue
        if phase == "linked" and kind == "offset":
            check("offset-binding", value == OFFSETS_MS[current % 4],
                  "wp7-stop%d ran at offset %d ms, not its matrix offset "
                  "%d ms" % (current, value, OFFSETS_MS[current % 4]))
            phase = "offset"
            finish = extra
            continue
        if phase == "offset" and kind == "complete" and value == current:
            check("finish-binding", finish == "published",
                  "wp7-stop%d completed with finish=%s, not published"
                  % (current, finish))
            next_case += 1
            phase = "done" if next_case == CASES else "start"
            continue
        check("sequence", False,
              "case record out of order, duplicated or mismatched: %s "
              "wp7-stop%s after phase %s of wp7-stop%s"
              % (kind, value, phase, current))

    if passed_run:
        check("pass-with-no-feed", phase != "nofeed",
              "joint cell passed with a no-feed preclusion tag "
              "(regression); a pass never precludes")
        missing = [str(k) for k in range(next_case, CASES)]
        check("matrix-short", phase == "done",
              "joint cell passed without the full stop matrix (missing "
              "completed cases: %s); the qualifying entry forces all 12 "
              "wp7-stop cases" % " ".join(missing))
        check("unexpected-pass", not expect_wedge,
              "joint cell unexpectedly passed under "
              "JOINT_EXPECTED_FAILURE=1; set 0 once the wedge is gone")
        return verdict("qualified", "full-matrix",
                       "linked joint stop reaches Published then WoundDown "
                       "(12-case matrix)", summary)

    terminal = terminal or ""
    if phase == "nofeed":
        k, tag = nofeed
        if tag == "s1-precluded" and terminal == S1_RECEIPT.format(k=k):
            check("s1-after-linked", k == 0,
                  "joint cell mixed linked operation with an S1 preclusion "
                  "at wp7-stop%d (regression); preclusion holds only "
                  "before any linked case" % k)
            return verdict("environment-precluded", "s1-first-case",
                           "environment-precluded: S1 seal without joint "
                           "feeds (producers unlinked, zero installs)",
                           summary)
        if tag == "no-feeds-unattributed" \
                and terminal == UNATTRIBUTED_RECEIPT.format(k=k):
            check("no-feed-unattributed", False,
                  "joint cell produced no feeds without an S1 seal "
                  "(unattributed: producers linked, zero installs "
                  "unexplained) at wp7-stop%d; not environmental" % k)
        check("receipt-mismatch", False,
              "wp7-stop%d %s tag without its own matching terminal "
              "receipt (ambiguous): %r" % (k, tag, terminal[:200]))
    check("receipt-mismatch", RECEIPT_TEXT not in terminal,
          "no-feed receipt without its case tag (ambiguous): %r"
          % terminal[:200])
    wedge = WEDGE_RE.fullmatch(terminal)
    if wedge and phase == "offset":
        want = OFFSETS_MS[current % 4]
        check("wedge-binding",
              int(wedge.group(1)) == want and int(wedge.group(2)) == want
              and wedge.group(3) == finish,
              "wedge error does not belong to wp7-stop%d (offset %d ms, "
              "finish=%s): %r" % (current, want, finish, terminal[:200]))
        check("wedge-unexpected", expect_wedge,
              "wedge reproduced under JOINT_EXPECTED_FAILURE=0 "
              "(regression); set 1 to re-arm the expectation")
        return verdict("expected-failure", "wedge",
                       "expected failure: joint finish wedges at "
                       "wp7-stop%d (task/v060-joint-wedge owns the fix)"
                       % current, summary)
    # Fail-closed default: a failure that is none of the classified
    # outcomes above. Not a check (nothing to disable): it is what is
    # left when every accept path refused.
    where = ("after the full matrix" if phase == "done"
             else "at wp7-stop%d" % current if current is not None
             else "before the first case")
    raise Refusal("case-failed", "joint cell failed %s without the wedge "
                  "signature (regression or new failure): %r"
                  % (where, terminal[:300]))


def _backtrace_only(after):
    """Only blank lines and one anyhow backtrace block may follow."""
    rest = [line for line in after]
    while rest and rest[0] == "":
        rest.pop(0)
    if not rest:
        return True
    if rest[0] != BACKTRACE_HEAD:
        return False
    for line in rest[1:]:
        if line == "" or BACKTRACE_FRAME_RE.fullmatch(line) \
                or BACKTRACE_NOTE_RE.fullmatch(line):
            continue
        return False
    return True


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
