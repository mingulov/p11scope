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

Position rules (evidence is judged where it stands, before or after
the deciding record):
  - any line carrying a record stem (P11SCOPE_CELL_BRANCH,
    P11SCOPE_STOP_COMPLETE, whatever separator follows) or a no-feed
    word (s1-precluded, no-feeds-unattributed) must be a full record;
  - the no-feed receipt text and the wedge phrase belong only to the
    terminal error; a summary only to the trailer;
  - a no-feed tag is followed directly by its receipt: a preclusion
    log holds nothing but setup output, the case-0 tag and its receipt;
  - diagnostics naming wp7-stopN sit inside case N (its prep before
    the tag, or its linked stage); stop outcome and check diagnostics
    sit in their case's linked or offset stage, bound to its offset;
    nothing names a case after the full matrix;
  - the terminal error carries no reserved record; only a backtrace
    block follows it, itself free of records and receipts;
  - a wedge terminal is one whole linked StopOutcome record (each field
    once), bound to the case's offset, finish and latch, and describing
    a failed stop (not published+joined+taken).
Stray libtest framing, competing errors and a second summary fail too.
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
# Reserved record stems: any line carrying one must be a full record,
# whatever separator follows the stem.
RECORD_STEMS = ("P11SCOPE_CELL_BRANCH", "P11SCOPE_STOP_COMPLETE")
# No-feed branch words: outside a full branch record they are a
# malformed no-feed record, never free text.
NO_FEED_WORDS = ("s1-precluded", "no-feeds-unattributed")
RECEIPT_TEXT = "no joint feeds"
# Decision text owned by the terminal records; never free text.
WEDGE_PHRASE = "Published then WoundDown"
S1_RECEIPT = ("Error: wp7-stop{k}: no joint feeds with S1 seal "
              "(producers unlinked, zero installs); not attempted")
UNATTRIBUTED_RECEIPT = ("Error: wp7-stop{k}: no joint feeds without S1 seal "
                        "(producers linked, zero installs unexplained); "
                        "not attempted")
# The Rust terminal check's error with the StopOutcome Display
# (src/inventory/joint_stop_races_privileged_tests.rs).
WEDGE_HEAD_RE = re.compile(
    r"Error: offset " + OFFSET
    + r": the finish must reach Published then WoundDown: (.*)")
OUTCOME_RE = re.compile(
    r"offset=" + OFFSET + r" begin=(\S+) finish=(published|abandoned|"
    r"not-begun|unpublished) \(([0-9]+) polls\) first_error=(None|Some\(.*\)) "
    r"latched=(true|false) latch=(None|Some\(.*\)) h0=(\S+) "
    r"wound=(joined|unwound|wound-refused:.*) \(([0-9]+) polls\) "
    r"taken=(true|false) minted=(true|false) stash=(None|Some\(.*\)) "
    r"stop_counts=(.*) api_a=([0-9]+) a_sem=([0-9]+) shed=([0-9]+) "
    r"reconciled=(true|false) abandon_gap=(None|Some\(.*\)) branch=(linked)")
OUTCOME_KEYS = (" begin=", " finish=", " first_error=", " latched=",
                " latch=", " h0=", " wound=", " taken=", " minted=",
                " stash=", " stop_counts=", " api_a=", " a_sem=", " shed=",
                " reconciled=", " abandon_gap=", " branch=")
# Case-bound diagnostics: legal only inside the linked case they name.
OUTCOME_LINE_RE = re.compile(r"JOINT_STOP (outcome: offset=|offset=)"
                             + OFFSET + r"\b.*")
CASE_MENTION_RE = re.compile(r"wp7-stop([0-9]+)")
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
    "wedge-binding", "wedge-unexpected", "text-reserved", "text-binding",
    "evidence-after-preclusion", "terminal-reserved", "wedge-record",
    "wedge-success",
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
        counts = tuple(match.group(i) for i in range(2, 6))
        want = ("1", "0", "0", "0") if word == "ok" else ("0", "1", "0", "0")
        check("summary-counts", counts == want,
              "summary counts %s are not exactly one %s test"
              % (tuple(c[:12] for c in counts),
                 "passing" if word == "ok" else "failing"))
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

    # Body records, in order. Free text is allowed only where it carries
    # no evidence: reserved stems and no-feed words must form full
    # records, receipts and the wedge phrase belong to the terminal
    # error, and case-bound diagnostics must sit inside the linked case
    # they name. Positions are checked against the case sequence below.
    items = []
    errors = []
    for index, line in enumerate(body):
        if line.startswith("Error: "):
            errors.append(index)
            items.append(("error", index, None))
            continue
        check("stray-framing",
              not (line in ("ok", "FAILED") or line.startswith("test ")
                   or line.startswith("running ") or line == "failures:"),
              "stray libtest framing inside the cell output: %r" % line[:200])
        if any(stem in line for stem in RECORD_STEMS) \
                or any(word in line for word in NO_FEED_WORDS):
            branch = BRANCH_RE.fullmatch(line)
            offset = OFFSET_RE.fullmatch(line)
            complete = COMPLETE_RE.fullmatch(line)
            check("record-malformed", branch or offset or complete,
                  "malformed or embedded record: %r" % line[:200])
            if branch:
                items.append(("tag", int(branch.group(1)), branch.group(2)))
            elif offset:
                items.append(("offset", int(offset.group(1)),
                              (offset.group(3), offset.group(2))))
            elif complete:
                items.append(("complete", int(complete.group(1)), None))
            continue
        check("receipt-stray", RECEIPT_TEXT not in line,
              "no-feed receipt outside the terminal error: %r" % line[:200])
        check("text-reserved", WEDGE_PHRASE not in line
              and "test result:" not in line,
              "terminal decision text inside a diagnostic: %r" % line[:200])
        items.append(("text", index, line))

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
    if terminal is not None:
        check("terminal-reserved",
              not any(stem in terminal for stem in RECORD_STEMS)
              and not any(word in terminal for word in NO_FEED_WORDS)
              and "test result:" not in terminal,
              "the terminal error embeds a reserved record: %r"
              % terminal[:200])

    # Case sequence: linked, offset diagnostic, completion; in order.
    next_case = 0
    phase = "start"
    current = None
    nofeed = None
    finish = None
    latch = None
    for kind, value, extra in items:
        if kind == "error":
            # The terminal error decides; what follows it is the
            # backtrace block, checked above.
            break
        if kind == "text":
            if extra != "":
                _check_text(check, extra, phase, next_case, current)
            continue
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
            finish, latch = extra
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
    wedge = WEDGE_HEAD_RE.fullmatch(terminal)
    if wedge and phase == "offset":
        want = OFFSETS_MS[current % 4]
        outcome = OUTCOME_RE.fullmatch(wedge.group(2))
        check("wedge-record",
              outcome is not None
              and all(wedge.group(2).count(key) == 1 for key in OUTCOME_KEYS),
              "wedge terminal is not one whole linked StopOutcome record: %r"
              % terminal[:300])
        if outcome is not None:
            check("wedge-binding",
                  int(wedge.group(1)) == want
                  and int(outcome.group(1)) == want
                  and outcome.group(3) == finish
                  and outcome.group(6) == ("true" if latch == "latched"
                                           else "false"),
                  "wedge error does not belong to wp7-stop%d (offset %d ms, "
                  "finish=%s, %s): %r"
                  % (current, want, finish, latch, terminal[:200]))
            check("wedge-success",
                  not (outcome.group(3) == "published"
                       and outcome.group(9) == "joined"
                       and outcome.group(11) == "true"),
                  "wedge terminal describes a successful stop (published, "
                  "joined, taken); the terminal check cannot fail on it: %r"
                  % terminal[:200])
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


def _check_text(check, line, phase, next_case, current):
    """Position rules for free text: no evidence after a no-feed tag,
    and case-bound diagnostics only inside the case they name."""
    check("evidence-after-preclusion", phase != "nofeed",
          "output after the no-feed tag of wp7-stop%s; the tag must be "
          "followed directly by its receipt: %r" % (current, line[:200]))
    bound = next_case if phase == "start" else current
    for mention in CASE_MENTION_RE.findall(line):
        check("text-binding", phase != "done" and int(mention) == bound,
              "diagnostic names wp7-stop%s outside that case (phase %s of "
              "wp7-stop%s): %r" % (mention, phase, bound, line[:200]))
    outcome = OUTCOME_LINE_RE.fullmatch(line)
    if outcome is not None:
        stage = "linked" if outcome.group(1).startswith("outcome") else "offset"
        check("text-binding",
              phase == stage and current is not None
              and int(outcome.group(2)) == OFFSETS_MS[current % 4],
              "stop outcome diagnostic outside its linked case's %s stage: "
              "%r" % (stage, line[:200]))
    if re.search(r"wp7-stop[0-9]+: finish=", line):
        check("text-binding", phase == "linked",
              "stop finish diagnostic outside a linked case: %r" % line[:200])


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
        if any(stem in line for stem in RECORD_STEMS) \
                or RECEIPT_TEXT in line or WEDGE_PHRASE in line:
            return False
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
