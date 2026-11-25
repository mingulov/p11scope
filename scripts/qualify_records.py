#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Typed evidence loader and judges for scripts/qualify-public-cli.sh.

Every qualifier decision about structured evidence is made here, once:

* Inputs decode strictly: duplicate JSON object keys, NaN/Infinity and
  non-JSON text are refused before any value is read.
* Each input kind is a typed record: every field a judge reads has its
  exact JSON type (bool is never an int, a float is never a count) and
  counters are unsigned 64-bit, like their Rust producers. Records the
  qualifier or its fixtures own, and product records whose shape is
  closed (the event envelope, `stdout_lost`, `event_output`, unobserved
  windows, pass totals), refuse unknown keys. Product records the
  schema declares additive within v1 are open: unknown keys are legal
  there, every key read is still typed.
* Every input file is bound to the current run: the shell writes a run
  stamp (run id and cell) after removing the leg's destinations, and an
  input must be a regular file written at or after that stamp, under
  the same run id.
* Relations are declared rules (`RULES`), each checked once, by id.

Each judge prints one human detail line on stdout and, with
`--verdict FILE`, writes the typed verdict
`{"schema": VERDICT_SCHEMA, "judge", "verdict": "pass"|"fail", "rule",
"stage", "detail"}`; `stage` is "type" when a field kind or the JSON
decoder refused, "relation" when a rule between typed values did,
"input" when an input could not be read, and null on a pass.
Exit status: 0 pass, 1 fail, 64 usage.
"""

import argparse
import json
import os
import platform
import re
import stat
import sys

VERDICT_SCHEMA = "p11scope/qualify-verdict/v1"
STAMP_SCHEMA = "p11scope/qualify-stamp/v1"
U64_LIMIT = 2**64
PID_MAX = 4194304
MAX_INPUT_BYTES = 64 * 1024 * 1024
# The stamp is three short fields; a larger stamp is not one this loader wrote.
MAX_STAMP_BYTES = 4096
READ_CHUNK = 1024 * 1024

# -- rules ---------------------------------------------------------------

MISSING = object()
ABSENT_AS_NULL = "absent-as-null"

RULES = {}


def declare(rule_id, text):
    if rule_id in RULES:
        raise KeyError("rule declared twice: " + rule_id)
    RULES[rule_id] = text
    return rule_id


class Refusal(AssertionError):
    """A refused input. `stage` is "type" when a field kind (or the JSON
    decoder) refused it and "relation" when a rule between typed values
    did."""

    def __init__(self, rule_id, detail, stage="relation"):
        if rule_id not in RULES:
            raise KeyError("undeclared rule: " + rule_id)
        super().__init__(detail)
        self.rule = rule_id
        self.detail = detail
        self.stage = stage


def require(condition, rule_id, detail):
    if rule_id not in RULES:
        raise KeyError("undeclared rule: " + rule_id)
    if not condition:
        raise Refusal(rule_id, detail)


def require_type(condition, rule_id, detail):
    """`require` for a shape check made outside a field kind."""
    try:
        require(condition, rule_id, detail)
    except Refusal as refusal:
        refusal.stage = "type"
        raise


JSON_DECODE = declare("json.decode", "an input is one well-formed JSON value")
JSON_DUPLICATE = declare("json.duplicate-key", "no JSON object repeats a key (no last-wins)")
JSON_CONSTANT = declare("json.constant", "no NaN or Infinity literal")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, JSON_DUPLICATE, "duplicate JSON key %r" % (key,))
        result[key] = value
    return result


def strict_json(text, what):
    """Decode one JSON value: a repeated key (last-wins) or a NaN or
    Infinity literal refuses."""
    constants = []

    def constant(name):
        constants.append(name)
        return None

    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_constant=constant)
    except Refusal as refusal:
        raise Refusal(refusal.rule, "%s: %s" % (what, refusal.detail), "type") from None
    except ValueError:
        value = MISSING
    require_type(value is not MISSING, JSON_DECODE, "%s is not JSON: %r" % (what, text[:200]))
    require_type(not constants, JSON_CONSTANT, "%s: JSON constant %s" % (what, constants[:1]))
    return value


# -- typed fields --------------------------------------------------------



def _tname(value):
    return type(value).__name__


class Kind:
    """A field validator: `check(value, label, rule)` returns the value.
    Every refusal raised inside a kind's check is a type-stage refusal."""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        inner = cls.__dict__.get("check")
        if inner is None:
            return

        def check(self, value, *args, **kwargs):
            try:
                return inner(self, value, *args, **kwargs)
            except Refusal as refusal:
                refusal.stage = "type"
                raise

        cls.check = check

    def check(self, value, label, rule):
        raise NotImplementedError


class Exact(Kind):
    def __init__(self, *types):
        self.types = types

    def check(self, value, label, rule):
        require(type(value) in self.types, rule, "%s has type %s: %r" % (label, _tname(value), value))
        return value


class Unsigned(Kind):
    def __init__(self, low=0, high=U64_LIMIT - 1):
        self.low, self.high = low, high

    def check(self, value, label, rule):
        require(type(value) is int, rule, "%s has type %s: %r" % (label, _tname(value), value))
        require(self.low <= value <= self.high, rule,
                "%s out of range [%d, %d]: %r" % (label, self.low, self.high, value))
        return value


class OneOf(Kind):
    def __init__(self, *values):
        self.values = values

    def check(self, value, label, rule):
        require(type(value) is str, rule, "%s has type %s: %r" % (label, _tname(value), value))
        require(value in self.values, rule, "%s %r is not one of %r" % (label, value, self.values))
        return value


class Nullable(Kind):
    def __init__(self, inner):
        self.inner = inner

    def check(self, value, label, rule):
        return None if value is None else self.inner.check(value, label, rule)


class Anything(Kind):
    """Any JSON value: the record leaves this field to a declared relation
    rule that types it (with that rule's own message)."""

    def check(self, value, label, rule):
        return value


class Decided(Kind):
    """A field whose typing belongs to a declared relation rule: any type
    or shape fault refuses under that rule, with its message first and
    the typed detail after it."""

    def __init__(self, inner, rule, message):
        self.inner, self.rule, self.message = inner, rule, message

    def check(self, value, label, rule):
        try:
            return self.inner.check(value, label, self.rule)
        except Refusal as refusal:
            raise Refusal(self.rule, "%s (%s)" % (self.message.replace("{value!r}", repr(value)),
                                                  refusal.detail)) from None


class ListOf(Kind):
    def __init__(self, inner, low=0, high=None, item=None):
        self.inner, self.low, self.high, self.item = inner, low, high, item

    def check(self, value, label, rule):
        require(type(value) is list, rule, "%s has type %s: %r" % (label, _tname(value), value))
        require(len(value) >= self.low and (self.high is None or len(value) <= self.high), rule,
                "%s has %d entries: %r" % (label, len(value), value))
        for item in value:
            self.inner.check(item, self.item or label, rule)
        return value


class Record(Kind):
    """A JSON object: required and optional keys, each typed; `closed`
    refuses any other key. Records declare their own rule."""

    def __init__(self, name, required, optional=None, closed=True, rule=None):
        self.name = name
        self.required = required
        self.optional = optional or {}
        self.closed = closed
        self.rule = rule or declare("record." + name, "a %s record has its exact keys and types" % name)

    def check(self, value, label=None, rule=None):
        label = label or self.name
        rule = self.rule
        require(type(value) is dict, rule, "%s has type %s: %r" % (label, _tname(value), value))
        for key, spec in self.required.items():
            kind, key_label = spec[:2]
            item = value.get(key, MISSING)
            if item is MISSING and spec[2:] == (ABSENT_AS_NULL,):
                # Read like the absent value it is: a missing key reports
                # as a null of the wrong type.
                item = None
            require(item is not MISSING, rule, "%s missing" % key_label)
            kind.check(item, key_label, rule)
        for key, spec in self.optional.items():
            kind, key_label = spec[:2]
            if key in value:
                kind.check(value[key], key_label, rule)
        if self.closed:
            extra = sorted(set(value) - set(self.required) - set(self.optional))
            require(not extra, rule, "%s has unknown keys %r" % (label, extra))
        return value


U64 = Unsigned()
PID = Unsigned(1, PID_MAX)
STR = Exact(str)
BOOL = Exact(bool)


# -- run binding ---------------------------------------------------------

FRESH_RUN = declare("fresh.run", "the run stamp names this run id and cell")
FRESH_FILE = declare("fresh.file", "every input is a regular file written at or after this run's stamp")
FRESH_PRIVATE = declare("fresh.private", "every product report is read from this run's private output directory")
# The shell gives each invocation a private producer-output directory named
# by its random run id (scripts/qualify-public-cli.sh setup_local_output).
PRIVATE_PREFIX = "run-"

STAMP = Record("stamp", {"schema": (OneOf(STAMP_SCHEMA), "stamp schema"),
                         "run_id": (STR, "stamp run_id"),
                         "cell": (STR, "stamp cell")})


def write_stamp(path, run_id, cell):
    data = json.dumps({"schema": STAMP_SCHEMA, "run_id": run_id, "cell": cell}) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as handle:
        handle.write(data)


def open_regular(path, rule, what):
    """One open descriptor: its metadata and its bytes are the same file
    (no symlink is followed and a FIFO never blocks)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise Refusal(rule, "%s %s missing" % (what, path)) from None
    except OSError as error:
        raise Refusal(rule, "%s %s is not a regular file (%s)" % (what, path, error.strerror)) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal(rule, "%s %s is not a regular file" % (what, path))
    except BaseException:
        os.close(fd)  # every refusal and failure after the open closes it (hungerg r11e #3)
        raise
    return fd, info


def read_bounded(path, rule, what, limit, newer_than_ns=None):
    """Every file read: one descriptor, at most `limit` bytes. A file with
    more bytes than the limit refuses under `rule`; it is never truncated
    to a prefix. With `newer_than_ns`, an input older than that refuses."""
    fd, info = open_regular(path, rule, what)
    chunks = []
    try:
        if newer_than_ns is not None:
            require(info.st_mtime_ns >= newer_than_ns, rule,
                    "%s %s predates this run's stamp (stale)" % (what, path))
        # The bytes read from this descriptor decide the size, not a
        # metadata size that could change after fstat. Unbuffered: the
        # descriptor never reads more than limit + 1 bytes.
        budget = limit + 1
        while budget > 0:
            chunk = os.read(fd, min(budget, READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    require(len(data) <= limit, rule, "%s %s exceeds the %d-byte limit" % (what, path, limit))
    return data, info


def decode_text(data, rule, what, path, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeDecodeError:
        raise Refusal(rule, "%s %s is not %s" % (what, path, encoding)) from None


class Run:
    """The current run: its stamp time bounds every input below."""

    def __init__(self, stamp_path, run_id, cell):
        data, info = read_bounded(stamp_path, FRESH_RUN, "run stamp", MAX_STAMP_BYTES)
        stamp = STAMP.check(strict_json(decode_text(data, FRESH_RUN, "run stamp", stamp_path), "run stamp"))
        require(stamp["run_id"] == run_id and run_id != "", FRESH_RUN,
                "run stamp run id %r is not this run %r" % (stamp["run_id"], run_id))
        require(stamp["cell"] == cell, FRESH_RUN,
                "run stamp cell %r is not %r" % (stamp["cell"], cell))
        self.stamp_ns = info.st_mtime_ns
        self.run_id = run_id

    def read_product(self, path, what, binary=False):
        """A product report: only from this run's private output
        directory (a real directory named by the run id), so another
        invocation's report never qualifies this run."""
        parent = os.path.dirname(os.path.abspath(path))
        require(os.path.basename(parent) == PRIVATE_PREFIX + self.run_id, FRESH_PRIVATE,
                "%s %s is outside this run's private output directory" % (what, path))
        info = os.lstat(parent)
        require(stat.S_ISDIR(info.st_mode), FRESH_PRIVATE,
                "%s %s: the private output directory is not a real directory" % (what, path))
        return self.read(path, what, binary)

    def read(self, path, what, binary=False):
        data, _ = read_bounded(path, FRESH_FILE, what, MAX_INPUT_BYTES, self.stamp_ns)
        return data if binary else decode_text(data, FRESH_FILE, what, path)


ARG_INT = declare("arg.integer", "every numeric argument is an exact decimal integer")


def arg_int(text, what, low=0, high=U64_LIMIT - 1):
    require(re.fullmatch(r"0|-?[1-9][0-9]*", text or "") is not None, ARG_INT,
            "%s argument is not a decimal integer: %r" % (what, text))
    value = int(text)
    require(low <= value <= high, ARG_INT, "%s argument out of range: %r" % (what, text))
    return value


# -- shared product records ----------------------------------------------

STDOUT_LOST = Record("stdout-lost", {"lines": (U64, "stdout_lost lines"),
                                     "bytes": (U64, "stdout_lost bytes")})
SHED_REASONS = ("broken_pipe", "slow_reader", "write_error", "zero_write", "invalid_descriptor")
EVENT_OUTPUT_RULE = declare("record.event-output", "event_output has exactly its four typed fields")
EVENT_OUTPUT_CONSISTENT = declare(
    "event-output.consistent",
    "complete means zero loss and reason none; truncated means at least one lost line, "
    "at least one byte per lost line and a shed reason; failed means event_log_error")


EVENT_OUTPUT_FIELDS = {"status": OneOf("complete", "truncated", "failed"), "lines_lost": U64,
                       "bytes_lost": U64, "reason": OneOf("none", "event_log_error", "unknown", *SHED_REASONS)}


def event_output(report, what):
    """The report's typed event-log outcome: exactly its four fields with
    exact types (a bool is not a count), then its own consistency."""
    outcome = report.get("event_output")
    require_type(type(outcome) is dict, EVENT_OUTPUT_RULE, "%s report event_output %r" % (what, outcome))
    require_type(set(outcome) == set(EVENT_OUTPUT_FIELDS), EVENT_OUTPUT_RULE,
            "%s event_output fields %r" % (what, sorted(outcome)))
    for key, kind in EVENT_OUTPUT_FIELDS.items():
        Decided(kind, EVENT_OUTPUT_RULE, "%s event_output %s %r" % (what, key, outcome[key])).check(
            outcome[key], "event_output " + key, None)
    return outcome


def check_event_output_consistent(outcome, what):
    status, lines, size, reason = (outcome["status"], outcome["lines_lost"],
                                   outcome["bytes_lost"], outcome["reason"])
    if status == "complete":
        ok = lines == 0 and size == 0 and reason == "none"
    elif status == "truncated":
        ok = lines >= 1 and size >= lines and reason in SHED_REASONS
    else:
        ok = reason == "event_log_error"
    require(ok, EVENT_OUTPUT_CONSISTENT, "%s event_output contradicts itself: %r" % (what, outcome))
    return outcome


# -- second SIGINT --------------------------------------------------------

# The producer's QuiescenceState (src/render.rs, serde snake_case).
STOP_STATES = ("not_reached", "proven", "unproven")
SIGINT_EXIT = declare("sigint.exit", "the observer exits 130 after the second SIGINT")
SIGINT_CUSTODY = declare("sigint.custody", "the owned child was in custody and every owned process was collected")
SIGINT_PARTIAL = declare("sigint.partial", "an abandoned teardown never seals COMPLETE")
SIGINT_DRAIN = declare("sigint.drain-proof", "drain_proven equals the stop-gate evidence")
SIGINT_SAMPLES = declare("sigint.drain-samples", "the report carries this capture's live-loop drain samples")
SIGINT_CHILD = declare("sigint.child-settled", "the owned child is settled, not still running")
SIGINT_CLEANUP = declare("sigint.cleanup-line", "stderr carries exactly one full line 'p11scope: cleanup incomplete'")
SIGINT_PANIC = declare("sigint.no-panic", "stderr never reports a panic")
PROFILE = Record("observed-profile", {
    "schema": (OneOf("p11scope/observed-profile/v3"), "schema"),
    "evidence": (Record("profile-evidence", {
        "completeness": (STR, "evidence completeness"),
        "stop_quiescence": (Record("stop-quiescence", {
            "state": (OneOf(*STOP_STATES), "stop_quiescence state"),
            "post_q_events": (BOOL, "stop_quiescence post_q_events"),
            "post_q_discovery": (BOOL, "stop_quiescence post_q_discovery")}, closed=False),
            "evidence stop_quiescence"),
        "drain_proven": (BOOL, "evidence drain_proven"),
        "scheduling": (Decided(Record("profile-scheduling", {
            "inter_drain_gap": (Record("inter-drain-gap", {
                "samples": (Unsigned(1), "inter_drain_gap samples")}, closed=False, rule=SIGINT_SAMPLES),
                "scheduling inter_drain_gap")}, closed=False, rule=SIGINT_SAMPLES),
            SIGINT_SAMPLES, "report must carry this capture live-loop drain samples"),
            "evidence scheduling", ABSENT_AS_NULL),
        "child_still_running": (Decided(BOOL, SIGINT_CHILD, "owned child must be settled, not still running"),
                                "evidence child_still_running", ABSENT_AS_NULL)}, closed=False), "evidence")},
    closed=False)
CLEANUP_LINE = "p11scope: cleanup incomplete"


def judge_second_sigint(args):
    run = Run(args.stamp, args.run_id, "second-sigint")
    rc = arg_int(args.rc, "rc", 0, 255)
    custody = arg_int(args.custody, "custody", 0, 1)
    cleanup = arg_int(args.cleanup, "cleanup", 0, 1)
    report = PROFILE.check(strict_json(run.read_product(args.report, "profile report"), "profile report"))
    stderr = run.read(args.stderr, "observer stderr")
    require(rc == 130, SIGINT_EXIT, "observer rc=%d, expected 130" % rc)
    require(custody == 1 and cleanup == 1, SIGINT_CUSTODY,
            "child custody=%d cleanup complete=%d" % (custody, cleanup))
    evidence = report["evidence"]
    require(evidence["completeness"] == "PARTIAL", SIGINT_PARTIAL, "abandoned teardown cannot seal COMPLETE")
    stop = evidence["stop_quiescence"]
    proven = stop["state"] == "proven" and stop["post_q_events"] is False and stop["post_q_discovery"] is False
    require(evidence["drain_proven"] is proven, SIGINT_DRAIN, "drain_proven must match the stop-gate evidence")
    require(evidence["child_still_running"] is False, SIGINT_CHILD, "owned child must be settled, not still running")
    lines = stderr.split("\n")
    require(lines.count(CLEANUP_LINE) == 1, SIGINT_CLEANUP,
            "stderr has %d exact %r lines" % (lines.count(CLEANUP_LINE), CLEANUP_LINE))
    require("panicked" not in stderr, SIGINT_PANIC, "observer stderr reports a panic")
    return "second SIGINT settled: rc=130, PARTIAL, child settled"


# -- FIFO refusal ----------------------------------------------------------

FIFO_RC = declare("fifo.exit", "the refused observer exits nonzero (not a timeout or a harness code)")
FIFO_KEPT = declare("fifo.kept", "the FIFO destination is still a FIFO")
FIFO_LINE = declare("fifo.refusal-line", "stderr carries exactly one full product refusal line")
FIFO_REFUSAL = ("p11scope: output {path} exists and is a FIFO; refusing to replace it (-o publishes "
                "the report by renaming a new file over that name). Name a new or regular file, or "
                "leave out -o to write no report file")


def judge_fifo(args):
    run = Run(args.stamp, args.run_id, "fifo-refused")
    rc = arg_int(args.rc, "rc", 0, 255)
    require(rc not in (0, 124, 125), FIFO_RC, "observer rc=%d" % rc)
    info = os.lstat(args.fifo) if os.path.lexists(args.fifo) else None
    require(info is not None and stat.S_ISFIFO(info.st_mode), FIFO_KEPT, "%s is no longer a FIFO" % args.fifo)
    lines = run.read(args.stderr, "observer stderr").split("\n")
    want = FIFO_REFUSAL.format(path=args.fifo)
    require(lines.count(want) == 1, FIFO_LINE, "stderr has %d exact refusal lines" % lines.count(want))
    return "rc=%d" % rc


# -- cgroup membership ------------------------------------------------------

MEMBER_LINES = declare("cgroup.procs-lines", "cgroup.procs is one decimal pid per line")
MEMBER_ONCE = declare("cgroup.procs-once", "the moved pid is listed exactly once")
MEMBER_READ = declare("cgroup.procs-read", "cgroup.procs is one regular file within the size limit")


def judge_cgroup_member(args):
    pid = arg_int(args.pid, "pid", 1, PID_MAX)
    data, _ = read_bounded(args.procs, MEMBER_READ, "cgroup.procs", MAX_INPUT_BYTES)
    text = decode_text(data, MEMBER_LINES, "cgroup.procs", args.procs, "ascii")
    rows = text.split("\n")
    if rows and rows[-1] == "":
        rows.pop()
    for row in rows:
        require(re.fullmatch(r"[1-9][0-9]*", row) is not None, MEMBER_LINES,
                "cgroup.procs line is not a pid: %r" % (row,))
    require(rows.count(str(pid)) == 1, MEMBER_ONCE, "pid %d listed %d times" % (pid, rows.count(str(pid))))
    return "pid %d in cgroup" % pid


# -- event stdout -----------------------------------------------------------

EVENT_SCHEMA = "p11scope/inventory-events/v1"
EVENT_NO_LOSS = declare("event.full-no-loss", "the full run lost nothing: every totals and ended stdout_lost is zero")
EVENT_ROW = Record("event-row", {
    "schema": (OneOf(EVENT_SCHEMA), "row schema"),
    "seq": (U64, "row seq"),
    "at_ns": (U64, "row at_ns"),
    "kind": (STR, "row kind"),
    "event": (Exact(dict), "row event")})
COUNTS = {"callers": (U64, "callers"), "modules": (U64, "modules"), "edges": (U64, "edges")}
PASS_EVENT = Record("pass-committed", {"pass": (U64, "pass_committed pass"),
                                       "totals": (Record("pass-totals", dict(COUNTS)), "pass_committed totals")},
                    closed=False)
TOTALS_EVENT = Record("totals-event", dict(COUNTS, **{
    "pass": (U64, "totals pass"), "passes": (U64, "totals passes"),
    "stdout_lost": (STDOUT_LOST, "totals stdout_lost")}), closed=False)
ENDED_EVENT = Record("ended-event", {
    "passes": (U64, "ended passes"),
    "stdout_lost": (Decided(STDOUT_LOST, "event.full-no-loss", "full run ended stdout_lost {value!r}"),
                    "ended stdout_lost", ABSENT_AS_NULL)}, closed=False)
EPIPE_DOC = Record("early-close-document", {"schema": (OneOf("p11scope/inventory/v1"), "report schema")},
                   closed=False)
INVENTORY_DOC = Record("inventory-document", {
    "schema": (OneOf("p11scope/inventory/v1"), "report schema"),
    "observation": (Record("observation", {"passes": (U64, "observation passes")}, closed=False),
                    "report observation"),
    "callers": (ListOf(Exact(dict)), "report callers"),
    "modules": (ListOf(Exact(dict)), "report modules"),
    "edges": (ListOf(Exact(dict)), "report edges")}, closed=False)
EVENT_FULL_EXIT = declare("event.full-exit", "the full run exits 0")
EVENT_JSONL = declare("event.jsonl", "stdout is pure JSONL: no blank or partial line")
EVENT_SEQ = declare("event.seq", "rows are sequenced from 0 without a gap")
EVENT_FRAME = declare("event.framing", "the stream opens with started and closes with ended")
EVENT_PASSES = declare("event.report-passes", "the report and ended agree on the pass count")
EVENT_FINAL = declare("event.report-totals", "the report's callers, modules and edges equal the last pass totals")
EVENT_CADENCE_COUNT = declare("event.totals-count", "a 6 s run at a 2 s interval publishes 1..4 totals")
EVENT_MARKER = declare("event.totals-marker", "each totals follows a pass marker and repeats its pass and counts")
EVENT_CADENCE = declare("event.totals-cadence", "totals are at least one interval apart, from started")
EVENT_FULL_OUTPUT = declare("event.full-output", "the full run's report says complete")
EVENT_EARLY_EXIT = declare("event.early-exit", "the early-closed run exits 1")
EVENT_EARLY_HEAD = declare("event.early-head", "the reader received event bytes before closing")
EVENT_EARLY_OUTPUT = declare("event.early-output", "the early-closed run's report says truncated by a broken pipe")
INTERVAL_NS = 2_000_000_000


def load_event_stream(text):
    rows = []
    lines = text.split("\n")
    require(lines[-1] == "", EVENT_JSONL, "stream does not end with a newline")
    for number, line in enumerate(lines[:-1]):
        require(line != "", EVENT_JSONL, "line %d: blank line breaks the JSONL framing" % number)
        row = EVENT_ROW.check(strict_json(line, "event line %d" % number), "event line %d" % number)
        rows.append(row)
    return rows


def judge_event_stdout(args):
    run = Run(args.stamp, args.run_id, "inventory-event-stdout")
    rc1 = arg_int(args.rc1, "rc1", 0, 255)
    rc2 = arg_int(args.rc2, "rc2", 0, 255)
    require(rc1 == 0, EVENT_FULL_EXIT, "full run rc=%d" % rc1)
    stream = load_event_stream(run.read(args.jsonl, "event stream"))
    require(len(stream) >= 3, EVENT_FRAME, "started, a pass marker and ended: %d rows" % len(stream))
    for index, row in enumerate(stream):
        require(row["seq"] == index, EVENT_SEQ, "seq %s != %s" % (row["seq"], index))
    require(stream[0]["kind"] == "started" and stream[-1]["kind"] == "ended",
            EVENT_FRAME, "stream is not started ... ended: %r %r" % (stream[0], stream[-1]))
    for row in stream:
        if row["kind"] == "pass_committed":
            PASS_EVENT.check(row["event"], "pass_committed event")
        elif row["kind"] == "totals":
            TOTALS_EVENT.check(row["event"], "totals event")
    ended = ENDED_EVENT.check(stream[-1]["event"], "ended event")
    report = INVENTORY_DOC.check(strict_json(run.read_product(args.full_report, "full report"), "full report"))
    require(report["observation"]["passes"] == ended["passes"], EVENT_PASSES,
            "passes agree: report %d, ended %d" % (report["observation"]["passes"], ended["passes"]))
    markers = [row["event"] for row in stream if row["kind"] == "pass_committed"]
    require(markers, EVENT_FINAL, "no pass marker")
    for key in ("callers", "modules", "edges"):
        require(len(report[key]) == markers[-1]["totals"][key], EVENT_FINAL,
                repr((key, len(report[key]), markers[-1]["totals"])))
    totals = [(position, row) for position, row in enumerate(stream) if row["kind"] == "totals"]
    require(1 <= len(totals) <= 4, EVENT_CADENCE_COUNT, "totals count %d" % len(totals))
    last_at = stream[0]["at_ns"]
    for position, row in totals:
        before = [r["event"] for r in stream[:position] if r["kind"] == "pass_committed"]
        require(before, EVENT_MARKER, "totals before any pass marker: %r" % (row,))
        marker, event = before[-1], row["event"]
        require(marker["pass"] == event["pass"] and event["passes"] == event["pass"] + 1, EVENT_MARKER,
                repr((marker["pass"], event)))
        for key in ("callers", "modules", "edges"):
            require(event[key] == marker["totals"][key], EVENT_MARKER, repr((key, event, marker["totals"])))
        require(row["at_ns"] - last_at >= INTERVAL_NS, EVENT_CADENCE,
                "totals at_ns %d is not one interval after %d: %r" % (row["at_ns"], last_at, row))
        last_at = row["at_ns"]
        require(event["stdout_lost"] == {"lines": 0, "bytes": 0}, EVENT_NO_LOSS,
                "full run totals stdout_lost %r" % (event["stdout_lost"],))
    full = event_output(report, "full")
    require(full == {"status": "complete", "lines_lost": 0, "bytes_lost": 0, "reason": "none"},
            EVENT_FULL_OUTPUT, "full run event_output %r" % (full,))
    check_event_output_consistent(full, "full")
    require(ended["stdout_lost"] == {"lines": 0, "bytes": 0}, EVENT_NO_LOSS,
            "full run ended stdout_lost %r" % (ended["stdout_lost"],))
    require(rc2 == 1, EVENT_EARLY_EXIT, "early-close rc=%d" % rc2)
    head = run.read(args.epipe_head, "early-close head", binary=True)
    require(head[:1] == b"{", EVENT_EARLY_HEAD, "the head holds event bytes")
    epipe = EPIPE_DOC.check(strict_json(run.read_product(args.epipe_report, "early-close report"),
                                        "early-close report"))
    lost = event_output(epipe, "early-close")
    require(lost["status"] == "truncated" and lost["reason"] == "broken_pipe", EVENT_EARLY_OUTPUT,
            "early-close event_output %r" % (lost,))
    require(lost["lines_lost"] >= 1 and lost["bytes_lost"] >= lost["lines_lost"], EVENT_EARLY_OUTPUT,
            "early-close event_output counts %r" % (lost,))
    check_event_output_consistent(lost, "early-close")
    return "ok lines=%d totals=%d" % (len(stream), len(totals))


# -- cgroup inventory -------------------------------------------------------

LEDGER_SCHEMA = "p11scope/public-cli-ledger/v1"
LEDGER_FUNCTIONS = ["C_GenerateRandom", "C_DigestInit", "C_Digest",
                    "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]


def ledger_record_kind(what):
    # The fixture ledgers (cgroup-fork inside, gated outside) are closed
    # producer records. Attempts and successes are typed by the ledger
    # relation rules below (exact u64 ints there, with their messages).
    function = Record("%s-ledger-function" % what, {
        "name": (STR, "%s ledger function name" % what),
        "attempts": (Anything(), "%s ledger function attempts" % what),
        "successful": (Anything(), "%s ledger function successful" % what)})
    return Record("%s-ledger" % what, {
        "schema": (OneOf(LEDGER_SCHEMA), "%s ledger schema" % what),
        "pid": (PID, "%s ledger pid" % what),
        "complete": (Anything(), "%s ledger complete" % what),
        "functions": (ListOf(function, item="%s ledger function" % what), "%s ledger functions" % what)})


INSIDE_LEDGER = ledger_record_kind("inside")
OUTSIDE_LEDGER = ledger_record_kind("outside")
N = ABSENT_AS_NULL
CALLER = Record("caller", {
    "id": (STR, "caller id", N), "pid": (PID, "caller pid", N),
    "start_time": (U64, "caller start_time", N), "start_time_unit": (STR, "caller start_time_unit", N),
    "retired": (BOOL, "caller retired", N),
    "image": (Record("caller-image", {"authority": (STR, "caller authority", N)}, closed=False),
              "caller image", N)}, closed=False)
MODULE = Record("module", {
    "id": (STR, "module id", N),
    "identity": (Record("module-identity", {
        "device": (Record("module-device", {"major": (U64, "module device major"),
                                            "minor": (U64, "module device minor")}, closed=False),
                   "module device"),
        "inode": (U64, "module inode"),
        "sha256": (Nullable(STR), "module sha256")}, closed=False), "module identity"),
    "admission": (Record("module-admission", {"state": (STR, "module admission state")}, closed=False),
                  "module admission")}, closed=False)
EDGE = Record("edge", {
    "caller": (STR, "edge caller", N), "module": (STR, "edge module", N),
    "entries": (Record("edge-entries", {
        "count": (U64, "edge count", N),
        "coverage": (Record("edge-coverage", {"state": (STR, "edge coverage state", N),
                                              "lossy": (Nullable(BOOL), "edge coverage lossy")},
                            closed=False), "edge coverage", N),
        "observation": (STR, "edge observation", N),
        "saturated": (BOOL, "edge saturated", N),
        "in_flight": (BOOL, "edge in_flight", N)}, closed=False), "edge entries", N)}, closed=False)
GAP = Record("gap", {
    "caller": (Nullable(STR), "gap caller"), "pid": (Nullable(PID), "gap pid"),
    "module": (Nullable(STR), "gap module"), "subject": (STR, "gap subject"),
    "reason": (Nullable(STR), "gap reason")}, closed=False)
CGROUP_REPORT = Record("cgroup-report", {
    "schema": (OneOf("p11scope/inventory/v1"), "inventory schema"),
    "scope": (STR, "inventory scope"),
    "callers": (ListOf(CALLER, item="caller"), "callers", N),
    "modules": (ListOf(MODULE, item="module"), "modules", N),
    "edges": (ListOf(EDGE, item="edge"), "edges", N),
    "gaps": (ListOf(GAP, item="gap"), "gaps", N)}, closed=False)
PIN = Record("provider-pin", {"dev": (Decided(ListOf(U64, 2, 2), "record.provider-pin",
                                               "pin dev is not [major, minor]: {value!r}"), "pin dev"),
                              "ino": (U64, "pin ino"),
                              "sha256": (STR, "pin sha256")}, closed=False)

CG_SCOPE = declare("cgroup.scope", "the report is a cgroup-scope inventory")
WL_PROTOCOL = declare("workload.protocol", "each workload prints exactly one READY (inside: one CHILD) line 'TAG pid=<pid>'")
WL_LEDGER_LINE = declare("workload.ledger-line", "each workload prints exactly one LEDGER line")
WL_LAUNCHED = declare("workload.launched", "the protocol pids are the launched and registered processes")
WL_DISTINCT = declare("workload.distinct", "the inside parent, fork child and outside workload are three distinct processes")
WL_GENERATION = declare("workload.generation", "each inside member has a registered decimal generation")
CG_UNIQUE = declare("cgroup.unique-ids", "caller and module ids are unique")
CG_OWNED = declare("cgroup.owned-module", "the owned provider (pin identity, exact types) is inventoried")
CG_ADMISSION = declare("cgroup.owned-admission", "the owned provider is admitted (overlayfs: admitted or unresolved)")
LEDGER_COMPLETE = declare("ledger.complete", "both workload ledgers are complete")
LEDGER_FUNCS = declare("ledger.functions", "both ledgers list the six driven calls in order")
LEDGER_SUCCESS = declare("ledger.successes", "every attempt of every ledger row succeeded, exactly")
LEDGER_INSIDE = declare("ledger.inside-attempts", "inside attempts are equal per call and two members of the launched iterations")
LEDGER_OUTSIDE = declare("ledger.outside-attempts", "outside attempts equal the launched iterations")
CG_EXCLUDED = declare("cgroup.outside-excluded", "the outside workload is not inventoried")
CG_INSIDE_EDGE = declare("cgroup.inside-edge", "an inside caller has an edge to the owned module")
CG_NO_EXTRA = declare("cgroup.no-extra-caller", "every caller is an inside member")
CG_ONCE = declare("cgroup.member-once", "each inside member is exactly one caller incarnation")
CG_NO_ORPHAN = declare("cgroup.no-orphan-edge", "every edge belongs to an inside member")
GAP_UNCLASSIFIED = declare("gap.unclassified", "every gap is one named allowance")
GAP_ACTIVATION = declare("gap.activation", "an activation refusal binds a workload caller that recovered native_exact")
GAP_RETAINED = declare("gap.retained", "a retained-refresh refusal binds a workload caller, at most once, with a run deadline")
GAP_DEADLINE = declare("gap.deadline", "the collection deadline gap is unattributed")
GAP_ADMISSION = declare("gap.admission-note", "an admission note binds a workload caller and names an upward transition")
GAP_PREP = declare("gap.prep", "an interrupted-preparation row carries its exact shape, deduped, with a run deadline")
GAP_UNPROVEN = declare("gap.unproven-cover", "the degraded shape names exactly one unproven gap per inside member")
CG_GENERATION = declare("cgroup.generation", "each member caller is the registered generation in clock ticks")
CG_LIVE = declare("cgroup.live", "no member caller is retired at report time")
CG_AUTHORITY = declare("cgroup.authority", "each member caller ends native_exact")
CG_EDGE = declare("cgroup.owned-edge", "each member has exactly its one owned edge")
CG_EXACT = declare("cgroup.exact-count", "each owned edge is counted exactly at what the member drove")

ACTIVATION = "native owner activation refused"
UNPROVEN = "original_file_unproven: kernel witness unavailable"
DEADLINE = "cgroup collection deadline reached"
RETAINED = "the final-sample permit was not granted; prior owner facts retained"
DEFERRED_REASON = ("only one native owner activation per transaction; the staged owner is deferred to a "
                   "later pass; scan-pinned fallback retained")
SETTLE_REASON = ("no settled expected native image for this caller in the acquisition domain; "
                 "scan-pinned fallback retained")
ACTIVATION_REFUSALS = {DEFERRED_REASON: "deferred activation never recovered",
                       SETTLE_REASON: "native activation never recovered"}
PREP_SUBJECT = "cgroup provider preparation incomplete"
# The producer files eight reasons under this subject and shape
# (src/discovery/inventory_attach_set.rs prepare_absorption). A ninth
# reason — or a prep reason under another subject — stays unclassified.
PREP_REASONS = frozenset([
    "cgroup provider preparation input ceiling reached",
    "cgroup provider preparation interrupted or allowance exhausted",
    "cgroup provider preparation interrupted after retention",
    "cgroup provider resolution interrupted",
    "cgroup provider preparation comparison ceiling reached",
    "cgroup provider identity comparison interrupted",
    "cgroup provider input comparison interrupted",
    "cgroup provider preparation interrupted before completion",
])
TRANSITIONS = ("unresolved to refused", "unresolved to admitted", "refused to admitted")
EXACT_ENTRIES = {"state": "counted", "lossy": False, "observation": "observed",
                 "saturated": False, "in_flight": False}


def protocol_pid(text, tag, what):
    rows = [line for line in text.split("\n") if line.startswith(tag + " ")]
    require(len(rows) == 1, WL_PROTOCOL, "%s workload printed %d %s lines" % (what, len(rows), tag))
    match = re.fullmatch(tag + r" pid=([1-9][0-9]*)", rows[0])
    require(match is not None, WL_PROTOCOL, "%s workload %s line malformed: %r" % (what, tag, rows[0]))
    value = int(match.group(1))
    require(value <= PID_MAX, WL_PROTOCOL, "%s workload %s pid out of range: %r" % (what, tag, rows[0]))
    return value


def ledger_line(text, what, kind):
    rows = [line for line in text.split("\n") if line.startswith("LEDGER ")]
    missing = "outside ledger missing (leak test invalid)" if what == "outside" else "inside ledger missing"
    require(len(rows) == 1, WL_LEDGER_LINE, "%s: %d LEDGER lines, expected one" % (missing, len(rows)))
    return kind.check(strict_json(rows[0][len("LEDGER "):], "%s ledger" % what), "%s ledger" % what)


def check_ledger(record, what, pid):
    require(record["pid"] == pid, WL_LAUNCHED, "%s ledger pid %r is not the workload %d" % (what, record["pid"], pid))
    require(record["complete"] is True, LEDGER_COMPLETE,
            ("inside ledger incomplete: driven counts unknown: %r" if what == "inside"
             else "outside ledger incomplete: exclusion control unproven: %r") % (record,))


def check_ledger_names(record, what):
    for function in record["functions"]:
        # Exact int here; its range follows from equality with the
        # u64-typed attempts.
        Decided(Exact(int), LEDGER_SUCCESS, "%s ledger function successful has type %s: %r"
                % (what, type(function["successful"]).__name__, function["successful"])).check(
            function["successful"], "%s ledger function successful" % what, None)
        require(function["successful"] == function["attempts"], LEDGER_SUCCESS,
                "%s ledger %r successful %r of %r attempts" % (what, function["name"], function["successful"],
                                                               function["attempts"]))
    names = [function["name"] for function in record["functions"]]
    require(names == LEDGER_FUNCTIONS, LEDGER_FUNCS,
            "%s ledger functions are not the six driven calls: %r" % (what, names))


def judge_cgroup_inventory(args):
    run = Run(args.stamp, args.run_id, args.cell)
    inside_iters = arg_int(args.inside_iters, "inside iterations", 1)
    outside_iters = arg_int(args.outside_iters, "outside iterations", 1)
    launched_inside = arg_int(args.inside_pid, "inside pid", 1, PID_MAX)
    launched_outside = arg_int(args.outside_pid, "outside pid", 1, PID_MAX)
    modpath, modfs = args.module, args.module_fs
    report = CGROUP_REPORT.check(strict_json(run.read_product(args.report, "inventory report"), "inventory report"))
    inside = run.read(args.inside_wl, "inside workload log")
    outside = run.read(args.outside_wl, "outside workload log")
    pin = PIN.check(strict_json(args.pin, "provider pin"))
    require(report["scope"] == "cgroup", CG_SCOPE, "inventory scope %r" % (report["scope"],))
    inside_pid = protocol_pid(inside, "READY", "inside")
    child_pid = protocol_pid(inside, "CHILD", "inside")
    outside_pid = protocol_pid(outside, "READY", "outside")
    inside_ledger = ledger_line(inside, "inside", INSIDE_LEDGER)
    outside_ledger = ledger_line(outside, "outside", OUTSIDE_LEDGER)
    roles = {"inside parent": inside_pid, "fork child": child_pid, "outside workload": outside_pid}
    require(len(set(roles.values())) == 3, WL_DISTINCT, "workload roles share a process: %r" % (roles,))
    require(inside_pid == launched_inside and outside_pid == launched_outside, WL_LAUNCHED,
            "READY pids %d/%d are not the launched %d/%d" % (inside_pid, outside_pid,
                                                              launched_inside, launched_outside))
    registered_child = arg_int(args.child_pid, "registered child pid", 0, PID_MAX) if args.child_pid else 0
    require(registered_child == child_pid, WL_LAUNCHED,
            "CHILD pid %d is not the registered owned child %r" % (child_pid, args.child_pid))
    generations = {}
    for label, text in (("inside parent", args.inside_gen), ("fork child", args.child_gen)):
        require(re.fullmatch(r"0|[1-9][0-9]*", text or "") is not None, WL_GENERATION,
                "%s generation not recorded: %r" % (label, text))
        generations[label] = int(text)
    for kind in ("callers", "modules"):
        ids = [x["id"] for x in report[kind]]
        require(len(ids) == len(set(ids)), CG_UNIQUE, "duplicate %s id: %r" % (kind[:-1], ids))
    owned = None
    for module in report["modules"]:
        ident = module["identity"]
        if ([ident["device"]["major"], ident["device"]["minor"]] == pin["dev"] and ident["inode"] == pin["ino"]
                and ident["sha256"] == pin["sha256"]):
            owned = module
            break
    require(owned is not None, CG_OWNED,
            "owned provider not inventoried (modfs=%s): empty view never qualifies" % modfs)
    owned_id, state = owned["id"], owned["admission"]["state"]
    if modfs == "overlayfs":
        require(state in ("admitted", "unresolved"), CG_ADMISSION, "overlay owned provider admission: %r" % state)
    else:
        require(state == "admitted", CG_ADMISSION, "owned provider not admitted")
    check_ledger(inside_ledger, "inside", inside_pid)
    functions = inside_ledger["functions"]
    attempts = {(type(function["attempts"]), json.dumps(function["attempts"])) for function in functions}
    require(len(functions) == 6 and len(attempts) == 1, LEDGER_INSIDE,
            "inside ledger attempts differ per function: %r" % (inside_ledger,))
    total = functions[0]["attempts"]
    require(type(total) is int and 0 < total < U64_LIMIT and total % 2 == 0, LEDGER_INSIDE,
            "inside ledger attempts not split per member: %r" % (total,))
    check_ledger_names(inside_ledger, "inside")
    require(total == 2 * inside_iters, LEDGER_INSIDE,
            "inside ledger attempts %d are not two members of %d launched iterations" % (total, inside_iters))
    driven = 6 * inside_iters + 7
    check_ledger(outside_ledger, "outside", outside_pid)
    check_ledger_names(outside_ledger, "outside")
    for function in outside_ledger["functions"]:
        Decided(U64, LEDGER_OUTSIDE, "outside ledger function attempts has type %s: %r"
                % (type(function["attempts"]).__name__, function["attempts"])).check(
            function["attempts"], "outside ledger function attempts", None)
        require(function["attempts"] == outside_iters, LEDGER_OUTSIDE,
                "outside ledger %s attempts %r, drove %d" % (function["name"], function["attempts"], outside_iters))
    edges = report["edges"]
    records = [{"id": c["id"], "pid": c["pid"], "start_time": c["start_time"],
                "start_time_unit": c["start_time_unit"], "retired": c["retired"],
                "authority": c["image"]["authority"],
                "edges": [(e["module"], {"count": e["entries"]["count"],
                                         "state": e["entries"]["coverage"]["state"],
                                         "lossy": e["entries"]["coverage"]["lossy"],
                                         "observation": e["entries"]["observation"],
                                         "saturated": e["entries"]["saturated"],
                                         "in_flight": e["entries"]["in_flight"]})
                          for e in edges if e["caller"] == c["id"]]} for c in report["callers"]]
    require(not [r for r in records if r["pid"] == outside_pid], CG_EXCLUDED,
            "outside workload leaked into cgroup inventory")
    require(any(r["pid"] in (inside_pid, child_pid) and m == owned_id for r in records for m, _ in r["edges"]),
            CG_INSIDE_EDGE, "no inside edge to owned module")
    extra = [r for r in records if r["pid"] not in (inside_pid, child_pid)]
    require(not extra, CG_NO_EXTRA, "unexpected caller outside the workload: %r" % (extra,))
    expected = [("inside parent", inside_pid), ("fork child", child_pid)]
    row = {}
    for label, pid in expected:
        found = [r for r in records if r["pid"] == pid]
        require(len(found) == 1, CG_ONCE,
                "%s has %d caller incarnations, expected one: %r" % (label, len(found), found))
        row[label] = found[0]
    workload = {r["id"]: r for r in row.values()}
    orphans = [e for e in edges if e["caller"] not in workload]
    require(not orphans, CG_NO_ORPHAN, "edge from a caller outside the workload: %r" % (orphans,))

    def named_unbound(g):
        reason = g["reason"] or ""
        return (g["module"] == owned_id and g["subject"] == "used by an unidentified caller image"
                and g["caller"] is None and g["pid"] is None
                and reason.startswith(modpath + ": native witness rows of this module were not bound to a "
                                      "caller incarnation (first: ")
                and reason.endswith("); module-level positive use only, never attributed by pid"))

    def classify(g):
        reason = g["reason"] or ""
        if reason in ACTIVATION_REFUSALS:
            return "activation"
        if g["subject"] == ACTIVATION:
            return "unexpected-activation"
        if reason.startswith(UNPROVEN):
            return "unproven"
        if g["subject"] == "module admission changed":
            return "admission-note"
        if named_unbound(g):
            return "unbound"
        if reason == DEADLINE:
            return "deadline"
        if reason == RETAINED:
            return "retained"
        if reason in PREP_REASONS and g["subject"] == PREP_SUBJECT:
            return "prep"
        return None

    def admission_framed(reason):
        prefix = modpath + ": admission changed from "
        if not reason.startswith(prefix):
            return False
        rest = reason[len(prefix):]
        return any(rest == t or (rest.startswith(t + " (") and rest.endswith(")") and len(rest) > len(t) + 3)
                   for t in TRANSITIONS)

    def at_workload(g, module=None):
        r = workload.get(g["caller"])
        return r is not None and g["pid"] == r["pid"] and g["module"] == module

    kinds = [(classify(g), g) for g in report["gaps"]]
    degraded = modfs == "overlayfs" or any(k == "unproven" for k, _ in kinds)
    for kind, g in kinds:
        if g["module"] == owned_id:
            unnamed = "inventory gaps about owned module: %r"
        else:
            unnamed = "overlay published extra gap: %r" if degraded else "witness-available published extra gap: %r"
        require(kind is not None, GAP_UNCLASSIFIED, unnamed % (g,))
        if kind == "activation":
            require(g["subject"] == ACTIVATION, GAP_ACTIVATION, "activation refusal under another subject: %r" % (g,))
            require(at_workload(g) and workload[g["caller"]]["authority"] == "native_exact", GAP_ACTIVATION,
                    "%s: %r" % (ACTIVATION_REFUSALS[g["reason"]], g))
        require(kind != "unexpected-activation", GAP_ACTIVATION, "unexpected activation refusal: %r" % (g,))
        if kind == "retained":
            require(g["subject"] == "native owner refresh refused" and at_workload(g), GAP_RETAINED,
                    "retained refresh attribution: %r" % (g,))
        if kind == "deadline":
            require(g["subject"] == "cgroup scope transaction incomplete" and g["caller"] is None
                    and g["pid"] is None and g["module"] is None, GAP_DEADLINE,
                    "collection deadline attribution: %r" % (g,))
        if kind == "admission-note":
            require(at_workload(g, owned_id) and admission_framed(g["reason"] or ""), GAP_ADMISSION,
                    "admission note attribution: %r" % (g,))
        if kind == "prep":
            require(g["caller"] is None and g["pid"] is None and g["module"] is None, GAP_PREP,
                    "malformed interrupted preparation scope: %r" % (g,))
            require_type("budget" in g and g["budget"] is None, GAP_PREP,
                         "malformed interrupted preparation budget: %r" % (g,))
            require_type("repeats" in g and type(g["repeats"]) is int and g["repeats"] >= 1, GAP_PREP,
                         "malformed interrupted preparation count: %r" % (g,))
    retained = [g for k, g in kinds if k == "retained"]
    if retained:
        require(any(k == "deadline" for k, _ in kinds), GAP_RETAINED,
                "retained refresh without a run deadline: %r" % (retained,))
        require(len({g["caller"] for g in retained}) == len(retained), GAP_RETAINED,
                "duplicate retained refresh for one caller: %r" % (retained,))
    # A preparation failure only comes with a run-deadline straddle:
    # the pass was cancelled mid-preparation, so the deadline gap
    # must be present in the same run. The producer dedupes identical
    # rows, so duplicates are malformed.
    prep = [g for k, g in kinds if k == "prep"]
    if prep:
        require(len(prep) == 1, GAP_PREP, "duplicate interrupted preparation rows: %r" % (prep,))
        require(any(k == "deadline" for k, _ in kinds), GAP_PREP,
                "interrupted preparation without a run deadline: %r" % (prep,))
    # The run-deadline row carries its exact producer shape: an
    # explicitly present null budget (the row records no budget
    # refusal) and a positive integer recording count. The producer
    # dedupes identical rows, so duplicates are malformed.
    deadline_rows = [g for k, g in kinds if k == "deadline"]
    if deadline_rows:
        for g in deadline_rows:
            require_type("budget" in g and g["budget"] is None, GAP_DEADLINE,
                         "malformed run deadline budget: %r" % (g,))
            require_type("repeats" in g and type(g["repeats"]) is int and g["repeats"] >= 1,
                         GAP_DEADLINE, "malformed run deadline count: %r" % (g,))
        require(len(deadline_rows) == 1, GAP_DEADLINE,
                "duplicate run deadline rows: %r" % (deadline_rows,))
    for label, _pid in expected:
        r = row[label]
        require(r["start_time_unit"] == "clock_ticks_since_boot", CG_GENERATION,
                "%s start time unit %r" % (label, r["start_time_unit"]))
        require(r["start_time"] == generations[label], CG_GENERATION,
                "%s start time %r is not the workload generation %s" % (label, r["start_time"], generations[label]))
        require(r["retired"] is False, CG_LIVE, "%s caller retired at report time: %r" % (label, r))
        require(r["authority"] == "native_exact", CG_AUTHORITY, "%s never activated a native owner: %r" % (label, r))
        own = [x for m, x in r["edges"] if m == owned_id]
        require(own, CG_EDGE, "%s has no edge to the owned module" % label)
        require(len(r["edges"]) == 1, CG_EDGE,
                "%s has %d edges, expected its one owned edge: %r" % (label, len(r["edges"]), r["edges"]))
        x = own[0]
        require({k: x[k] for k in EXACT_ENTRIES} == EXACT_ENTRIES, CG_EXACT, "%s calls not counted exactly: %r" % (label, x))
        require(x["count"] == driven, CG_EXACT, "%s counted %r entries, drove %d" % (label, x["count"], driven))
    unproven = [g for k, g in kinds if k == "unproven"]
    if degraded:
        require(sorted(g["caller"] or "" for g in unproven) == sorted(workload), GAP_UNPROVEN,
                "overlay unproven caller cover")
        for g in unproven:
            require(g["subject"] == modpath, GAP_UNPROVEN, "overlay unproven subject")
            require(g["module"] is None, GAP_UNPROVEN, "overlay unproven module")
            require(g["pid"] == workload[g["caller"]]["pid"], GAP_UNPROVEN, "overlay unproven pid")
    return ("inventory cgroup: inside=%d child=%d outside=%d excluded module=%s admission=%s unproven=%d gaps=%d"
            % (inside_pid, child_pid, outside_pid, owned_id, state, len(unproven), len(report["gaps"])))


# -- run pre-arm --------------------------------------------------------------

WINDOW = Record("unobserved-window", {"start_ns": (U64, "window start_ns"), "end_ns": (U64, "window end_ns"),
                                      "reason": (STR, "window reason")})
# Every discovery row has the producer's types (src/render.rs
# ModuleSummary): `attached_at_ns` is absent before assembly and null when
# nothing attached; `unobserved_windows` is absent when undisclosed.
DISCOVERY_ROW = Record("prearm-discovery-row", {},
                       optional={"attached_at_ns": (Nullable(U64), "module attached_at_ns"),
                                 "unobserved_windows": (ListOf(WINDOW), "module unobserved_windows")},
                       closed=False)
# Selection reads only a row's sources (the same rule); the optional keys
# are typed after the selected module's strict check.
ROW_SOURCES = Record("prearm-row-sources", {"sources": (ListOf(STR), "module sources")}, closed=False,
                     rule=DISCOVERY_ROW.rule)
# The selected pre-armed module carries both keys: an exact window claim
# is relative to its attach stamp.
PREARM_MODULE = Record("prearm-module", {
    "sources": (ListOf(STR), "module sources"),
    "unobserved_windows": (ListOf(WINDOW), "module unobserved_windows"),
    "attached_at_ns": (Nullable(U64), "module attached_at_ns")}, closed=False)
PREARM_EVIDENCE = Record("prearm-evidence", {"discovery": (ListOf(ROW_SOURCES), "evidence discovery")},
                         closed=False)
PREARM_PAIR = Record("prearm-pair", {"pair": (U64, "ledger pair"), "init_ns": (U64, "ledger init_ns"),
                                     "init_returned_ns": (U64, "ledger init_returned_ns"),
                                     "fini_returned_ns": (U64, "ledger fini_returned_ns")})
PREARM_SUMMARY = Record("prearm-summary", {"initializes": (U64, "ledger initializes"),
                                           "finalizes": (U64, "ledger finalizes")})
PREARM_RELEASE = declare("prearm.release", "the kernel release parses as MAJOR.MINOR")
PREARM_EVIDENCE_ONCE = declare("prearm.evidence-once", "each twin's report carries exactly one EVIDENCE line")
PREARM_ONE = declare("prearm.one-prearmed", "exactly one discovery module is pre-armed")
PREARM_SCAN = declare("prearm.scan-source", "the pre-armed module is also scan-discovered")
PREARM_ATTACHED = declare("prearm.attached", "the pre-armed module of each twin carries its attach stamp")
PREARM_HELD = declare("prearm.held-windows", "the held twin publishes no unobserved window (>= 6.8)")
PREARM_PASSIVE = declare("prearm.passive-window", "the passive twin keeps its single pre_attach window ending at attach")
PREARM_HANDOFF = declare("prearm.handoff-pair", "a pre-6.8 live handoff is exactly late_discovery then mapped_unattached")
PREARM_LEDGER = declare("prearm.ledger", "each loader ledger is its pair rows then one 3/3 summary, one pair per initialize")
PREARM_TRACE = declare("prearm.trace-counts", "the held trace completes 3 C_Initialize, 3 C_Finalize, 1 C_GetFunctionList")


def kernel_is_pre_68(release=None):
    release = platform.release() if release is None else release
    match = re.match(r"([0-9]+)\.([0-9]+)(?![0-9])", release)
    require(match is not None, PREARM_RELEASE, "unparseable kernel release %r" % (release,))
    return (int(match.group(1)), int(match.group(2))) < (6, 8)


def assert_handoff_pair(module):
    # The exact W8B-66 live-handoff disclosure: the live join lands
    # across an id change, so the late discovery reads late_discovery
    # up to the declared attach and the out-of-declared-set mapping
    # reads mapped_unattached from the same start. The undeclared end is
    # an independent real attach stamp (unordered against the declared
    # maximum); only the window's own well-formedness is required.
    windows = module["unobserved_windows"]
    reasons = [w["reason"] for w in windows]
    require(reasons == ["late_discovery", "mapped_unattached"], PREARM_HANDOFF, repr(windows))
    late, unattached = windows
    require(late["end_ns"] == module["attached_at_ns"], PREARM_HANDOFF, repr(windows))
    require(unattached["start_ns"] == late["start_ns"], PREARM_HANDOFF, repr(windows))
    require(unattached["start_ns"] <= unattached["end_ns"], PREARM_HANDOFF, repr(windows))


def assert_pre68_held(module):
    # Pre-6.8 held twin: merged into the kept pre-arm object ([]) or the
    # exact handoff pair; the reasons dispatch, nothing else passes.
    reasons = [w["reason"] for w in module["unobserved_windows"]]
    if reasons == ["late_discovery", "mapped_unattached"]:
        assert_handoff_pair(module)
        return "handoff pair"
    require(module["unobserved_windows"] == [], PREARM_HELD, repr(module["unobserved_windows"]))
    return "merged []"


def assert_single_pre_attach(module):
    windows = module["unobserved_windows"]
    require(len(windows) == 1 and windows[0]["reason"] == "pre_attach", PREARM_PASSIVE, repr(windows))
    require(windows[0]["end_ns"] == module["attached_at_ns"], PREARM_PASSIVE, repr(windows))


def assert_pre68_passive(module):
    # Pre-6.8 passive twin: the same dispatch, the merged arm the exact
    # single pre_attach window of the >= 6.8 branch.
    reasons = [w["reason"] for w in module["unobserved_windows"]]
    if reasons == ["late_discovery", "mapped_unattached"]:
        assert_handoff_pair(module)
        return "handoff pair"
    assert_single_pre_attach(module)
    return "merged pre_attach"


def completed_calls(text, function):
    # The -o trace report is the product's text format (the only form
    # `run --trace` publishes): one completed call per line, "NAME -> RV".
    return sum(1 for line in text.split("\n") if (" %s " % function) in line and " -> " in line)


def check_trace_counts(counts):
    require(counts == (3, 3, 1), PREARM_TRACE, repr(counts))


def prearm_evidence(text, name):
    rows = [line for line in text.split("\n") if line.startswith("EVIDENCE ")]
    require(len(rows) == 1, PREARM_EVIDENCE_ONCE, "%s: %d EVIDENCE lines" % (name, len(rows))
            if rows else "%s: no EVIDENCE line" % name)
    return PREARM_EVIDENCE.check(strict_json(rows[0][len("EVIDENCE "):], "%s evidence" % name),
                                 "%s evidence" % name)


def prearm_ledger(text, name):
    rows = [strict_json(line, "%s ledger line" % name) for line in text.split("\n") if line.strip()]
    require(rows, PREARM_LEDGER, "%s ledger is empty" % name)
    pairs = [PREARM_PAIR.check(row, "%s ledger pair" % name) for row in rows[:-1]]
    summary = PREARM_SUMMARY.check(rows[-1], "%s ledger summary" % name)
    require((summary["initializes"], summary["finalizes"]) == (3, 3), PREARM_LEDGER, repr(summary))
    require(len(pairs) == summary["initializes"], PREARM_LEDGER,
            "%s ledger has %d pair rows for %d initializes" % (name, len(pairs), summary["initializes"]))
    return summary


def prearmed_module(evidence):
    rows = evidence["discovery"]
    mods = [m for m in rows if "prearm" in m["sources"]]
    require(len(mods) == 1, PREARM_ONE, "one pre-armed module, got %d" % len(mods))
    selected = PREARM_MODULE.check(mods[0])
    for row in rows:
        DISCOVERY_ROW.check(row)
    return selected


def judge_run_prearm(args):
    run = Run(args.stamp, args.run_id, "run-prearm")
    pre_68 = kernel_is_pre_68(args.kernel_release)
    held_text = run.read_product(args.held_report, "held report")
    held = prearmed_module(prearm_evidence(held_text, "held"))
    prearm_ledger(run.read(args.held_ledger, "held ledger"), "held")
    passive = prearmed_module(prearm_evidence(run.read_product(args.passive_report, "passive report"), "passive"))
    prearm_ledger(run.read(args.passive_ledger, "passive ledger"), "passive")
    require("scan" in held["sources"], PREARM_SCAN, repr(held["sources"]))
    require("scan" in passive["sources"], PREARM_SCAN, repr(passive["sources"]))
    # An exact window claim is relative to the attach stamp: a pre-armed
    # module that never attached proves nothing.
    require(held["attached_at_ns"] is not None, PREARM_ATTACHED, "held pre-armed module never attached")
    require(passive["attached_at_ns"] is not None, PREARM_ATTACHED, "passive pre-armed module never attached")
    if pre_68:
        held_shape = assert_pre68_held(held)
    else:
        require(held["unobserved_windows"] == [], PREARM_HELD, repr(held["unobserved_windows"]))
    check_trace_counts(tuple(completed_calls(held_text, name)
                             for name in ("C_Initialize", "C_Finalize", "C_GetFunctionList")))
    if pre_68:
        passive_shape = assert_pre68_passive(passive)
        return "pre-6.8 exact: held %s, passive %s, 3/3 ledger and 3/3/1 trace" % (held_shape, passive_shape)
    assert_single_pre_attach(passive)
    return "held [] with 3/3 ledger and 3/3/1 trace; passive keeps single pre_attach"


# -- parent chain ---------------------------------------------------------------

CHAIN_ANCESTOR = declare("chain.ancestor", "each further ancestor is an exact typed incarnation")
ANCESTOR = Record("ancestor", {"pid": (PID, "ancestor pid"), "start_time": (U64, "ancestor start_time"),
                               "exe": (Nullable(STR), "ancestor exe")},
                  optional={"label": (STR, "ancestor label"), "folded": (U64, "ancestor folded"),
                            "exe_gap": (STR, "ancestor exe_gap")}, closed=False, rule=CHAIN_ANCESTOR)
CHAIN_CALLER = Record("chain-caller", {
    "launched_by_origin": (STR, "caller launched_by_origin"),
    "launched_by_unit": (Nullable(STR), "caller launched_by_unit"),
    "launched_by_gap": (Nullable(Record("chain-gap", {"subject": (STR, "launched_by_gap subject"),
                                                      "reason": (STR, "launched_by_gap reason")}, closed=False)),
                        "caller launched_by_gap")}, closed=False)
CHAIN_REPORT = Record("chain-report", {"callers": (ListOf(Record("chain-report-caller", {
    "pid": (PID, "caller pid"), "start_time": (U64, "caller start_time")}, closed=False), item="caller"),
    "callers")}, closed=False)
CHAIN_ONCE = declare("chain.workload-once", "the workload is one caller incarnation")
CHAIN_GENERATION = declare("chain.generation", "the caller is the registered workload generation")
CHAIN_WALK = declare("chain.walk", "the walk keeps 1..=4 ancestors")
CHAIN_PARENT = declare("chain.named-parent", "the nearest ancestor is the registered chain-parent generation")
CHAIN_INIT = declare("chain.no-init", "init is never shown as the launcher")
CHAIN_ORIGIN = declare("chain.origin", "the origin is a real chain, with no unit beside it")
CHAIN_GAP = declare("chain.gap", "a chain gap names the parent chain and one documented reason")
CHAIN_TEXT = declare("chain.text", "the concise and -v human renderings name the chain (the cell's subject)")
CHAIN_GAP_REASONS = ("launcher exited before read", "launcher hidden by /proc hidepid",
                     "parent chain truncated after 4 ancestors", "parent chain not sampled in cgroup transaction")


def judge_parent_chain(args):
    run = Run(args.stamp, args.run_id, "parent-chain")
    wl = arg_int(args.workload_pid, "workload pid", 1, PID_MAX)
    wl_gen = arg_int(args.workload_gen, "workload generation")
    parent = arg_int(args.parent_pid, "parent pid", 1, PID_MAX)
    parent_gen = arg_int(args.parent_gen, "parent generation")
    report = CHAIN_REPORT.check(strict_json(run.read_product(args.report, "chain report"), "chain report"))
    callers = [c for c in report["callers"] if c["pid"] == wl]
    require(len(callers) == 1, CHAIN_ONCE, "one incarnation for the workload")
    c = CHAIN_CALLER.check(callers[0], "workload caller")
    require(c["start_time"] == wl_gen, CHAIN_GENERATION, "caller generation unchanged")
    lb = c.get("launched_by")
    require_type(type(lb) is list and 1 <= len(lb) <= 4, CHAIN_WALK, "walk keeps 1..=4 ancestors")
    # Every ancestor is an exact typed record (a float pid or a bool
    # start time never stands for an identity); the nearest one is the
    # registered chain-parent incarnation.
    Decided(ANCESTOR, CHAIN_PARENT, "named parent first: %r" % (lb[0],)).check(lb[0], "named parent", None)
    require(lb[0]["pid"] == parent and lb[0]["exe"] == "chain-parent" and lb[0]["start_time"] == parent_gen,
            CHAIN_PARENT, "named parent first: %r" % (lb[0],))
    for a in lb[1:]:
        Decided(ANCESTOR, CHAIN_ANCESTOR, "ancestor generation: %r" % (a,)).check(a, "ancestor", None)
    for a in lb:
        require(a["pid"] != 1, CHAIN_INIT, "init is never shown as the launcher: %r" % (a,))
    require(c["launched_by_origin"] == "chain", CHAIN_ORIGIN, "real chain origin: %r" % (c["launched_by_origin"],))
    require(c["launched_by_unit"] is None, CHAIN_ORIGIN, "no unit beside a real chain")
    gap = c["launched_by_gap"]
    if gap is not None:
        require(gap["subject"] == "caller parent chain" and gap["reason"] in CHAIN_GAP_REASONS, CHAIN_GAP, repr(gap))
    concise = run.read(args.concise, "concise stdout")
    verbose = run.read(args.verbose, "verbose stdout")
    require("gated (from chain-parent)" in concise, CHAIN_TEXT, "concise one-hop")
    require("gated <- chain-parent" in verbose, CHAIN_TEXT, "verbose chain")
    return "chain to chain-parent with %d ancestors; concise and -v agree" % len(lb)


# -- command line -----------------------------------------------------------------

JUDGES = {}


def parser():
    top = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = top.add_subparsers(dest="judge", required=True)
    stamp = sub.add_parser("stamp")
    stamp.add_argument("path")
    stamp.add_argument("run_id")
    stamp.add_argument("cell")

    def judge(name, function, *options):
        p = sub.add_parser(name)
        p.add_argument("--verdict")
        if name != "cgroup-member":
            p.add_argument("--stamp", required=True)
            p.add_argument("--run-id", required=True)
        for option in options:
            p.add_argument("--" + option, required=option not in ("child-pid", "kernel-release"),
                           default=None)
        JUDGES[name] = function

    judge("second-sigint", judge_second_sigint, "report", "stderr", "rc", "custody", "cleanup")
    judge("fifo-refusal", judge_fifo, "stderr", "fifo", "rc")
    judge("cgroup-member", judge_cgroup_member, "procs", "pid")
    judge("event-stdout", judge_event_stdout, "jsonl", "full-report", "epipe-report", "epipe-head", "rc1", "rc2")
    judge("cgroup-inventory", judge_cgroup_inventory, "cell", "report", "inside-wl", "outside-wl", "pin",
          "inside-iters", "outside-iters", "module", "module-fs", "inside-pid", "inside-gen", "child-pid",
          "child-gen", "outside-pid")
    judge("run-prearm", judge_run_prearm, "held-report", "held-ledger", "passive-report", "passive-ledger",
          "kernel-release")
    judge("parent-chain", judge_parent_chain, "report", "concise", "verbose", "workload-pid", "workload-gen",
          "parent-pid", "parent-gen")
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    if args.judge == "stamp":
        write_stamp(args.path, args.run_id, args.cell)
        return 0
    try:
        detail = JUDGES[args.judge](args)
        verdict = {"verdict": "pass", "rule": None, "stage": None, "detail": detail}
    except Refusal as refusal:
        verdict = {"verdict": "fail", "rule": refusal.rule, "stage": refusal.stage, "detail": refusal.detail}
    except OSError as error:
        verdict = {"verdict": "fail", "rule": FRESH_FILE, "stage": "input", "detail": "input unreadable: %s" % error}
    record = dict({"schema": VERDICT_SCHEMA, "judge": args.judge}, **verdict)
    if args.verdict:
        with open(args.verdict, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    print(verdict["detail"] if verdict["verdict"] == "pass" else "%s: %s" % (verdict["rule"], verdict["detail"]))
    return 0 if verdict["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
