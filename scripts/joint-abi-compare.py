#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate a 104-entry ABI ledger and its observer-side counts.

The ledger is E17-pattern JSONL emitted by
tests/fixtures/abi-execution/abi-104.c: one `ready` row, sequenced body
rows (`thread` declarations, `call` rows with entry/fn/rv stamps, `entry`
rows for unreturned calls, `cpu` rows for migration attempts), one `ack`
row. Clocks are CLOCK_MONOTONIC nanoseconds. The counts doc is the
observer's per-(cell, entry) population: calls, returns, fn label and the
full-width return-value multiset.

The comparison joins the two per cell and entry: every ledger key has
counts and vice versa, calls and returns match exactly, fn labels agree,
and return values match full-width (catching truncation). The full cell
additionally proves actual 104/104 execution with verified names, never a
macro count. Twins live in tests/python/test_joint_abi_oracle.py.
"""

import argparse
import json
import re
import sys

MAX_CALLS = 200000
# ready + body rows + ack: the T0 ceiling, reused so a large hot-key
# population validates exactly like a large per-call ledger.
MAX_ROWS = MAX_CALLS + 2
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
TABLE_SLOTS = 104
FN_PATTERN = re.compile(r"[A-Za-z0-9_\[\]]{1,64}\Z")
CELL_PATTERN = re.compile(r"[A-Za-z0-9_.\-]{1,64}\Z")
FULL_FN_PATTERN = re.compile(r"(?:C_[A-Za-z]+|P11ScopeSlot[0-9]+)\Z")

# Workload tags the fixture emits; the join key is the cell label, which
# stays an opaque tag (population names such as g31-575 bind to real cells
# in the post-L drivers, never here).
CONDS = {
    "full", "threads", "hot", "cellrun", "rv64", "entry", "migration",
    "nesting", "recursion", "longjmp", "thread-exit", "held-detach",
    "blocked",
}


class LedgerError(ValueError):
    """The ledger or counts stream is incomplete or inconsistent."""


def _require(condition, reason):
    if not condition:
        raise LedgerError(reason)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_WORD


def _keys(row, expected):
    _require(type(row) is dict and set(row) == set(expected), "unexpected fields")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise LedgerError("nonfinite JSON number")


def _shown(value):
    """Render an untrusted value inside a refusal reason.

    Integers print verbatim (claim narrowing needs the measured numbers);
    anything else prints as its fixed JSON kind, never its content, so a
    refusal carries numbers only and never echoes ledger payload.
    """
    if type(value) is int:
        return str(value)
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is float:
        return "non-integer number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    return "object"


def _read_jsonl(stream, what):
    """Read bounded JSONL without retaining or printing unrecognized payloads."""
    rows = []
    total = 0
    while line := stream.readline(MAX_LINE_BYTES + 1):
        _require(type(line) is str, f"{what} must be text")
        try:
            size = len(line.encode("utf-8"))
        except UnicodeError as error:
            raise LedgerError(f"invalid {what} encoding") from error
        total += size
        _require(size <= MAX_LINE_BYTES and total <= MAX_LEDGER_BYTES,
                 f"{what} byte limit")
        _require(len(rows) < MAX_ROWS, f"{what} row limit")
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line, object_pairs_hook=_unique_object,
                                   parse_constant=_invalid_constant))
        except json.JSONDecodeError as error:
            raise LedgerError(f"invalid {what} row") from error
    return rows


def read_ledger(stream):
    """Read bounded ledger JSONL rows."""
    return _read_jsonl(stream, "ledger")


def read_counts(stream):
    """Read bounded per-cell counts JSONL rows."""
    return _read_jsonl(stream, "counts")


def _check_common(row, ready, position, kinds):
    _keys(row, kinds)
    _require(type(row["entry"]) is int and 0 <= row["entry"] < TABLE_SLOTS,
             f"entry {_shown(row['entry'])} out of range at seq {position}")
    _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
             f"fn label invalid at seq {position}")
    _require(row["pid"] == ready["pid"],
             f"pid {_shown(row['pid'])} disagrees with ready pid at seq {position}")
    _require(row["cond"] in CONDS,
             f"cond {_shown(row['cond'])} is not a cond at seq {position}")
    _require(type(row["cell"]) is str and CELL_PATTERN.match(row["cell"]),
             f"cell label invalid at seq {position}")


def _check_stamp(value, ready_t, ack_t, position, name):
    _require(_integer(value), f"{name} out of range at seq {position}")
    _require(ready_t <= value <= ack_t,
             f"seq {position} lies outside the ready/ack window")


def validate_ledger(rows):
    """Validate ready/body/ack shape; return the issued/blocked summary."""
    _require(rows, "empty ledger")
    _require(type(rows[0]) is dict and rows[0].get("kind") == "ready",
             "first row must be ready")
    _require(type(rows[-1]) is dict and rows[-1].get("kind") == "ack",
             "last row must be ack")
    ready = rows[0]
    _keys(ready, {"kind", "pid", "tid", "t", "clock", "unit"})
    _require(_integer(ready["pid"], minimum=1), "ready pid out of range")
    _require(_integer(ready["tid"], minimum=1), "ready tid out of range")
    _require(_integer(ready["t"]), "ready t out of range")
    _require(ready["clock"] == "CLOCK_MONOTONIC", "ready clock basis mismatch")
    _require(ready["unit"] == "ns", "ready clock unit mismatch")
    ack = rows[-1]
    _keys(ack, {"kind", "issued", "blocked", "t"})
    _require(_integer(ack["issued"]), "ack issued out of range")
    _require(_integer(ack["blocked"]), "ack blocked out of range")
    _require(_integer(ack["t"]), "ack t out of range")
    _require(ack["t"] >= ready["t"], "ack precedes ready window")
    body = rows[1:-1]
    for position, row in enumerate(body, start=1):
        _require(type(row) is dict, f"row at position {position} must be an object")
        _require(row.get("seq") == position,
                 f"seq {_shown(row.get('seq'))} breaks contiguity at position {position}")
        _require(row.get("kind") in ("thread", "call", "entry", "cpu"),
                 f"unexpected ledger kind {_shown(row.get('kind'))} at seq {position}")
    tids = {ready["tid"]}
    for row in body:
        if row["kind"] != "thread":
            continue
        _keys(row, {"kind", "seq", "pid", "tid"})
        _require(row["pid"] == ready["pid"],
                 f"thread pid {_shown(row['pid'])} disagrees with ready pid")
        _require(_integer(row["tid"], minimum=1), "thread tid out of range")
        _require(row["tid"] not in tids,
                 f"thread tid {_shown(row['tid'])} declared twice")
        tids.add(row["tid"])
    calls = 0
    blocked = 0
    cells = set()
    nested = {"nesting": [], "recursion": []}
    for position, row in enumerate(body, start=1):
        kind = row["kind"]
        if kind == "thread":
            continue
        if kind == "call":
            _check_common(row, ready, position,
                          {"kind", "seq", "entry", "fn", "rv", "pid", "tid",
                           "t0", "t1", "cond", "cell"})
            _require(_integer(row["rv"]), f"rv out of range at seq {position}")
            _require(row["tid"] in tids,
                     f"tid {_shown(row['tid'])} undeclared at seq {position}")
            _require(_integer(row["t0"]) and _integer(row["t1"]),
                     f"t0/t1 out of range at seq {position}")
            _require(row["t0"] <= row["t1"],
                     f"t1 {row['t1']} precedes t0 {row['t0']} at seq {position}")
            _require(ready["t"] <= row["t0"] and row["t1"] <= ack["t"],
                     f"seq {position} lies outside the ready/ack window")
            calls += 1
            cells.add(row["cell"])
            if row["cond"] in nested:
                nested[row["cond"]].append(row)
        elif kind == "entry":
            _check_common(row, ready, position,
                          {"kind", "seq", "entry", "fn", "pid", "tid",
                           "t0", "cond", "cell"})
            _require(row["tid"] in tids,
                     f"tid {_shown(row['tid'])} undeclared at seq {position}")
            _check_stamp(row["t0"], ready["t"], ack["t"], position, "t0")
            blocked += 1
            cells.add(row["cell"])
        elif kind == "cpu":
            _keys(row, {"kind", "seq", "pid", "tid", "cpu", "t"})
            _require(row["pid"] == ready["pid"],
                     f"pid {_shown(row['pid'])} disagrees with ready pid at seq {position}")
            _require(row["tid"] in tids,
                     f"tid {_shown(row['tid'])} undeclared at seq {position}")
            _require(_integer(row["cpu"]), f"cpu out of range at seq {position}")
            _check_stamp(row["t"], ready["t"], ack["t"], position, "t")
    _require(ack["issued"] == calls,
             f"issued {ack['issued']} disagrees with {calls} call rows")
    _require(ack["blocked"] == blocked,
             f"blocked {ack['blocked']} disagrees with {blocked} entry rows")
    for cond in sorted(nested):
        group = nested[cond]
        if not group:
            continue
        _require(len(group) >= 2,
                 f"cond {cond} needs at least two nested calls")
        ordered = sorted(group, key=lambda row: row["t0"])
        for outer, inner in zip(ordered, ordered[1:]):
            contained = (outer["t0"] <= inner["t0"] <= inner["t1"] <= outer["t1"])
            strict = (outer["t0"] < inner["t0"] or inner["t1"] < outer["t1"])
            _require(contained and strict,
                     f"cond {cond} intervals do not nest")
    return {"issued": ack["issued"], "blocked": ack["blocked"],
            "cells": len(cells)}


def validate_counts(rows):
    """Validate counts shape; return the row summary."""
    seen = set()
    for position, row in enumerate(rows, start=1):
        _require(type(row) is dict,
                 f"counts at position {position} must be an object")
        _require(row.get("kind") == "counts",
                 f"unexpected counts kind {_shown(row.get('kind'))} at position {position}")
        _keys(row, {"kind", "cell", "entry", "fn", "calls", "returns", "rv"})
        _require(type(row["cell"]) is str and CELL_PATTERN.match(row["cell"]),
                 f"cell label invalid at counts position {position}")
        _require(type(row["entry"]) is int and 0 <= row["entry"] < TABLE_SLOTS,
                 f"entry {_shown(row['entry'])} out of range at counts position {position}")
        _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
                 f"fn label invalid at counts position {position}")
        _require(_integer(row["calls"]), f"calls out of range at counts position {position}")
        _require(_integer(row["returns"]),
                 f"returns out of range at counts position {position}")
        _require(row["returns"] <= row["calls"],
                 f"returns exceed calls at counts position {position}")
        _require(type(row["rv"]) is list and
                 all(_integer(value) for value in row["rv"]),
                 f"rv out of range at counts position {position}")
        _require(len(row["rv"]) == row["returns"],
                 f"rv list length disagrees with returns at counts position {position}")
        key = (row["cell"], row["entry"])
        _require(key not in seen,
                 f"cell {row['cell']} entry {row['entry']} counted twice")
        seen.add(key)
    return {"count_rows": len(rows)}


def _ledger_keys(rows):
    """Per-(cell, entry) ledger populations: fn labels and return values."""
    keys = {}
    for row in rows:
        if row.get("kind") not in ("call", "entry"):
            continue
        key = (row["cell"], row["entry"])
        slot = keys.setdefault(key, {"fns": set(), "rvs": [], "total": 0})
        slot["fns"].add(row["fn"])
        slot["total"] += 1
        if row["kind"] == "call":
            slot["rvs"].append(row["rv"])
    return keys


def compare_abi(rows, counts):
    """Join ledger rows to counts rows. Both must have been validated.

    The comparison needs populations on both sides: at least one ledger
    call/entry row and at least one counts row, else it refuses."""
    ledger = _ledger_keys(rows)
    observed = {}
    for row in counts:
        observed[(row["cell"], row["entry"])] = row
    # An empty counts side already refuses below ("counts missing for
    # cell ..."), so only the empty ledger side needs its own floor.
    _require(ledger, "comparison without ledger populations")
    for key in sorted(ledger):
        _require(len(ledger[key]["fns"]) == 1,
                 f"fn disagrees within cell {key[0]} entry {key[1]}")
    for key in sorted(ledger):
        _require(key in observed,
                 f"counts missing for cell {key[0]} entry {key[1]}")
    for key in sorted(observed):
        _require(key in ledger,
                 f"counts without ledger rows for cell {key[0]} entry {key[1]}")
    calls_total = 0
    returns_total = 0
    for key in sorted(ledger):
        slot = ledger[key]
        row = observed[key]
        _require(row["calls"] == slot["total"],
                 f"calls disagree for cell {key[0]} entry {key[1]}")
        _require(row["returns"] == len(slot["rvs"]),
                 f"returns disagree for cell {key[0]} entry {key[1]}")
        _require(row["fn"] == next(iter(slot["fns"])),
                 f"fn disagrees for cell {key[0]} entry {key[1]}")
        _require(sorted(row["rv"]) == sorted(slot["rvs"]),
                 f"rv multiset disagrees for cell {key[0]} entry {key[1]}")
        calls_total += row["calls"]
        returns_total += row["returns"]
    full_entries = [row["entry"] for row in rows
                    if row.get("kind") == "call" and row.get("cell") == "full"]
    full_blocked = [row for row in rows
                    if row.get("kind") == "entry" and row.get("cell") == "full"]
    _require(not full_blocked, "cell full carries an unreturned entry row")
    if full_entries or any(row.get("cell") == "full" for row in rows):
        missing = sorted(set(range(TABLE_SLOTS)) - set(full_entries))
        if missing:
            raise LedgerError(f"entry {missing[0]} never executed in cell full")
        seen_entries = set()
        dup = None
        for entry in full_entries:
            if entry in seen_entries and dup is None:
                dup = entry
            seen_entries.add(entry)
        _require(dup is None, f"entry {dup} executed twice in cell full")
        for row in rows:
            if row.get("kind") == "call" and row.get("cell") == "full":
                _require(FULL_FN_PATTERN.match(row["fn"]) is not None,
                         f"cell full entry {row['entry']} lacks a verified name")
    cells = {key[0] for key in ledger}
    return {"cells": len(cells), "keys": len(ledger),
            "calls": calls_total, "returns": returns_total}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="ledger JSONL file, or - for stdin")
    parser.add_argument("counts", nargs="?",
                        help="per-cell counts JSONL file, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.ledger == "-":
            rows = read_ledger(sys.stdin)
        else:
            with open(args.ledger, encoding="utf-8") as stream:
                rows = read_ledger(stream)
        result = validate_ledger(rows)
        if args.counts is not None:
            if args.counts == "-":
                counts = read_counts(sys.stdin)
            else:
                with open(args.counts, encoding="utf-8") as stream:
                    counts = read_counts(stream)
            result.update(validate_counts(counts))
            result.update(compare_abi(rows, counts))
    except LedgerError as error:
        print(f"abi refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("abi refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
