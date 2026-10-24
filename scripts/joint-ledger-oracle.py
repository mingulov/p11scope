#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate an independent per-call ledger and its settlement join.

The ledger is E17-pattern JSONL: one `ready` row, N `call` rows with
(seq, fn, rv, pid, tid, t0, t1), one `ack` row. Clocks are CLOCK_MONOTONIC
nanoseconds. The settlement join matches each ledger END t1 to the at_ns of
the JSONL event that publishes it; latency is at_ns minus t1, never merged
into totals. Twins live in tests/python/test_joint_ledger_oracle.py.
"""

import argparse
import json
import re
import sys

MAX_ROWS = 200000
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
FN_PATTERN = re.compile(r"[A-Za-z0-9_\[\]]{1,64}\Z")


class LedgerError(ValueError):
    """The ledger or event stream is incomplete or inconsistent."""


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


def read_events(stream):
    """Read bounded settled-event JSONL rows, each {at_ns, ledger_seq}."""
    rows = _read_jsonl(stream, "events")
    for row in rows:
        _keys(row, {"at_ns", "ledger_seq"})
        _require(_integer(row["at_ns"]), "event at_ns out of range")
        _require(_integer(row["ledger_seq"], minimum=1), "event seq out of range")
    return rows


def validate_ledger(rows):
    """Validate ready/call/ack shape; return the issued/call summary."""
    _require(rows, "empty ledger")
    _require(rows[0].get("kind") == "ready", "first row must be ready")
    _require(rows[-1].get("kind") == "ack", "last row must be ack")
    ready = rows[0]
    _keys(ready, {"kind", "pid", "tid", "t", "clock", "unit"})
    _require(_integer(ready["pid"], minimum=1), "ready pid out of range")
    _require(_integer(ready["tid"], minimum=1), "ready tid out of range")
    _require(_integer(ready["t"]), "ready t out of range")
    _require(ready["clock"] == "CLOCK_MONOTONIC", "ready clock basis mismatch")
    _require(ready["unit"] == "ns", "ready clock unit mismatch")
    ack = rows[-1]
    _keys(ack, {"kind", "issued", "t"})
    _require(_integer(ack["issued"]), "ack issued out of range")
    _require(_integer(ack["t"]), "ack t out of range")
    _require(ack["t"] >= ready["t"], "ack precedes ready window")
    calls = rows[1:-1]
    _require(all(type(row) is dict and row.get("kind") == "call" for row in calls),
             "unexpected non-call row between ready and ack")
    _require(ack["issued"] == len(calls),
             f"issued {ack['issued']} disagrees with {len(calls)} call rows")
    for position, row in enumerate(calls, start=1):
        _keys(row, {"kind", "seq", "fn", "rv", "pid", "tid", "t0", "t1"})
        _require(row["seq"] == position,
                 f"seq {row['seq']} breaks contiguity at position {position}")
        _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
                 f"fn label invalid at seq {position}")
        _require(_integer(row["rv"]), f"rv out of range at seq {position}")
        _require(row["pid"] == ready["pid"],
                 f"pid {row['pid']} disagrees with ready pid at seq {position}")
        _require(row["tid"] == ready["tid"],
                 f"tid {row['tid']} disagrees with ready tid at seq {position}")
        _require(_integer(row["t0"]) and _integer(row["t1"]),
                 f"t0/t1 out of range at seq {position}")
        _require(row["t0"] <= row["t1"],
                 f"t1 {row['t1']} precedes t0 {row['t0']} at seq {position}")
        _require(ready["t"] <= row["t0"] and row["t1"] <= ack["t"],
                 f"seq {position} lies outside the ready/ack window")
    return {"issued": ack["issued"], "calls": len(calls)}


def compare_settlement(rows, events, p99_ns=None, min_rate_per_s=None):
    """Join ledger END t1 values to event at_ns values by seq.

    Every issued call must settle exactly once (no loss, no extras), every
    latency must be non-negative, and the optional p99/rate budgets must
    hold. Returns settled/loss/p99/rate; the achieved rate comes from
    fixture-side t0/t1 stamps, never from observer claims.
    """
    calls = [row for row in rows if row.get("kind") == "call"]
    _require(calls, "empty settlement: no calls to join")
    end = {}
    for row in calls:
        _require(row["seq"] not in end, f"duplicate seq {row['seq']} in ledger")
        end[row["seq"]] = row["t1"]
    expected = set(end)
    seen = set()
    latencies = []
    for event in events:
        _require(type(event) is dict, "event row must be an object")
        at_ns = event.get("at_ns")
        seq = event.get("ledger_seq")
        _require(_integer(at_ns), "event at_ns out of range")
        _require(seq in expected, f"event for unknown seq {seq}")
        _require(seq not in seen, f"duplicate event for seq {seq}")
        seen.add(seq)
        _require(at_ns >= end[seq], f"event at_ns precedes END t1 at seq {seq}")
        latencies.append(at_ns - end[seq])
    missing = sorted(expected - seen)
    if missing:
        raise LedgerError(
            f"loss: {len(missing)} of {len(expected)} calls unsettled "
            f"(missing seq {missing[0]})")
    ordered = sorted(latencies)
    p99 = ordered[(99 * len(ordered) + 99) // 100 - 1]
    if p99_ns is not None:
        _require(p99 <= p99_ns, f"p99 {p99} exceeds budget {p99_ns}")
    span = max(end.values()) - min(row["t0"] for row in calls)
    rate = len(calls) * 1_000_000_000 / max(span, 1)
    if min_rate_per_s is not None:
        _require(rate >= min_rate_per_s,
                 f"rate {rate:.1f} below minimum {min_rate_per_s}")
    return {"settled": len(calls), "loss": 0, "p99_ns": p99, "rate_per_s": rate}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="ledger JSONL file, or - for stdin")
    parser.add_argument("events", nargs="?",
                        help="settled-event JSONL file, or - for stdin")
    parser.add_argument("--p99-ns", type=int, default=None,
                        help="budget for END->publication p99 latency in ns")
    parser.add_argument("--min-rate", type=float, default=None,
                        help="minimum achieved calls/s from fixture stamps")
    args = parser.parse_args(argv)
    try:
        if args.ledger == "-":
            rows = read_ledger(sys.stdin)
        else:
            with open(args.ledger, encoding="utf-8") as stream:
                rows = read_ledger(stream)
        result = validate_ledger(rows)
        if args.events is not None:
            if args.events == "-":
                events = read_events(sys.stdin)
            else:
                with open(args.events, encoding="utf-8") as stream:
                    events = read_events(stream)
            result.update(compare_settlement(
                rows, events, args.p99_ns, args.min_rate))
    except (LedgerError, OSError, UnicodeError):
        print("ledger refused: incomplete or inconsistent input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
