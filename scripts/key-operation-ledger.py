#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate only the controlled application's RSA operation ledger."""

import argparse
from collections import Counter
import json
import sys


MAX_ROWS = 1024
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 1024 * 1024
MAX_WORD = (1 << 64) - 1
REQUESTED = {"public": {"class": 2, "key_type": 0, "token": False, "modulus_bits": 2048},
             "private": {"class": 3, "key_type": 0, "token": False}}


class LedgerError(ValueError):
    """The application ledger is incomplete or inconsistent."""


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


def read_ledger(stream):
    """Read bounded JSONL without retaining or printing unrecognized payloads."""
    rows = []
    total = 0
    while line := stream.readline(MAX_LINE_BYTES + 1):
        _require(type(line) is str, "ledger must be text")
        try:
            size = len(line.encode("utf-8"))
        except UnicodeError as error:
            raise LedgerError("invalid ledger encoding") from error
        total += size
        _require(size <= MAX_LINE_BYTES and total <= MAX_LEDGER_BYTES, "ledger byte limit")
        _require(len(rows) < MAX_ROWS, "ledger row limit")
        try:
            row = json.loads(line, object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)
        except (ValueError, RecursionError) as error:
            raise LedgerError("invalid ledger JSON") from error
        _require(type(row) is dict, "ledger row must be an object")
        rows.append(row)
    return rows


class _Ledger:
    def __init__(self, rows):
        _require(type(rows) is list and 0 < len(rows) <= MAX_ROWS, "ledger row limit")
        self.rows = rows
        self.index = 0
        self.last_time = 0
        self.counts = Counter()

    def take(self, kind, **facts):
        _require(self.index < len(self.rows), "incomplete application ledger")
        row = self.rows[self.index]
        self.index += 1
        _require(type(row) is dict and row.get("kind") == kind, "application phase order")
        _require(_integer(row.get("seq"), 1) and row["seq"] == self.index,
                 "application sequence order")
        _require(all(type(row.get(key)) is type(value) and row[key] == value
                     for key, value in facts.items()), "application protocol mismatch")
        if kind == "call":
            _require(_integer(row.get("start_ns"), 1) and _integer(row.get("end_ns"), 1)
                     and self.last_time <= row["start_ns"] <= row["end_ns"],
                     "application call clock order")
            self.last_time = row["end_ns"]
        else:
            _require(_integer(row.get("time_ns"), 1) and row["time_ns"] >= self.last_time,
                     "application clock order")
            self.last_time = row["time_ns"]
        return row

    def marker(self, kind):
        row = self.take(kind)
        _keys(row, {"seq", "kind", "time_ns"})

    def call(self, fn, operation=0, phase="setup", rv=0, **facts):
        row = self.take("call", fn=fn, operation=operation, phase=phase, **facts)
        _keys(row, {"seq", "kind", "start_ns", "end_ns", "fn", "operation", "phase", "rv"}
              | set(facts))
        _require(_integer(row["rv"]), "invalid application return value")
        allowed = (rv,) if type(rv) is int else rv
        _require(row["rv"] in allowed, "unexpected application return value")
        self.counts[fn] += 1
        return row

    def begin(self, operation, category, mode, key, **facts):
        row = self.take("operation", event="begin", operation=operation, category=category,
                        mode=mode, key=key, **facts)
        _keys(row, {"seq", "kind", "time_ns", "event", "operation", "category", "mode", "key"}
              | set(facts))

    def end(self, operation, outcome):
        row = self.take("operation", event="end", operation=operation, outcome=outcome)
        _keys(row, {"seq", "kind", "time_ns", "event", "operation", "outcome"})


def _metadata(ledger, key, class_id):
    ledger.call("C_GetAttributeValue", phase="metadata", key=key, rv=(0, 0x11, 0x12, 0x150))
    row = ledger.take("metadata", key=key, origin="provider_query")
    _keys(row, {"seq", "kind", "time_ns", "key", "origin", "attributes"})
    attributes = row["attributes"]
    _keys(attributes, {"class", "key_type", "token", "modulus_bits"})
    expected = {"class": class_id, "key_type": 0, "token": False, "modulus_bits": 2048}
    for name, value in expected.items():
        cell = attributes[name]
        _require(type(cell) is dict, "invalid metadata cell")
        if cell.get("status") == "value":
            _keys(cell, {"status", "value"})
            _require(type(cell["value"]) is type(value) and cell["value"] == value,
                     "provider metadata disagrees with RSA cell")
        else:
            _keys(cell, {"status"})
            _require(key == "private" and name == "modulus_bits"
                     and cell["status"] in ("unsupported", "unavailable", "invalid"),
                     "required provider metadata unavailable")
    return attributes


def validate_ledger(rows):
    """Check the fixed workload, deriving counts from calls rather than summaries.

    This validates application self-reports. It is neither independent proof
    of a dishonest provider nor observer capture/settlement qualification.
    """
    ledger = _Ledger(rows)
    header = ledger.take("header", version=1, layout="lp64", mechanism="CKM_SHA256_RSA_PKCS")
    _keys(header, {"seq", "kind", "time_ns", "version", "layout", "mechanism", "requested"})
    requested = header["requested"]
    _keys(requested, {"public", "private"})
    for key, fields in REQUESTED.items():
        _keys(requested[key], fields)
        _require(all(type(requested[key][name]) is type(value) and requested[key][name] == value
                     for name, value in fields.items()), "wrong RSA creation request")
    ledger.marker("ready")
    ledger.marker("go")
    for fn in ("C_GetFunctionList", "C_Initialize", "C_GetSlotList", "C_OpenSession",
               "C_Login", "C_GenerateKeyPair"):
        ledger.call(fn)
    established = {"public": _metadata(ledger, "public", 2),
                   "private": _metadata(ledger, "private", 3)}
    outcomes = {"sign": Counter(), "verify": Counter()}
    for operation in range(1, 11):
        mode = "one_shot" if operation <= 7 else "multipart"
        ledger.begin(operation, "sign", mode, "private")
        ledger.call("C_SignInit", operation, "init")
        if operation == 1:
            ledger.call("C_Sign", operation, "query")
            ledger.call("C_Sign", operation, "too_small", 0x150)
        if mode == "multipart":
            for _ in range(3):
                ledger.call("C_SignUpdate", operation, "update")
            ledger.call("C_SignFinal", operation, "terminal")
        else:
            ledger.call("C_Sign", operation, "terminal")
        ledger.end(operation, "completed")
        outcomes["sign"]["completed"] += 1
    for operation in range(11, 23):
        valid = operation <= 20
        sign_operation = operation - 10 if valid else operation - 20
        ledger.begin(operation, "verify", "one_shot", "public", sign_operation=sign_operation,
                     expectation="valid" if valid else "invalid")
        ledger.call("C_VerifyInit", operation, "init")
        ledger.call("C_Verify", operation, "terminal", 0 if valid else 0xC0)
        outcome = "completed" if valid else "failed"
        ledger.end(operation, outcome)
        outcomes["verify"][outcome] += 1
    for fn in ("C_DestroyObject", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize"):
        ledger.call(fn, phase="cleanup")
    operations = {category: {outcome: counts[outcome] for outcome in ("completed", "failed")}
                  for category, counts in outcomes.items()}
    done = ledger.take("done")
    _keys(done, {"seq", "kind", "time_ns", "api_calls", "calls_by_function", "operations"})
    _require(_integer(done["api_calls"]) and done["api_calls"] == sum(ledger.counts.values()),
             "API summary disagrees with calls")
    _keys(done["calls_by_function"], ledger.counts)
    _require(all(_integer(value) and value == ledger.counts[name]
                 for name, value in done["calls_by_function"].items()),
             "function summary disagrees with calls")
    _keys(done["operations"], operations)
    for category, counts in operations.items():
        _keys(done["operations"][category], counts)
        _require(all(_integer(done["operations"][category][name])
                     and done["operations"][category][name] == value
                     for name, value in counts.items()), "operation summary disagrees with calls")
    _require(ledger.index == len(rows), "trailing application records")
    return {"version": 1, "api_calls": sum(ledger.counts.values()),
            "calls_by_function": dict(ledger.counts), "operations": operations,
            "requested": requested, "established": established}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="application JSONL file, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.ledger == "-":
            rows = read_ledger(sys.stdin)
        else:
            with open(args.ledger, encoding="utf-8") as stream:
                rows = read_ledger(stream)
        result = validate_ledger(rows)
    except (LedgerError, OSError, UnicodeError):
        print("application ledger refused: incomplete or inconsistent input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
