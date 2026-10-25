#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure one first-use sweep cell from fixture ledger plus observer record.

The fixture ledger comes from tests/fixtures/system-first-use.c delay/mode
knob runs: verified publication, one cell row (mode, delay_us, armed), one
provider body call. The observer record is ``{"observed_calls",
"caller_rows"}`` with trace/profile caller labels (an executable label when
established, else ``Unknown executable``).

Two shares are reported as separate exact integers, never merged: the
missed-call count (provider body counter minus observed calls) and the
caller-attribution count (observed calls with an established label on the
cell pid). A gated cell never counts as positive. The delay-indexed bound
table stays an input document: the measured bounds land with the installed
cells, so this module only checks cells against a given table. Twins live
in tests/python/test_first_use_oracle.py and import this module.
"""

import argparse
import json
import sys

MODES = ("known-inode", "equal-bytes-new-inode", "unseen-provider",
         "late-heap")
COPY_MODES = ("equal-bytes-new-inode", "unseen-provider")
DELAYS_US = (0, 10, 100, 1000)
ARMS = ("ungated", "prearmed", "gated")
UNKNOWN_LABEL = "Unknown executable"
MAX_ROWS = 1024
MAX_LINE_BYTES = 65536
MAX_LEDGER_BYTES = 1024 * 1024


class MeasureError(ValueError):
    """The cell ledger or observer record is incomplete or inconsistent."""


def _require(condition, reason):
    if not condition:
        raise MeasureError(reason)


def _shown(value):
    """Render an untrusted value inside a refusal reason.

    Integers print verbatim (claim narrowing needs the measured numbers);
    anything else prints as its fixed JSON kind, never its content.
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


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def read_rows(stream):
    """Read bounded ledger JSONL rows."""
    rows = []
    total = 0
    while True:
        line = stream.readline(MAX_LINE_BYTES + 1)
        if not line:
            break
        _require(type(line) is str, "ledger must be text")
        total += len(line.encode("utf-8", "replace"))
        _require(total <= MAX_LEDGER_BYTES, "ledger byte limit")
        _require(len(rows) < MAX_ROWS, "ledger row limit")
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise MeasureError("invalid ledger row") from error
    return rows


def _common_fields(row):
    for key in ("phase", "mono_ns", "pid", "birth", "module_dev",
                "module_ino", "mount_ns_ino"):
        _require(key in row, f"ledger row without {key}")
    _require(type(row["phase"]) is str, "phase must be text")
    for key in ("mono_ns", "pid", "birth", "module_dev", "module_ino",
                "mount_ns_ino"):
        _require(_integer(row[key], minimum=1) if key != "mono_ns"
                 else _integer(row[key]),
                 f"{key} out of range")


def validate_cell(rows):
    """Validate one knob ledger; return the measured cell facts.

    The ledger must carry exactly one cell row naming a known mode, delay
    and arm. A complete cell (verified table plus executed and returned
    entry) additionally proves the delay on its stamps; copy modes prove a
    distinct source identity. Anything else reports complete False or is
    refused for its reason.
    """
    _require(type(rows) is list and rows, "cell ledger must be non-empty")
    for row in rows:
        _require(type(row) is dict, "ledger row must be an object")
        _common_fields(row)
    identities = {(row["pid"], row["birth"]) for row in rows}
    _require(len(identities) == 1, "ledger mixes caller identities")
    cells = [row for row in rows if row["phase"] == "cell"]
    _require(cells, "not a knob cell: no cell row")
    _require(len(cells) == 1, "ledger must carry exactly one cell row")
    body = cells[0]
    mode = body.get("mode")
    _require(mode in MODES, f"unknown mode {_shown(mode)}")
    delay_us = body.get("delay_us")
    _require(delay_us in DELAYS_US, f"unknown delay {_shown(delay_us)}")
    armed = body.get("armed")
    _require(armed in ARMS, f"unknown armed {_shown(armed)}")
    verified = next((row for row in rows
                     if row["phase"] == "table_verified"), None)
    executed = next((row for row in rows
                     if row["phase"] == "entry_executed"), None)
    returned = next((row for row in rows
                     if row["phase"] == "entry_returned"), None)
    storage = None
    if verified is not None:
        storage = verified.get("table_storage")
        _require(type(storage) is str, "table_storage must be text")
    count = 0
    if executed is not None:
        count = executed.get("body_count")
        _require(_integer(count), "body_count must be an integer")
    complete = (verified is not None and executed is not None and
                returned is not None and count >= 1)
    honored = False
    if complete:
        honored = (executed["mono_ns"] - verified["mono_ns"] >=
                   delay_us * 1000)
        _require(honored, "delay not honored on the ledger stamps")
    if mode == "late-heap" and complete:
        _require(storage == "heap",
                 "late-heap cell without heap publication")
    if mode in COPY_MODES:
        source_dev = body.get("source_dev")
        source_ino = body.get("source_ino")
        _require(_integer(source_dev, minimum=1) and
                 _integer(source_ino, minimum=1),
                 "copy mode without source identity")
        _require((source_dev, source_ino) !=
                 (body["module_dev"], body["module_ino"]),
                 "copy shares its source identity")
        equal = body.get("bytes_equal")
        _require(type(equal) is bool, "bytes_equal must be a boolean")
        delta = body.get("size_delta")
        _require(_integer(delta), "size_delta must be an integer")
        if mode == "equal-bytes-new-inode":
            _require(equal and delta == 0,
                     f"{mode} disagrees with bytes_equal {_shown(equal)}")
        else:
            _require(not equal and delta >= 1,
                     f"{mode} disagrees with bytes_equal {_shown(equal)} "
                     f"and size_delta {_shown(delta)}")
    return {"mode": mode, "delay_us": delay_us, "armed": armed,
            "complete": complete, "body_count": count if complete else 0,
            "storage": storage, "delay_honored": honored,
            "pid": rows[0]["pid"], "birth": rows[0]["birth"]}


def _observer(observer):
    _require(type(observer) is dict, "observer record must be an object")
    observed = observer.get("observed_calls")
    _require(_integer(observed), "observer must carry observed_calls")
    caller_rows = observer.get("caller_rows")
    _require(type(caller_rows) is list, "observer must carry caller_rows")
    for row in caller_rows:
        _require(type(row) is dict and _integer(row.get("pid"),
                                                minimum=1) and
                 type(row.get("label")) is str,
                 "caller row must carry pid and label")
    return observed, caller_rows


def missed_calls(cell, observer):
    """Exact missed-call count: body calls minus observed calls."""
    observed, _ = _observer(observer)
    body = cell["body_count"]
    _require(observed <= body,
             f"observer counted {observed} calls but the body ran {body}")
    return {"body_calls": body, "observed_calls": observed,
            "missed_calls": body - observed}


def attribution(cell, observer):
    """Caller-attribution count on the cell pid with established labels."""
    observed, caller_rows = _observer(observer)
    _require(len(caller_rows) == observed,
             f"caller rows {len(caller_rows)} do not account "
             f"observed {observed}")
    attributed = 0
    for row in caller_rows:
        _require(row["pid"] == cell["pid"],
                 f"caller row for pid {row['pid']} outside the cell pid "
                 f"{cell['pid']}")
        if row["label"] != UNKNOWN_LABEL:
            attributed += 1
    return {"observed_calls": observed, "attributed_calls": attributed}


def validate_report(report):
    """Validate a measurement report: two separate integer sections."""
    _require(type(report) is dict and set(report) == {"missed",
                                                      "attribution"},
             "report must carry separate missed and attribution sections")
    missed = report["missed"]
    _require(type(missed) is dict and
             set(missed) == {"body_calls", "observed_calls",
                             "missed_calls"} and
             all(_integer(missed[key]) for key in missed),
             "missed counts must be integers")
    attributed = report["attribution"]
    _require(type(attributed) is dict and
             set(attributed) == {"observed_calls", "attributed_calls"} and
             all(_integer(attributed[key]) for key in attributed),
             "attribution counts must be integers")
    body = missed["body_calls"]
    observed = missed["observed_calls"]
    _require(observed <= body,
             f"observed {observed} above body {body}")
    _require(missed["missed_calls"] == body - observed,
             "missed section disagrees with its body count")
    _require(0 <= attributed["attributed_calls"] <=
             attributed["observed_calls"],
             "attributed outside observed")
    _require(attributed["observed_calls"] == observed,
             "sections disagree on observed")
    return {"verdict": "pass"}


def cell_verdict(cell, observer):
    """Verdict for one cell: gated and incomplete cells stay non-positive."""
    context = {"mode": cell["mode"], "delay_us": cell["delay_us"],
               "armed": cell["armed"]}
    if cell["armed"] == "gated":
        return {"positive": False,
                "reason": "gated cell never counts as positive", **context}
    if not cell["complete"]:
        return {"positive": False, "reason": "incomplete cell", **context}
    missed = missed_calls(cell, observer)
    attributed = attribution(cell, observer)
    validate_report({"missed": missed, "attribution": attributed})
    return {"positive": True, "missed": missed,
            "attribution": attributed, **context}


def check_bounds(entries, bound_table):
    """Check per-cell missed counts against a delay-indexed bound table."""
    _require(type(bound_table) is dict and
             set(bound_table) == {"0", "10", "100", "1000"} and
             all(_integer(bound_table[key]) for key in bound_table),
             "bound table must map every sweep delay to an integer")
    _require(type(entries) is list and entries, "bounds need cell entries")
    for entry in entries:
        _require(type(entry) is dict and
                 set(entry) == {"mode", "delay_us", "missed_calls"},
                 "bound entry must carry mode, delay_us and missed_calls")
        _require(entry["mode"] in MODES,
                 f"unknown mode {_shown(entry['mode'])}")
        _require(entry["delay_us"] in DELAYS_US,
                 f"unknown delay {_shown(entry['delay_us'])}")
        _require(_integer(entry["missed_calls"]),
                 "missed_calls must be an integer")
        bound = bound_table[str(entry["delay_us"])]
        _require(entry["missed_calls"] <= bound,
                 f"mode {entry['mode']} at delay {entry['delay_us']} "
                 f"missed {entry['missed_calls']} above bound {bound}")
    return {"verdict": "pass", "cells": len(entries)}


def _read_object(path, what):
    try:
        with open(path, encoding="utf-8") as stream:
            text = stream.read(MAX_LEDGER_BYTES + 1)
    except OSError as error:
        raise MeasureError(f"unreadable {what}") from error
    _require(len(text.encode("utf-8", "replace")) <= MAX_LEDGER_BYTES,
             f"{what} byte limit")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise MeasureError(f"invalid {what}") from error
    _require(type(value) is dict, f"{what} must be an object")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="fixture ledger JSONL file")
    parser.add_argument("observer", help="observer record JSON file")
    parser.add_argument("--bounds", default=None,
                        help="delay-indexed bound table JSON file")
    args = parser.parse_args(argv)
    try:
        with open(args.ledger, encoding="utf-8") as stream:
            rows = read_rows(stream)
        observer = _read_object(args.observer, "observer record")
        bounds = (_read_object(args.bounds, "bound table")
                  if args.bounds is not None else None)
        cell = validate_cell(rows)
        verdict = cell_verdict(cell, observer)
        if bounds is not None and verdict["positive"]:
            check_bounds([{"mode": cell["mode"],
                           "delay_us": cell["delay_us"],
                           "missed_calls": verdict["missed"][
                               "missed_calls"]}], bounds)
            verdict["within_bounds"] = True
    except MeasureError as error:
        print(f"first-use refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("first-use refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(verdict, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
