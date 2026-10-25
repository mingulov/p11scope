#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate an A/B promotion ledger and its observer-side evidence.

The ledger is E17-pattern JSONL emitted by
tests/fixtures/promotion/ab-pair.c: one `ready` row, sequenced body rows
(`hold_begin`, side-B `call`, `alive`, `cancel`, `hold_end`, `retire`), one
`ack` row. Clocks are CLOCK_MONOTONIC nanoseconds. The evidence doc is the
observer's promotion record: drawn/revalidated/detailed/completed rows,
seal-settlement rows, owner-transfer and retirement rows, cancel rows,
refusal rows with exact labels, and broad-Inventory pulse rows.

The comparison joins the two: drawn precedes revalidation precedes real
Detailed; every completion and owner transfer consumes a settled seal; each
refusal carries its exact label and its ledger precondition; a cancel keeps
the caller live while B stays withheld until the same-A completion; and
retirement lands only after the final completion. Twins live in
tests/python/test_joint_promotion_oracle.py.
"""

import argparse
import json
import re
import sys

MAX_CALLS = 200000
# ready + body rows + ack: the T0 ceiling, reused so a large B population
# validates exactly like a large per-call ledger.
MAX_ROWS = MAX_CALLS + 2
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
FN_PATTERN = re.compile(r"[A-Za-z0-9_\[\]]{1,64}\Z")

# The four refusal cells, with the exact PromotionRefusal::label() strings
# from src/inventory_promotion/state.rs. The scan cell is the parent scan
# ending before activation (ScopeEnded); the unsupported cell is a cgroup
# parent scope, which SelectedSession revalidation leaves unqualified
# (src/attach/selected_detailed.rs).
REFUSAL_CELLS = {
    "view expired": "stale",
    "another promotion is outstanding": "busy",
    "parent scope ended": "scan",
    "parent scope unsupported": "unsupported",
}

EVENT_KINDS = {
    "drawn", "revalidated", "seal_settled", "detailed", "completed",
    "owner_transferred", "retired", "cancelled", "refused", "view_expired",
    "inventory_ended", "inventory_pulse", "scope",
}


class LedgerError(ValueError):
    """The ledger or evidence stream is incomplete or inconsistent."""


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


def read_events(stream):
    """Read bounded promotion-evidence JSONL rows."""
    return _read_jsonl(stream, "events")


def _check_identity(row, ready, position):
    _require(row["pid"] == ready["pid"],
             f"pid {_shown(row['pid'])} disagrees with ready pid at seq {position}")
    _require(row["tid"] == ready["tid"],
             f"tid {_shown(row['tid'])} disagrees with ready tid at seq {position}")


def _check_stamp(value, ready_t, ack_t, position, name):
    _require(_integer(value), f"{name} out of range at seq {position}")
    _require(ready_t <= value <= ack_t,
             f"seq {position} lies outside the ready/ack window")


def validate_ledger(rows):
    """Validate ready/body/ack shape; return the issued/held summary."""
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
    _keys(ack, {"kind", "issued", "held", "t"})
    _require(_integer(ack["issued"]), "ack issued out of range")
    _require(_integer(ack["held"]), "ack held out of range")
    _require(_integer(ack["t"]), "ack t out of range")
    _require(ack["t"] >= ready["t"], "ack precedes ready window")
    begins = {}
    ends = {}
    calls = 0
    cancels = []
    retires = []
    for position, row in enumerate(rows[1:-1], start=1):
        _require(type(row) is dict, f"row at position {position} must be an object")
        _require(row.get("seq") == position,
                 f"seq {_shown(row.get('seq'))} breaks contiguity at position {position}")
        kind = row.get("kind")
        if kind == "hold_begin":
            _keys(row, {"kind", "seq", "side", "fn", "pid", "tid", "t0"})
            _require(row["side"] == "A",
                     f"hold_begin side {_shown(row['side'])} is not A at seq {position}")
            _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
                     f"fn label invalid at seq {position}")
            _check_identity(row, ready, position)
            _check_stamp(row["t0"], ready["t"], ack["t"], position, "t0")
            begins[position] = row["t0"]
        elif kind == "call":
            _keys(row, {"kind", "seq", "side", "fn", "rv", "pid", "tid", "t0", "t1"})
            _require(row["side"] == "B",
                     f"call side {_shown(row['side'])} is not B at seq {position}")
            _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
                     f"fn label invalid at seq {position}")
            _require(_integer(row["rv"]), f"rv out of range at seq {position}")
            _check_identity(row, ready, position)
            _require(_integer(row["t0"]) and _integer(row["t1"]),
                     f"t0/t1 out of range at seq {position}")
            _require(row["t0"] <= row["t1"],
                     f"t1 {row['t1']} precedes t0 {row['t0']} at seq {position}")
            _require(ready["t"] <= row["t0"] and row["t1"] <= ack["t"],
                     f"seq {position} lies outside the ready/ack window")
            calls += 1
        elif kind == "alive":
            _keys(row, {"kind", "seq", "pid", "tid", "t"})
            _check_identity(row, ready, position)
            _check_stamp(row["t"], ready["t"], ack["t"], position, "t")
        elif kind == "cancel":
            _keys(row, {"kind", "seq", "t"})
            _check_stamp(row["t"], ready["t"], ack["t"], position, "t")
            cancels.append(row)
        elif kind == "hold_end":
            _keys(row, {"kind", "seq", "side", "ref", "rv", "t1"})
            _require(row["side"] == "A",
                     f"hold_end side {_shown(row['side'])} is not A at seq {position}")
            _require(_integer(row["rv"]), f"rv out of range at seq {position}")
            _check_stamp(row["t1"], ready["t"], ack["t"], position, "t1")
            ends[position] = (row["ref"], row["t1"])
        elif kind == "retire":
            _keys(row, {"kind", "seq", "side", "after", "t"})
            _require(row["side"] == "A",
                     f"retire side {_shown(row['side'])} is not A at seq {position}")
            _require(_integer(row["after"], minimum=1),
                     f"after out of range at seq {position}")
            _check_stamp(row["t"], ready["t"], ack["t"], position, "t")
            retires.append((position, row["after"], row["t"]))
        else:
            raise LedgerError(
                f"unexpected ledger kind {_shown(kind)} at seq {position}")
    _require(ack["issued"] == calls,
             f"issued {ack['issued']} disagrees with {calls} call rows")
    _require(ack["held"] == len(begins),
             f"held {ack['held']} disagrees with {len(begins)} hold windows")
    _require(len(ends) == len(begins),
             f"{len(ends)} hold ends close {len(begins)} hold begins")
    closed = set()
    for seq, (ref, t1) in ends.items():
        _require(ref in begins,
                 f"hold_end seq {seq} names unknown hold_begin ref {_shown(ref)}")
        _require(ref not in closed,
                 f"hold_begin ref {_shown(ref)} closes twice")
        closed.add(ref)
        _require(t1 >= begins[ref],
                 f"hold_end seq {seq} t1 precedes its hold_begin t0")
    _require(len(cancels) <= 1, "two cancel markers in one ledger")
    for row in cancels:
        inside = any(begins[ref] <= row["t"] <= t1
                     for _seq, (ref, t1) in ends.items())
        _require(inside, "cancel marker outside the A hold window")
    seen_after = set()
    for seq, after, stamp in retires:
        _require(after in ends,
                 f"retire seq {seq} names unknown hold_end after {_shown(after)}")
        _require(after not in seen_after,
                 f"hold_end after {_shown(after)} retires twice")
        seen_after.add(after)
        _require(seq > after,
                 f"retire seq {seq} precedes its hold_end completion")
        _require(stamp >= ends[after][1],
                 f"retire seq {seq} precedes its hold_end completion")
    return {"issued": ack["issued"], "held": ack["held"]}


def _event_req(row, kind):
    _require(_integer(row["req"], minimum=1), f"{kind} req out of range")
    return row["req"]


def _event_stamp(row, kind):
    _require(_integer(row["t"]), f"{kind} t out of range")
    return row["t"]


def _event_seal(row, kind):
    _require(_integer(row["seal"], minimum=1), f"{kind} seal out of range")
    return row["seal"]


def validate_events(rows):
    """Validate evidence shape; return the request/seal summary."""
    drawn = {}
    revalidated = {}
    seals = {}
    detailed = {}
    for position, row in enumerate(rows, start=1):
        _require(type(row) is dict, f"event at position {position} must be an object")
        kind = row.get("kind")
        _require(kind in EVENT_KINDS,
                 f"unexpected event kind {_shown(kind)} at position {position}")
        if kind == "drawn":
            _keys(row, {"kind", "req", "caller", "provider", "view", "t"})
            req = _event_req(row, kind)
            _require(_integer(row["caller"]), "drawn caller out of range")
            _require(_integer(row["provider"]), "drawn provider out of range")
            _require(_integer(row["view"], minimum=1), "drawn view out of range")
            stamp = _event_stamp(row, kind)
            _require(req not in drawn, f"req {_shown(req)} drawn twice")
            drawn[req] = stamp
        elif kind == "revalidated":
            _keys(row, {"kind", "req", "t"})
            req = _event_req(row, kind)
            stamp = _event_stamp(row, kind)
            _require(req not in revalidated, f"req {_shown(req)} revalidated twice")
            revalidated[req] = stamp
        elif kind == "seal_settled":
            _keys(row, {"kind", "seal", "t"})
            seal = _event_seal(row, kind)
            stamp = _event_stamp(row, kind)
            _require(seal not in seals, f"seal {_shown(seal)} settled twice")
            seals[seal] = stamp
        elif kind == "detailed":
            _keys(row, {"kind", "req", "seal", "t"})
            req = _event_req(row, kind)
            seal = _event_seal(row, kind)
            stamp = _event_stamp(row, kind)
            _require(req not in detailed, f"req {_shown(req)} detailed twice")
            detailed[req] = (stamp, seal)
        elif kind == "completed":
            _keys(row, {"kind", "req", "seal", "t"})
            _event_req(row, kind)
            _event_seal(row, kind)
            _event_stamp(row, kind)
        elif kind == "owner_transferred":
            _keys(row, {"kind", "req", "from", "to", "seal", "t"})
            _event_req(row, kind)
            _require(row["from"] == "A",
                     f"transfer from {_shown(row['from'])} is not A")
            _require(row["to"] == "B",
                     f"transfer to {_shown(row['to'])} is not B")
            _event_seal(row, kind)
            _event_stamp(row, kind)
        elif kind == "retired":
            _keys(row, {"kind", "req", "side", "t"})
            _event_req(row, kind)
            _require(row["side"] in ("A", "B"),
                     f"retired side {_shown(row['side'])} is not a lane")
            _event_stamp(row, kind)
        elif kind == "cancelled":
            _keys(row, {"kind", "req", "t"})
            _event_req(row, kind)
            _event_stamp(row, kind)
        elif kind == "refused":
            _keys(row, {"kind", "req", "reason", "t"})
            _event_req(row, kind)
            _require(row["reason"] in REFUSAL_CELLS,
                     f"refusal reason {_shown(row['reason'])} is outside the four cells")
            _event_stamp(row, kind)
        elif kind == "view_expired":
            _keys(row, {"kind", "req", "view", "t"})
            _event_req(row, kind)
            _require(_integer(row["view"], minimum=1), "view_expired view out of range")
            _event_stamp(row, kind)
        elif kind == "inventory_ended":
            _keys(row, {"kind", "t"})
            _event_stamp(row, kind)
        elif kind == "inventory_pulse":
            _keys(row, {"kind", "t", "calls"})
            _event_stamp(row, kind)
            _require(_integer(row["calls"]), "inventory_pulse calls out of range")
        elif kind == "scope":
            _keys(row, {"kind", "req", "parent"})
            _event_req(row, kind)
            _require(row["parent"] in ("pid", "system", "cgroup"),
                     f"scope parent {_shown(row['parent'])} is not a scope")
    return {"reqs": len(drawn), "seals": len(seals), "detailed": len(detailed)}


def _ledger_index(rows):
    begins = {}
    ends = {}
    calls = []
    cancels = []
    retires = []
    alive = []
    for row in rows:
        kind = row.get("kind")
        if kind == "hold_begin":
            begins[row["seq"]] = row["t0"]
        elif kind == "hold_end":
            ends[row["seq"]] = (row["ref"], row["t1"])
        elif kind == "call":
            calls.append(row)
        elif kind == "cancel":
            cancels.append(row)
        elif kind == "retire":
            retires.append(row)
        elif kind == "alive":
            alive.append(row["t"])
    return begins, ends, calls, cancels, retires, alive


def _events_index(rows):
    index = {
        "drawn": {}, "revalidated": {}, "seals": {}, "detailed": {},
        "completed": {}, "transfers": {}, "retired": {}, "cancelled": {},
        "refused": {}, "expired": [], "ended": [], "pulses": [], "scopes": {},
    }
    for row in rows:
        kind = row.get("kind")
        if kind == "drawn":
            index["drawn"][row["req"]] = row["t"]
        elif kind == "revalidated":
            index["revalidated"][row["req"]] = row["t"]
        elif kind == "seal_settled":
            index["seals"][row["seal"]] = row["t"]
        elif kind == "detailed":
            index["detailed"][row["req"]] = (row["t"], row["seal"])
        elif kind == "completed":
            _require(row["req"] not in index["completed"],
                     f"req {_shown(row['req'])} completed twice")
            index["completed"][row["req"]] = (row["t"], row["seal"])
        elif kind == "owner_transferred":
            _require(row["req"] not in index["transfers"],
                     f"req {_shown(row['req'])} transferred twice")
            index["transfers"][row["req"]] = (row["t"], row["seal"])
        elif kind == "retired":
            _require(row["req"] not in index["retired"],
                     f"req {_shown(row['req'])} retired twice")
            index["retired"][row["req"]] = (row["t"], row["side"])
        elif kind == "cancelled":
            _require(row["req"] not in index["cancelled"],
                     f"req {_shown(row['req'])} cancelled twice")
            index["cancelled"][row["req"]] = row["t"]
        elif kind == "refused":
            _require(row["req"] not in index["refused"],
                     f"req {_shown(row['req'])} refused twice")
            index["refused"][row["req"]] = (row["t"], row["reason"])
        elif kind == "view_expired":
            index["expired"].append(row)
        elif kind == "inventory_ended":
            index["ended"].append(row["t"])
        elif kind == "inventory_pulse":
            index["pulses"].append(row)
        elif kind == "scope":
            index["scopes"][row["req"]] = row["parent"]
    return index


def _terminal_before(index, req, stamp):
    """The first terminal row at or before stamp for req, if any."""
    moments = []
    for kind in ("completed", "retired"):
        if req in index[kind]:
            moments.append(index[kind][req][0])
    if req in index["cancelled"]:
        moments.append(index["cancelled"][req])
    if req in index["refused"]:
        moments.append(index["refused"][req][0])
    earlier = [moment for moment in moments if moment <= stamp]
    return min(earlier) if earlier else None


def _window_end(index, req):
    """The first terminal row for req, if any (stamps never exceed MAX_WORD)."""
    return _terminal_before(index, req, MAX_WORD)


def compare_promotion(rows, events):
    """Join ledger rows to evidence rows. Both must have been validated.

    The comparison needs populations on both sides: at least one drawn
    request and at least one A hold window or B call, else it refuses."""
    begins, ends, calls, cancels, retires, alive = _ledger_index(rows)
    index = _events_index(events)
    drawn = index["drawn"]
    revalidated = index["revalidated"]
    seals = index["seals"]
    detailed = index["detailed"]
    for req, stamp in sorted(revalidated.items()):
        _require(req in drawn, f"revalidated without drawn req {_shown(req)}")
        _require(drawn[req] <= stamp, f"revalidation precedes drawn req {_shown(req)}")
    for req, (stamp, _seal) in sorted(detailed.items()):
        _require(req in drawn, f"detailed without drawn req {_shown(req)}")
        _require(req in revalidated, f"detailed without revalidated req {_shown(req)}")
        _require(drawn[req] <= revalidated[req] <= stamp,
                 f"detailed precedes revalidation req {_shown(req)}")
    sealed_uses = []
    for req, (stamp, seal) in detailed.items():
        sealed_uses.append(("detailed", req, stamp, seal))
    for req, (stamp, seal) in index["completed"].items():
        sealed_uses.append(("completed", req, stamp, seal))
    for req, (stamp, seal) in index["transfers"].items():
        sealed_uses.append(("owner_transferred", req, stamp, seal))
    for kind, req, stamp, seal in sorted(sealed_uses):
        _require(seal in seals,
                 f"req {_shown(req)} {kind} names unsettled seal {_shown(seal)}")
        _require(seals[seal] <= stamp,
                 f"req {_shown(req)} {kind} precedes seal {_shown(seal)} settlement")
    for req, (stamp, _seal) in sorted(index["completed"].items()):
        _require(req in detailed, f"completed without detailed req {_shown(req)}")
        _require(detailed[req][0] <= stamp,
                 f"completed precedes detailed req {_shown(req)}")
    for req, (stamp, _seal) in sorted(index["transfers"].items()):
        _require(req in index["completed"],
                 f"transfer without completed req {_shown(req)}")
        _require(index["completed"][req][0] <= stamp,
                 f"transfer precedes completed req {_shown(req)}")
    for req, (stamp, side) in sorted(index["retired"].items()):
        _require(req in index["completed"],
                 f"retired without completed req {_shown(req)}")
        _require(index["completed"][req][0] <= stamp,
                 f"retired before completion req {_shown(req)}")
        _require(side == "A", f"retired side {side} is not the A lane req {_shown(req)}")
    for req, stamp in sorted(index["cancelled"].items()):
        _require(req in drawn, f"cancelled without drawn req {_shown(req)}")
        _require(drawn[req] <= stamp, f"cancelled precedes drawn req {_shown(req)}")
    for req, (stamp, reason) in sorted(index["refused"].items()):
        _require(req in drawn, f"refused without drawn req {_shown(req)}")
        _require(drawn[req] <= stamp, f"refused precedes drawn req {_shown(req)}")
        cell = REFUSAL_CELLS[reason]
        if cell == "busy":
            outstanding = any(
                other != req and drawn[other] <= stamp
                and _terminal_before(index, other, stamp) is None
                for other in drawn)
            _require(outstanding, "busy refusal without an outstanding promotion")
        elif cell == "stale":
            expired = any(row["req"] == req and row["t"] <= stamp
                          for row in index["expired"])
            _require(expired,
                     f"stale refusal without a view_expired row for req {_shown(req)}")
        elif cell == "scan":
            ended = any(moment <= stamp for moment in index["ended"])
            _require(ended, "scan refusal without an inventory_ended row")
        elif cell == "unsupported":
            parent = index["scopes"].get(req)
            _require(parent == "cgroup",
                     f"unsupported refusal without a cgroup parent scope req {_shown(req)}")
    windows = {}
    for req, (stamp, _seal) in detailed.items():
        windows[req] = (stamp, _window_end(index, req))
    for req, (start, end) in sorted(windows.items()):
        inside = [call for call in calls
                  if call["t0"] >= start and (end is None or call["t1"] <= end)]
        _require(inside, f"no B useful call inside the Detailed window of req {_shown(req)}")
    for call in calls:
        covered = any(call["t0"] >= start and (end is None or call["t1"] <= end)
                      for start, end in windows.values())
        _require(covered,
                 f"B call seq {_shown(call['seq'])} outside every Detailed window")
    for req, (start, _end) in sorted(windows.items()):
        before = any(row["calls"] > 0 and row["t"] < start for row in index["pulses"])
        _require(before, f"broad Inventory stalls before Detailed req {_shown(req)}")
        after = any(row["calls"] > 0 and row["t"] > start for row in index["pulses"])
        _require(after, f"broad Inventory stalls after Detailed req {_shown(req)}")
    if cancels:
        _require(index["cancelled"],
                 "ledger cancel marker without an observed cancelled row")
        moment = cancels[0]["t"]
        _require(any(tick > moment for tick in alive),
                 "cancel drops caller: no liveness after the cancel marker")
        enclosing = [t1 for _seq, (ref, t1) in ends.items()
                     if begins[ref] <= moment <= t1]
        _require(enclosing, "cancel marker outside the A hold window")
        horizon = min(enclosing)
        for call in calls:
            _require(not (moment < call["t0"] < horizon),
                     f"B call seq {_shown(call['seq'])} admitted during the cancel gap")
    if index["cancelled"]:
        _require(cancels, "observed cancelled row without a ledger cancel marker")
    if retires:
        _require(index["retired"], "ledger retirement without an observed retired row")
    if index["retired"]:
        _require(retires, "observed retired row without a ledger retirement")
    if retires:
        floor = max(row["t"] for row in retires)
        for req, (stamp, _seal) in sorted(index["transfers"].items()):
            _require(stamp >= floor,
                     f"B admitted before A retires req {_shown(req)}")
    elif index["transfers"]:
        _require(ends, "transfer without an A hold window")
        floor = max(t1 for _ref, t1 in ends.values())
        for req, (stamp, _seal) in sorted(index["transfers"].items()):
            _require(stamp >= floor,
                     f"B admitted before the A completion req {_shown(req)}")
    # Minimum-population floor, checked after the specific joins so their
    # reasons keep precedence: a comparison with zero populations on
    # either side refuses instead of passing vacuously.
    _require(drawn, "comparison without drawn populations")
    _require(begins or calls, "comparison without ledger populations")
    return {"reqs": len(drawn),
            "detailed": len(detailed),
            "transfers": len(index["transfers"])}


def compare_runs(first, second):
    """Require two ledgers to converge structurally, ignoring stamps.

    Only kind, fn and rv are compared: validation already pins every
    side and every ref/after link, so same-length valid ledgers cannot
    diverge on those, and an unreachable comparison would prove nothing.
    """
    validate_ledger(first)
    validate_ledger(second)
    _require(len(first) == len(second),
             f"run ledgers differ in length {len(first)} against {len(second)}")
    for position, (left, right) in enumerate(zip(first, second), start=1):
        _require(left.get("kind") == right.get("kind"),
                 f"run ledgers diverge at row {position}")
        kind = left.get("kind")
        if kind in ("hold_begin", "call"):
            _require(left.get("fn") == right.get("fn"),
                     f"run ledgers diverge at row {position}")
        if kind in ("call", "hold_end"):
            _require(left.get("rv") == right.get("rv"),
                     f"run ledgers diverge at row {position}")
    return {"matched_rows": len(first)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="ledger JSONL file, or - for stdin")
    parser.add_argument("events", nargs="?",
                        help="promotion-evidence JSONL file, or - for stdin")
    parser.add_argument("--second", default=None, metavar="LEDGER2",
                        help="second ledger JSONL file for a run-convergence check")
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
            validate_events(events)
            result.update(compare_promotion(rows, events))
        if args.second is not None:
            with open(args.second, encoding="utf-8") as stream:
                other = read_ledger(stream)
            result.update(compare_runs(rows, other))
    except LedgerError as error:
        print(f"promotion refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("promotion refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
