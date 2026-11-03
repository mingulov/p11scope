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

With --exact, one more document joins the verdict: the sweep-side
exact-arm evidence (``{"prearmed", "module", "verdict"}``), where the
module is the judged evidence.discovery[] record projection (sources,
watch, attached_at_ns, unobserved_windows) and the verdict is the
terminal completeness plus gap_classes. The pre-armed arm passes only on
explicitly empty windows with exact counts, an armed watch at the
declared attach maximum and an exact verdict-cause allowlist; the
passive twin passes only on a disclosed pre_attach/late_discovery window
with no invented count. An absent key is never read as exact.
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
# Exact-arm verdict vocabulary (evidence.discovery[] + gap_classes shapes).
EXACT_NATURAL_ENDS = ("scope_end", "stop")
TWIN_WINDOW_REASONS = ("pre_attach", "late_discovery")
# Bare pre-arm attribution in the product's fixed cause order: every
# pre-arm slot is count-only (never semantic-authorized), and the bare
# module reads uncorroborated.
BARE_ATTRIBUTION_CAUSES = ["semantic_unverified_slots",
                           "discovery_uncorroborated"]
MAX_ROWS = 1024
MAX_LINE_BYTES = 65536
MAX_LEDGER_BYTES = 1024 * 1024
MAX_WORD = (1 << 64) - 1


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
    return type(value) is int and minimum <= value <= MAX_WORD


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise MeasureError("nonfinite JSON number")


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
            rows.append(json.loads(line, object_pairs_hook=_unique_object,
                                   parse_constant=_invalid_constant))
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
    for phase in ("table_verified", "entry_executed", "entry_returned"):
        _require(sum(1 for row in rows if row["phase"] == phase) <= 1,
                 f"ledger must carry at most one {phase} row")
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


def cell_verdict(cell, observer, exact=None):
    """Verdict for one cell: gated and incomplete cells stay non-positive.

    With ``exact`` evidence (a real ``--prearm-module`` cell or its
    passive twin), the verdict additionally judges the pre-arm proof
    shape: an explicitly empty window list with exact counts, an armed
    watch at the declared attach maximum and an exact verdict-cause
    allowlist on the pre-armed arm, or a disclosed pre_attach /
    late_discovery window with no invented count on the twin. Any
    deviation is refused; only full exactness (or full disclosure on
    the twin) counts as positive.
    """
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
    if exact is None:
        return {"positive": True, "missed": missed,
                "attribution": attributed, **context}
    return _exact_cell_verdict(missed, attributed, exact, context)


def _exact_shape(exact):
    """Split exact evidence into its arm flag, module and verdict records."""
    _require(type(exact) is dict, "exact evidence must be an object")
    prearmed = exact.get("prearmed")
    _require(type(prearmed) is bool,
             "exact evidence must name a prearmed arm")
    allowed = {"prearmed", "module", "verdict"} if prearmed else {
        "prearmed", "module"}
    _require(set(exact) <= allowed,
             "exact evidence carries unexpected keys")
    module = exact.get("module")
    _require(type(module) is dict,
             "exact arm without its module record" if prearmed
             else "twin without its module record")
    verdict = exact.get("verdict")
    if prearmed:
        _require(type(verdict) is dict,
                 "exact arm without its verdict record")
    return prearmed, module, verdict


def _exact_watch(module):
    """The judged watch state of a pre-armed exact module record.

    The armed interval reads ``armed``/``armed_idle`` while open; the
    terminal close of a used watch voids ``armed`` into ``ended``, so a
    natural close (``scope_end``/``stop``) with the arm instant intact
    proves the same interval. Anything else never armed.
    """
    watch = module.get("watch")
    _require(type(watch) is dict, "exact arm without its watch")
    _require(watch.get("changed") is None,
             "pinned object changed under its watch")
    state = watch.get("state")
    ended_by = watch.get("ended_by")
    until_ns = watch.get("until_ns")
    if state == "armed":
        _require(ended_by is None and until_ns is None,
                 "armed watch carries an end")
    elif state == "armed_idle":
        _require(ended_by is None or ended_by in EXACT_NATURAL_ENDS,
                 f"watch ended by {_shown(ended_by)} instead of a "
                 "natural close")
    elif state == "ended":
        _require(ended_by in EXACT_NATURAL_ENDS,
                 f"watch ended by {_shown(ended_by)} instead of a "
                 "natural close")
    else:
        raise MeasureError(f"watch state {_shown(state)} is not an "
                           "armed interval")
    since_ns = watch.get("since_ns")
    _require(_integer(since_ns), "watch without its since_ns arm instant")
    attached_at_ns = module.get("attached_at_ns")
    _require(_integer(attached_at_ns),
             "module without its attached_at_ns instant")
    _require(since_ns == attached_at_ns,
             f"watch since_ns {since_ns} disagrees with attached_at_ns "
             f"{attached_at_ns}")
    return state


def _exact_class(classes, name, status, causes):
    """One gap class against its exact status and cause list."""
    group = classes.get(name)
    _require(type(group) is dict, f"verdict without its {name} class")
    _require(group.get("status") == status,
             f"{name} status {_shown(group.get('status'))} outside the "
             "exact allowlist")
    got = group.get("causes")
    _require(type(got) is list and
             all(type(cause) is str for cause in got) and got == causes,
             f"{name} causes outside the exact allowlist")


def _exact_causes(module, verdict):
    """The judged completeness of a pre-armed exact verdict record.

    The variant follows the module sources: bare pre-arm reads PARTIAL
    solely for its expected attribution pair, while a manifest-backed
    module reads COMPLETE with every cause list empty. Observation stays
    exact, semantics stay clean, no call is left open and the terminal
    drain stays proven on both.
    """
    sources = module.get("sources")
    _require(type(sources) is list and
             all(type(source) is str for source in sources),
             "module sources must be a string list")
    _require("prearm" in sources, "module without a prearm source")
    manifest_backed = "manifest" in sources
    completeness = verdict.get("completeness")
    detail = verdict.get("verdict_detail")
    classes = verdict.get("gap_classes")
    _require(type(classes) is dict, "verdict without gap_classes")
    if manifest_backed:
        _require(completeness == "COMPLETE",
                 f"completeness {_shown(completeness)} outside the "
                 "manifest-backed allowlist")
        _require(detail == "clean_proven",
                 f"verdict_detail {_shown(detail)} outside the "
                 "manifest-backed allowlist")
        _exact_class(classes, "observation", "exact", [])
        _exact_class(classes, "attribution", "attested", [])
        _exact_class(classes, "semantics", "complete", [])
    else:
        _require(completeness == "PARTIAL",
                 f"completeness {_shown(completeness)} outside the "
                 "bare pre-arm allowlist")
        _require(detail == "attribution_only",
                 f"verdict_detail {_shown(detail)} outside the bare "
                 "pre-arm allowlist")
        _exact_class(classes, "observation", "exact", [])
        _exact_class(classes, "attribution", "withheld",
                     BARE_ATTRIBUTION_CAUSES)
        _exact_class(classes, "semantics", "not_applicable", [])
    open_calls = classes.get("open_calls")
    _require(type(open_calls) is int and open_calls == 0,
             f"open_calls {_shown(open_calls)} outside the exact "
             "allowlist")
    settlement = classes.get("settlement")
    _require(settlement == "proven",
             f"settlement {_shown(settlement)} outside the exact "
             "allowlist")
    return completeness


def _twin_window(window, attached_at_ns):
    """One disclosed twin window against the attach instant."""
    _require(type(window) is dict, "twin window must be an object")
    start_ns = window.get("start_ns")
    end_ns = window.get("end_ns")
    _require(_integer(start_ns) and _integer(end_ns),
             "twin window without integer bounds")
    _require(start_ns <= end_ns,
             f"twin window ends {end_ns} before it starts {start_ns}")
    _require(end_ns == attached_at_ns,
             f"twin window end {end_ns} disagrees with attached_at_ns "
             f"{attached_at_ns}")
    reason = window.get("reason")
    _require(reason in TWIN_WINDOW_REASONS,
             f"twin window reason {_shown(reason)} outside "
             "pre_attach/late_discovery")


def _exact_cell_verdict(missed, attributed, exact, context):
    """Exact-arm verdict over judged counts: refuse any deviation."""
    prearmed, module, verdict = _exact_shape(exact)
    _require("unobserved_windows" in module,
             "module without its unobserved_windows key")
    windows = module["unobserved_windows"]
    _require(type(windows) is list, "unobserved_windows must be a list")
    if prearmed:
        _require(not windows,
                 f"exact arm discloses {len(windows)} unobserved windows")
        _require(missed["missed_calls"] == 0,
                 f"exact arm missed {missed['missed_calls']} of "
                 f"{missed['body_calls']} calls")
        state = _exact_watch(module)
        completeness = _exact_causes(module, verdict)
        return {"positive": True, "missed": missed,
                "attribution": attributed,
                "exactness": {"prearmed": True, "windows": 0,
                              "watch_state": state,
                              "completeness": completeness}, **context}
    _require(windows, "passive arm claims exact windows")
    attached_at_ns = module.get("attached_at_ns")
    _require(_integer(attached_at_ns),
             "twin without its attached_at_ns instant")
    for window in windows:
        _twin_window(window, attached_at_ns)
    _require(module.get("watch") is None,
             "passive module carries a watch")
    return {"positive": True, "missed": missed, "attribution": attributed,
            "exactness": {"prearmed": False, "windows": len(windows),
                          "watch_state": None, "completeness": None},
            **context}


def check_bounds(entries, bound_table):
    """Check per-cell missed counts against a delay-indexed bound table.

    Part B always passes the full 4-key table, even for subset checks
    such as the Fedora 0/1000us corners (delays without entries are
    simply never looked up); subset tables stay refused."""
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
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
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
    parser.add_argument("--exact", default=None,
                        help="exact-arm evidence JSON file")
    args = parser.parse_args(argv)
    try:
        with open(args.ledger, encoding="utf-8") as stream:
            rows = read_rows(stream)
        observer = _read_object(args.observer, "observer record")
        bounds = (_read_object(args.bounds, "bound table")
                  if args.bounds is not None else None)
        exact = (_read_object(args.exact, "exact evidence")
                 if args.exact is not None else None)
        cell = validate_cell(rows)
        verdict = cell_verdict(cell, observer, exact)
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
