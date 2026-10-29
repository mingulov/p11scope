#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare two-provider ledger evidence against snapshot rows.

Ledger input: E17-pattern JSONL extended with feed labels and cut/handle
marker rows, as emitted by tests/fixtures/two-providers/dlmopen-sibs.c
(same-file dlmopen siblings, colliding handles), late-b.c (late B
arrival, physical cut, post-cut burst) and forward-sparse-stub.c
(provider-free forwarding and sparse emission). The first row is ready;
further
ready rows, call rows and cut/handle marker rows follow in arrival order;
one ack row closes. Call seq is global and contiguous across feeds;
issued counts call rows only, so markers are transparent to counts.
A forwarding layer evidences its sums with forward marker rows
{kind, feed, count, t}: shaped and window-checked like handle rows,
likewise transparent to issued. Snapshot key_rows carry the echoed
forwarded sum beside started/completed/failed/unknown; the comparison
proves the forwarded sum is never merged into any hardware-operation
tally (per-feed exact match against ledger calls, unchanged) and that
the echo equals the ledgered sum exactly. Forwarded sums are
fixture-evidenced, never derived; the oracle proves only non-merger
and the exact echo.
Clocks are CLOCK_MONOTONIC ns.

Ready rows may arrive late (feed B loads after feed A runs); every
call and marker must still start at or after its own feed's ready stamp.
Snapshot input: one JSON document with instances[] ({id, caller, module,
feed, state, reason, first_seen_ns, last_seen_ns}), modules[] ({id, key
{device [major, minor], inode, sha256}, lifecycle}), key_rows[] ({instance,
feed, started, completed, failed, unknown} plus optional cut_published /
cut_published_failed), gaps[] ({subject, reason}), optional edges[]
({module, mapping {state, interruptions}}) and optional budgets ({instances
{limit, occupied, refused}}). Feed labels on snapshot rows are join keys
from the known fixture wiring (which file is feed A), not observer
claims. Ledger rows use exact keys; snapshot rows need their required
keys only, so producer-side additions never break the comparison.

Verdicts, in order: framing/shape; one module means the same-file merge
path (the double-load gap must name it and no feed may claim a positive);
otherwise the split path (one caller across feeds, distinct module per
feed, per-feed counts exact, cut arithmetic with mapping-interruption and
identity-gap evidence, uncertainty in one feed never weakens another);
forwarded sums echo the ledgered markers exactly on every path and never
merge into hardware-operation tallies; the association bound over observed
rows. Refusal exits 1 with a
numbers-only reason; feed names print verbatim (charset-bound labels,
never payload). Twins live in
tests/python/test_joint_two_provider_oracle.py.
"""

import argparse
import json
import re
import sys

MAX_CALLS = 200000
# ready + calls + ack plus cut/handle/forward marker headroom: the
# fixtures emit at most two readys, two handles, one cut and a bounded
# run of forward markers beside 2*COUNT calls.
MAX_ROWS = MAX_CALLS + 128
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
MAX_CUTS = 64
MAX_HANDLES = 64
MAX_FORWARDS = 64
MAX_INSTANCES = 4096
FN_PATTERN = re.compile(r"[A-Za-z0-9_\[\]]{1,64}\Z")
FEED_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
REF_PATTERN = re.compile(r"[icm][0-9]{1,10}\Z")
SHA_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
DOUBLE_LOAD_GAP = "same-file double-load detected"
CHANGED_IDENTITY_GAP = "inventory attach target changed identity"


class LedgerError(ValueError):
    """The ledger, snapshot or comparison is incomplete or inconsistent."""


def _require(condition, reason):
    if not condition:
        raise LedgerError(reason)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_WORD


def _keys(row, expected, optional=()):
    _require(type(row) is dict, "row must be an object")
    keys = set(row)
    _require(set(expected) <= keys <= set(expected) | set(optional),
             "unexpected fields")


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


def _read_jsonl(stream, what, cap_bytes):
    """Read bounded JSONL without retaining or printing unknown payloads."""
    rows = []
    total = 0
    while line := stream.readline(MAX_LINE_BYTES + 1):
        _require(type(line) is str, f"{what} must be text")
        try:
            size = len(line.encode("utf-8"))
        except UnicodeError as error:
            raise LedgerError(f"invalid {what} encoding") from error
        total += size
        _require(size <= MAX_LINE_BYTES and total <= cap_bytes,
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
    """Read bounded two-provider ledger JSONL rows."""
    return _read_jsonl(stream, "ledger", MAX_LEDGER_BYTES)


def _feed_of(row, feeds, single):
    feed = row.get("feed", single)
    _require(type(feed) is str and feed in feeds,
             f"call names undeclared feed {_shown(row.get('feed'))}")
    return feed


def validate_ledger(rows):
    """Validate ready/call/ack/cut/handle shape; return feed summaries."""
    _require(rows, "empty ledger")
    _require(type(rows[0]) is dict and rows[0].get("kind") == "ready",
             "first row must be ready")
    _require(type(rows[-1]) is dict and rows[-1].get("kind") == "ack",
             "last row must be ack")
    readys = [row for row in rows[:-1]
              if type(row) is dict and row.get("kind") == "ready"]
    _require(readys, "first row must be ready")
    feeds = []
    for ready in readys:
        _keys(ready, {"kind", "pid", "tid", "t", "clock", "unit"},
              optional=("feed",))
        _require(_integer(ready["pid"], minimum=1), "ready pid out of range")
        _require(_integer(ready["tid"], minimum=1), "ready tid out of range")
        _require(_integer(ready["t"]), "ready t out of range")
        _require(ready["clock"] == "CLOCK_MONOTONIC",
                 "ready clock basis mismatch")
        _require(ready["unit"] == "ns", "ready clock unit mismatch")
        feed = ready.get("feed")
        if feed is not None:
            _require(type(feed) is str and FEED_PATTERN.match(feed),
                     "ready feed label invalid")
            _require(feed not in feeds, f"duplicate ready for feed {feed}")
            feeds.append(feed)
    if not feeds:
        _require(len(readys) == 1, "unlabeled ready rows need one feed")
        feeds = ["main"]
    else:
        _require(len(feeds) == len(readys),
                 "mixed labeled and unlabeled ready rows")
    single = feeds[0] if len(feeds) == 1 else None
    ack = rows[-1]
    _keys(ack, {"kind", "issued", "t"})
    _require(_integer(ack["issued"]), "ack issued out of range")
    _require(_integer(ack["t"]), "ack t out of range")
    window_start = min(ready["t"] for ready in readys)
    _require(ack["t"] >= window_start, "ack precedes ready window")
    for ready in readys:
        _require(ready["t"] <= ack["t"], "ready follows the ack")
    declared = {(ready["pid"], ready["tid"]) for ready in readys}
    calls = []
    cuts = []
    handles = []
    forwards = []
    for row in rows[1:-1]:
        _require(type(row) is dict, "middle row must be an object")
        kind = row.get("kind")
        _require(kind in ("ready", "call", "cut", "handle", "forward"),
                 f"unexpected {_shown(kind)} row between ready and ack")
        if kind == "call":
            _keys(row, {"kind", "seq", "fn", "rv", "pid", "tid", "t0", "t1"},
                  optional=("feed",))
            calls.append(row)
        elif kind == "cut":
            _keys(row, {"kind", "feed", "at_seq", "t"})
            _require(type(row["feed"]) is str and row["feed"] in feeds,
                     f"cut names undeclared feed {_shown(row['feed'])}")
            _require(_integer(row["at_seq"]), "cut at_seq out of range")
            _require(_integer(row["t"]), "cut t out of range")
            _require(window_start <= row["t"] <= ack["t"],
                     "cut lies outside the ready/ack window")
            cuts.append(row)
        elif kind == "handle":
            _keys(row, {"kind", "feed", "slot", "value", "t"})
            _require(type(row["feed"]) is str and row["feed"] in feeds,
                     f"handle names undeclared feed {_shown(row['feed'])}")
            _require(_integer(row["slot"]) and row["slot"] <= 103,
                     "handle slot out of range")
            _require(_integer(row["value"]), "handle value out of range")
            _require(_integer(row["t"]), "handle t out of range")
            _require(window_start <= row["t"] <= ack["t"],
                     "handle lies outside the ready/ack window")
            handles.append(row)
        elif kind == "forward":
            _keys(row, {"kind", "feed", "count", "t"})
            _require(type(row["feed"]) is str and row["feed"] in feeds,
                     f"forward names undeclared feed {_shown(row['feed'])}")
            _require(_integer(row["count"]) and row["count"] >= 1,
                     "forward count out of range")
            _require(_integer(row["t"]), "forward t out of range")
            _require(window_start <= row["t"] <= ack["t"],
                     "forward lies outside the ready/ack window")
            forwards.append(row)
    _require(len(cuts) <= MAX_CUTS, "cut row limit")
    _require(len(handles) <= MAX_HANDLES, "handle row limit")
    _require(len(forwards) <= MAX_FORWARDS, "forward row limit")
    _require(ack["issued"] == len(calls),
             f"issued {ack['issued']} disagrees with {len(calls)} call rows")
    if len(readys) == 1 and "feed" not in readys[0]:
        ready_t = {"main": readys[0]["t"]}
    else:
        ready_t = {ready["feed"]: ready["t"] for ready in readys}
    for cut in cuts:
        _require(cut["t"] >= ready_t[cut["feed"]],
                 f"cut precedes the {cut['feed']} ready row")
    for handle in handles:
        _require(handle["t"] >= ready_t[handle["feed"]],
                 f"handle precedes the {handle['feed']} ready row")
    for forward in forwards:
        _require(forward["t"] >= ready_t[forward["feed"]],
                 f"forward precedes the {forward['feed']} ready row")
    feed_rows = {feed: [] for feed in feeds}
    for position, row in enumerate(calls, start=1):
        _require(row["seq"] == position,
                 f"seq {_shown(row['seq'])} breaks contiguity at position {position}")
        _require(type(row["fn"]) is str and FN_PATTERN.match(row["fn"]),
                 f"fn label invalid at seq {position}")
        _require(_integer(row["rv"]), f"rv out of range at seq {position}")
        _require(single is not None or "feed" in row,
                 f"call without feed label is ambiguous at seq {position}")
        feed = _feed_of(row, feeds, single)
        _require((row["pid"], row["tid"]) in declared,
                 f"pid/tid {_shown(row['pid'])}/{_shown(row['tid'])} match "
                 f"no ready row at seq {position}")
        _require(_integer(row["t0"]) and _integer(row["t1"]),
                 f"t0/t1 out of range at seq {position}")
        _require(row["t0"] <= row["t1"],
                 f"t1 {row['t1']} precedes t0 {row['t0']} at seq {position}")
        _require(window_start <= row["t0"] and row["t1"] <= ack["t"],
                 f"seq {position} lies outside the ready/ack window")
        _require(row["t0"] >= ready_t[feed],
                 f"seq {position} precedes the {feed} ready row")
        feed_rows[feed].append(row)
    by_seq = {row["seq"]: row for row in calls}
    position_of = {}
    for index, row in enumerate(rows[1:-1]):
        if row.get("kind") == "call":
            position_of[row["seq"]] = index
    cut_positions = {}
    for index, row in enumerate(rows[1:-1]):
        if row.get("kind") == "cut":
            cut_positions.setdefault((row["feed"], row["at_seq"]), []).append(index)
    seen_cut = {}
    for cut in cuts:
        feed = cut["feed"]
        at_seq = cut["at_seq"]
        if at_seq:
            _require(at_seq in by_seq, f"cut at_seq {_shown(at_seq)} names no call")
            _require(by_seq[at_seq].get("feed", single) == feed,
                     f"cut at_seq {_shown(at_seq)} names another feed's call")
            _require(cut["t"] >= by_seq[at_seq]["t1"],
                     f"cut precedes its last pre-cut call at seq {_shown(at_seq)}")
            slot = cut_positions[(feed, at_seq)].pop(0)
            _require(slot > position_of[at_seq],
                     f"cut emitted before its last pre-cut call at seq {_shown(at_seq)}")
        _require(at_seq not in seen_cut.get(feed, ()),
                 f"duplicate cut at_seq {_shown(at_seq)} for feed {feed}")
        seen_cut.setdefault(feed, []).append(at_seq)
    summary = {"issued": ack["issued"], "calls": len(calls), "feeds": {},
               "cuts": cuts, "handles": handles, "forwards": forwards,
               "window_start": window_start, "ack_t": ack["t"]}
    for feed in feeds:
        rows_for = feed_rows[feed]
        summary["feeds"][feed] = {
            "calls": len(rows_for),
            "ok": sum(1 for row in rows_for if row["rv"] == 0),
            "failed": sum(1 for row in rows_for if row["rv"] != 0),
            "forwarded": sum(row["count"] for row in forwards
                             if row["feed"] == feed),
            "ready_t": ready_t[feed],
            "seqs": sorted(row["seq"] for row in rows_for),
            "ok_seqs": sorted(row["seq"] for row in rows_for
                              if row["rv"] == 0),
        }
    return summary


def read_snapshot(stream):
    """Read and shape-check one snapshot JSON document."""
    try:
        text = stream.read(MAX_SNAPSHOT_BYTES + 1)
    except UnicodeError as error:
        raise LedgerError("invalid snapshot encoding") from error
    _require(type(text) is str, "snapshot must be text")
    _require(len(text.encode("utf-8")) <= MAX_SNAPSHOT_BYTES,
             "snapshot byte limit")
    try:
        snapshot = json.loads(text, object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
    except json.JSONDecodeError as error:
        raise LedgerError("invalid snapshot row") from error
    _require(type(snapshot) is dict, "snapshot must be an object")
    for key in ("instances", "modules", "key_rows", "gaps"):
        _require(key in snapshot, f"snapshot without {key}")
        _require(type(snapshot[key]) is list, f"snapshot {key} must be a list")
    for row in snapshot["instances"]:
        _require(type(row) is dict, "instance row must be an object")
        for key in ("id", "caller", "module", "feed", "state", "reason",
                    "first_seen_ns", "last_seen_ns"):
            _require(key in row, f"instance without {key}")
        _require(type(row["id"]) is str and REF_PATTERN.match(row["id"]),
                 "instance id invalid")
        _require(type(row["caller"]) is str and REF_PATTERN.match(row["caller"]),
                 "instance caller invalid")
        _require(type(row["module"]) is str and REF_PATTERN.match(row["module"]),
                 "instance module invalid")
        _require(type(row["feed"]) is str and FEED_PATTERN.match(row["feed"]),
                 "instance feed label invalid")
        _require(row["state"] in ("observed", "uncertain", "retired"),
                 "instance state invalid")
        _require(row["reason"] is None or (
            type(row["reason"]) is str and TOKEN_PATTERN.match(row["reason"])),
            "instance reason invalid")
        _require(_integer(row["first_seen_ns"]), "instance first_seen invalid")
        _require(_integer(row["last_seen_ns"]), "instance last_seen invalid")
        _require(row["first_seen_ns"] <= row["last_seen_ns"],
                 "instance last_seen precedes first_seen")
    identifiers = [row["id"] for row in snapshot["instances"]]
    _require(len(set(identifiers)) == len(identifiers), "duplicate instance id")
    for row in snapshot["modules"]:
        _require(type(row) is dict, "module row must be an object")
        for key in ("id", "key", "lifecycle"):
            _require(key in row, f"module without {key}")
        _require(type(row["id"]) is str and REF_PATTERN.match(row["id"]),
                 "module id invalid")
        key = row["key"]
        _require(type(key) is dict, "module without identity key")
        for name in ("device", "inode", "sha256"):
            _require(name in key, f"module key without {name}")
        _require(type(key["device"]) is list and len(key["device"]) == 2 and
                 all(_integer(part) for part in key["device"]),
                 "module device invalid")
        _require(_integer(key["inode"], minimum=1), "module inode invalid")
        _require(type(key["sha256"]) is str and SHA_PATTERN.match(key["sha256"]),
                 "module sha256 invalid")
        _require(row["lifecycle"] in ("mapped", "unloaded", "unknown"),
                 "module lifecycle invalid")
    identifiers = [row["id"] for row in snapshot["modules"]]
    _require(len(set(identifiers)) == len(identifiers), "duplicate module id")
    seen_keys = set()
    for row in snapshot["modules"]:
        key = row["key"]
        digest = (tuple(key["device"]), key["inode"], key["sha256"])
        _require(digest not in seen_keys, "duplicate module key")
        seen_keys.add(digest)
    for row in snapshot["key_rows"]:
        _require(type(row) is dict, "key row must be an object")
        for key in ("instance", "feed", "started", "completed", "failed",
                    "unknown"):
            _require(key in row, f"key row without {key}")
        _require(type(row["instance"]) is str and
                 REF_PATTERN.match(row["instance"]), "key row instance invalid")
        _require(type(row["feed"]) is str and FEED_PATTERN.match(row["feed"]),
                 "key row feed label invalid")
        for key in ("started", "completed", "failed", "unknown"):
            _require(_integer(row[key]), f"key row {key} out of range")
        for key in ("cut_published", "cut_published_failed"):
            value = row.get(key, 0)
            _require(_integer(value), f"key row {key} out of range")
        forwarded = row.get("forwarded", 0)
        _require(_integer(forwarded), "key row forwarded out of range")
        _require(row.get("cut_published_failed", 0) <= row.get("cut_published", 0),
                 "key row cut_published_failed exceeds cut_published")
    identifiers = [row["instance"] for row in snapshot["key_rows"]]
    _require(len(set(identifiers)) == len(identifiers),
             "duplicate key row instance")
    for row in snapshot["gaps"]:
        _require(type(row) is dict, "gap row must be an object")
        for key in ("subject", "reason"):
            _require(key in row, f"gap without {key}")
            _require(type(row[key]) is str and 1 <= len(row[key]) <= 256,
                     f"gap {key} invalid")
    edges = snapshot.get("edges", [])
    _require(type(edges) is list, "snapshot edges must be a list")
    for row in edges:
        _require(type(row) is dict, "edge row must be an object")
        for key in ("module", "mapping"):
            _require(key in row, f"edge without {key}")
        _require(type(row["module"]) is str and REF_PATTERN.match(row["module"]),
                 "edge module invalid")
        mapping = row["mapping"]
        _require(type(mapping) is dict, "edge without mapping")
        _require(mapping.get("state") in ("mapped", "ended", "uncertain"),
                 "edge mapping state invalid")
        _require(_integer(mapping.get("interruptions")),
                 "edge interruptions out of range")
    budgets = snapshot.get("budgets")
    if budgets is not None:
        _require(type(budgets) is dict, "snapshot budgets must be an object")
        instances = budgets.get("instances")
        _require(type(instances) is dict, "budgets without instances")
        for key in ("limit", "occupied", "refused"):
            _require(key in instances, f"instance budget without {key}")
            _require(_integer(instances[key]), f"instance budget {key} invalid")
        _require(instances["limit"] >= 1, "instance budget limit invalid")
    return snapshot


def check_associations(snapshot):
    instances = snapshot["instances"]
    observed = [row for row in instances if row["state"] == "observed"]
    ordered = sorted(observed,
                     key=lambda row: (row["first_seen_ns"], row["id"]))
    _require(len(ordered) <= MAX_INSTANCES,
             f"association bound exceeded: {len(ordered)} observed past "
             f"{MAX_INSTANCES}")
    pairs = set()
    for row in ordered:
        pair = (row["caller"], row["module"])
        _require(pair not in pairs,
                 f"duplicate observed association {pair[0]} {pair[1]}")
        pairs.add(pair)
    budgets = snapshot.get("budgets")
    if budgets is not None:
        held = budgets["instances"]
        _require(held["occupied"] == min(len(instances), held["limit"]),
                 f"budget occupied {held['occupied']} disagrees with "
                 f"{len(instances)} instance rows")
        if len(instances) > held["limit"]:
            _require(held["refused"] >= len(instances) - held["limit"],
                     "budget refused undercounts overflow rows")
        else:
            _require(held["refused"] == 0,
                     f"budget refused {held['refused']} without overflow")
    return {"associations": len(ordered), "rows": len(instances)}


def compare(summary, snapshot):
    """Compare feed summaries against snapshot rows; return the verdict.

    The summary must come from validate_ledger and the snapshot from
    read_snapshot; feed labels and references print verbatim because the
    readers already bound their charset.
    """
    feeds = summary["feeds"]
    _require(feeds, "comparison without feeds")
    for feed, counts in feeds.items():
        _require(counts["calls"] >= 1, f"feed {feed} has no positive")
    associations = check_associations(snapshot)
    instances = {row["id"]: row for row in snapshot["instances"]}
    modules = {row["id"]: row for row in snapshot["modules"]}
    key_rows = {row["instance"]: row for row in snapshot["key_rows"]}
    for row in snapshot["instances"]:
        _require(row["module"] in modules,
                 f"instance {row['id']} names missing module {_shown(row['module'])}")
        _require(row["feed"] in feeds,
                 f"instance {row['id']} names undeclared feed {row['feed']}")
    for row in snapshot["key_rows"]:
        _require(row["instance"] in instances,
                 f"key row names missing instance {_shown(row['instance'])}")
        _require(row["feed"] in feeds,
                 f"key row names undeclared feed {row['feed']}")
        _require(row["feed"] == instances[row["instance"]]["feed"],
                 f"key row feed {row['feed']} disagrees with instance feed")
    handles = summary["handles"]
    if handles:
        values = {row["value"] for row in handles}
        _require(len(values) == 1,
                 f"no collision evidenced: {_shown(len(values))} handle values")
        covered = {row["feed"] for row in handles}
        for feed in feeds:
            _require(feed in covered, f"feed {feed} without a handle row")
    callers = {row["caller"] for row in snapshot["instances"]}
    _require(len(callers) == 1, "instances span more than one caller")
    referenced = {row["module"] for row in snapshot["instances"]}
    for module_id in modules:
        _require(module_id in referenced,
                 f"module {module_id} without an instance row")
    if len(modules) == 1:
        return _compare_merge(summary, snapshot, instances, key_rows,
                              associations)
    current = {row["module"] for row in snapshot["instances"]
               if row["state"] != "retired"}
    _require(len(current) == len(feeds),
             f"split needs {len(feeds)} current modules, "
             f"found {len(current)}")
    return _compare_split(summary, snapshot, key_rows, associations)


def _compare_merge(summary, snapshot, instances, key_rows, associations):
    subjects = [row["subject"] for row in snapshot["gaps"]]
    _require(DOUBLE_LOAD_GAP in subjects,
             "merge without the double-load gap")
    _require(len(instances) == 1, "merge without exactly one instance")
    for instance_id, key_row in key_rows.items():
        _require(key_row["started"] == 0 and key_row["completed"] == 0,
                 f"double-loaded calls claim a positive on {instance_id}")
        _require(key_row["failed"] == 0 and key_row["unknown"] == 0,
                 f"double-loaded calls claim failures or unknowns "
                 f"on {instance_id}")
        _require(key_row.get("forwarded", 0) == 0,
                 f"double-loaded calls claim forwarded sums "
                 f"on {instance_id}")
    return {"path": "merge", "feeds": sorted(summary["feeds"]),
            "issued": summary["issued"],
            "associations": associations["associations"]}


def _compare_split(summary, snapshot, key_rows, associations):
    feeds = summary["feeds"]
    by_feed = {}
    for row in snapshot["instances"]:
        by_feed.setdefault(row["feed"], []).append(row)
    _require(set(by_feed) == set(feeds),
             "a feed lacks an instance row")
    feed_modules = {}
    for feed, rows_in in by_feed.items():
        current = [row for row in rows_in if row["state"] != "retired"]
        _require(current, f"feed {feed} without a current instance")
        found = {row["module"] for row in current}
        _require(len(found) == 1, f"feed {feed} spans two modules")
        feed_modules[feed] = next(iter(found))
    _require(len(set(feed_modules.values())) == len(feeds),
             "two feeds share one module")
    cuts = {}
    for cut in summary["cuts"]:
        cuts.setdefault(cut["feed"], []).append(cut["at_seq"])
    if cuts:
        subjects = [row["subject"] for row in snapshot["gaps"]]
        _require(CHANGED_IDENTITY_GAP in subjects,
                 "cut without the changed-identity gap")
    edges = {row["module"]: row["mapping"]
             for row in snapshot.get("edges", [])}
    for feed, counts in feeds.items():
        observed = [row for row in by_feed[feed]
                    if row["state"] == "observed"]
        if not observed:
            continue
        _require(len(observed) == 1,
                 f"feed {feed} without exactly one observed instance")
        instance = observed[0]
        key_row = key_rows.get(instance["id"])
        _require(key_row is not None,
                 f"observed instance {instance['id']} without a key row")
        _require(key_row.get("forwarded", 0) == counts["forwarded"],
                 f"feed {feed} forwarded {key_row.get('forwarded', 0)} disagrees "
                 f"with {counts['forwarded']} ledgered forwarded calls")
        if feed in cuts:
            _check_cut_feed(feed, counts, key_row, cuts[feed],
                            feed_modules[feed], edges)
        else:
            _require(key_row["started"] == counts["calls"],
                     f"feed {feed} started {key_row['started']} disagrees "
                     f"with {counts['calls']} ledger calls")
            _require(key_row["completed"] == counts["ok"],
                     f"feed {feed} completed {key_row['completed']} disagrees "
                     f"with {counts['ok']} ok ledger calls")
            _require(key_row["failed"] == counts["failed"],
                     f"feed {feed} failed {key_row['failed']} disagrees with "
                     f"{counts['failed']} error ledger calls")
            _require(key_row["unknown"] == 0,
                     f"feed {feed} leaves {key_row['unknown']} calls unknown")
    for row in snapshot["instances"]:
        if row["state"] == "observed":
            continue
        key_row = key_rows.get(row["id"])
        if key_row is None:
            continue
        counts = feeds[row["feed"]]
        _require(key_row["completed"] <= counts["ok"],
                 f"feed {row['feed']} over-claims completed while {row['state']}")
        _require(key_row["failed"] <= counts["failed"],
                 f"feed {row['feed']} over-claims failed while {row['state']}")
        _require(key_row["started"] <= counts["calls"],
                 f"feed {row['feed']} over-claims started while {row['state']}")
        _require(key_row.get("forwarded", 0) <= counts["forwarded"],
                 f"feed {row['feed']} over-claims forwarded while {row['state']}")
    return {"path": "split", "feeds": sorted(summary["feeds"]),
            "issued": summary["issued"],
            "associations": associations["associations"]}


def _check_cut_feed(feed, counts, key_row, at_seqs, module_id, edges):
    # Latest cut wins: earlier cuts are history inside the pre burst.
    edge = max(at_seqs)
    seqs = counts["seqs"]
    ok_seqs = set(counts["ok_seqs"])
    pre = sum(1 for seq in seqs if seq <= edge)
    post = sum(1 for seq in seqs if seq > edge)
    _require(pre >= 1 and post >= 1,
             f"feed {feed} cut leaves an empty pre or post burst")
    published = key_row.get("cut_published", 0)
    published_failed = key_row.get("cut_published_failed", 0)
    _require(published <= pre,
             f"feed {feed} cut_published {published} exceeds {pre} pre-cut calls")
    post_ok = sum(1 for seq in seqs if seq > edge and seq in ok_seqs)
    post_failed = post - post_ok
    _require(key_row["started"] == counts["calls"],
             f"feed {feed} started {key_row['started']} disagrees with "
             f"{counts['calls']} ledger calls")
    _require(key_row["completed"] == post_ok + published - published_failed,
             f"feed {feed} completed {key_row['completed']} mixes pre-cut "
             "unpublished calls with post-cut calls")
    _require(key_row["failed"] == post_failed + published_failed,
             f"feed {feed} failed {key_row['failed']} mixes pre-cut "
             "unpublished calls with post-cut calls")
    _require(key_row["unknown"] == pre - published,
             f"feed {feed} unknown {key_row['unknown']} hides pre-cut calls")
    mapping = edges.get(module_id)
    _require(mapping is not None and mapping["interruptions"] >= 1,
             f"feed {feed} cut without a mapping interruption")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", help="two-provider ledger JSONL file")
    parser.add_argument("snapshot", help="snapshot JSON document file")
    args = parser.parse_args(argv)
    try:
        with open(args.ledger, encoding="utf-8") as stream:
            summary = validate_ledger(read_ledger(stream))
        with open(args.snapshot, encoding="utf-8") as stream:
            snapshot = read_snapshot(stream)
        result = compare(summary, snapshot)
    except LedgerError as error:
        print(f"comparison refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("comparison refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
