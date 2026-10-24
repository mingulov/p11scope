#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare two interleaved feed ledgers against H9 joint output.

Inputs: two per-feed ledgers from tests/fixtures/joint-populations/two-feed.c
(E17 ready/call/ack framing plus one feed row declaring the workload
identity), one object_observations section document (the frozen H9 shape,
as in tests/fixtures/key-operations/object-observations.json; the live
driver extracts the section from the inventory -o snapshot), and
optionally the companion event stream (production envelope lines; the
object_observed and key_operations_observed kinds bind from
src/inventory_events.rs).

Checked here (each names its output field below): per-feed operation
order and phase scripts from ledger rows; key_row started/completed and
the row equation per (instance, object, category, role); metadata_at_use
equality with the ledger-declared established label (a null declaration
must land in unknown_key_operations, never in a key row); role rows kept
separate (a summed row fails the per-role match); unit agreement per
category (message_* rows carry message_contexts); unknown rows
partitioned by (category, reason) with no started field; S1Only feeds
never upgraded to key rows (neither in the snapshot nor in any known
stream row); equal numeric handles in different scopes kept on distinct
objects (and equal scope+handle kept on one object); revision order,
cumulative completed, stream/snapshot reconciliation, per-operation
receipts with the at_ns < t0 hard-fail rule, and cross-feed interleave
order for non-overlapping operations.

Exactly-one-H3-take, once-only reduction and no-stranded-roles are
asserted by Part B library tests at the registry seam (invisible in CLI
output); this module asserts their CLI-visible consequences: one
non-decreasing revision chain, exact-once counts, and no duplicate rows.
"""

import argparse
import json
import re
import sys

MAX_CALLS = 100000
# ready + feed + calls + ack.
MAX_ROWS = MAX_CALLS + 3
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
STREAM_SCHEMA = "p11scope/inventory-events/v1"
FN_PATTERN = re.compile(r"table\[([0-9]{1,3})\]\Z")
INSTANCE_PATTERN = re.compile(r"i[0-9]+\Z")
SCOPE_PATTERN = re.compile(r"(session|provider|image):[A-Za-z0-9_.\-]{1,32}\Z")
TABLE_SLOTS = 104

CATEGORIES = {"digest", "sign", "verify", "encrypt", "decrypt", "sign_recover",
              "verify_recover", "message_encrypt", "message_decrypt",
              "message_sign", "message_verify", "generate_key",
              "generate_key_pair", "wrap", "unwrap", "derive", "encapsulate",
              "decapsulate", "wrap_authenticated", "unwrap_authenticated",
              "operation", "direct", "unknown"}
ROLES = {"key", "wrapping_key", "wrapped_object", "unwrapping_key", "base_key",
         "other"}
LABELS = {"rsa_1024", "rsa_2048", "rsa_3072", "rsa_4096", "rsa_other", "aes_128",
          "aes_192", "aes_256", "aes_other", "ec_p256", "ec_p384", "ec_p521"}
UNITS = {"operations", "message_contexts"}
UNKNOWN_REASONS = {"unbound", "key_join_lost", "metadata_unknown",
                   "metadata_conflicting", "role_unavailable", "not_applicable"}
STATUSES = {"populated", "partial", "stale", "unavailable"}
STATUS_REASONS = {"none", "bootstrap_unavailable", "proof_refused_fallback",
                  "authority_lost", "row_budget_exhausted",
                  "publication_budget_exhausted", "serialization_refused",
                  "sink_failed"}
KEY_COUNTERS = ("started", "completed", "failed", "cancelled", "unknown",
                "active", "key_join_lost")
UNKNOWN_COUNTERS = ("completed", "failed", "cancelled", "unknown", "active")


class LedgerError(ValueError):
    """A ledger, snapshot or stream is incomplete or inconsistent."""


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
    """Read bounded per-feed ledger JSONL rows."""
    return _read_jsonl(stream, "ledger")


def read_events(stream):
    """Read bounded event-stream envelope JSONL rows."""
    return _read_jsonl(stream, "events")


def read_snapshot(text):
    """Parse one bounded object_observations section document."""
    _require(type(text) is str, "snapshot must be text")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as error:
        raise LedgerError("invalid snapshot encoding") from error
    _require(size <= MAX_SNAPSHOT_BYTES, "snapshot byte limit")
    try:
        document = json.loads(text, object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
    except json.JSONDecodeError as error:
        raise LedgerError("invalid snapshot JSON") from error
    _require(type(document) is dict, "snapshot must be an object")
    return document


def _check_fn_label(label, where):
    match = FN_PATTERN.match(label) if type(label) is str else None
    _require(match is not None, f"fn label invalid at {where}")
    _require(int(match.group(1)) < TABLE_SLOTS, f"fn label invalid at {where}")


def validate_ledger(rows, tag):
    """Validate one feed ledger; return the feed summary with op outcomes."""
    _require(rows, f"{tag}: empty ledger")
    _require(type(rows[0]) is dict and rows[0].get("kind") == "ready",
             f"{tag}: first row must be ready")
    _require(len(rows) >= 3 and type(rows[1]) is dict
             and rows[1].get("kind") == "feed", f"{tag}: second row must be feed")
    _require(type(rows[-1]) is dict and rows[-1].get("kind") == "ack",
             f"{tag}: last row must be ack")
    ready = rows[0]
    _keys(ready, {"kind", "pid", "tid", "t", "clock", "unit"})
    _require(_integer(ready["pid"], minimum=1), f"{tag}: ready pid out of range")
    _require(_integer(ready["tid"], minimum=1), f"{tag}: ready tid out of range")
    _require(_integer(ready["t"]), f"{tag}: ready t out of range")
    _require(ready["clock"] == "CLOCK_MONOTONIC", f"{tag}: ready clock basis mismatch")
    _require(ready["unit"] == "ns", f"{tag}: ready clock unit mismatch")
    feed = rows[1]
    _keys(feed, {"kind", "feed", "path", "instance", "object", "category",
                 "role", "metadata", "scope", "handle"})
    _require(feed["feed"] in ("A", "B"), f"{tag}: feed label invalid")
    _require(feed["path"] in ("joint", "s1only"), f"{tag}: feed path invalid")
    _require(type(feed["instance"]) is str
             and INSTANCE_PATTERN.match(feed["instance"]),
             f"{tag}: feed instance invalid")
    _require(_integer(feed["object"]), f"{tag}: feed object out of range")
    _require(feed["category"] in CATEGORIES, f"{tag}: feed category invalid")
    _require(feed["role"] in ROLES, f"{tag}: feed role invalid")
    _require(feed["metadata"] is None or feed["metadata"] in LABELS,
             f"{tag}: feed metadata invalid")
    _require(type(feed["scope"]) is str and SCOPE_PATTERN.match(feed["scope"]),
             f"{tag}: feed scope invalid")
    _require(_integer(feed["handle"]), f"{tag}: feed handle out of range")
    ack = rows[-1]
    _keys(ack, {"kind", "issued", "t"})
    _require(_integer(ack["issued"]), f"{tag}: ack issued out of range")
    _require(_integer(ack["t"]), f"{tag}: ack t out of range")
    _require(ack["t"] >= ready["t"], f"{tag}: ack precedes ready window")
    calls = rows[2:-1]
    _require(all(type(row) is dict and row.get("kind") == "call" for row in calls),
             f"{tag}: unexpected non-call row between feed and ack")
    _require(ack["issued"] == len(calls),
             f"{tag}: issued {ack['issued']} disagrees with {len(calls)} call rows")
    for position, row in enumerate(calls, start=1):
        where = f"{tag} seq {position}"
        _keys(row, {"kind", "seq", "fn", "rv", "pid", "tid", "t0", "t1",
                    "feed", "op", "phase"})
        _require(row["seq"] == position,
                 f"{tag}: seq {_shown(row['seq'])} breaks contiguity"
                 f" at position {position}")
        _check_fn_label(row["fn"], where)
        _require(_integer(row["rv"]), f"{where}: rv out of range")
        _require(row["pid"] == ready["pid"],
                 f"{tag}: pid {_shown(row['pid'])} disagrees with ready pid"
                 f" at seq {position}")
        _require(row["tid"] == ready["tid"],
                 f"{tag}: tid {_shown(row['tid'])} disagrees with ready tid"
                 f" at seq {position}")
        _require(_integer(row["t0"]) and _integer(row["t1"]),
                 f"{where}: t0/t1 out of range")
        _require(row["t0"] <= row["t1"],
                 f"{tag}: t1 {row['t1']} precedes t0 {row['t0']} at seq {position}")
        _require(ready["t"] <= row["t0"] and row["t1"] <= ack["t"],
                 f"{tag}: seq {position} lies outside the ready/ack window")
        _require(row["feed"] == feed["feed"],
                 f"{tag}: call feed {_shown(row['feed'])} disagrees with feed row"
                 f" at seq {position}")
        _require(_integer(row["op"], minimum=1), f"{where}: op out of range")
        _require(row["phase"] in ("init", "update", "terminal"),
                 f"{where}: phase invalid")
    by_op = {}
    for row in calls:
        by_op.setdefault(row["op"], []).append(row)
    _require(sorted(by_op) == list(range(1, len(by_op) + 1)),
             f"{tag}: op ids are not 1..{len(by_op)}")
    ops = {}
    for op_id in sorted(by_op):
        phases = [row["phase"] for row in by_op[op_id]]
        ordered = phases[0] == "init"
        if phases[-1] == "terminal":
            ordered = ordered and all(p == "update" for p in phases[1:-1])
        else:
            # Only the tail op may be in flight (init/update*, no terminal).
            ordered = (ordered and op_id == len(by_op)
                       and all(p == "update" for p in phases[1:]))
        _require(ordered, f"{tag}: feed {feed['feed']} op {op_id} phase order")
        first, last = by_op[op_id][0], by_op[op_id][-1]
        if first["rv"] != 0:
            outcome = "unbegun"
        elif last["phase"] != "terminal":
            outcome = "pending"
        elif all(row["rv"] == 0 for row in by_op[op_id]):
            outcome = "completed"
        else:
            outcome = "failed"
        ops[op_id] = {"outcome": outcome, "init_t0": first["t0"],
                      "terminal_t0": last["t0"] if last["phase"] == "terminal" else None,
                      "terminal_t1": last["t1"] if last["phase"] == "terminal" else None}
    return {"tag": tag, "feed": feed["feed"], "path": feed["path"],
            "instance": feed["instance"], "object": feed["object"],
            "category": feed["category"], "role": feed["role"],
            "metadata": feed["metadata"], "scope": feed["scope"],
            "handle": feed["handle"], "ops": ops,
            "begun": sum(1 for op in ops.values() if op["outcome"] != "unbegun"),
            "completed": sum(1 for op in ops.values() if op["outcome"] == "completed"),
            "failed": sum(1 for op in ops.values() if op["outcome"] == "failed"),
            "pending": sum(1 for op in ops.values() if op["outcome"] == "pending")}


def _check_counters(row, names, where):
    for name in names:
        _require(_integer(row[name]), f"{where}: {name} out of range")


def _check_key_row(row, where):
    _require(type(row) is dict, f"{where}: key row must be an object")
    _keys(row, {"instance", "object", "category", "role", "metadata_at_use",
                "unit"} | set(KEY_COUNTERS))
    _require(type(row["instance"]) is str
             and INSTANCE_PATTERN.match(row["instance"]),
             f"{where}: key row instance invalid")
    _require(_integer(row["object"]), f"{where}: key row object out of range")
    _require(row["category"] in CATEGORIES, f"{where}: key row category invalid")
    _require(row["role"] in ROLES, f"{where}: key row role invalid")
    _require(row["metadata_at_use"] in LABELS,
             f"{where}: key row metadata_at_use invalid")
    _require(row["unit"] in UNITS, f"{where}: key row unit invalid")
    want_unit = ("message_contexts" if row["category"].startswith("message_")
                 else "operations")
    _require(row["unit"] == want_unit,
             f"{where}: key row unit {_shown(row['unit'])} disagrees with"
             f" category {row['category']}")
    _check_counters(row, KEY_COUNTERS, where)
    total = sum(row[name] for name in KEY_COUNTERS[1:])
    _require(row["started"] == total,
             f"{where}: key row equation: started {row['started']}"
             f" disagrees with {total}")
    return (row["instance"], row["object"], row["category"], row["role"],
            row["metadata_at_use"])


def _check_unknown_row(row, where):
    _require(type(row) is dict, f"{where}: unknown row must be an object")
    _keys(row, {"category", "reason", "unit"} | set(UNKNOWN_COUNTERS))
    _require(row["category"] in CATEGORIES,
             f"{where}: unknown row category invalid")
    _require(row["reason"] in UNKNOWN_REASONS,
             f"{where}: unknown row reason invalid")
    _require(row["unit"] in UNITS, f"{where}: unknown row unit invalid")
    want_unit = ("message_contexts" if row["category"].startswith("message_")
                 else "operations")
    _require(row["unit"] == want_unit,
             f"{where}: unknown row unit {_shown(row['unit'])} disagrees with"
             f" category {row['category']}")
    _check_counters(row, UNKNOWN_COUNTERS, where)
    return (row["category"], row["reason"])


def _check_object_row(row, where):
    _require(type(row) is dict, f"{where}: object row must be an object")
    _keys(row, {"object", "session", "origin", "creation", "birth", "lifetime",
                "lifetime_reason", "attribution", "attribution_reason",
                "requested", "established", "queries", "label",
                "successful_references", "successful_key_references",
                "accessing_sessions"})
    _require(_integer(row["object"]), f"{where}: object id out of range")
    _require(row["label"] is None or row["label"] in LABELS,
             f"{where}: object label invalid")
    return row["object"]


def _check_sorted_unique(keys, where):
    _require(len(set(keys)) == len(keys), f"{where}: duplicate row key")
    _require(keys == sorted(keys), f"{where}: rows out of order")


def _check_row_budget(node, where):
    _require(type(node) is dict, f"{where}: budget must be an object")
    _keys(node, {"limit", "occupied", "refused"})
    _require(node["limit"] == 65536, f"{where}: budget limit changed")
    _require(_integer(node["occupied"]), f"{where}: budget occupied out of range")
    _require(_integer(node["refused"]), f"{where}: budget refused out of range")


def validate_snapshot(document):
    """Validate the frozen H9 subset; refuse anything but populated output."""
    _keys(document, {"version", "revision", "status", "reason", "sessions",
                     "objects", "key_operations", "unknown_key_operations",
                     "gaps", "budgets"})
    _require(document["version"] == 1, "snapshot version mismatch")
    _require(_integer(document["revision"]), "snapshot revision out of range")
    _require(document["status"] in STATUSES, "snapshot status invalid")
    _require(document["reason"] in STATUS_REASONS, "snapshot reason invalid")
    _require((document["status"] == "populated")
             == (document["reason"] == "none"),
             "snapshot status/reason disagree")
    if document["status"] != "populated":
        raise LedgerError(f"snapshot status {document['status']}"
                          f" reason {document['reason']}: joint evidence absent")
    _require(type(document["sessions"]) is list, "snapshot sessions must be a list")
    session_ids = []
    for position, row in enumerate(document["sessions"]):
        where = f"snapshot session {position}"
        _require(type(row) is dict, f"{where} must be an object")
        _keys(row, {"session", "origin", "status"})
        _require(_integer(row["session"]), f"{where}: id out of range")
        _require(row["origin"] in ("opened", "first_observed"),
                 f"{where}: origin invalid")
        _require(row["status"] in ("live", "closed", "lost"),
                 f"{where}: status invalid")
        session_ids.append(row["session"])
    _check_sorted_unique(session_ids, "snapshot sessions")
    _require(type(document["objects"]) is list, "snapshot objects must be a list")
    object_ids = [_check_object_row(row, f"snapshot object {position}")
                  for position, row in enumerate(document["objects"])]
    _check_sorted_unique(object_ids, "snapshot objects")
    _require(type(document["key_operations"]) is list,
             "snapshot key_operations must be a list")
    known_keys = [_check_key_row(row, f"snapshot key row {position}")
                  for position, row in enumerate(document["key_operations"])]
    _check_sorted_unique(known_keys, "snapshot key rows")
    _require(type(document["unknown_key_operations"]) is list,
             "snapshot unknown_key_operations must be a list")
    unknown_keys = [_check_unknown_row(row, f"snapshot unknown row {position}")
                    for position, row in enumerate(document["unknown_key_operations"])]
    _check_sorted_unique(unknown_keys, "snapshot unknown rows")
    gaps = document["gaps"]
    _require(type(gaps) is dict, "snapshot gaps must be an object")
    _keys(gaps, {"rows", "suppressed"})
    _require(type(gaps["rows"]) is list, "snapshot gap rows must be a list")
    _require(len(gaps["rows"]) <= 256, "snapshot gap rows exceed 256")
    for position, row in enumerate(gaps["rows"]):
        where = f"snapshot gap {position}"
        _require(type(row) is dict, f"{where} must be an object")
        _keys(row, {"subject", "reason", "repeats"})
        _require(row["subject"] in ("model", "key_operation"),
                 f"{where}: subject invalid")
        _require(type(row["reason"]) is str, f"{where}: reason invalid")
        _require(_integer(row["repeats"]), f"{where}: repeats out of range")
    _require(_integer(gaps["suppressed"]), "snapshot gaps suppressed out of range")
    budgets = document["budgets"]
    _require(type(budgets) is dict, "snapshot budgets must be an object")
    _keys(budgets, {"key_rows", "object_rows", "unknown_rows", "encoded_bytes",
                    "allocation_refused", "refusal_reason"})
    _check_row_budget(budgets["key_rows"], "snapshot key_rows budget")
    _check_row_budget(budgets["object_rows"], "snapshot object_rows budget")
    _require(type(budgets["unknown_rows"]) is dict,
             "snapshot unknown_rows budget must be an object")
    _keys(budgets["unknown_rows"], {"occupied"})
    _require(_integer(budgets["unknown_rows"]["occupied"]),
             "snapshot unknown_rows budget occupied out of range")
    _require(_integer(budgets["encoded_bytes"]),
             "snapshot encoded_bytes out of range")
    _require(budgets["allocation_refused"] is False,
             "snapshot allocation_refused changed")
    _require(budgets["refusal_reason"] == "none",
             "snapshot refusal_reason changed")
    return document


def _feed_key(feed):
    return (feed["instance"], feed["object"], feed["category"], feed["role"],
            feed["metadata"])


def compare_pair(first, second, snapshot):
    """Compare two validated feeds against one validated snapshot.

    Joint feeds with established metadata match exactly one key row each
    (grouped when two feeds share one key); joint feeds without metadata
    and S1Only feeds match unknown rows (metadata_unknown and unbound).
    Feeds observing equal handles in different scopes must sit on
    distinct objects; equal scope+handle must sit on one object. Every
    snapshot row must be claimed by a feed; nothing extra may ride along
    (the live driver scopes the run and filters to the workload keys).
    """
    feeds = [first, second]
    _require(first["feed"] != second["feed"], "feeds share one label")
    same_scope = first["scope"] == second["scope"]
    same_handle = first["handle"] == second["handle"]
    if same_handle and not same_scope:
        _require(first["object"] != second["object"],
                 f"joined equal handles: feeds {first['feed']},{second['feed']}"
                 f" share object {first['object']} across scopes"
                 f" {first['scope']},{second['scope']}")
    if same_scope and same_handle:
        _require(first["object"] == second["object"],
                 f"split same-scope handle: feeds {first['feed']},{second['feed']}"
                 f" use objects {first['object']},{second['object']}"
                 f" in scope {first['scope']}")
    known = {}
    for row in snapshot["key_operations"]:
        known[(_check_key_row(row, "snapshot key row"))] = row
    unknown = {}
    for row in snapshot["unknown_key_operations"]:
        unknown[(_check_unknown_row(row, "snapshot unknown row"))] = row
    objects = {row["object"] for row in snapshot["objects"]}
    keyed, unkeyed = {}, {}
    for feed in feeds:
        if feed["path"] == "joint" and feed["metadata"] is not None:
            keyed.setdefault(_feed_key(feed), []).append(feed)
        else:
            reason = ("metadata_unknown"
                      if feed["path"] == "joint" else "unbound")
            unkeyed.setdefault((feed["category"], reason), []).append(feed)
    claimed_known, claimed_unknown = set(), set()
    for key, group in keyed.items():
        label = ",".join(feed["feed"] for feed in group)
        _require(key in known, f"missing key row for feed {label}"
                               f" {key[0]},{key[1]},{key[2]},{key[3]},{key[4]}")
        row = known[key]
        begun = sum(feed["begun"] for feed in group)
        completed = sum(feed["completed"] for feed in group)
        failed = sum(feed["failed"] for feed in group)
        pending = sum(feed["pending"] for feed in group)
        for name, want in (("started", begun), ("completed", completed),
                           ("failed", failed), ("cancelled", 0),
                           ("unknown", 0), ("active", pending),
                           ("key_join_lost", 0)):
            _require(row[name] == want,
                     f"key row {name} {row[name]} disagrees with ledger"
                     f" {want} for feed {label}")
        for feed in group:
            _require(feed["object"] in objects,
                     f"missing object row {feed['object']} for feed {feed['feed']}")
        claimed_known.add(key)
    for key, group in unkeyed.items():
        label = ",".join(feed["feed"] for feed in group)
        _require(key in unknown, f"missing unknown row for feed {label}"
                                 f" {key[0]},{key[1]}")
        row = unknown[key]
        completed = sum(feed["completed"] for feed in group)
        failed = sum(feed["failed"] for feed in group)
        pending = sum(feed["pending"] for feed in group)
        for name, want in (("completed", completed), ("failed", failed),
                           ("cancelled", 0), ("unknown", 0),
                           ("active", pending)):
            _require(row[name] == want,
                     f"unknown row {name} {row[name]} disagrees with ledger"
                     f" {want} for feed {label}")
        for feed in group:
            clashes = [row for row in snapshot["key_operations"]
                       if (row["instance"], row["object"], row["category"],
                           row["role"]) == (feed["instance"], feed["object"],
                                            feed["category"], feed["role"])]
            _require(not clashes,
                     f"feed {feed['feed']} carried by key row"
                     f" {feed['instance']},{feed['object']}"
                     f",{feed['category']},{feed['role']}: upgrade refused")
            _require(feed["object"] not in objects,
                     f"object row {feed['object']} staged for"
                     f" unkeyed feed {feed['feed']}")
        claimed_unknown.add(key)
    for key in known:
        _require(key in claimed_known, f"unmatched key row {key[0]},{key[1]}"
                                       f",{key[2]},{key[3]},{key[4]}")
    for key in unknown:
        _require(key in claimed_unknown, f"unmatched unknown row {key[0]},{key[1]}")
    return {"feeds": 2,
            "ops": sum(len(feed["ops"]) for feed in feeds),
            "completed": sum(feed["completed"] for feed in feeds),
            "failed": sum(feed["failed"] for feed in feeds),
            "key_rows": len(known), "unknown_rows": len(unknown)}


def _claim_of(feeds, bucket, key):
    if bucket == "known":
        return [feed for feed in feeds
                if feed["path"] == "joint" and feed["metadata"] is not None
                and _feed_key(feed) == key]
    return [feed for feed in feeds
            if not (feed["path"] == "joint" and feed["metadata"] is not None)
            and (feed["category"],
                 "metadata_unknown" if feed["path"] == "joint" else "unbound") == key]


def compare_stream(events, feeds, snapshot):
    """Walk H9 row events: order, cumulative counts, receipts, reconciliation.

    Row events carry cumulative snapshots keyed by (bucket, row key);
    revisions per key rise strictly, completed never decreases, and the
    last carried row equals the snapshot row. Each completed operation
    takes its receipt at the first event covering it; a receipt with
    at_ns before the operation's terminal t0 is impossible (at_ns inside
    [t0, t1) is the fixture preemption window and passes). For two
    non-overlapping operations on different feeds the receipt revisions
    follow terminal order. pass_committed/ended markers present in the
    excerpt must agree on object_status and carry gaps_suppressed 0;
    suppressed gaps would hide dispositions. Other kinds pass through.
    """
    last_seq = None
    last_revision = None
    series = {}
    for position, line in enumerate(events):
        where = f"stream line {position}"
        _require(type(line) is dict, f"{where} must be an object")
        _keys(line, {"schema", "seq", "at_ns", "kind", "event"})
        _require(line["schema"] == STREAM_SCHEMA, f"{where}: schema mismatch")
        _require(_integer(line["seq"]), f"{where}: seq out of range")
        _require(last_seq is None or line["seq"] >= last_seq,
                 f"{where}: seq order")
        last_seq = line["seq"]
        _require(_integer(line["at_ns"]), f"{where}: at_ns out of range")
        _require(type(line["kind"]) is str, f"{where}: kind invalid")
        _require(type(line["event"]) is dict, f"{where}: event must be an object")
        kind, event = line["kind"], line["event"]
        if kind == "object_observed":
            _keys(event, {"revision", "row"})
            _require(_integer(event["revision"]), f"{where}: revision out of range")
            key = ("object", _check_object_row(event["row"], where))
            series.setdefault(key, []).append(
                (event["revision"], line["at_ns"], event["row"]))
        elif kind == "key_operations_observed":
            _keys(event, {"revision", "bucket", "row"})
            _require(_integer(event["revision"]), f"{where}: revision out of range")
            _require(event["bucket"] in ("known", "unknown"),
                     f"{where}: bucket invalid")
            if event["bucket"] == "known":
                key = ("known", _check_key_row(event["row"], where))
            else:
                key = ("unknown", _check_unknown_row(event["row"], where))
            series.setdefault(key, []).append(
                (event["revision"], line["at_ns"], event["row"]))
        elif kind == "pass_committed":
            if "object_status" in event:
                _require(event["object_status"] == snapshot["status"],
                         f"{where}: object_status {_shown(event['object_status'])}"
                         f" disagrees with snapshot status {snapshot['status']}")
            if "gaps_suppressed" in event:
                _require(event["gaps_suppressed"] == 0,
                         f"{where}: gaps_suppressed"
                         f" {_shown(event['gaps_suppressed'])} hides dispositions")
        elif kind == "ended":
            if "gaps_suppressed" in event:
                _require(event["gaps_suppressed"] == 0,
                         f"{where}: gaps_suppressed"
                         f" {_shown(event['gaps_suppressed'])} hides dispositions")
    for key, points in series.items():
        revisions = [revision for revision, _, _ in points]
        _require(revisions == sorted(revisions)
                 and len(set(revisions)) == len(revisions),
                 f"stream row {key}: revision order")
        if key[0] in ("known", "unknown"):
            completed = [row["completed"] for _, _, row in points]
            _require(completed == sorted(completed),
                     f"stream row {key}: completed decreases")
    # One non-decreasing revision chain across H9 rows (single take).
    chain = []
    for position, line in enumerate(events):
        if type(line) is dict and line.get("kind") in ("object_observed",
                                                       "key_operations_observed"):
            chain.append(line["event"]["revision"])
    _require(chain == sorted(chain), "stream revisions leave one chain")
    if chain:
        last_revision = chain[-1]
    # Reconciliation: the last carried row equals the snapshot row, for
    # every snapshot row, and no unclaimed row rides the stream.
    carried = {key: points[-1][2] for key, points in series.items()}
    snapshot_rows = {}
    for row in snapshot["objects"]:
        snapshot_rows[("object", row["object"])] = row
    for row in snapshot["key_operations"]:
        snapshot_rows[("known", (row["instance"], row["object"], row["category"],
                                 row["role"], row["metadata_at_use"]))] = row
    for row in snapshot["unknown_key_operations"]:
        snapshot_rows[("unknown", (row["category"], row["reason"]))] = row
    for key, row in snapshot_rows.items():
        _require(key in carried, f"stream never carries snapshot row {key}")
        _require(carried[key] == row,
                 f"stream row {key} disagrees with snapshot")
    for key in carried:
        _require(key in snapshot_rows, f"stream carries unclaimed row {key}")
    # Receipts: the first event covering each completed operation, per
    # single-claimant row, with causality and cross-feed interleave order.
    receipts = {}
    for (bucket, key), points in series.items():
        if bucket == "object":
            continue
        claimants = _claim_of(feeds, bucket, key)
        if len(claimants) != 1:
            continue
        feed = claimants[0]
        done = sorted(op_id for op_id, op in feed["ops"].items()
                      if op["outcome"] == "completed")
        rank = 0
        for op_id in done:
            rank += 1
            cover = next(((revision, at_ns) for revision, at_ns, row in points
                          if row["completed"] >= rank), None)
            _require(cover is not None,
                     f"stream row {(bucket, key)} never covers"
                     f" feed {feed['feed']} op {op_id}")
            op = feed["ops"][op_id]
            _require(cover[1] >= op["terminal_t0"],
                     f"receipt at_ns {cover[1]} precedes call t0"
                     f" {op['terminal_t0']} for feed {feed['feed']} op {op_id}")
            receipts[(feed["feed"], op_id)] = cover[0]
    by_feed = {}
    for feed in feeds:
        by_feed[feed["feed"]] = feed
    names = [feed["feed"] for feed in feeds]
    if len(names) == 2:
        left, right = by_feed[names[0]], by_feed[names[1]]
        left_done = [op_id for op_id, op in left["ops"].items()
                     if op["outcome"] == "completed"]
        right_done = [op_id for op_id, op in right["ops"].items()
                      if op["outcome"] == "completed"]
        for op_a in left_done:
            for op_b in right_done:
                if (names[0], op_a) not in receipts or (names[1], op_b) not in receipts:
                    continue
                term_a, term_b = left["ops"][op_a], right["ops"][op_b]
                if term_a["terminal_t1"] < term_b["terminal_t0"]:
                    _require(receipts[(names[0], op_a)] <= receipts[(names[1], op_b)],
                             f"interleave order: feed {names[0]} op {op_a}"
                             f" precedes feed {names[1]} op {op_b}")
                if term_b["terminal_t1"] < term_a["terminal_t0"]:
                    _require(receipts[(names[1], op_b)] <= receipts[(names[0], op_a)],
                             f"interleave order: feed {names[1]} op {op_b}"
                             f" precedes feed {names[0]} op {op_a}")
    return {"events": len(events), "rows": len(series),
            "revision": last_revision}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger_a", help="first feed ledger JSONL file")
    parser.add_argument("ledger_b", help="second feed ledger JSONL file")
    parser.add_argument("snapshot", help="object_observations section JSON file")
    parser.add_argument("events", nargs="?",
                        help="event-stream JSONL file (production envelope)")
    args = parser.parse_args(argv)
    try:
        with open(args.ledger_a, encoding="utf-8") as stream:
            first = validate_ledger(read_ledger(stream), "ledger A")
        with open(args.ledger_b, encoding="utf-8") as stream:
            second = validate_ledger(read_ledger(stream), "ledger B")
        with open(args.snapshot, encoding="utf-8") as stream:
            snapshot = validate_snapshot(read_snapshot(stream.read()))
        result = compare_pair(first, second, snapshot)
        if args.events is not None:
            with open(args.events, encoding="utf-8") as stream:
                result.update(compare_stream(read_events(stream),
                                             [first, second], snapshot))
    except LedgerError as error:
        print(f"h9 refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("h9 refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

