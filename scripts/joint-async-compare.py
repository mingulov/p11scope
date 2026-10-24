#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare an async-collision ledger pair against joint/s1only output.

Inputs: two per-process ledgers from
tests/fixtures/async-collision/collide.c (E17 ready/call/ack framing,
one scenario row declaring the collision identity, sequenced
call/fence/transfer rows), a joint-path object_observations section, an
S1Only-path section (same frozen H9 shape; the live driver extracts
each section from its inventory -o snapshot), and optionally one event
stream per path (production envelope lines).

The pair must collide: distinct processes, one owner and one
challenger, different pending mechanisms, equal slot/target, distinct
sessions, and every challenger-begun async id owned. Outcomes derive
from observed return values (truth over script intent): a begin that
fails creates no operation; query and BUFFER_TOO_SMALL phases retain;
the first decisive terminal/cancel/failure settles the op; calls past
the fence row are fenced. A terminal by a non-beginner is a refused
join (duplicate_completion gap, S1 completion preserved in unknown
rows) unless a transfer row legitimizes it, in which case it completes
under the owner's key. Post-fence terminals are gapped (finalize/exec)
with no completion preserved in either path. The S1Only section carries
no key rows and no gaps; its unknown completed/cancelled/failed/active
must equal the joint totals exactly (cross-run equality).
"""

import argparse
import json
import re
import sys

MAX_CALLS = 1024
# ready + scenario + sequenced rows + ack.
MAX_ROWS = MAX_CALLS + 3
MAX_LINE_BYTES = 4096
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
STREAM_SCHEMA = "p11scope/inventory-events/v1"
INSTANCE_PATTERN = re.compile(r"i[0-9]+\Z")

CATEGORY = "operation"
ROLE = "key"
LABELS = {"rsa_1024", "rsa_2048", "rsa_3072", "rsa_4096", "rsa_other", "aes_128",
          "aes_192", "aes_256", "aes_other", "ec_p256", "ec_p384", "ec_p521"}
CATEGORIES = {"digest", "sign", "verify", "encrypt", "decrypt", "sign_recover",
              "verify_recover", "message_encrypt", "message_decrypt",
              "message_sign", "message_verify", "generate_key",
              "generate_key_pair", "wrap", "unwrap", "derive", "encapsulate",
              "decapsulate", "wrap_authenticated", "unwrap_authenticated",
              "operation", "direct", "unknown"}
ROLES = {"key", "wrapping_key", "wrapped_object", "unwrapping_key", "base_key",
         "other"}
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

CKR_OK = 0
CKR_PENDING = 0x204
CKR_BUFFER_TOO_SMALL = 0x150

FUNCTIONS = {"async_begin", "async_poll", "async_status", "async_wait",
             "async_cancel", "async_begin_fail", "async_finalize"}
PHASES = {"begin", "pending", "terminal", "query", "too_small", "cancel",
          "teardown"}
# Entry/phase agreement: which entries may carry each phase.
PHASE_FUNCTIONS = {
    "begin": {"async_begin", "async_begin_fail"},
    "pending": {"async_poll"},
    "terminal": {"async_poll", "async_wait"},
    "query": {"async_status"},
    "too_small": {"async_wait"},
    "cancel": {"async_cancel"},
    "teardown": {"async_finalize"},
}


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
    """Read bounded per-process collision ledger JSONL rows."""
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


def validate_ledger(rows, tag):
    """Validate one collision ledger; derive per-op outcomes from rvs."""
    _require(rows, f"{tag}: empty ledger")
    _require(type(rows[0]) is dict and rows[0].get("kind") == "ready",
             f"{tag}: first row must be ready")
    _require(len(rows) >= 3 and type(rows[1]) is dict
             and rows[1].get("kind") == "scenario",
             f"{tag}: second row must be scenario")
    _require(type(rows[-1]) is dict and rows[-1].get("kind") == "ack",
             f"{tag}: last row must be ack")
    ready = rows[0]
    _keys(ready, {"kind", "pid", "tid", "t", "clock", "unit"})
    _require(_integer(ready["pid"], minimum=1), f"{tag}: ready pid out of range")
    _require(_integer(ready["tid"], minimum=1), f"{tag}: ready tid out of range")
    _require(_integer(ready["t"]), f"{tag}: ready t out of range")
    _require(ready["clock"] == "CLOCK_MONOTONIC", f"{tag}: ready clock basis mismatch")
    _require(ready["unit"] == "ns", f"{tag}: ready clock unit mismatch")
    scenario = rows[1]
    _keys(scenario, {"kind", "process", "role", "mechanism", "slot", "target",
                     "metadata", "session", "instance", "object"})
    _require(scenario["process"] in ("A", "B"), f"{tag}: process label invalid")
    _require(scenario["role"] in ("owner", "challenger"),
             f"{tag}: scenario role invalid")
    _require(scenario["mechanism"] in ("poll", "message", "persisted", "cancel"),
             f"{tag}: scenario mechanism invalid")
    _require(_integer(scenario["slot"]), f"{tag}: scenario slot out of range")
    _require(scenario["target"] == "async_begin",
             f"{tag}: scenario target invalid")
    _require(scenario["metadata"] is None or scenario["metadata"] in LABELS,
             f"{tag}: scenario metadata invalid")
    _require(_integer(scenario["session"]), f"{tag}: scenario session out of range")
    _require(type(scenario["instance"]) is str
             and INSTANCE_PATTERN.match(scenario["instance"]),
             f"{tag}: scenario instance invalid")
    _require(_integer(scenario["object"]), f"{tag}: scenario object out of range")
    ack = rows[-1]
    _keys(ack, {"kind", "issued", "sequenced", "t"})
    _require(_integer(ack["issued"]), f"{tag}: ack issued out of range")
    _require(_integer(ack["sequenced"]), f"{tag}: ack sequenced out of range")
    _require(_integer(ack["t"]), f"{tag}: ack t out of range")
    _require(ack["t"] >= ready["t"], f"{tag}: ack precedes ready window")
    sequenced = rows[2:-1]
    calls = [row for row in sequenced
             if type(row) is dict and row.get("kind") == "call"]
    fences = [row for row in sequenced
              if type(row) is dict and row.get("kind") == "fence"]
    transfers = [row for row in sequenced
                 if type(row) is dict and row.get("kind") == "transfer"]
    _require(len(calls) + len(fences) + len(transfers) == len(sequenced)
             and all(type(row) is dict for row in sequenced),
             f"{tag}: unexpected row between scenario and ack")
    _require(ack["issued"] == len(calls),
             f"{tag}: issued {ack['issued']} disagrees with {len(calls)}"
             " call rows")
    _require(ack["sequenced"] == len(sequenced),
             f"{tag}: sequenced {ack['sequenced']} disagrees with"
             f" {len(sequenced)} sequenced rows")
    for position, row in enumerate(sequenced, start=1):
        _require(row["seq"] == position,
                 f"{tag}: seq {_shown(row.get('seq'))} breaks contiguity"
                 f" at position {position}")
    for row in calls:
        where = f"{tag} seq {row['seq']}"
        _keys(row, {"kind", "seq", "fn", "rv", "pid", "tid", "t0", "t1",
                    "process", "op", "phase", "async_id"})
        _require(row["fn"] in FUNCTIONS, f"{where}: fn invalid")
        _require(_integer(row["rv"]), f"{where}: rv out of range")
        _require(row["pid"] == ready["pid"],
                 f"{tag}: pid {_shown(row['pid'])} disagrees with ready pid"
                 f" at seq {row['seq']}")
        _require(row["tid"] == ready["tid"],
                 f"{tag}: tid {_shown(row['tid'])} disagrees with ready tid"
                 f" at seq {row['seq']}")
        _require(_integer(row["t0"]) and _integer(row["t1"]),
                 f"{where}: t0/t1 out of range")
        _require(row["t0"] <= row["t1"],
                 f"{tag}: t1 {row['t1']} precedes t0 {row['t0']}"
                 f" at seq {row['seq']}")
        _require(ready["t"] <= row["t0"] and row["t1"] <= ack["t"],
                 f"{tag}: seq {row['seq']} lies outside the ready/ack window")
        _require(row["process"] == scenario["process"],
                 f"{tag}: call process {_shown(row['process'])} disagrees with"
                 f" scenario at seq {row['seq']}")
        _require(row["phase"] in PHASES, f"{where}: phase invalid")
        _require(row["fn"] in PHASE_FUNCTIONS[row["phase"]],
                 f"{where}: fn {_shown(row['fn'])} disagrees with"
                 f" phase {row['phase']}")
        if row["phase"] == "teardown":
            _require(row["op"] == 0, f"{where}: teardown op must be 0")
            _require(row["async_id"] == 0, f"{where}: teardown carries async id")
        else:
            _require(_integer(row["op"], minimum=1), f"{where}: op out of range")
            _require(_integer(row["async_id"]), f"{where}: async id out of range")
    for row in fences:
        where = f"{tag} seq {row['seq']}"
        _keys(row, {"kind", "seq", "fence", "t"})
        _require(row["fence"] in ("finalize", "exec"), f"{where}: fence invalid")
        _require(_integer(row["t"]), f"{where}: fence t out of range")
        _require(ready["t"] <= row["t"] <= ack["t"],
                 f"{where}: fence lies outside the ready/ack window")
    _require(len(fences) <= 1, f"{tag}: duplicate fence")
    for row in transfers:
        where = f"{tag} seq {row['seq']}"
        _keys(row, {"kind", "seq", "op", "from_pid", "to_pid", "async_id", "t"})
        _require(_integer(row["op"], minimum=1), f"{where}: op out of range")
        _require(_integer(row["from_pid"], minimum=1),
                 f"{where}: from_pid out of range")
        _require(_integer(row["to_pid"], minimum=1), f"{where}: to_pid out of range")
        _require(row["from_pid"] != row["to_pid"],
                 f"{where}: transfer from_pid equals to_pid")
        _require(_integer(row["async_id"], minimum=1),
                 f"{where}: async id out of range")
        _require(_integer(row["t"]), f"{where}: transfer t out of range")
        _require(ready["t"] <= row["t"] <= ack["t"],
                 f"{where}: transfer lies outside the ready/ack window")
    seen_transfers = set()
    for row in transfers:
        key = (row["op"], row["async_id"])
        _require(key not in seen_transfers, f"{tag}: duplicate transfer")
        seen_transfers.add(key)
    fence_seq = fences[0]["seq"] if fences else None
    transfer_keys = {(row["op"], row["async_id"]) for row in transfers}
    by_op = {}
    for row in calls:
        if row["phase"] == "teardown":
            continue
        by_op.setdefault(row["op"], []).append(row)
    _require(sorted(by_op) == list(range(1, len(by_op) + 1)),
             f"{tag}: op ids are not 1..{len(by_op)}")
    begun_ids = {}
    for op_id, op_calls in by_op.items():
        begins = [row for row in op_calls
                  if row["phase"] == "begin" and row["rv"] == CKR_OK
                  and (fence_seq is None or row["seq"] < fence_seq)]
        _require(len(begins) <= 1,
                 f"{tag}: op {op_id} begun twice")
        if begins:
            _require(begins[0]["async_id"] != 0,
                     f"{tag}: op {op_id} begin without async id")
            begun_ids[op_id] = begins[0]["async_id"]
    for op_id, op_calls in by_op.items():
        for row in op_calls:
            if fence_seq is not None and row["seq"] > fence_seq:
                continue
            if row["phase"] == "begin" and row["rv"] != CKR_OK:
                _require(row["async_id"] == 0,
                         f"{tag}: failed begin carries async id"
                         f" at seq {row['seq']}")
            if row["phase"] == "begin" or row["phase"] == "teardown":
                continue
            if (row["op"], row["async_id"]) in transfer_keys:
                continue
            _require(op_id in begun_ids and row["async_id"] == begun_ids[op_id],
                     f"{tag}: call for unknown async id {_shown(row['async_id'])}"
                     f" at seq {row['seq']}")
    ops = {}
    for op_id, op_calls in by_op.items():
        own = [row for row in op_calls
               if fence_seq is None or row["seq"] < fence_seq]
        touched_fence = len(own) != len(op_calls)
        if touched_fence:
            ops[op_id] = {"outcome": "fenced",
                          "async_id": begun_ids.get(op_id),
                          "terminal_t0": None, "terminal_t1": None,
                          "init_t0": own[0]["t0"] if own else None}
            continue
        if op_id not in begun_ids:
            transferred = any((row["op"], row["async_id"]) in transfer_keys
                              for row in op_calls)
            outcome = "adopted" if transferred else "unbegun"
            ops[op_id] = {"outcome": outcome,
                          "async_id": None, "terminal_t0": None,
                          "terminal_t1": None,
                          "init_t0": op_calls[0]["t0"]}
            if transferred:
                _settle_adopted(ops[op_id], op_calls, tag)
            continue
        outcome, terminal = _settle_calls(op_calls, tag)
        first = op_calls[0]
        ops[op_id] = {"outcome": outcome, "async_id": begun_ids[op_id],
                      "terminal_t0": terminal[0] if terminal else None,
                      "terminal_t1": terminal[1] if terminal else None,
                      "init_t0": first["t0"]}
    return {"tag": tag, "process": scenario["process"], "role": scenario["role"],
            "mechanism": scenario["mechanism"], "slot": scenario["slot"],
            "target": scenario["target"], "metadata": scenario["metadata"],
            "session": scenario["session"], "instance": scenario["instance"],
            "object": scenario["object"], "pid": ready["pid"],
            "fence": fences[0]["fence"] if fences else None, "ops": ops,
            "transfers": [{"op": row["op"], "from_pid": row["from_pid"],
                           "to_pid": row["to_pid"],
                           "async_id": row["async_id"]} for row in transfers]}


def _decisive(phase, rv):
    """Settle one call: completed/cancelled/failed, retained, or malformed."""
    if phase == "terminal":
        if rv == CKR_OK:
            return "completed"
        if rv == CKR_PENDING:
            return "retained"
        return "failed"
    if phase == "cancel":
        if rv == CKR_OK:
            return "cancelled"
        return "retained"
    if phase == "pending":
        if rv == CKR_PENDING:
            return "retained"
        if rv == CKR_OK:
            return "completed"
        return "malformed"
    if phase == "too_small":
        if rv == CKR_BUFFER_TOO_SMALL:
            return "retained"
        if rv == CKR_OK:
            return "completed"
        return "malformed"
    return "retained"


def _settle_calls(op_calls, tag):
    """Settle one op's calls; return (outcome, terminal stamps).

    The first decisive terminal/cancel/failure settles the op; later
    terminal/cancel phases are duplicate terminals, while later
    observations (query, and polls that still answer OK) pass through.
    A pending answer after a terminal contradicts the settlement.
    """
    outcome, terminal, decided = "pending", None, False
    for row in op_calls:
        verdict = _decisive(row["phase"], row["rv"])
        _require(verdict != "malformed",
                 f"{tag}: op {row['op']} {row['phase']} rv"
                 f" {_shown(row['rv'])} at seq {row['seq']}")
        if verdict == "retained":
            if decided and row["phase"] == "pending" and row["rv"] == CKR_PENDING:
                raise LedgerError(f"{tag}: op {row['op']} pending after terminal"
                                  f" at seq {row['seq']}")
            continue
        if decided:
            _require(row["phase"] not in ("terminal", "cancel"),
                     f"{tag}: op {row['op']} duplicate terminal"
                     f" at seq {row['seq']}")
            continue
        outcome, terminal, decided = verdict, (row["t0"], row["t1"]), True
    return outcome, terminal


def _settle_adopted(entry, op_calls, tag):
    """Settle a transfer-adopted op (begin lives in the other ledger)."""
    outcome, terminal = _settle_calls(op_calls, tag)
    entry["outcome"] = "adopted-" + outcome
    entry["terminal_t0"] = terminal[0] if terminal else None
    entry["terminal_t1"] = terminal[1] if terminal else None


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


def validate_snapshot(document, tag):
    """Validate the frozen H9 subset; refuse anything but populated output."""
    _keys(document, {"version", "revision", "status", "reason", "sessions",
                     "objects", "key_operations", "unknown_key_operations",
                     "gaps", "budgets"})
    _require(document["version"] == 1, f"{tag}: snapshot version mismatch")
    _require(_integer(document["revision"]), f"{tag}: snapshot revision out of range")
    _require(document["status"] in STATUSES, f"{tag}: snapshot status invalid")
    _require(document["reason"] in STATUS_REASONS, f"{tag}: snapshot reason invalid")
    _require((document["status"] == "populated")
             == (document["reason"] == "none"),
             f"{tag}: snapshot status/reason disagree")
    if document["status"] != "populated":
        raise LedgerError(f"{tag}: snapshot status {document['status']}"
                          f" reason {document['reason']}: joint evidence absent")
    _require(type(document["sessions"]) is list,
             f"{tag}: snapshot sessions must be a list")
    session_ids = []
    for position, row in enumerate(document["sessions"]):
        where = f"{tag} snapshot session {position}"
        _require(type(row) is dict, f"{where} must be an object")
        _keys(row, {"session", "origin", "status"})
        _require(_integer(row["session"]), f"{where}: id out of range")
        _require(row["origin"] in ("opened", "first_observed"),
                 f"{where}: origin invalid")
        _require(row["status"] in ("live", "closed", "lost"),
                 f"{where}: status invalid")
        session_ids.append(row["session"])
    _check_sorted_unique(session_ids, f"{tag} snapshot sessions")
    _require(type(document["objects"]) is list,
             f"{tag}: snapshot objects must be a list")
    object_ids = [_check_object_row(row, f"{tag} snapshot object {position}")
                  for position, row in enumerate(document["objects"])]
    _check_sorted_unique(object_ids, f"{tag} snapshot objects")
    _require(type(document["key_operations"]) is list,
             f"{tag}: snapshot key_operations must be a list")
    known_keys = [_check_key_row(row, f"{tag} snapshot key row {position}")
                  for position, row in enumerate(document["key_operations"])]
    _check_sorted_unique(known_keys, f"{tag} snapshot key rows")
    _require(type(document["unknown_key_operations"]) is list,
             f"{tag}: snapshot unknown_key_operations must be a list")
    unknown_keys = [_check_unknown_row(row, f"{tag} snapshot unknown row {position}")
                    for position, row in enumerate(document["unknown_key_operations"])]
    _check_sorted_unique(unknown_keys, f"{tag} snapshot unknown rows")
    gaps = document["gaps"]
    _require(type(gaps) is dict, f"{tag}: snapshot gaps must be an object")
    _keys(gaps, {"rows", "suppressed"})
    _require(type(gaps["rows"]) is list, f"{tag}: snapshot gap rows must be a list")
    _require(len(gaps["rows"]) <= 256, f"{tag}: snapshot gap rows exceed 256")
    for position, row in enumerate(gaps["rows"]):
        where = f"{tag} snapshot gap {position}"
        _require(type(row) is dict, f"{where} must be an object")
        _keys(row, {"subject", "reason", "repeats"})
        _require(row["subject"] in ("model", "key_operation"),
                 f"{where}: subject invalid")
        _require(type(row["reason"]) is str, f"{where}: reason invalid")
        _require(_integer(row["repeats"]), f"{where}: repeats out of range")
    _require(_integer(gaps["suppressed"]),
             f"{tag}: snapshot gaps suppressed out of range")
    budgets = document["budgets"]
    _require(type(budgets) is dict, f"{tag}: snapshot budgets must be an object")
    _keys(budgets, {"key_rows", "object_rows", "unknown_rows", "encoded_bytes",
                    "allocation_refused", "refusal_reason"})
    _check_row_budget(budgets["key_rows"], f"{tag} snapshot key_rows budget")
    _check_row_budget(budgets["object_rows"], f"{tag} snapshot object_rows budget")
    _require(type(budgets["unknown_rows"]) is dict,
             f"{tag}: snapshot unknown_rows budget must be an object")
    _keys(budgets["unknown_rows"], {"occupied"})
    _require(_integer(budgets["unknown_rows"]["occupied"]),
             f"{tag}: snapshot unknown_rows budget occupied out of range")
    _require(_integer(budgets["encoded_bytes"]),
             f"{tag}: snapshot encoded_bytes out of range")
    _require(budgets["allocation_refused"] is False,
             f"{tag}: snapshot allocation_refused changed")
    _require(budgets["refusal_reason"] == "none",
             f"{tag}: snapshot refusal_reason changed")
    return document


def _begun_ids(feed):
    """Non-fenced begun async ids mapped from op id (owned begins only)."""
    return {op_id: op["async_id"] for op_id, op in feed["ops"].items()
            if op["async_id"] is not None and op["outcome"] in (
                "completed", "cancelled", "failed", "pending")}


def compare_collision(first, second):
    """Check the pair collides; settle transfers across ledgers.

    The pair must hold distinct processes, one owner and one
    challenger, different pending mechanisms, equal slot/target,
    distinct sessions, and every challenger-begun async id owned.
    Each transfer must name the pair's pids, an op the from-side
    began and left unsettled, and adopted calls on the to-side; its
    outcome settles under the owner's key.
    """
    _require(first["process"] != second["process"], "processes share one label")
    roles = {first["role"], second["role"]}
    _require(roles == {"owner", "challenger"},
             "roles must be owner and challenger")
    owner = first if first["role"] == "owner" else second
    challenger = second if first["role"] == "owner" else first
    _require(owner["pid"] != challenger["pid"],
             f"processes share pid {owner['pid']}:"
             " collision needs distinct processes")
    _require(owner["mechanism"] != challenger["mechanism"],
             "mechanisms agree: collision needs different pending mechanisms")
    _require(owner["slot"] == challenger["slot"]
             and owner["target"] == challenger["target"],
             "slot/target diverge: no collision")
    _require(owner["session"] != challenger["session"],
             "sessions agree: collision needs distinct sessions")
    owner_ids = _begun_ids(owner)
    chal_ids = _begun_ids(challenger)
    for op_id in sorted(chal_ids):
        _require(chal_ids[op_id] in set(owner_ids.values()),
                 f"challenger async id {chal_ids[op_id]} has no owner")
    by_pid = {owner["pid"]: owner, challenger["pid"]: challenger}
    transfers = []
    seen = set()
    for feed in (first, second):
        for row in feed["transfers"]:
            _require(row["from_pid"] in by_pid and row["to_pid"] in by_pid,
                     f"transfer op {row['op']} outside the pair")
            _require((row["op"], row["async_id"]) not in seen,
                     f"transfer op {row['op']} declared twice")
            seen.add((row["op"], row["async_id"]))
            source = by_pid[row["from_pid"]]
            dest = by_pid[row["to_pid"]]
            src_op = source["ops"].get(row["op"])
            _require(src_op is not None
                     and src_op.get("async_id") == row["async_id"],
                     f"transfer op {row['op']} without begin")
            dst_op = dest["ops"].get(row["op"])
            _require(src_op["outcome"] != "fenced"
                     and (dst_op is None or dst_op["outcome"] != "fenced"),
                     f"transfer op {row['op']} fenced")
            _require(src_op["outcome"] == "pending",
                     f"transfer op {row['op']} already settled"
                     f" by pid {row['from_pid']}")
            _require(dst_op is not None
                     and dst_op["outcome"].startswith("adopted-"),
                     f"transfer op {row['op']} has no adopted calls")
            outcome = dst_op["outcome"][len("adopted-"):]
            transfers.append({"op": row["op"], "async_id": row["async_id"],
                              "outcome": outcome,
                              "terminal_t0": dst_op["terminal_t0"],
                              "terminal_t1": dst_op["terminal_t1"]})
    fenced = [op_id for feed in (owner, challenger)
              for op_id, op in feed["ops"].items()
              if op["outcome"] == "fenced"]
    return {"owner": owner, "challenger": challenger,
            "collided": sorted(set(chal_ids.values())),
            "transfers": transfers, "fenced": len(fenced)}


def _owner_tally(owner, collision):
    """Expected owner-key counters: derived outcomes plus transfers."""
    handed = {item["op"] for item in collision["transfers"]}
    tally = {"begun": 0, "completed": 0, "cancelled": 0, "failed": 0,
             "pending": 0}
    for op_id, op in owner["ops"].items():
        if op_id in handed or op["outcome"] not in (
                "completed", "cancelled", "failed", "pending"):
            continue
        tally["begun"] += 1
        if op["outcome"] == "completed":
            tally["completed"] += 1
        elif op["outcome"] == "cancelled":
            tally["cancelled"] += 1
        elif op["outcome"] == "failed":
            tally["failed"] += 1
        else:
            tally["pending"] += 1
    for item in collision["transfers"]:
        tally["begun"] += 1
        if item["outcome"] == "completed":
            tally["completed"] += 1
        elif item["outcome"] == "cancelled":
            tally["cancelled"] += 1
        elif item["outcome"] == "failed":
            tally["failed"] += 1
        else:
            tally["pending"] += 1
    return tally


def _challenger_tally(challenger, collision):
    """Expected challenger-unknown counters; handed-off ops excluded."""
    handed = {(item["op"], item["async_id"]) for item in collision["transfers"]}
    tally = {"completed": 0, "cancelled": 0, "failed": 0, "pending": 0}
    for op_id, op in challenger["ops"].items():
        if (op_id, op["async_id"]) in handed:
            continue
        if op["outcome"] == "completed":
            tally["completed"] += 1
        elif op["outcome"] == "cancelled":
            tally["cancelled"] += 1
        elif op["outcome"] == "failed":
            tally["failed"] += 1
        elif op["outcome"] == "pending":
            tally["pending"] += 1
    return tally


def _fence_gaps(owner, challenger):
    gaps = {}
    for feed in (owner, challenger):
        count = sum(1 for op in feed["ops"].values()
                    if op["outcome"] == "fenced")
        if count:
            gaps[feed["fence"]] = gaps.get(feed["fence"], 0) + count
    return gaps


def compare_joint(collision, snapshot):
    """Compare the collision against the joint-path snapshot.

    The owner's ops join (key row, or unknown metadata_unknown without
    established metadata); the challenger's untransferred completions
    are refused joins (duplicate_completion gaps with S1 completion
    preserved in unknown rows); fenced ops gap by fence value with no
    completion preserved. Every row and gap must match exactly.
    """
    owner, challenger = collision["owner"], collision["challenger"]
    _require(snapshot["gaps"]["suppressed"] == 0,
             f"joint snapshot gaps suppressed"
             f" {_shown(snapshot['gaps']['suppressed'])} hides dispositions")
    for row in snapshot["key_operations"]:
        if type(row) is dict and (row.get("instance"), row.get("object"),
                                  row.get("category"), row.get("role")) == (
                challenger["instance"], challenger["object"], CATEGORY, ROLE):
            raise LedgerError(f"challenger joined by key row"
                              f" {challenger['instance']},{challenger['object']}"
                              f",{CATEGORY},{ROLE}")
    owner_key = (owner["instance"], owner["object"], CATEGORY, ROLE,
                 owner["metadata"])
    owner_tally = _owner_tally(owner, collision)
    chal_tally = _challenger_tally(challenger, collision)
    known = {}
    for row in snapshot["key_operations"]:
        known[_check_key_row(row, "joint snapshot key row")] = row
    unknown = {}
    for row in snapshot["unknown_key_operations"]:
        unknown[_check_unknown_row(row, "joint snapshot unknown row")] = row
    objects = {row["object"] for row in snapshot["objects"]}
    claimed_known, claimed_unknown = set(), set()
    if owner["metadata"] is not None:
        _require(owner_key in known,
                 f"missing key row for owner {owner_key[0]},{owner_key[1]}"
                 f",{owner_key[2]},{owner_key[3]},{owner_key[4]}")
        row = known[owner_key]
        for name, want in (("started", owner_tally["begun"]),
                           ("completed", owner_tally["completed"]),
                           ("failed", owner_tally["failed"]),
                           ("cancelled", owner_tally["cancelled"]),
                           ("unknown", 0),
                           ("active", owner_tally["pending"]),
                           ("key_join_lost", 0)):
            _require(row[name] == want,
                     f"joint key row {name} {row[name]} disagrees with ledger"
                     f" {want} for owner")
        _require(owner["object"] in objects,
                 f"joint missing object row {owner['object']} for owner")
        claimed_known.add(owner_key)
    else:
        _require((CATEGORY, "metadata_unknown") in unknown,
                 "joint missing unknown row for owner"
                 f" {CATEGORY},metadata_unknown")
    chal_reason = ("metadata_unknown" if challenger["metadata"] is None
                   else "unbound")
    # Unknown rows are capture-wide: owner-without-metadata and the
    # challenger may share one (category, reason) row; sum those groups.
    expected_unknown = {}
    if owner["metadata"] is None:
        key = (CATEGORY, "metadata_unknown")
        group = expected_unknown.setdefault(
            key, {"completed": 0, "failed": 0, "cancelled": 0, "unknown": 0,
                  "active": 0})
        group["completed"] += owner_tally["completed"]
        group["failed"] += owner_tally["failed"]
        group["cancelled"] += owner_tally["cancelled"]
        group["active"] += owner_tally["pending"]
    key = (CATEGORY, chal_reason)
    group = expected_unknown.setdefault(
        key, {"completed": 0, "failed": 0, "cancelled": 0, "unknown": 0,
              "active": 0})
    group["completed"] += chal_tally["completed"]
    group["failed"] += chal_tally["failed"]
    group["cancelled"] += chal_tally["cancelled"]
    group["active"] += chal_tally["pending"]
    for key, want in expected_unknown.items():
        _require(key in unknown,
                 f"joint missing unknown row {key[0]},{key[1]}")
        row = unknown[key]
        for name in ("completed", "failed", "cancelled", "unknown", "active"):
            _require(row[name] == want[name],
                     f"joint unknown row {name} {row[name]} disagrees with"
                     f" ledger {want[name]} for {key[0]},{key[1]}")
        claimed_unknown.add(key)
    if owner["metadata"] is None:
        _require(owner["object"] not in objects,
                 f"joint object row {owner['object']} staged for unkeyed owner")
    _require(challenger["object"] not in objects,
             f"joint object row {challenger['object']} staged for challenger")
    expected_gaps = {("key_operation", "duplicate_completion"):
                     chal_tally["completed"]}
    for fence, count in _fence_gaps(owner, challenger).items():
        expected_gaps[("key_operation", fence)] = (
            expected_gaps.get(("key_operation", fence), 0) + count)
    expected_gaps = {key: value for key, value in expected_gaps.items() if value}
    seen_gaps = {}
    for row in snapshot["gaps"]["rows"]:
        key = (row["subject"], row["reason"])
        _require(key not in seen_gaps, f"joint duplicate gap {key[0]},{key[1]}")
        seen_gaps[key] = row["repeats"]
    _require(seen_gaps == expected_gaps,
             f"joint gaps {sorted(seen_gaps.items())} disagree with ledger"
             f" {sorted(expected_gaps.items())}")
    for key in known:
        _require(key in claimed_known,
                 f"joint unmatched key row {key[0]},{key[1]}"
                 f",{key[2]},{key[3]},{key[4]}")
    for key in unknown:
        _require(key in claimed_unknown,
                 f"joint unmatched unknown row {key[0]},{key[1]}")
    return {"owner_completed": owner_tally["completed"],
            "challenger_refused": chal_tally["completed"],
            "joint_completed": (owner_tally["completed"]
                                + sum(group["completed"]
                                      for group in expected_unknown.values()))}


def compare_s1only(collision, snapshot):
    """Compare the collision against the S1Only-path snapshot.

    Nothing joins: no key rows, no gaps. One unknown (operation,
    unbound) row preserves every S1 completion, cancellation, failure
    and pending op across both processes.
    """
    owner, challenger = collision["owner"], collision["challenger"]
    _require(snapshot["gaps"]["suppressed"] == 0,
             f"s1only snapshot gaps suppressed"
             f" {_shown(snapshot['gaps']['suppressed'])} hides dispositions")
    for row in snapshot["key_operations"]:
        if type(row) is dict:
            detail = (f"{_shown(row.get('instance'))}"
                      f",{_shown(row.get('object'))}"
                      f",{_shown(row.get('category'))}"
                      f",{_shown(row.get('role'))}")
        else:
            detail = _shown(row)
        raise LedgerError(f"s1only key row present {detail}")
    owner_tally = _owner_tally(owner, collision)
    chal_tally = _challenger_tally(challenger, collision)
    want = {"completed": owner_tally["completed"] + chal_tally["completed"],
            "failed": owner_tally["failed"] + chal_tally["failed"],
            "cancelled": owner_tally["cancelled"] + chal_tally["cancelled"],
            "unknown": 0,
            "active": owner_tally["pending"] + chal_tally["pending"]}
    _require(len(snapshot["unknown_key_operations"]) == 1
             and (snapshot["unknown_key_operations"][0]["category"],
                  snapshot["unknown_key_operations"][0]["reason"])
             == (CATEGORY, "unbound"),
             "s1only unknown rows must be exactly operation,unbound")
    row = snapshot["unknown_key_operations"][0]
    for name in ("completed", "failed", "cancelled", "unknown", "active"):
        _require(row[name] == want[name],
                 f"s1only unknown row {name} {row[name]} disagrees with ledger"
                 f" {want[name]}")
    _require(snapshot["gaps"]["rows"] == [],
             "s1only gaps present: direct path refuses no joins")
    return {"s1only_completed": want["completed"]}


def cross_totals(joint_snapshot, s1only_snapshot):
    """Require joint and S1Only snapshot totals to agree exactly."""
    joint = {"completed": 0, "failed": 0, "cancelled": 0, "unknown": 0,
             "active": 0}
    for row in (joint_snapshot["key_operations"]
                + joint_snapshot["unknown_key_operations"]):
        for name in joint:
            joint[name] += row[name]
    single = {"completed": 0, "failed": 0, "cancelled": 0, "unknown": 0,
              "active": 0}
    for row in s1only_snapshot["unknown_key_operations"]:
        for name in single:
            single[name] += row[name]
    for name in joint:
        _require(joint[name] == single[name],
                 f"cross-run {name} diverge: joint {joint[name]}"
                 f" s1only {single[name]}")
    return joint


def _row_completions(collision, view, bucket, key):
    """Completion stamps for one row, in completion order, or None to skip.

    The joint view receipts the owner's key row (own terminals plus
    transfer terminals, which land under the owner's key) and the
    challenger's unknown row by terminal order; async completions are
    not op-ordered. The S1Only unknown row sums both processes, so its
    receipts stay unchecked.
    """
    if bucket == "object" or view != "joint":
        return None
    owner, challenger = collision["owner"], collision["challenger"]
    owner_key = (owner["instance"], owner["object"], CATEGORY, ROLE,
                 owner["metadata"])
    chal_reason = ("metadata_unknown" if challenger["metadata"] is None
                   else "unbound")
    shared_unknown = (owner["metadata"] is None
                      and chal_reason == "metadata_unknown")
    stamps = None
    if bucket == "known" and owner["metadata"] is not None and key == owner_key:
        stamps = [(op["terminal_t0"], op["terminal_t1"])
                  for op in owner["ops"].values()
                  if op["outcome"] == "completed"]
        stamps += [(item["terminal_t0"], item["terminal_t1"])
                   for item in collision["transfers"]
                   if item["outcome"] == "completed"]
    elif bucket == "unknown" and key == (CATEGORY, chal_reason) \
            and not shared_unknown:
        stamps = [(op["terminal_t0"], op["terminal_t1"])
                  for op in challenger["ops"].values()
                  if op["outcome"] == "completed"]
    elif bucket == "unknown" and owner["metadata"] is None and key == (
            CATEGORY, "metadata_unknown") and not shared_unknown:
        stamps = [(op["terminal_t0"], op["terminal_t1"])
                  for op in owner["ops"].values()
                  if op["outcome"] == "completed"]
        stamps += [(item["terminal_t0"], item["terminal_t1"])
                   for item in collision["transfers"]
                   if item["outcome"] == "completed"]
    if stamps is None:
        return None
    return sorted(stamps, key=lambda pair: pair[1])


def compare_stream(events, collision, snapshot, view):
    """Walk H9 row events: order, cumulative counts, receipts, reconciliation.

    Row events carry cumulative snapshots keyed by (bucket, row key);
    revisions per key rise strictly, completed never decreases, and the
    last carried row equals the snapshot row. Each completion takes its
    receipt at the first event covering it in terminal order; a receipt
    with at_ns before the terminal t0 is impossible (at_ns inside
    [t0, t1) is the fixture preemption window and passes). For two
    non-overlapping completions on different rows the receipt revisions
    follow terminal order. pass_committed/ended markers present in the
    excerpt must agree on object_status and carry gaps_suppressed 0.
    Other kinds pass through.
    """
    _require(view in ("joint", "s1only"), "view invalid")
    last_seq = None
    last_revision = None
    series = {}
    for position, line in enumerate(events):
        where = f"{view} stream line {position}"
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
                 f"{view} stream row {key}: revision order")
        if key[0] in ("known", "unknown"):
            completed = [row["completed"] for _, _, row in points]
            _require(completed == sorted(completed),
                     f"{view} stream row {key}: completed decreases")
    chain = []
    for line in events:
        if type(line) is dict and line.get("kind") in ("object_observed",
                                                       "key_operations_observed"):
            chain.append(line["event"]["revision"])
    _require(chain == sorted(chain), f"{view} stream revisions leave one chain")
    if chain:
        last_revision = chain[-1]
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
        _require(key in carried, f"{view} stream never carries snapshot row {key}")
        _require(carried[key] == row,
                 f"{view} stream row {key} disagrees with snapshot")
    for key in carried:
        _require(key in snapshot_rows,
                 f"{view} stream carries unclaimed row {key}")
    receipts = {}
    for (bucket, key), points in series.items():
        stamps = _row_completions(collision, view, bucket, key)
        if stamps is None:
            continue
        for rank, (start, _end) in enumerate(stamps, start=1):
            cover = next(((revision, at_ns)
                          for revision, at_ns, row in points
                          if row["completed"] >= rank), None)
            _require(cover is not None,
                     f"{view} stream row {(bucket, key)} never covers"
                     f" completion {rank}")
            _require(cover[1] >= start,
                     f"{view} receipt at_ns {cover[1]} precedes call t0"
                     f" {start} for {(bucket, key)} completion {rank}")
            receipts[((bucket, key), rank)] = cover[0]
    rows = [(key, _row_completions(collision, view, *key))
            for key in series if _row_completions(collision, view, *key)]
    for left in range(len(rows)):
        for right in range(left + 1, len(rows)):
            (key_a, done_a), (key_b, done_b) = rows[left], rows[right]
            for rank_a, (t0_a, t1_a) in enumerate(done_a, start=1):
                for rank_b, (t0_b, t1_b) in enumerate(done_b, start=1):
                    if t1_a < t0_b:
                        _require(receipts[(key_a, rank_a)]
                                 <= receipts[(key_b, rank_b)],
                                 f"{view} interleave order: {key_a}"
                                 f" completion {rank_a} precedes {key_b}"
                                 f" completion {rank_b}")
                    if t1_b < t0_a:
                        _require(receipts[(key_b, rank_b)]
                                 <= receipts[(key_a, rank_a)],
                                 f"{view} interleave order: {key_b}"
                                 f" completion {rank_b} precedes {key_a}"
                                 f" completion {rank_a}")
    return {"events": len(events), "rows": len(series),
            "revision": last_revision}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger_a", help="first process ledger JSONL file")
    parser.add_argument("ledger_b", help="second process ledger JSONL file")
    parser.add_argument("joint_snapshot",
                        help="joint-path object_observations section JSON file")
    parser.add_argument("s1only_snapshot",
                        help="S1Only-path object_observations section JSON file")
    parser.add_argument("joint_events", nargs="?",
                        help="joint-path event-stream JSONL file")
    parser.add_argument("s1only_events", nargs="?",
                        help="S1Only-path event-stream JSONL file")
    args = parser.parse_args(argv)
    try:
        with open(args.ledger_a, encoding="utf-8") as stream:
            first = validate_ledger(read_ledger(stream), "ledger A")
        with open(args.ledger_b, encoding="utf-8") as stream:
            second = validate_ledger(read_ledger(stream), "ledger B")
        with open(args.joint_snapshot, encoding="utf-8") as stream:
            joint = validate_snapshot(read_snapshot(stream.read()), "joint")
        with open(args.s1only_snapshot, encoding="utf-8") as stream:
            single = validate_snapshot(read_snapshot(stream.read()), "s1only")
        collision = compare_collision(first, second)
        result = {"processes": 2, "collided": len(collision["collided"]),
                  "transfers": len(collision["transfers"]),
                  "fenced": collision["fenced"]}
        result.update(compare_joint(collision, joint))
        result.update(compare_s1only(collision, single))
        cross_totals(joint, single)
        if args.joint_events is not None:
            with open(args.joint_events, encoding="utf-8") as stream:
                outcome = compare_stream(read_events(stream), collision,
                                         joint, "joint")
            result["joint_events"] = outcome["events"]
        if args.s1only_events is not None:
            with open(args.s1only_events, encoding="utf-8") as stream:
                outcome = compare_stream(read_events(stream), collision,
                                         single, "s1only")
            result["s1only_events"] = outcome["events"]
    except LedgerError as error:
        print(f"async refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("async refused: unreadable input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

