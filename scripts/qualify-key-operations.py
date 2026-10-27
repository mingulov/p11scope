#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare observed key operations with the independent RSA ledger.

Inputs are the controlled application's JSONL ledger (validated by
scripts/key-operation-ledger.py, which derives counts from call rows rather
than summaries) and the observer's saved `p11scope/inventory/v1` document,
from which the `object_observations` section is read (a bare section
is also accepted). When the document carries top-level `edges`, the S1
`edges[].mechanisms` rows are additionally checked for the expected
CKM_SHA256_RSA_PKCS attribution of sign/verify; bare sections and
edge-less envelopes leave the mechanism dimension unknown. The oracle
re-sums observed completed/failed outcomes from the per-row counters
itself, pins the frozen H9 key/enum contract and the row equation, and
refuses any unattributed, cancelled, unknown, active, lost, gapped or
otherwise unsettled sign/verify outcome. It never trusts the product's own
accounting (`done`, `budgets.occupied`, `encoded_bytes`): occupancy is
cross-checked against the rows the oracle counted, never used as a tally.
Secondary `wrapped_object` rows and `message_contexts` units never count
as operations (all-zero rows of any category/role/unit/metadata are
tolerated as idle and contribute nothing). Refusal diagnostics name only
frozen labels and counts; unknown product strings are never echoed.

With `--s1` the current Inventory topology proves 68 physical entries separately
from one owned instance child's 65 reducer-admitted API observations, operations and
mechanisms. The parent deliberately withholds its semantic summary. Only the
exact stopped disclosure {capture_stopped, semantic_loss} is accepted beside
proven terminal drain and the fixed ledger/child counts; the disclosure remains
in the match summary. Any present child-topology key forces this strict path.
When both additive keys are absent, the previous strict observed-parent format
remains historical data compatibility, not a current release live receipt.

This oracle proves only facts in the supplied ledger and Inventory document.
Inventory does not publish lifetime Detailed EVENTS loss or collected/joined/
shed accounting. A live qualification must separately require identity-bound
held-map EVENTS loss of zero through observer exit and the actual 68/68/0 stop receipt.
Neither those facts nor caller/module identities are invented from the ledger.

Exit 0 prints the match summary as JSON; exit 1 leaves stdout empty and
names the finite refusal cause on stderr.
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


# Whole inventory-document bound (the CLI reads the full inventory/v1
# document, not just the section); section rows are additionally capped by
# the 65536 row budgets, the 256 gap cap and the occupancy cross-checks.
MAX_OBSERVER_BYTES = 8 * 1024 * 1024
MAX_WORD = (1 << 64) - 1
INVENTORY_SCHEMA = "p11scope/inventory/v1"
OBSERVATIONS_VERSION = 1
ROW_BUDGET_LIMIT = 65536
GAPS_CAPACITY = 256

# Frozen H9 vocabularies (src/key_operation_projection.rs contract tables
# and docs/schema/inventory-v1-object-observations.schema.json). A schema
# revision edits these tables, not the logic below.
STATUSES = ("populated", "partial", "stale", "unavailable")
REASONS = ("none", "bootstrap_unavailable", "journal_unavailable", "proof_refused_fallback",
           "authority_lost", "row_budget_exhausted", "publication_budget_exhausted",
           "serialization_refused", "sink_failed")
SESSION_ORIGINS = ("opened", "first_observed")
SESSION_STATUSES = ("live", "closed", "lost")
OBJECT_ORIGINS = ("created", "first_observed")
CREATIONS = ("create", "copy", "generate", "generate_pair", "derive", "unwrap")
LIFETIMES = ("live", "destroyed", "access_ended", "retired")
ATTRIBUTIONS = ("valid", "downgraded")
METADATA_KEYS = ("class", "key_type", "token", "value_len", "modulus_bits", "ec_params")
FIELD_STATUSES = ("unknown", "value", "conflict", "invalidated")
METADATA_FIELD_VALUES = {
    "class": (0, 1, 2, 3, 4),
    "key_type": (0, 1, 2, 3, 4, 16, 31, 64, 65),
    "token": (0, 1),
    "value_len": (16, 24, 32),
    "modulus_bits": (1024, 2048, 3072, 4096, 8192),
}
CURVE_LABELS = ("secp256r1", "secp384r1", "secp521r1")
QUERY_STATUSES = ("not_queried", "established", "unavailable", "size_only", "unsupported",
                  "malformed", "excluded")
METADATA_LABELS = ("rsa_1024", "rsa_2048", "rsa_3072", "rsa_4096", "rsa_other", "aes_128",
                   "aes_192", "aes_256", "aes_other", "ec_p256", "ec_p384", "ec_p521")
CATEGORIES = ("digest", "sign", "verify", "encrypt", "decrypt", "sign_recover",
              "verify_recover", "message_encrypt", "message_decrypt", "message_sign",
              "message_verify", "generate_key", "generate_key_pair", "wrap", "unwrap",
              "derive", "encapsulate", "decapsulate", "wrap_authenticated",
              "unwrap_authenticated", "operation", "direct", "unknown")
ROLES = ("key", "wrapping_key", "wrapped_object", "unwrapping_key", "base_key", "other")
UNITS = ("operations", "message_contexts")
UNKNOWN_REASONS = ("unbound", "key_join_lost", "metadata_unknown", "metadata_conflicting",
                   "role_unavailable", "not_applicable")
GAP_SUBJECTS = ("model", "key_operation")
GAP_REASONS = ("bootstrap_unproven", "bootstrap_refused", "prefix_contradiction",
               "stale_prefix", "closed_frontier", "duplicate_call", "duplicate_completion",
               "stale_token", "fenced_completion", "malformed_fact", "unsupported_function",
               "domain_ended", "result_protocol_unavailable", "pending_result_unavailable",
               "output_unreadable", "pair_duplicate", "null_mechanism_cancel",
               "same_session_overlap", "overlap_uncertain", "output_collision", "stale_origin",
               "dependency_broken", "unproven_input", "unproven_session", "metadata_uncertain",
               "destroy_alias", "close_uncertain", "close_all_uncertain", "logout_uncertain",
               "session_closed", "invalid_handle", "ambiguous_outcome", "session_contradiction",
               "handle_reuse", "finalize", "token_reset", "exec", "fork", "unload", "loss",
               "pending_capacity", "session_capacity", "object_capacity", "instance_capacity",
               "id_exhausted", "device_loss", "unseen_finalize", "inconsistent_mechanism",
               "outcome_lost", "unknown_domain", "domain_pruned", "pruned_object_referenced")

SECTION_KEYS = {"version", "revision", "status", "reason", "sessions", "objects",
                "key_operations", "unknown_key_operations", "gaps", "budgets"}
SESSION_ROW_KEYS = {"session", "origin", "status"}
OBJECT_ROW_KEYS = {"object", "session", "origin", "creation", "birth", "lifetime",
                   "lifetime_reason", "attribution", "attribution_reason", "requested",
                   "established", "queries", "label", "successful_references",
                   "successful_key_references", "accessing_sessions"}
KEY_ROW_KEYS = {"instance", "object", "category", "role", "metadata_at_use", "unit",
                "started", "completed", "failed", "cancelled", "unknown", "active",
                "key_join_lost"}
UNKNOWN_ROW_KEYS = {"category", "reason", "unit", "completed", "failed", "cancelled",
                    "unknown", "active"}
GAP_ROW_KEYS = {"subject", "reason", "repeats"}
BUDGET_KEYS = {"key_rows", "object_rows", "unknown_rows", "encoded_bytes",
               "allocation_refused", "refusal_reason"}
ROW_BUDGET_KEYS = {"limit", "occupied", "refused"}
UNKNOWN_BUDGET_KEYS = {"occupied"}
FIELD_KEYS = {"status", "value"}
MECHANISM_ROW_KEYS = {"mechanism", "mechanism_hex", "name", "operations", "calls",
                      "errors", "last_seen_ns", "evidence"}
MECHANISM_EVIDENCE_KEYS = {"functions", "returns", "truncated"}
MECHANISM_RETURN_KEYS = {"rv", "rv_hex", "name"}

INSTANCE_RE = re.compile(r"i[0-9]+")

# This cell's fixed expectations: the V5-10 RSA workload only.
CELL_CATEGORIES = ("sign", "verify")
CELL_ROLE = "key"
CELL_METADATA = "rsa_2048"
CELL_MECHANISM = 0x40
CELL_MECHANISM_HEX = "0x40"
CELL_MECHANISM_NAME = "CKM_SHA256_RSA_PKCS"
CELL_MECHANISM_OPS = ("sign", "verify")
EXPECTED_API_CALLS = 68
EXPECTED_CALLS = {"C_Sign": 9, "C_SignUpdate": 9, "C_Verify": 12}
EXPECTED_OPERATIONS = {"sign": {"completed": 10, "failed": 0},
                       "verify": {"completed": 10, "failed": 2}}
EXPECTED_STARTED = {"sign": 10, "verify": 12}

# S1 expectations for the same RSA cell: the 68-call workload read from the
# S1 edge shapes (entries, operations, mechanisms) while object_observations
# stays unavailable. Per-function results come from the ledger's own call
# rows: C_Sign runs 9 times (8 OK, 1 BUFFER_TOO_SMALL retry probe), C_Verify
# 12 times (10 OK, 2 SIGNATURE_INVALID). The 31/24/13 split counts workload
# calls by operation category (operation 0 is setup). The edge numbers follow
# the S1 reducer rules: operations.calls counts the 65 gated calls (68 minus
# the 3 COUNT_ONLY setup calls), started counts the 22 OK inits plus the
# GenerateKeyPair direct call, and mechanism 0x40 carries the 55 attributed
# sign/verify calls with 3 errors.
S1_STATUS = "unavailable"
S1_REASON = "journal_unavailable"
S1_CALL_SPLIT = {"sign": 31, "verify": 24, "setup": 13}
S1_PER_FUNCTION = {"C_Sign": {0x0: 8, 0x150: 1},
                   "C_Verify": {0x0: 10, 0xC0: 2}}
S1_OPERATIONS = {"calls": 65, "started": 23, "completed": 21, "cancelled": 0,
                 "failed": 2, "unknown": 0, "orphans": 0, "dropped": 0}
S1_MECHANISMS = (
    {"id": 0x0, "name": "CKM_RSA_PKCS_KEY_PAIR_GEN",
     "operations": ("generate_key_pair",), "calls": 1, "errors": 0,
     "functions": ("C_GenerateKeyPair",), "returns": {0x0: "CKR_OK"}},
    {"id": CELL_MECHANISM, "name": CELL_MECHANISM_NAME,
     "operations": CELL_MECHANISM_OPS, "calls": 55, "errors": 3,
     "functions": ("C_Sign", "C_SignFinal", "C_SignInit", "C_SignUpdate",
                   "C_Verify", "C_VerifyInit"),
     "returns": {0x0: "CKR_OK", 0xC0: "CKR_SIGNATURE_INVALID",
                 0x150: "CKR_BUFFER_TOO_SMALL"}},
)
OPERATION_KEYS = {"calls", "started", "completed", "cancelled", "failed",
                  "unknown", "orphans", "dropped", "last_seen_ns", "active",
                  "evidence"}
OPERATION_EVIDENCE_KEYS = ("state_reconciliations", "session_cancel_ambiguities",
                            "session_cancel_unknown_flags", "operation_state_imports",
                            "auth_state_ambiguities", "semantic_capture_failures",
                            "async_duplicates", "async_evictions", "unmatched_closes")
ACTIVE_ROW_KEYS = {"category", "state", "count"}
ACTIVE_STATES = ("initialized", "in_progress")
COVERAGE_STATES = ("counted", "witnessed", "watched_no_use", "unknown")


class OracleRefusal(ValueError):
    """The observed output does not match the independent ledger."""


def _ledger_module():
    path = Path(__file__).with_name("key-operation-ledger.py")
    spec = importlib.util.spec_from_file_location("key_operation_ledger", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEDGER = _ledger_module()


def _require(condition, reason):
    if not condition:
        raise OracleRefusal(reason)


def _u64(value):
    return type(value) is int and 0 <= value <= MAX_WORD


def _uint(value):
    return type(value) is int and value >= 0


def _keys(row, expected):
    _require(type(row) is dict and set(row) == set(expected), "unexpected fields")


def _label(value, vocab, what):
    """Return a frozen label, refusing (without echo) anything outside it."""
    if type(value) is str and value in vocab:
        return value
    raise OracleRefusal(f"unexpected {what} label")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise OracleRefusal("nonfinite JSON number")


def read_observer_file(path):
    """Read one bounded observer JSON document without trusting its shape."""
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_OBSERVER_BYTES + 1)
    except OSError:
        raise OracleRefusal("cannot read observer input") from None
    _require(len(raw) <= MAX_OBSERVER_BYTES, "observer input exceeds size bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise OracleRefusal("observer input is not UTF-8") from None
    try:
        doc = json.loads(text, object_pairs_hook=_unique_object,
                         parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise OracleRefusal("invalid observer JSON") from None
    _require(type(doc) is dict, "observer input must be an object")
    return doc


def _metadata_block(block):
    _keys(block, METADATA_KEYS)
    for name in METADATA_KEYS:
        cell = block[name]
        _keys(cell, FIELD_KEYS)
        _label(cell["status"], FIELD_STATUSES, "metadata field status")
        value = cell["value"]
        if name == "ec_params":
            _require(value is None or (type(value) is str and value in CURVE_LABELS),
                     "unexpected metadata curve")
        else:
            _require(value is None or (type(value) is int
                                       and value in METADATA_FIELD_VALUES[name]),
                     "invalid metadata scalar")


def _check_sessions(rows):
    _require(type(rows) is list, "unexpected fields")
    ids = set()
    for row in rows:
        _keys(row, SESSION_ROW_KEYS)
        _require(_u64(row["session"]), "invalid session row")
        _label(row["origin"], SESSION_ORIGINS, "session origin")
        _label(row["status"], SESSION_STATUSES, "session status")
        _require(row["session"] not in ids, "duplicate session row")
        ids.add(row["session"])
    _require(sorted(ids) == [row["session"] for row in rows], "session rows out of order")
    return ids


def _check_objects(rows, sessions):
    _require(type(rows) is list, "unexpected fields")
    ids = set()
    for row in rows:
        _keys(row, OBJECT_ROW_KEYS)
        _require(_u64(row["object"]) and _u64(row["session"]), "invalid object row")
        _label(row["origin"], OBJECT_ORIGINS, "object origin")
        if row["creation"] is not None:
            _label(row["creation"], CREATIONS, "object creation")
        birth = row["birth"]
        if birth is not None:
            _keys(birth, {"start_ns", "end_ns"})
            _require(_u64(birth["start_ns"]) and _u64(birth["end_ns"]), "invalid object birth")
        _label(row["lifetime"], LIFETIMES, "object lifetime")
        if row["lifetime_reason"] is not None:
            _label(row["lifetime_reason"], GAP_REASONS, "lifetime reason")
        _label(row["attribution"], ATTRIBUTIONS, "object attribution")
        if row["attribution_reason"] is not None:
            _label(row["attribution_reason"], GAP_REASONS, "attribution reason")
        _metadata_block(row["requested"])
        _metadata_block(row["established"])
        queries = row["queries"]
        _keys(queries, METADATA_KEYS)
        for name in METADATA_KEYS:
            _label(queries[name], QUERY_STATUSES, "query status")
        if row["label"] is not None:
            _label(row["label"], METADATA_LABELS, "object metadata")
        _require(_u64(row["successful_references"])
                 and _u64(row["successful_key_references"])
                 and _u64(row["accessing_sessions"]), "invalid object counters")
        _require(row["session"] in sessions,
                 f"object {row['object']} references unknown session {row['session']}")
        _require(row["object"] not in ids, "duplicate object row")
        ids.add(row["object"])
    _require(sorted(ids) == [row["object"] for row in rows], "object rows out of order")
    return ids


def _check_key_row(row, objects):
    _keys(row, KEY_ROW_KEYS)
    _require(type(row["instance"]) is str and INSTANCE_RE.fullmatch(row["instance"]) is not None,
             "unexpected instance label")
    _require(_u64(row["object"]), "invalid key row")
    _require(row["object"] in objects, f"key row references unknown object {row['object']}")
    category = _label(row["category"], CATEGORIES, "operation category")
    role = _label(row["role"], ROLES, "operation role")
    metadata = _label(row["metadata_at_use"], METADATA_LABELS, "operation metadata")
    unit = _label(row["unit"], UNITS, "operation unit")
    counters = {name: row[name] for name in
                ("started", "completed", "failed", "cancelled", "unknown", "active",
                 "key_join_lost")}
    _require(all(_u64(value) for value in counters.values()), "invalid key row counters")
    _require(counters["started"] == counters["completed"] + counters["failed"]
             + counters["cancelled"] + counters["unknown"] + counters["active"]
             + counters["key_join_lost"], "key row equation mismatch")
    if all(value == 0 for value in counters.values()):
        return category, counters
    _require(unit == "operations", f"unexpected observed unit {unit}")
    _require(category in CELL_CATEGORIES, f"unexpected observed category {category}")
    _require(role == CELL_ROLE, f"unexpected observed role {role}")
    _require(metadata == CELL_METADATA, f"unexpected key metadata {metadata}")
    return category, counters


def _check_unknown_row(row):
    _keys(row, UNKNOWN_ROW_KEYS)
    category = _label(row["category"], CATEGORIES, "operation category")
    reason = _label(row["reason"], UNKNOWN_REASONS, "unknown-key reason")
    unit = _label(row["unit"], UNITS, "operation unit")
    counters = {name: row[name] for name in
                ("completed", "failed", "cancelled", "unknown", "active")}
    _require(all(_u64(value) for value in counters.values()), "invalid unknown row counters")
    return category, reason, unit, counters


def _check_gaps(gaps):
    _keys(gaps, {"rows", "suppressed"})
    _require(type(gaps["rows"]) is list and _u64(gaps["suppressed"]), "invalid gaps")
    _require(len(gaps["rows"]) <= GAPS_CAPACITY, "too many gap rows")
    seen = set()
    for row in gaps["rows"]:
        _keys(row, GAP_ROW_KEYS)
        subject = _label(row["subject"], GAP_SUBJECTS, "gap subject")
        reason = _label(row["reason"], GAP_REASONS, "gap reason")
        _require(_u64(row["repeats"]), "invalid gap repeats")
        _require((subject, reason) not in seen, "duplicate gap row")
        seen.add((subject, reason))
    ordered = sorted(seen)
    actual = [(row["subject"], row["reason"]) for row in gaps["rows"]]
    _require(ordered == actual, "gap rows out of order")
    return gaps


def _check_budgets(budgets, key_len, object_len, unknown_len):
    _keys(budgets, BUDGET_KEYS)
    for name, length in (("key_rows", key_len), ("object_rows", object_len)):
        block = budgets[name]
        _keys(block, ROW_BUDGET_KEYS)
        _require(block["limit"] == ROW_BUDGET_LIMIT, "unexpected row budget limit")
        _require(_uint(block["occupied"]) and _u64(block["refused"]), "invalid row budget")
        _require(block["occupied"] == length,
                 f"{name} budget occupancy disagrees with rows")
        _require(block["occupied"] <= block["limit"],
                 f"{name} budget occupancy exceeds limit")
        _require(block["refused"] == 0, "budget rows were refused")
    unknown = budgets["unknown_rows"]
    _keys(unknown, UNKNOWN_BUDGET_KEYS)
    _require(_uint(unknown["occupied"]), "invalid row budget")
    # No upper bound: the schema leaves unknown_rows.occupied unbounded
    # (finite by construction, category x reason, capture-wide, with no
    # limit or refusal path); only the cross-check against rows applies.
    _require(unknown["occupied"] == unknown_len,
             "unknown_rows budget occupancy disagrees with rows")
    _require(_uint(budgets["encoded_bytes"]), "invalid budget encoding size")
    _require(budgets["allocation_refused"] is False, "unexpected allocation state")
    _require(budgets["refusal_reason"] == "none", "unexpected budget refusal reason")


def check_section(section):
    """Validate the section shape and return the checked facts."""
    _keys(section, SECTION_KEYS)
    _require(section["version"] == OBSERVATIONS_VERSION
             and type(section["version"]) is int,
             "unsupported observations version")
    _require(_u64(section["revision"]), "invalid observations revision")
    status = _label(section["status"], STATUSES, "status")
    reason = _label(section["reason"], REASONS, "reason")
    _require((reason == "none") == (status == "populated"), "status and reason disagree")
    sessions = _check_sessions(section["sessions"])
    objects = _check_objects(section["objects"], sessions)
    tallies = {}
    order = []
    _require(type(section["key_operations"]) is list, "unexpected fields")
    for row in section["key_operations"]:
        category, counters = _check_key_row(row, objects)
        key = (row["instance"], row["object"], category, row["role"], row["metadata_at_use"])
        _require(key not in tallies, "duplicate key row")
        tallies[key] = (category, counters)
        order.append(key)
    _require(sorted(order) == order, "key rows out of order")
    unknown = []
    _require(type(section["unknown_key_operations"]) is list, "unexpected fields")
    for row in section["unknown_key_operations"]:
        unknown.append(_check_unknown_row(row))
    pairs = [(category, reason) for category, reason, _, _ in unknown]
    _require(len(set(pairs)) == len(pairs), "duplicate unknown row")
    _require(sorted(pairs) == pairs, "unknown rows out of order")
    gaps = _check_gaps(section["gaps"])
    _check_budgets(section["budgets"], len(order), len(objects), len(unknown))
    return {"status": status, "reason": reason, "rows": list(tallies.values()),
            "unknown": unknown, "gaps": gaps}


def _check_mechanism_row(row):
    _keys(row, MECHANISM_ROW_KEYS)
    _require(_u64(row["mechanism"]), "invalid mechanism row")
    _require(type(row["mechanism_hex"]) is str
             and row["mechanism_hex"] == f"0x{row['mechanism']:x}",
             "inconsistent mechanism hex")
    _require(row["name"] is None or type(row["name"]) is str,
             "unexpected mechanism name shape")
    operations = row["operations"]
    _require(type(operations) is list
             and all(type(item) is str and item in CATEGORIES for item in operations),
             "unexpected mechanism operation")
    _require(sorted(operations) == operations
             and len(set(operations)) == len(operations),
             "mechanism operations out of order")
    _require(_u64(row["calls"]) and _u64(row["errors"])
             and _u64(row["last_seen_ns"]), "invalid mechanism counters")
    evidence = row["evidence"]
    _keys(evidence, MECHANISM_EVIDENCE_KEYS)
    functions = evidence["functions"]
    _require(type(functions) is list
             and all(type(item) is str for item in functions),
             "unexpected mechanism function")
    _require(sorted(functions) == functions
             and len(set(functions)) == len(functions),
             "mechanism functions out of order")
    returns = evidence["returns"]
    _require(type(returns) is list, "unexpected mechanism returns")
    seen = set()
    for entry in returns:
        _keys(entry, MECHANISM_RETURN_KEYS)
        _require(_u64(entry["rv"]), "invalid mechanism return")
        _require(type(entry["rv_hex"]) is str
                 and entry["rv_hex"] == f"0x{entry['rv']:x}",
                 "inconsistent return hex")
        _require(entry["name"] is None or type(entry["name"]) is str,
                 "unexpected return name")
        _require(entry["rv"] not in seen, "duplicate mechanism return")
        seen.add(entry["rv"])
    _require(sorted(seen) == [entry["rv"] for entry in returns],
             "mechanism returns out of order")
    _require(type(evidence["truncated"]) is bool, "unexpected mechanism truncation")
    return (row["mechanism"], row["name"], operations, row["calls"],
            evidence["truncated"])


def _check_mechanisms(doc):
    """Check the S1 mechanism dimension when the document carries edges.

    Returns the observed operations of the expected CKM_SHA256_RSA_PKCS
    row, or None when the document has no edges (bare section or
    edge-less envelope: mechanism unknown, judged on the
    object_observations dimension only).
    """
    if "edges" not in doc:
        return None
    edges = doc["edges"]
    _require(type(edges) is list, "unexpected edges shape")
    found = None
    for edge in edges:
        _require(type(edge) is dict, "unexpected edges shape")
        if "mechanisms" not in edge:
            continue
        rows = edge["mechanisms"]
        _require(rows is None or type(rows) is list, "unexpected mechanisms shape")
        if rows is None:
            continue
        ids = []
        for row in rows:
            mechanism, name, operations, calls, truncated = _check_mechanism_row(row)
            ids.append(mechanism)
            if mechanism == CELL_MECHANISM:
                _require(name == CELL_MECHANISM_NAME, "unexpected mechanism name")
                _require(calls > 0, "mechanism without calls")
                _require(truncated is False, "truncated mechanism provenance")
                _require(set(CELL_MECHANISM_OPS) <= set(operations),
                         f"mechanism {CELL_MECHANISM_NAME} missing expected operations")
                if found is None:
                    found = sorted(operations)
            else:
                _require(not (set(operations) & set(CELL_MECHANISM_OPS)),
                         f"inconsistent_mechanism for sign/verify under {mechanism}")
        _require(sorted(ids) == ids and len(set(ids)) == len(ids),
                 "mechanism rows out of order")
    _require(found is not None, f"missing expected mechanism {CELL_MECHANISM_NAME}")
    return found


def _dispatch(doc):
    _require(type(doc) is dict, "unrecognized observer document")
    if "schema" in doc:
        _require(doc["schema"] == INVENTORY_SCHEMA, "unexpected inventory schema")
        section = doc.get("object_observations")
        _require(type(section) is dict, "missing object observations")
        return section
    _require("key_operations" in doc and "status" in doc, "unrecognized observer document")
    return doc


def compare(application_rows, observer_doc):
    """Compare the independent ledger with the observed section.

    Returns {"match": True, "application": ..., "observed": ...} when the
    observed sign/verify units equal the ledger's, else raises OracleRefusal
    naming the finite cause.
    """
    checked = check_section(_dispatch(observer_doc))
    try:
        application = LEDGER.validate_ledger(application_rows)
    except LEDGER.LedgerError as error:
        raise OracleRefusal(f"application ledger refused: {error}") from None
    _require(application["api_calls"] == EXPECTED_API_CALLS
             and application["operations"] == EXPECTED_OPERATIONS
             and all(application["calls_by_function"].get(name) == count
                     for name, count in EXPECTED_CALLS.items()),
             "application workload is not the RSA cell")
    _require(checked["status"] == "populated",
             f"observer status {checked['status']} with reason {checked['reason']}")
    gaps = checked["gaps"]
    if gaps["rows"]:
        first = gaps["rows"][0]
        raise OracleRefusal(f"observation gap {first['subject']}/{first['reason']}"
                            f" repeats {first['repeats']}")
    _require(gaps["suppressed"] == 0, "suppressed observation gaps")
    for category, reason, unit, counters in checked["unknown"]:
        _require(unit == "operations", f"unexpected observed unit {unit}")
        _require(all(value == 0 for value in counters.values()),
                 f"unattributed {category} outcomes under {reason}:"
                 f" completed {counters['completed']} failed {counters['failed']}"
                 f" cancelled {counters['cancelled']} unknown {counters['unknown']}"
                 f" active {counters['active']}")
    mechanism_operations = _check_mechanisms(observer_doc)
    observed = {}
    for category in CELL_CATEGORIES:
        counters = {"started": 0, "completed": 0, "failed": 0, "cancelled": 0, "unknown": 0,
                    "active": 0, "key_join_lost": 0}
        for row_category, row in checked["rows"]:
            if row_category == category:
                for name in counters:
                    counters[name] += row[name]
        _require(counters["cancelled"] == 0 and counters["unknown"] == 0
                 and counters["active"] == 0 and counters["key_join_lost"] == 0,
                 f"observed {category} has unsettled outcomes:"
                 f" cancelled {counters['cancelled']} unknown {counters['unknown']}"
                 f" active {counters['active']} key_join_lost {counters['key_join_lost']}")
        expected = EXPECTED_OPERATIONS[category]
        _require(counters["started"] == EXPECTED_STARTED[category]
                 and counters["completed"] == expected["completed"]
                 and counters["failed"] == expected["failed"],
                 f"observed {category} started/completed/failed"
                 f" {counters['started']}/{counters['completed']}/{counters['failed']}"
                 f" != expected {EXPECTED_STARTED[category]}/"
                 f"{expected['completed']}/{expected['failed']}")
        observed[category] = {"started": counters["started"], "completed": counters["completed"],
                              "failed": counters["failed"]}
    if mechanism_operations is None:
        observed["mechanism"] = None
    else:
        observed["mechanism"] = {"mechanism": CELL_MECHANISM,
                                 "mechanism_hex": CELL_MECHANISM_HEX,
                                 "name": CELL_MECHANISM_NAME,
                                 "operations": mechanism_operations}
    # The ledger pins the header mechanism to CKM_SHA256_RSA_PKCS during
    # validation, so repeating the constant here restates validated input.
    return {"match": True,
            "application": {"api_calls": application["api_calls"],
                            "calls_by_function": application["calls_by_function"],
                            "operations": application["operations"],
                            "mechanism": CELL_MECHANISM_NAME},
            "observed": observed}


def _dispatch_s1(doc):
    _require(type(doc) is dict and doc.get("schema") == INVENTORY_SCHEMA,
             "S1 mode needs the inventory envelope with edges")
    section = doc.get("object_observations")
    _require(type(section) is dict, "missing object observations")
    _require("edges" in doc, "S1 mode needs edges")
    _require(type(doc["edges"]) is list, "unexpected edges shape")
    return section, doc["edges"]


def _check_s1_section(section):
    checked = check_section(section)
    _require(checked["status"] == S1_STATUS,
             f"S1 mode needs unavailable object observations, observed status"
             f" {checked['status']} with reason {checked['reason']}")
    _require(checked["reason"] == S1_REASON,
             f"S1 mode needs reason {S1_REASON}, observed {checked['reason']}")
    gaps = checked["gaps"]
    if gaps["rows"]:
        first = gaps["rows"][0]
        raise OracleRefusal(f"observation gap {first['subject']}/{first['reason']}"
                            f" repeats {first['repeats']}")
    _require(gaps["suppressed"] == 0, "suppressed observation gaps")
    _require(not checked["rows"], "S1 mode needs no key-operation rows")
    _require(not checked["unknown"],
             "S1 mode needs no unknown key-operation rows")
    # Objects always ride with a session row (shape validation refuses a
    # dangling object), so one message covers both lists.
    _require(len(section["sessions"]) == 0 and len(section["objects"]) == 0,
             "S1 mode needs no session rows")


def _s1_application_tallies(application_rows):
    """Derive the call split and per-function results from ledger call rows."""
    categories = {}
    for row in application_rows:
        if row.get("kind") == "operation" and row.get("event") == "begin":
            categories[row["operation"]] = row["category"]
    split = {"sign": 0, "verify": 0, "setup": 0}
    per_function = {name: {} for name in S1_PER_FUNCTION}
    for row in application_rows:
        if row.get("kind") != "call":
            continue
        split[categories.get(row.get("operation", 0), "setup")] += 1
        if row["fn"] in per_function:
            tally = per_function[row["fn"]]
            tally[row["rv"]] = tally.get(row["rv"], 0) + 1
    return split, per_function


def _hex_results(tally):
    return "{" + ", ".join(f"0x{rv:x}: {count}"
                           for rv, count in sorted(tally.items())) + "}"


def _check_s1_application(application_rows, application):
    _require(application["api_calls"] == EXPECTED_API_CALLS
             and application["operations"] == EXPECTED_OPERATIONS
             and all(application["calls_by_function"].get(name) == count
                     for name, count in EXPECTED_CALLS.items()),
             "application workload is not the RSA cell")
    split, per_function = _s1_application_tallies(application_rows)
    _require(split == S1_CALL_SPLIT,
             f"application call split sign/verify/setup"
             f" {split['sign']}/{split['verify']}/{split['setup']}"
             f" != expected 31/24/13")
    for name, expected in S1_PER_FUNCTION.items():
        tally = per_function[name]
        _require(tally == expected,
                 f"application {name} results {_hex_results(tally)}"
                 f" != expected {_hex_results(expected)}")
    return split, per_function


def _check_s1_zero_count_edge(edge):
    """Empty edges must be quiet: allowed mechanism ids, zero counts."""
    rows = edge.get("mechanisms")
    if rows is None:
        rows = []
    _require(type(rows) is list, "unexpected mechanisms shape")
    allowed = {spec["id"] for spec in S1_MECHANISMS}
    for row in rows:
        checked = _check_mechanism_row(row)
        if checked[0] not in allowed:
            raise OracleRefusal(
                f"unexpected S1 mechanism 0x{checked[0]:x}")
        _require(checked[3] == 0,
                 f"S1 zero-count edge carries mechanism calls {checked[3]}"
                 f" != expected 0")
        _require(row["errors"] == 0,
                 f"S1 zero-count edge carries mechanism errors"
                 f" {row['errors']} != expected 0")
    operations = edge.get("operations")
    if operations is None:
        return
    counters, active = _check_s1_operations_row(operations)
    for name, value in counters.items():
        _require(value == 0,
                 f"S1 zero-count edge carries operations {name} {value}"
                 f" != expected 0")
    _require(active == 0,
             f"S1 zero-count edge carries active operations {active}"
             f" != expected 0")


def _check_s1_edge_counts(edges, *, parent_semantics=True):
    """Sum loss-free physical entry counts; legacy also requires parent S1.

    The current topology validates the withheld parent and child separately.

    Zero-count edges contribute nothing but must still be empty: their
    mechanism rows keep the allowed ids with zero calls/errors, and any
    present operations row must be all zero.
    """
    total = 0
    counted = []
    for edge in edges:
        _require(type(edge) is dict, "unexpected S1 edge shape")
        entries = edge.get("entries")
        _require(type(entries) is dict and _u64(entries.get("count")),
                 "unexpected S1 edge shape")
        count = entries["count"]
        total += count
        if count == 0:
            _check_s1_zero_count_edge(edge)
            continue
        coverage = entries.get("coverage")
        _require(type(coverage) is dict, "unexpected S1 coverage shape")
        state = coverage.get("state")
        if state != "counted":
            if type(state) is str and state in COVERAGE_STATES:
                raise OracleRefusal(f"S1 edge with {count} entries reads"
                                    f" {state}, not counted")
            raise OracleRefusal("unexpected S1 coverage state")
        _require(coverage.get("lossy") is False,
                 f"S1 edge with {count} entries is lossy")
        if parent_semantics:
            _require(edge.get("semantics") == "observed",
                     "S1 edge semantics is not observed")
        counted.append(edge)
    _require(total == EXPECTED_API_CALLS,
             f"S1 entries total {total} != expected {EXPECTED_API_CALLS}")
    return total, counted


def _s1_singleton(doc, name):
    rows = doc.get(name)
    _require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
             f"S1 current topology needs exactly one {name} row")
    return rows[0]


def _s1_current_child(doc):
    """Validate the single PID-scoped RSA population without mixing authorities.

    The ledger has no PID or module hash: these are consistent envelope
    references, while the live controller separately binds its actual child
    PID generation and mapped provider. No missing topology may fall back.
    """
    caller = _s1_singleton(doc, "callers")
    module = _s1_singleton(doc, "modules")
    edge = _s1_singleton(doc, "edges")
    instance = _s1_singleton(doc, "instances")
    child = _s1_singleton(doc, "semantic_edges")
    for row, prefix in ((caller, "c"), (module, "m"), (instance, "i")):
        _require(type(row.get("id")) is str
                 and re.fullmatch(prefix + r"[0-9]+", row["id"]) is not None,
                 "invalid S1 current topology identity")
    pid = caller.get("pid")
    _require(_u64(pid) and 0 < pid < 2 ** 32 and doc.get("scope") == f"pid:{pid}"
             and _u64(caller.get("start_time")) and caller.get("retired") is False,
             "S1 caller is not the retained PID scope")
    pair = (caller["id"], module["id"])
    _require(all((row.get("caller"), row.get("module")) == pair
                 for row in (edge, instance, child))
             and child.get("instance") == instance["id"],
             "S1 child does not resolve to the owned caller/module/instance")
    admission = module.get("admission")
    _require(type(admission) is dict and admission.get("state") == "admitted"
             and admission.get("class") == "operator" and admission.get("reasons") == []
             and _u64(admission.get("endpoints")) and admission["endpoints"] > 0,
             "S1 module lacks validated manifest admission")
    mapping = edge.get("mapping")
    _require(type(mapping) is dict and mapping.get("state") == "mapped"
             and _u64(mapping.get("interruptions")) and mapping["interruptions"] == 0,
             "S1 physical mapping is retired or interrupted")
    entries = edge.get("entries")
    _require(type(entries) is dict and entries.get("observation") == "observed"
             and entries.get("in_flight") is False and entries.get("saturated") is False,
             "S1 physical entries are not complete observed counts")
    _require(edge.get("semantics") == "unknown (per-edge summary withheld; see semantic children)"
             and "operations" in edge and edge["operations"] is None
             and "mechanisms" in edge and edge["mechanisms"] is None,
             "S1 current parent is not the exact withheld semantic summary")
    _require(child.get("semantics") == "observed"
             and child.get("entries") == {"unit": "api_entries", "count": None,
                                          "observation": "unavailable"},
             "S1 child lacks observed semantics or invents physical entries")
    returns = child.get("api_returns")
    _require(type(returns) is dict and returns.get("unit") == "api_returns"
             and _u64(returns.get("count")) and returns["count"] == S1_OPERATIONS["calls"]
             and returns.get("saturated") is False
             and _u64(returns.get("historical_only_returns"))
             and returns["historical_only_returns"] == 0,
             "S1 child API returns are not exactly 65 current observations")

    observation = doc.get("observation")
    _require(type(observation) is dict and observation.get("lane") == "native",
             "S1 current capture is not native")
    lifecycle = observation.get("lifecycle")
    _require(type(lifecycle) is dict and all(_u64(lifecycle.get(name)) and lifecycle[name] == 0
             for name in ("ring_loss", "malformed", "failed_quanta")),
             "S1 lifecycle loss is unknown or nonzero")
    capture = observation.get("semantic_capture")
    _require(type(capture) is dict and capture.get("status") == "stopped"
             and capture.get("final_drain") is True and capture.get("stop_quiescence") == "quiesced"
             and _u64(capture.get("admitted_endpoints")) and capture["admitted_endpoints"] > 0
             and all(_u64(capture.get(name)) and capture[name] == 0
                     for name in ("refused_endpoints", "continuity_cuts", "unrouted_returns")),
             "S1 terminal semantic drain or continuity is unproven")
    _require(_u64(doc.get("gaps_suppressed")) and doc["gaps_suppressed"] == 0,
             "S1 suppressed gaps are unknown or nonzero")
    coverage = child.get("coverage")
    _require(type(coverage) is dict, "S1 child coverage missing")
    if coverage.get("lossy") is False and coverage.get("reasons") == []:
        _require(instance.get("state") == "observed" and instance.get("reason") is None,
                 "S1 child has unproven instance authority")
    else:
        _require(coverage.get("lossy") is True
                 and coverage.get("reasons") == ["capture_stopped", "semantic_loss"]
                 and instance.get("state") == "uncertain" and instance.get("reason") == "semantic_loss",
                 "S1 child is not the exact R59 stopped instance disclosure")
    return child


def _check_s1_operations_row(operations):
    _keys(operations, OPERATION_KEYS)
    counters = {name: operations[name] for name in S1_OPERATIONS}
    _require(all(_u64(value) for value in counters.values()),
             "invalid S1 operations counters")
    _require(_u64(operations["last_seen_ns"]), "invalid S1 operations recency")
    active = operations["active"]
    _require(type(active) is list, "unexpected S1 active shape")
    active_total = 0
    for row in active:
        _keys(row, ACTIVE_ROW_KEYS)
        _label(row["category"], CATEGORIES, "S1 active category")
        _require(row["state"] in ACTIVE_STATES, "unexpected S1 active state")
        _require(_u64(row["count"]), "invalid S1 active count")
        active_total += row["count"]
    evidence = operations["evidence"]
    _require(type(evidence) is dict, "unexpected S1 operations evidence")
    for name in OPERATION_EVIDENCE_KEYS:
        value = evidence.get(name)
        _require(_u64(value), f"S1 operations evidence {name} is not a counter")
        _require(value == 0, f"S1 operations evidence {name} is {value}, expected 0")
    _keys(evidence, OPERATION_EVIDENCE_KEYS)
    return counters, active_total


def _check_s1_operations(counted):
    totals = dict.fromkeys(S1_OPERATIONS, 0)
    active_total = 0
    for edge in counted:
        operations = edge.get("operations")
        _require(type(operations) is dict,
                 f"S1 edge with {edge['entries']['count']} entries"
                 f" needs S1 operations")
        counters, active = _check_s1_operations_row(operations)
        for name in totals:
            totals[name] += counters[name]
        active_total += active
    for name in ("cancelled", "unknown", "orphans", "dropped"):
        _require(totals[name] == 0,
                 f"S1 operations {name} {totals[name]} != expected 0")
    for name in ("calls", "started", "completed", "failed"):
        _require(totals[name] == S1_OPERATIONS[name],
                 f"S1 operations {name} {totals[name]}"
                 f" != expected {S1_OPERATIONS[name]}")
    _require(active_total == 0,
             f"S1 operations active {active_total} != expected 0")
    return totals, active_total


def _check_s1_mechanisms(counted):
    wanted = {spec["id"]: spec for spec in S1_MECHANISMS}
    aggregate = {spec["id"]: {"present": False, "calls": 0, "errors": 0,
                              "operations": set(), "functions": set(),
                              "returns": {}}
                 for spec in S1_MECHANISMS}
    for edge in counted:
        rows = edge.get("mechanisms")
        if rows is None:
            rows = []
        _require(type(rows) is list, "unexpected mechanisms shape")
        ids = []
        for row in rows:
            mechanism, name, operations, calls, truncated = _check_mechanism_row(row)
            ids.append(mechanism)
            spec = wanted.get(mechanism)
            if spec is None:
                raise OracleRefusal(f"unexpected S1 mechanism 0x{mechanism:x}")
            _require(name == spec["name"], "unexpected mechanism name")
            _require(set(spec["operations"]) <= set(operations),
                     f"mechanism {spec['name']} missing expected operations")
            _require(set(operations) <= set(spec["operations"]),
                     f"mechanism {spec['name']} has unexpected operations")
            _require(truncated is False, "truncated mechanism provenance")
            seen = aggregate[mechanism]
            seen["present"] = True
            seen["calls"] += calls
            seen["errors"] += row["errors"]
            seen["operations"] |= set(operations)
            seen["functions"] |= set(row["evidence"]["functions"])
            for entry in row["evidence"]["returns"]:
                seen["returns"].setdefault(entry["rv"], set()).add(entry["name"])
        _require(sorted(ids) == ids and len(set(ids)) == len(ids),
                 "mechanism rows out of order")
    observed = []
    for spec in S1_MECHANISMS:
        seen = aggregate[spec["id"]]
        _require(seen["present"], f"missing expected mechanism {spec['name']}")
        _require(seen["calls"] == spec["calls"] and seen["errors"] == spec["errors"],
                 f"S1 mechanism {spec['name']} calls/errors"
                 f" {seen['calls']}/{seen['errors']}"
                 f" != expected {spec['calls']}/{spec['errors']}")
        extra = seen["functions"] - set(spec["functions"])
        _require(not extra,
                 f"S1 mechanism {spec['name']} has {len(extra)}"
                 f" unexpected S1 functions")
        missing = set(spec["functions"]) - seen["functions"]
        _require(not missing,
                 f"S1 mechanism {spec['name']} misses expected functions"
                 f" {sorted(missing)}")
        seen_rv = set(seen["returns"])
        for rv in sorted(seen_rv - set(spec["returns"])):
            raise OracleRefusal(f"S1 mechanism {spec['name']}"
                                f" has unexpected S1 return 0x{rv:x}")
        missing_rv = set(spec["returns"]) - seen_rv
        _require(not missing_rv,
                 f"S1 mechanism {spec['name']} misses expected returns"
                 f" {sorted(f'0x{rv:x}' for rv in missing_rv)}")
        for rv, name in spec["returns"].items():
            _require(seen["returns"][rv] == {name},
                     f"S1 return 0x{rv:x} has unexpected name")
        observed.append({"mechanism": spec["id"],
                         "mechanism_hex": f"0x{spec['id']:x}",
                         "name": spec["name"],
                         "operations": sorted(seen["operations"]),
                         "calls": seen["calls"], "errors": seen["errors"]})
    return observed


def compare_s1(application_rows, observer_doc):
    """Compare the fixed RSA ledger with physical counts and owned S1 facts.

    Returns {"match": True, "mode": "s1", "application": ..., "observed": ...}
    when the ledger's per-function results and call split equal the RSA cell
    and the counted edges carry 68 entries, the expected operation aggregates
    and the expected mechanism rows, with object_observations unavailable;
    else raises OracleRefusal naming the finite cause.
    """
    section, edges = _dispatch_s1(observer_doc)
    _check_s1_section(section)
    try:
        application = LEDGER.validate_ledger(application_rows)
    except LEDGER.LedgerError as error:
        raise OracleRefusal(f"application ledger refused: {error}") from None
    split, per_function = _check_s1_application(application_rows, application)
    current = "instances" in observer_doc or "semantic_edges" in observer_doc
    child = _s1_current_child(observer_doc) if current else None
    total, counted = _check_s1_edge_counts(edges, parent_semantics=not current)
    if child is not None:
        counted = [child]
    totals, active_total = _check_s1_operations(counted)
    observed_mechanisms = _check_s1_mechanisms(counted)
    result = {"match": True, "mode": "s1",
            "application": {"api_calls": application["api_calls"],
                            "calls_by_function": application["calls_by_function"],
                            "operations": application["operations"],
                            "call_split": split,
                            "per_function": {name: {f"0x{rv:x}": count
                                                   for rv, count in sorted(tally.items())}
                                             for name, tally in per_function.items()},
                            "mechanism": CELL_MECHANISM_NAME},
            "observed": {"entries": total,
                         "operations": {**totals, "active": active_total},
                         "mechanisms": observed_mechanisms}}
    if child is not None:
        result["observed"]["semantic_source"] = {
            "caller": child["caller"], "module": child["module"], "instance": child["instance"],
            "api_returns": child["api_returns"]["count"],
            "coverage": {"lossy": child["coverage"]["lossy"],
                         "reasons": list(child["coverage"]["reasons"])}}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s1", action="store_true",
                        help="S1 mode: check physical entries and owned instance facts"
                        " with object_observations unavailable"
                        " (no key-operation feed)")
    parser.add_argument("application", help="application JSONL file")
    parser.add_argument("observer", help="observer inventory JSON file")
    args = parser.parse_args(argv)
    try:
        with open(args.application, encoding="utf-8") as stream:
            rows = LEDGER.read_ledger(stream)
        observer = read_observer_file(args.observer)
        result = compare_s1(rows, observer) if args.s1 else compare(rows, observer)
    except (OracleRefusal, LEDGER.LedgerError, OSError, UnicodeError) as error:
        if isinstance(error, (OracleRefusal, LEDGER.LedgerError)):
            print(error, file=sys.stderr)
        else:
            print("cannot read oracle input", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
