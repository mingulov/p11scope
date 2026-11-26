#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge the PQC CI cell (scripts/ci/pqc-cell.sh).

Both legs run the same workload (ML-DSA-44/65/87 + ML-KEM-512/768/1024,
each generated once and used once) under `inventory --pid
--key-operations`, once with `--key-sizes` and once without. This judge
requires, per leg: the workload's exact known counts and FIPS lengths;
section version 10 with the four PQC mechanism rows and exact call
counts; the exact (operation, parameter set) matrix — one completed
row per expected pair, zero unexpected pairs — with each row's
metadata label, inferred family and (sizes leg) inferred parameter
set naming its pair; each row's exact role (sign/verify use `key`,
encapsulate uses `encapsulation_key`, decapsulate uses
`decapsulation_key`) and its binding to the object row of the key it
used (sign on the private half, verify on the public half,
encapsulate on the public half, decapsulate on the private half, with
matching established class, key type, parameter set and label, and
both halves of each pair sharing one generate_pair birth); the exact
frozen row shapes (no missing or extra keys on key, object or unknown
rows); six generate_key_pair completions and no other unknown row,
with the keygen mechanism ids (28x3, 15x3) in first-seen order on
that row; and the verbose text showing one row per matrix tuple
(instance, object, operation, set), each with its own role, family
display and (sizes leg) length set or (nosizes leg) size-unknown
hint, plus the `pqc keys:` spotlight with all twelve
parameter-set/operation segments. Anything missing fails: no skip
counts as a pass.

Scope: exactly ML-DSA-44/65/87 and ML-KEM-512/768/1024.
SLH-DSA is not exercised by this cell; SLH-DSA inference stays
pinned by unit tests only.

Loss disclosure, not loss refusal: the workload's setup calls
(Initialize, sessions, login) legitimately precede the semantic
receipt under deferred admission, and the exact PQC mechanism
and row counts prove every PQC operation was observed instead (a
missed PQC op breaks counts first). Disclosed loss does not fail
the leg; the result row reports qualification "partial" with the
typed reason instead of "qualified". Qualified requires a typed
proof of absence on every read channel: a populated section with
reason none; no section gap rows and exactly zero suppressed
section gaps; zero refused section row budgets; no unattributed
counter rows; no lost or malformed session rows (a lost session
ended with a model gap); no top-level gap rows except the
producer's explicit "attribution complete" completeness note, and
exactly zero suppressed top-level gaps; zero refused or
loss-bearing top-level budget counters; and benign coverage on
every semantic edge — a clean edge, a fresh no-call edge, or
exactly the setup-only pre-boundary shape (lossy with only
`before_semantic_boundary`, the real producer shape for setup
loss). Any other shape — loss, contradiction, or missing or
malformed disclosure — is partial. Census, limit, occupancy,
exact-retention aggregation and classification keys are
measurements, not loss disclosures, and gate nothing;
observation, clock, instance, physical-edge, caller and module
detail are outside this cell's qualification contract.

Usage:
  pqc_cell_compare.py --sizes-log F --sizes-exit N --sizes-inventory F
      --sizes-text F --nosizes-log F --nosizes-exit N --nosizes-inventory F
      --nosizes-text F --out-results F --out-summary F
"""

import json
import re
import sys
from pathlib import Path

WANT_TRUTH = ("GROUND_TRUTH mldsa_gen=3 mldsa_sign=3 mldsa_verify=3 "
              "mlkem_gen=3 mlkem_enc=3 mlkem_dec=3")
WANT_LENGTHS = ("LENGTHS mldsa44=2420 mldsa65=3309 mldsa87=4627 "
                "mlkem512=768 mlkem768=1088 mlkem1024=1568")

# mechanism id -> (display name, exact calls)
WANT_MECHS = {
    15: ("CKM_ML_KEM_KEY_PAIR_GEN", 3),
    23: ("CKM_ML_KEM", 6),
    28: ("CKM_ML_DSA_KEY_PAIR_GEN", 3),
    29: ("CKM_ML_DSA", 12),
}

PQC_OPS = {"sign", "verify", "encapsulate", "decapsulate"}
# The exact expected matrix: one completed row per (operation,
# parameter set) pair. Totals per operation plus the union of
# labels are not enough: a relabeled row keeps every total and
# every union while voiding a required pair.
OP_LABELS = {"sign": ("ml_dsa_44", "ml_dsa_65", "ml_dsa_87"),
             "verify": ("ml_dsa_44", "ml_dsa_65", "ml_dsa_87"),
             "encapsulate": ("ml_kem_512", "ml_kem_768", "ml_kem_1024"),
             "decapsulate": ("ml_kem_512", "ml_kem_768",
                             "ml_kem_1024")}
WANT_PAIRS = frozenset((op, label)
                       for op, labels in OP_LABELS.items()
                       for label in labels)
LABEL_FAMILY = {
    "ml_kem_512": "ml_kem", "ml_kem_768": "ml_kem", "ml_kem_1024": "ml_kem",
    "ml_dsa_44": "ml_dsa", "ml_dsa_65": "ml_dsa", "ml_dsa_87": "ml_dsa",
}
LABEL_OCTETS = {
    "ml_kem_512": 768, "ml_kem_768": 1088, "ml_kem_1024": 1568,
    "ml_dsa_44": 2420, "ml_dsa_65": 3309, "ml_dsa_87": 4627,
}
OP_EVIDENCE = {
    "sign": "sign_output", "verify": "verify_input",
    "encapsulate": "encapsulate_output", "decapsulate": "decapsulate_input",
}
FAMILY_DISPLAY = {"ml_kem": "ML-KEM", "ml_dsa": "ML-DSA"}

# Attribution: the exact role each operation carries, and the
# established class of the object it must join (2 public, 3 private).
OP_ROLE = {"sign": "key", "verify": "key",
           "encapsulate": "encapsulation_key",
           "decapsulate": "decapsulation_key"}
OP_CLASS = {"sign": 3, "verify": 2, "encapsulate": 2, "decapsulate": 3}
# Established key type (CKK_ML_KEM 73, CKK_ML_DSA 74) and parameter-set
# code (1/2/3 within each family) behind each label.
LABEL_KEY_TYPE = {"ml_kem_512": 73, "ml_kem_768": 73, "ml_kem_1024": 73,
                  "ml_dsa_44": 74, "ml_dsa_65": 74, "ml_dsa_87": 74}
LABEL_PARAM_CODE = {"ml_dsa_44": 1, "ml_dsa_65": 2, "ml_dsa_87": 3,
                    "ml_kem_512": 1, "ml_kem_768": 2, "ml_kem_1024": 3}
# Frozen row shapes (exact key equality against the producer schema).
KEY_ROW_KEYS = frozenset({"instance", "object", "category", "role",
                          "metadata_at_use", "unit", "started",
                          "completed", "failed", "cancelled", "unknown",
                          "active", "key_join_lost", "inferred_family",
                          "inferred_size"})
OBJECT_ROW_KEYS = frozenset({"object", "session", "origin", "creation",
                             "birth", "lifetime", "lifetime_reason",
                             "attribution", "attribution_reason",
                             "requested", "established", "queries",
                             "label", "successful_references",
                             "successful_key_references",
                             "accessing_sessions"})
UNKNOWN_ROW_KEYS = frozenset({"category", "reason", "unit", "completed",
                              "failed", "cancelled", "unknown", "active",
                              "mechanisms"})
# The unknown keygen row's mechanism ids in first-seen order: the
# workload runs the three DSA keygens before the three KEM keygens.
WANT_UNKNOWN_MECHS = [{"id": 28, "count": 3}, {"id": 15, "count": 3}]
# Twelve PQC keys (six pairs) plus the six KEM shared secrets.
WANT_OBJECTS = 18
WANT_PQC_OBJECTS = 12
INSTANCE_RE = re.compile(r"^i[0-9]+$")
TEXT_ROW_RE = re.compile(
    r"^  key row (i[0-9]+) object ([0-9]+) ([A-Za-z_]+) ([A-Za-z_]+) "
    r"\(([A-Za-z0-9_]+)\): (.*)$")
SPOTLIGHT_ORDER = (("ML-DSA-44", "sign"), ("ML-DSA-44", "verify"),
                   ("ML-DSA-65", "sign"), ("ML-DSA-65", "verify"),
                   ("ML-DSA-87", "sign"), ("ML-DSA-87", "verify"),
                   ("ML-KEM-512", "decapsulate"),
                   ("ML-KEM-512", "encapsulate"),
                   ("ML-KEM-768", "decapsulate"),
                   ("ML-KEM-768", "encapsulate"),
                   ("ML-KEM-1024", "decapsulate"),
                   ("ML-KEM-1024", "encapsulate"))


class Failures:
    def __init__(self):
        self.problems = []

    def add(self, leg, message):
        self.problems.append(f"{leg}: {message}")

    def ok(self):
        return not self.problems


def check_truth(fail, leg, log_path, exit_code):
    text = Path(log_path).read_text(encoding="utf-8")
    if exit_code != 0:
        fail.add(leg, f"workload exit={exit_code}, want 0")
    if WANT_TRUTH not in text.splitlines():
        fail.add(leg, "ground-truth line missing or wrong")
    if WANT_LENGTHS not in text.splitlines():
        fail.add(leg, "lengths line missing or wrong")
    if "WORKLOAD_EXIT ok=1" not in text.splitlines():
        fail.add(leg, "WORKLOAD_EXIT ok=1 missing")


def load_inventory(fail, leg, json_path, exit_code):
    if exit_code != 0:
        fail.add(leg, f"inventory exit={exit_code}, want 0")
    try:
        return json.loads(Path(json_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail.add(leg, f"inventory.json unreadable: {exc}")
        return None


def check_mechanisms(fail, leg, inv):
    edges = inv.get("semantic_edges", [])
    if not edges:
        fail.add(leg, "no semantic_edges")
        return
    mechs = {}
    for edge in edges:
        for row in edge.get("mechanisms", []):
            mid = row.get("mechanism")
            if mid in mechs:
                fail.add(leg, f"mechanism {mid} listed twice")
            mechs[mid] = row
    if len(mechs) != len(WANT_MECHS):
        fail.add(leg, f"{len(mechs)} mechanism rows, "
                      f"want {len(WANT_MECHS)}")
    for mid, (name, calls) in WANT_MECHS.items():
        row = mechs.get(mid)
        if row is None:
            fail.add(leg, f"mechanism {mid} ({name}) missing")
            continue
        if row.get("name") != name:
            fail.add(leg, f"mechanism {mid} name {row.get('name')!r}, want {name!r}")
        if row.get("calls") != calls:
            fail.add(leg, f"mechanism {mid} calls={row.get('calls')}, want {calls}")
    for mid, row in sorted(mechs.items(), key=lambda kv: str(kv[0])):
        if row.get("errors") != 0:
            fail.add(leg, f"mechanism {mid} errors={row.get('errors')}, want 0")


def check_section_version(fail, leg, inv):
    oo = inv.get("object_observations", {})
    version = oo.get("version")
    if version != 10:
        fail.add(leg, f"object_observations version={version!r}, want 10")


def check_key_rows(fail, leg, inv, sizes):
    oo = inv.get("object_observations", {})
    rows = oo.get("key_operations", [])
    if len(rows) != 12:
        fail.add(leg, f"{len(rows)} key rows, want 12")
    pairs = []
    instances = set()
    for row in rows:
        keys = set(row) if isinstance(row, dict) else set()
        missing = KEY_ROW_KEYS - keys
        extra = keys - KEY_ROW_KEYS
        where = (f"{leg} row {row.get('instance')}/{row.get('object')}/"
                 f"{row.get('category')}" if isinstance(row, dict)
                 else f"{leg} row <malformed>")
        if missing:
            fail.add(leg, f"{where} keys missing {sorted(missing)}, "
                          "want the fifteen frozen keys")
        if extra:
            fail.add(leg, f"{where} keys extra {sorted(extra)}, "
                          "want the fifteen frozen keys")
        if not isinstance(row, dict):
            continue
        category = row.get("category")
        if category not in PQC_OPS:
            fail.add(leg, f"{where} category {category!r}, "
                          "want a PQC operation")
            continue
        want_role = OP_ROLE[category]
        if row.get("role") != want_role:
            fail.add(leg, f"{where} role {row.get('role')!r}, "
                          f"want {want_role!r}")
        actual_counters = (row.get("unit"), row.get("started"),
                           row.get("completed"), row.get("failed"),
                           row.get("cancelled"), row.get("unknown"),
                           row.get("active"), row.get("key_join_lost"))
        want_counters = ("operations", 1, 1, 0, 0, 0, 0, 0)
        if actual_counters != want_counters:
            fail.add(leg, f"{where} unit={row.get('unit')!r} "
                          f"started={row.get('started')!r} "
                          f"completed={row.get('completed')!r} "
                          f"failed={row.get('failed')!r} "
                          f"cancelled={row.get('cancelled')!r} "
                          f"unknown={row.get('unknown')!r} "
                          f"active={row.get('active')!r} "
                          f"key_join_lost={row.get('key_join_lost')!r}, "
                          "want unit='operations' started=1 completed=1 "
                          "failed=0 cancelled=0 unknown=0 active=0 "
                          "key_join_lost=0")
        instance = row.get("instance")
        if not isinstance(instance, str) or not INSTANCE_RE.match(instance):
            fail.add(leg, f"{where} instance {instance!r}, "
                          "want iN like 'i0'")
        else:
            instances.add(instance)
        label = row.get("metadata_at_use")
        if label not in LABEL_FAMILY:
            fail.add(leg, f"{where} metadata_at_use={label!r}, want a PQC set")
            continue
        pairs.append((category, label))
        want_family = {"status": "inferred",
                       "value": LABEL_FAMILY[label], "completions": 1}
        if row.get("inferred_family") != want_family:
            fail.add(leg, f"{where} family={row.get('inferred_family')!r}, "
                          f"want inferred {LABEL_FAMILY[label]}")
        if sizes:
            want_size = {
                "status": "inferred", "completions": 1,
                "detail": {"kind": "pqc_set", "parameter_set": label,
                           "octets": LABEL_OCTETS[label],
                           "evidence": OP_EVIDENCE[category]}}
            if row.get("inferred_size") != want_size:
                fail.add(leg, f"{where} size={row.get('inferred_size')!r}, "
                              f"want inferred {label}")
        elif row.get("inferred_size") != {"status": "unknown",
                                          "detail": None,
                                          "completions": 0}:
            fail.add(leg, f"{where} size={row.get('inferred_size')!r}, "
                          "want unknown without detail")
    if len(instances) > 1:
        fail.add(leg, f"instances {sorted(instances)}, "
                      "want one shared instance")
    missing = sorted(WANT_PAIRS - set(pairs))
    unexpected = sorted(set(pairs) - WANT_PAIRS)
    duplicated = sorted({pair for pair in pairs if pairs.count(pair) > 1})
    if missing:
        fail.add(leg, f"matrix pairs missing {missing}, "
                      "want all twelve (operation, set) pairs exactly once")
    if unexpected:
        fail.add(leg, f"matrix pairs unexpected {unexpected}, "
                      "want only the twelve (operation, set) pairs")
    if duplicated:
        fail.add(leg, f"matrix pairs duplicated {duplicated}, "
                      "want one completed row per pair")


def check_object_binding(fail, leg, inv):
    oo = inv.get("object_observations", {})
    objects = oo.get("objects", [])
    if len(objects) != WANT_OBJECTS:
        fail.add(leg, f"{len(objects)} objects, want {WANT_OBJECTS}")
    index = {}
    for entry in objects:
        keys = set(entry) if isinstance(entry, dict) else set()
        oid = entry.get("object") if isinstance(entry, dict) else None
        missing = OBJECT_ROW_KEYS - keys
        extra = keys - OBJECT_ROW_KEYS
        if missing:
            fail.add(leg, f"{leg} object {oid}: keys missing "
                          f"{sorted(missing)}, "
                          "want the sixteen frozen keys")
        if extra:
            fail.add(leg, f"{leg} object {oid}: keys extra "
                          f"{sorted(extra)}, "
                          "want the sixteen frozen keys")
        if not isinstance(entry, dict) or not isinstance(oid, int):
            continue
        if oid in index:
            fail.add(leg, f"object {oid} listed twice")
        else:
            index[oid] = entry
    pqc = [entry for entry in index.values()
           if entry.get("label") in LABEL_FAMILY]
    by_label = {}
    for entry in pqc:
        by_label.setdefault(entry.get("label"), []).append(entry)
    births = {}
    for label in sorted(LABEL_FAMILY):
        group = by_label.get(label, [])
        if len(group) != 2:
            fail.add(leg, f"{leg} label {label}: {len(group)} objects, "
                          "want 2")
            continue
        classes = sorted(entry.get("established", {}).get("class", {})
                         .get("value") for entry in group)
        if classes != [2, 3]:
            fail.add(leg, f"{leg} label {label}: pair classes {classes}, "
                          "want [2, 3]")
        pair_births = [entry.get("birth") for entry in group]
        if (any(not isinstance(birth, dict)
                   or not isinstance(birth.get("start_ns"), int)
                   or not isinstance(birth.get("end_ns"), int)
                   for birth in pair_births)
                or pair_births[0] != pair_births[1]):
            fail.add(leg, f"{leg} label {label}: pair births differ")
        else:
            key = (pair_births[0]["start_ns"], pair_births[0]["end_ns"])
            if key in births:
                fail.add(leg, f"{leg}: labels {births[key]} and {label} "
                              "share one birth")
            else:
                births[key] = label
    for entry in pqc:
        actual = (entry.get("creation"), entry.get("origin"),
                  entry.get("attribution"))
        if actual != ("generate_pair", "created", "valid"):
            fail.add(leg, f"{leg} object {entry.get('object')}: provenance "
                          f"(creation, origin, attribution) = {actual}, "
                          "want ('generate_pair', 'created', 'valid')")
    others = [entry for entry in index.values()
              if entry.get("label") not in LABEL_FAMILY]
    if len(others) != WANT_OBJECTS - WANT_PQC_OBJECTS:
        fail.add(leg, f"{leg}: {len(others)} non-PQC objects, "
                      "want the six generic_256 secrets")
    for entry in sorted(others, key=lambda item: str(item.get("object"))):
        if entry.get("label") != "generic_256":
            fail.add(leg, f"{leg}: secret object {entry.get('object')} "
                          f"label {entry.get('label')!r}, "
                          "want 'generic_256'")
    for row in oo.get("key_operations", []):
        if not isinstance(row, dict):
            continue
        category = row.get("category")
        if category not in PQC_OPS:
            continue
        where = (f"{leg} row {row.get('instance')}/{row.get('object')}/"
                 f"{category}")
        label = row.get("metadata_at_use")
        if label not in LABEL_FAMILY:
            continue
        entry = index.get(row.get("object"))
        if entry is None:
            fail.add(leg, f"{where} joins no object row")
            continue
        if entry.get("label") != label:
            fail.add(leg, f"{where} object label {entry.get('label')!r}, "
                          f"want {label!r}")
        established = entry.get("established", {})
        if not isinstance(established, dict):
            established = {}
        want_class = {"status": "value", "value": OP_CLASS[category],
                      "source": "creation_success", "reason": None}
        if established.get("class") != want_class:
            fail.add(leg, f"{where} object class="
                          f"{established.get('class')!r}, "
                          f"want value {OP_CLASS[category]} "
                          "from creation_success")
        want_key_type = {"status": "value",
                         "value": LABEL_KEY_TYPE[label],
                         "source": "creation_success", "reason": None}
        if established.get("key_type") != want_key_type:
            fail.add(leg, f"{where} object key_type="
                          f"{established.get('key_type')!r}, "
                          f"want value {LABEL_KEY_TYPE[label]} "
                          "from creation_success")
        want_param = {"status": "value",
                      "value": LABEL_PARAM_CODE[label],
                      "source": "creation_success", "reason": None}
        if established.get("parameter_set") != want_param:
            fail.add(leg, f"{where} object parameter_set="
                          f"{established.get('parameter_set')!r}, "
                          f"want value {LABEL_PARAM_CODE[label]} "
                          "from creation_success")


def check_unknown_rows(fail, leg, inv):
    oo = inv.get("object_observations", {})
    unknown = oo.get("unknown_key_operations", [])
    if len(unknown) != 1:
        fail.add(leg, f"{len(unknown)} unknown rows, want exactly the keygen row")
        return
    row = unknown[0]
    keys = set(row) if isinstance(row, dict) else set()
    missing = UNKNOWN_ROW_KEYS - keys
    extra = keys - (UNKNOWN_ROW_KEYS | {"further_mechanism_terminals"})
    if missing:
        fail.add(leg, f"{leg} unknown row keys missing {sorted(missing)}, "
                      "want the nine frozen keys")
    if extra:
        fail.add(leg, f"{leg} unknown row keys extra {sorted(extra)}, "
                      "want the nine frozen keys")
    if not isinstance(row, dict):
        return
    actual = (row.get("category"), row.get("reason"), row.get("unit"),
              row.get("completed"), row.get("failed"),
              row.get("cancelled"), row.get("unknown"), row.get("active"))
    want = ("generate_key_pair", "not_applicable", "operations",
            6, 0, 0, 0, 0)
    if actual != want:
        fail.add(leg, f"{leg} unknown row scalars {actual}, want {want}")
    if row.get("mechanisms") != WANT_UNKNOWN_MECHS:
        fail.add(leg, f"{leg} unknown row mechanisms="
                      f"{row.get('mechanisms')!r}, "
                      "want [(28, 3), (15, 3)] in first-seen order")
    if row.get("further_mechanism_terminals", 0) != 0:
        fail.add(leg, f"{leg} unknown row further_mechanism_terminals="
                      f"{row.get('further_mechanism_terminals')!r}, want 0")


OP_LENGTH_NOUN = {"sign": "signature", "verify": "signature",
                "encapsulate": "ciphertext", "decapsulate": "ciphertext"}


def check_text(fail, leg, text_path, sizes, inv):
    lines = Path(text_path).read_text(encoding="utf-8").splitlines()
    oo = inv.get("object_observations", {})
    want_tuples = set()
    for row in oo.get("key_operations", []):
        if not isinstance(row, dict):
            continue
        if row.get("category") not in PQC_OPS:
            continue
        if row.get("metadata_at_use") not in LABEL_FAMILY:
            continue
        want_tuples.add((row.get("instance"), row.get("object"),
                         row.get("category"), row.get("metadata_at_use")))
    key_rows = [ln for ln in lines if ln.startswith("  key row ")]
    if len(key_rows) != 12:
        fail.add(leg, f"text has {len(key_rows)} key rows, want 12")
    seen = []
    for ln in key_rows:
        match = TEXT_ROW_RE.match(ln)
        if match is None:
            fail.add(leg, f"text row malformed: {ln[:120]}")
            continue
        instance, number, op, role, label, _rest = match.groups()
        seen.append((instance, int(number), op, label))
        want_role = OP_ROLE.get(op)
        if want_role is not None and role != want_role:
            fail.add(leg, f"text row lacks the {op} role: {ln[:120]}")
        if label not in LABEL_FAMILY:
            continue
        want_family = FAMILY_DISPLAY[LABEL_FAMILY[label]]
        if f"probably {want_family} (from mechanism)" not in ln:
            fail.add(leg, f"text row lacks the {label} family: {ln[:120]}")
        if sizes:
            if op in OP_LENGTH_NOUN and \
                    f"(from {OP_LENGTH_NOUN[op]} length)" not in ln:
                fail.add(leg, f"text row lacks the {op} length set: "
                              f"{ln[:120]}")
        elif "size unknown (needs --key-sizes)" not in ln:
            fail.add(leg, f"text row lacks the size unknown hint "
                          f"(needs --key-sizes): {ln[:120]}")
    missing = sorted(want_tuples - set(seen))
    unexpected = sorted(set(seen) - want_tuples)
    if missing:
        fail.add(leg, f"text pairs missing {missing}, want one verbose "
                      "row per (instance, object, operation, set) tuple")
    if unexpected:
        fail.add(leg, f"text pairs unexpected {unexpected}, want one "
                      "verbose row per (instance, object, operation, set) "
                      "tuple")
    spot = [ln for ln in lines if ln.startswith("  pqc keys: ")]
    if len(spot) != 1:
        fail.add(leg, f"{len(spot)} spotlight (`pqc keys:`) lines, want 1")
    else:
        # The exact twelve tally segments (each pair completed once,
        # clean): presence is the proof, order stays unpinned. Each
        # segment itself contains ", ", so extras are whatever remains
        # after removing each expected segment once.
        want_segments = [f"{display} {op}: 1 completed, "
                         "0 returned errors, 0 active"
                         for display, op in SPOTLIGHT_ORDER]
        body = spot[0][len("  pqc keys: "):]
        missing_segments = [segment for segment in want_segments
                            if segment not in body]
        rest = body
        for segment in want_segments:
            rest = rest.replace(segment, "", 1)
        if missing_segments:
            fail.add(leg, f"spotlight lacks {missing_segments}")
        if rest.replace(", ", "").strip():
            fail.add(leg, f"spotlight has extra {rest.strip()!r}")


# Coverage reasons that describe expected setup (pre-admission
# workload calls). The producer selects BeforeSemanticBoundary
# as a historical reduction and sets lossy with it
# (src/discovery/caller_registry/instance_input.rs:3664-3668),
# so the benign shape is lossy with exactly this reason set.
BENIGN_COVERAGE_REASONS = frozenset({"before_semantic_boundary"})
# Fresh edges that observed zero calls carry exactly this reason
# with lossy false (instance_input.rs:3574,3664): no calls and
# no loss, so likewise benign.
NO_CALL_REASONS = frozenset({"no_calls"})
# The producer's refused/loss-bearing top-level budget counters:
# (block, counter) pairs that must be exactly zero for a run to
# qualify (src/inventory/mod.rs:10830-10977). Census, limit,
# occupancy, exact-retention aggregation (retired/folded rows,
# pair_dropped bases) and classification (unknown-edge counts,
# semantic status) keys are measurements, not loss disclosures,
# and gate nothing.
TOP_BUDGET_ZERO_INTS = (
    ("callers", "refused"),
    ("callers", "late_refused"),
    ("modules", "refused"),
    ("edges", "refused"),
    ("endpoints", "refused"),
    ("inventory_endpoints", "refused"),
    ("inventory_attach_modules", "refused"),
    ("counters", "saturated_edges"),
    ("semantic_state", "refused"),
    ("instances", "refused"),
    ("instance_semantic_state", "refused"),
    ("instance_negative_state", "refused"),
    ("instance_semantic_resources", "refused"),
    ("retained_history", "suppressed"),
    ("departed_use", "identities_dropped"),
    ("departed_use", "mech_overflow"),
    ("native_departed", "pair_prune_overflow"),
    ("native_departed", "exec_prune_overflow"),
    ("native_preadmission", "refused"),
    ("native_preadmission", "pruned"),
)


def _is_completeness_note(row):
    """Whether a top-level gap row is the producer's explicit
    completeness note (subject "discovery capped" with an
    "attribution complete: ..." reason from its single emitter
    at src/inspect_system.rs:3090-3099, documented as a note,
    not a loss): the one row shape that does not void
    qualification."""
    return (isinstance(row, dict)
            and row.get("subject") == "discovery capped"
            and isinstance(row.get("reason"), str)
            and row.get("reason").startswith("attribution complete"))


def leg_qualification(inv):
    """Derive a leg's (qualification, reason) from loss disclosure.

    "qualified" requires a typed proof of absence on every read
    channel (the module docstring lists them): populated status
    with reason none, empty section gaps with exactly zero
    suppressed, zero refused section row budgets, empty
    unattributed, no lost or malformed sessions, no non-note
    top-level gaps with exactly zero suppressed, zero refused
    top-level budget counters, and benign coverage on every
    edge. Anything else — loss, contradiction, or missing/
    malformed disclosure — is "partial" with the typed reason.
    Never raises: this runs on the same inventories the checks
    just judged, malformed or not.
    """
    if inv is None:
        return ("partial", "inventory_unreadable")
    if not isinstance(inv, dict):
        return ("partial", "inventory_malformed")
    oo = inv.get("object_observations")
    if not isinstance(oo, dict):
        return ("partial", "section_malformed")
    status = oo.get("status")
    reason = oo.get("reason")
    if status != "populated":
        return ("partial", f"status/{status}/{reason}")
    if reason != "none":
        # REASON_LABELS: "none" only when populated.
        return ("partial", f"status/populated/{reason}")
    gaps = oo.get("gaps")
    if not isinstance(gaps, dict):
        return ("partial", "gaps_malformed")
    rows = gaps.get("rows")
    if not isinstance(rows, list):
        return ("partial", "gaps_malformed")
    for gap in sorted(rows, key=str):
        gap_reason = gap.get("reason") if isinstance(gap, dict) else None
        if not isinstance(gap_reason, str) or not gap_reason:
            return ("partial", "gap/malformed")
        return ("partial", f"gap/{gap_reason}")
    suppressed = gaps.get("suppressed")
    if type(suppressed) is not int:
        return ("partial", "gaps_malformed")
    if suppressed != 0:
        return ("partial", "gap/suppressed")
    budgets = oo.get("budgets")
    if not isinstance(budgets, dict):
        return ("partial", "budgets_malformed")
    for name in ("key_rows", "object_rows"):
        block = budgets.get(name)
        if not isinstance(block, dict):
            return ("partial", f"budget/{name}_malformed")
        refused = block.get("refused")
        if type(refused) is not int:
            return ("partial", f"budget/{name}_malformed")
        if refused != 0:
            return ("partial", f"budget/{name}_refused")
    unattributed = oo.get("unattributed")
    if not isinstance(unattributed, list):
        return ("partial", "unattributed_malformed")
    for row in sorted(unattributed, key=str):
        row_reason = row.get("reason") if isinstance(row, dict) else None
        if not isinstance(row_reason, str) or not row_reason:
            return ("partial", "unattributed_malformed")
        return ("partial", f"unattributed/{row_reason}")
    sessions = oo.get("sessions")
    if not isinstance(sessions, list):
        return ("partial", "sessions_malformed")
    for entry in sorted(sessions, key=str):
        if not isinstance(entry, dict):
            return ("partial", "sessions_malformed")
        label = entry.get("session")
        label = label if type(label) is int else "?"
        entry_status = entry.get("status")
        if entry_status == "lost":
            # SessionState::Ended carries a model gap.
            return ("partial", f"session/{label}/lost")
        if entry_status not in ("live", "closed"):
            return ("partial", f"session/{label}/malformed")
    top_gaps = inv.get("gaps")
    if not isinstance(top_gaps, list):
        return ("partial", "root-gaps_malformed")
    for row in sorted(top_gaps, key=str):
        if _is_completeness_note(row):
            continue
        if not isinstance(row, dict):
            return ("partial", "root-gap/malformed")
        text = row.get("reason")
        if not isinstance(text, str) or not text:
            text = row.get("subject")
        if not isinstance(text, str) or not text:
            return ("partial", "root-gap/malformed")
        return ("partial", f"root-gap/{text}")
    top_suppressed = inv.get("gaps_suppressed")
    if type(top_suppressed) is not int:
        return ("partial", "root-gaps_malformed")
    if top_suppressed != 0:
        return ("partial", "root-gap/suppressed")
    top_budgets = inv.get("budgets")
    if not isinstance(top_budgets, dict):
        return ("partial", "top-budgets_malformed")
    for block, counter in TOP_BUDGET_ZERO_INTS:
        value = top_budgets.get(block)
        if value is None and block == "native_preadmission":
            continue  # scan lane emits null, not a stash
        if not isinstance(value, dict):
            return ("partial", f"top-budget/{block}/malformed")
        seen = value.get(counter)
        if type(seen) is not int:
            return ("partial",
                    f"top-budget/{block}/{counter}/malformed")
        if seen != 0:
            return ("partial", f"top-budget/{block}/{counter}")
    negative = top_budgets.get("instance_negative_state")
    if not isinstance(negative, dict):
        return ("partial",
                "top-budget/instance_negative_state/malformed")
    exhausted = negative.get("exhausted")
    if exhausted is True:
        return ("partial",
                "top-budget/instance_negative_state/exhausted")
    if exhausted is not False:
        return ("partial",
                "top-budget/instance_negative_state/exhausted/"
                "malformed")
    edges = inv.get("semantic_edges")
    if not isinstance(edges, list):
        return ("partial", "edges_malformed")
    for edge in edges:
        if not isinstance(edge, dict):
            return ("partial", "edge/edge_malformed")
        coverage = edge.get("coverage")
        if coverage is None:
            return ("partial", "edge/coverage_missing")
        if not isinstance(coverage, dict):
            return ("partial", "edge/coverage_malformed")
        lossy = coverage.get("lossy")
        if type(lossy) is not bool:
            return ("partial", "edge/lossy_malformed")
        reasons = coverage.get("reasons")
        if (not isinstance(reasons, list)
                or any(not isinstance(item, str)
                       for item in reasons)):
            return ("partial", "edge/reasons_malformed")
        have = set(reasons)
        if not have and lossy is False:
            continue  # clean active edge
        if have == NO_CALL_REASONS and lossy is False:
            continue  # fresh edge: zero calls, zero loss
        if have == BENIGN_COVERAGE_REASONS and lossy is True:
            continue  # setup-only pre-boundary loss
        outsiders = sorted(have - BENIGN_COVERAGE_REASONS
                           - NO_CALL_REASONS)
        if outsiders:
            return ("partial", f"edge/{outsiders[0]}")
        if not have:
            return ("partial", "edge/lossy")
        return ("partial", "edge/coverage_contradictory")
    return ("qualified", None)


def judge_leg(fail, leg, args, sizes):
    # A judge bug must fail loudly with results written, never as a bare
    # traceback with no results file (the wrapper then reports only that
    # the file is missing).
    inv = None
    try:
        inv = load_inventory(fail, leg, args[f"{leg}_inventory"],
                             int(args[f"{leg}_inventory_exit"]))
        if inv is None:
            return None
        check_section_version(fail, leg, inv)
        check_mechanisms(fail, leg, inv)
        check_key_rows(fail, leg, inv, sizes)
        check_object_binding(fail, leg, inv)
        check_unknown_rows(fail, leg, inv)
        check_text(fail, leg, args[f"{leg}_text"], sizes, inv)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        fail.add(leg, f"judge error: {exc!r}")
    return inv


def parse_args(argv):
    names = ("sizes_log", "sizes_exit", "sizes_inventory", "sizes_inventory_exit",
             "sizes_text", "nosizes_log", "nosizes_exit", "nosizes_inventory",
             "nosizes_inventory_exit", "nosizes_text", "out_results", "out_summary")
    args = {}
    items = list(argv)
    while items:
        token = items.pop(0)
        name = token[2:].replace("-", "_") if token.startswith("--") else ""
        if name not in names:
            raise ValueError(f"usage: unexpected {token}")
        if not items:
            raise ValueError(f"usage: {token} needs a value")
        args[name] = items.pop(0)
    missing = [name for name in names if name not in args]
    if missing:
        raise ValueError(f"usage: missing {missing}")
    return args


def main(argv):
    try:
        args = parse_args(argv)
    except ValueError as exc:
        print(f"pqc_cell_compare: {exc}", file=sys.stderr)
        return 2
    try:
        truth_fail = Failures()
        check_truth(truth_fail, "sizes",
                    args["sizes_log"], int(args["sizes_exit"]))
        check_truth(truth_fail, "nosizes",
                    args["nosizes_log"], int(args["nosizes_exit"]))
        sizes_fail = Failures()
        sizes_inv = judge_leg(sizes_fail, "sizes", args, True)
        nosizes_fail = Failures()
        nosizes_inv = judge_leg(nosizes_fail, "nosizes", args, False)
    except (OSError, ValueError) as exc:
        print(f"pqc_cell_compare: harness error: {exc}", file=sys.stderr)
        return 2
    sizes_qual, sizes_reason = leg_qualification(sizes_inv)
    nosizes_qual, nosizes_reason = leg_qualification(nosizes_inv)
    # The truth row joins both legs' runs, so it inherits both legs'
    # loss disclosure; each leg row discloses only its own leg.
    truth_loss = [(leg, reason)
                  for leg, qual, reason
                  in (("sizes", sizes_qual, sizes_reason),
                      ("nosizes", nosizes_qual, nosizes_reason))
                  if qual != "qualified"]
    if truth_loss:
        truth_qual = "partial"
        truth_reason = ", ".join(f"{leg}/{reason}"
                                 for leg, reason in truth_loss)
    else:
        truth_qual, truth_reason = "qualified", None

    def detail(base, fail, qual, reason):
        if not fail.ok():
            return "; ".join(fail.problems)
        if qual == "qualified":
            return base
        return f"partial ({reason}): {base}"

    rows = [
        {"cell": "pqc-workload-truth", "pass": truth_fail.ok(),
         "qualification": truth_qual,
         "detail": detail("both legs ran 3+3 PQC keypairs with exact "
                          "counts and FIPS lengths",
                          truth_fail, truth_qual, truth_reason)},
        {"cell": "pqc-sizes-rows", "pass": sizes_fail.ok(),
         "qualification": sizes_qual,
         "detail": detail("12 key rows carry exact roles, object "
                          "bindings, family + template label + length "
                          "set; 18 objects pair-bound; 6 keygens; "
                          "4 mechanism rows exact",
                          sizes_fail, sizes_qual, sizes_reason)},
        {"cell": "pqc-nosizes-rows", "pass": nosizes_fail.ok(),
         "qualification": nosizes_qual,
         "detail": detail("12 key rows carry exact roles, object "
                          "bindings and family + template label; "
                          "18 objects pair-bound; 6 keygens; "
                          "4 mechanism rows exact",
                          nosizes_fail, nosizes_qual, nosizes_reason)},
    ]
    with open(args["out_results"], "w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row) + "\n")
    summary = []
    for row in rows:
        summary.append(f"{row['cell']}: {'PASS' if row['pass'] else 'FAIL'}")
        if not row["pass"]:
            summary.append(f"  {row['detail']}")
    Path(args["out_summary"]).write_text("\n".join(summary) + "\n",
                                         encoding="utf-8")
    print("\n".join(summary))
    problems = (truth_fail.problems + sizes_fail.problems
                + nosizes_fail.problems)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
