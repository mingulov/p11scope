#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""PQC CI cell judge twins.

scripts/ci/pqc_cell_compare.py judges the two pqc-cell.sh legs (with
and without --key-sizes). Each leg must carry the full (category,
parameter set) matrix: one completed row per expected pair, zero
unexpected pairs, and one corresponding verbose row. Totals per
operation plus the union of labels are not enough: a relabeled row
keeps every total and every union while voiding a required pair.

Beyond the matrix, the judge refuses wrong attribution: every
key-operation row must carry its exact role (sign/verify use `key`,
encapsulate uses `encapsulation_key`, decapsulate uses
`decapsulation_key`), join its object row, and agree with that
object's established class, key type, parameter set and label (sign
on the private half, verify on the public half, encapsulate on the
public half, decapsulate on the private half). Both halves of each
pair share one generate_pair birth. Every row is shape-checked with
exact key equality against the producer schema: malformed rows
(missing or extra keys) and extra rows (duplicates or foreign
categories) fail. The fixtures below are producer-shaped: they mirror
the real kryoptic cell inventories field for field (full 15-key key
rows, 18 object rows with established/requested/queries blocks, the
10-shaped unknown keygen row, section version 10).

Run: python3 -I tests/python/test_pqc_cell_judge.py -v
"""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JUDGE = ROOT / "scripts" / "ci" / "pqc_cell_compare.py"

TRUTH_LOG = (
    "GROUND_TRUTH mldsa_gen=3 mldsa_sign=3 mldsa_verify=3 "
    "mlkem_gen=3 mlkem_enc=3 mlkem_dec=3\n"
    "LENGTHS mldsa44=2420 mldsa65=3309 mldsa87=4627 "
    "mlkem512=768 mlkem768=1088 mlkem1024=1568\n"
    "WORKLOAD_EXIT ok=1\n"
)

# Real loss-disclosure shapes below are verbatim from the fix5 CI
# artifact (privileged-tests 45677158379 on 38a0f9de6,
# art5/cells/sizes.json), whose sizes leg the suite mirrors.
REAL_TOP_GAP_JOINT = {
    "budget": None, "caller": "c0", "module": None, "pid": None,
    "reason": "joint_seal_h3_loss_history_loss", "repeats": 1,
    "subject": "Joint key operations unavailable; retained S1"}
REAL_EDGE_COVERAGE = {
    "lossy": True,
    "reasons": ["capture_stopped", "instance_retired",
                "semantic_loss", "task_retired"]}
REAL_TOP_BUDGETS = {
    "callers": {"late_refused": 0, "limit": 4096, "occupied": 1,
                "refused": 0, "retired": 0,
                "retired_with_calls": 0},
    "counters": {"cap": 18446744073709551615, "observed_edges": 1,
                 "saturated_edges": 0},
    "departed_use": {"identities_dropped": 0, "mech_overflow": 0},
    "edges": {"folded": 0, "folded_entries": 0, "limit": 32768,
              "occupied": 1, "refused": 0},
    "endpoints": {"limit": 1048576, "occupied": 92, "refused": 0},
    "instance_negative_state": {"exhausted": False, "limit": 4096,
                                "occupied": 2, "refused": 0},
    "instance_semantic_resources": {
        "charged_bytes": 2485730, "limit_bytes": 167772160,
        "occupancy": {"active_machines": 0,
                      "async_function_bytes": 0,
                      "async_function_capacity_bytes": 0,
                      "detached_calls": 0, "mechanisms": 4,
                      "open_bindings": 0, "operation_categories": 6,
                      "origin_capacity_elements": 0,
                      "origin_elements": 0, "origin_vectors": 0,
                      "pending_calls": 0,
                      "provenance_function_bytes": 102,
                      "provenance_function_capacity_bytes": 102,
                      "provenance_functions": 8,
                      "provenance_returns": 4},
        "peak_charged_bytes": 18130996, "refused": 0},
    "instance_semantic_state": {"limit": 4096, "occupied": 1,
                                "refused": 0, "shared_limit": 32768,
                                "shared_occupied": 1,
                                "unknown_edges": 0},
    "instances": {"folded": 0, "limit": 4096, "occupied": 1,
                  "refused": 0},
    "inventory_attach_modules": {"limit": 32768, "occupied": 1,
                                 "refused": 0},
    "inventory_endpoints": {"limit": 32768, "occupied": 92,
                            "refused": 0},
    "modules": {"limit": 4096, "occupied": 1, "refused": 0},
    "native_departed": {"exec_prune_overflow": 0,
                        "pair_dropped_base": 0,
                        "pair_dropped_rows": 0,
                        "pair_prune_overflow": 0},
    "native_preadmission": {"limit": 4096, "occupied": 0,
                            "pruned": 0, "refused": 0},
    "retained_history": {"limit": 8192, "retained": 12,
                         "suppressed": 0},
    "semantic_state": {"limit": 32768, "occupied": 0, "refused": 0,
                       "status": "withheld", "unknown_edges": 1}}
# The completeness note, transcribed from its single emitter
# (src/inspect_system.rs:3090-3099): subject "discovery capped"
# with an "attribution complete: ..." reason. No preserved
# artifact carries one (real runs have loss instead), so the
# emitter is the strictest available shape source.
COMPLETENESS_NOTE = {
    "budget": None, "caller": None, "module": None, "pid": None,
    "reason": ("attribution complete: 8 processes in scope; "
               "every other process maps only shared objects "
               "a deep scan examined"),
    "repeats": 1, "subject": "discovery capped"}
# The producer's real setup-boundary coverage
# (src/discovery/caller_registry/instance_input.rs:3664-3668:
# selecting BeforeSemanticBoundary sets lossy).
SETUP_COVERAGE = {"lossy": True,
                  "reasons": ["before_semantic_boundary"]}
CLEAN_COVERAGE = {"lossy": False, "reasons": []}

DSA_SETS = ("ml_dsa_44", "ml_dsa_65", "ml_dsa_87")
KEM_SETS = ("ml_kem_512", "ml_kem_768", "ml_kem_1024")
OPERATIONS = (("sign", DSA_SETS), ("verify", DSA_SETS),
              ("encapsulate", KEM_SETS), ("decapsulate", KEM_SETS))
FAMILY = {"ml_kem_512": "ml_kem", "ml_kem_768": "ml_kem",
          "ml_kem_1024": "ml_kem", "ml_dsa_44": "ml_dsa",
          "ml_dsa_65": "ml_dsa", "ml_dsa_87": "ml_dsa"}
OCTETS = {"ml_kem_512": 768, "ml_kem_768": 1088, "ml_kem_1024": 1568,
          "ml_dsa_44": 2420, "ml_dsa_65": 3309, "ml_dsa_87": 4627}
EVIDENCE = {"sign": "sign_output", "verify": "verify_input",
            "encapsulate": "encapsulate_output",
            "decapsulate": "decapsulate_input"}
DISPLAY = {"ml_kem_512": "ML-KEM-512", "ml_kem_768": "ML-KEM-768",
           "ml_kem_1024": "ML-KEM-1024", "ml_dsa_44": "ML-DSA-44",
           "ml_dsa_65": "ML-DSA-65", "ml_dsa_87": "ML-DSA-87"}
LENGTH_NOUN = {"sign": "signature", "verify": "signature",
               "encapsulate": "ciphertext", "decapsulate": "ciphertext"}
OP_ROLE = {"sign": "key", "verify": "key",
           "encapsulate": "encapsulation_key",
           "decapsulate": "decapsulation_key"}
OP_CLASS = {"sign": 3, "verify": 2, "encapsulate": 2, "decapsulate": 3}
LABEL_KEY_TYPE = {"ml_kem_512": 73, "ml_kem_768": 73, "ml_kem_1024": 73,
                  "ml_dsa_44": 74, "ml_dsa_65": 74, "ml_dsa_87": 74}
LABEL_PARAM_CODE = {"ml_dsa_44": 1, "ml_dsa_65": 2, "ml_dsa_87": 3,
                    "ml_kem_512": 1, "ml_kem_768": 2, "ml_kem_1024": 3}
# Producer object layout, mirroring the real cell: DSA pairs take
# objects 1-6 (public odd, private even); each KEM pair takes two
# objects followed by its two shared-secret objects.
PAIRS = (("ml_dsa_44", 1, 2), ("ml_dsa_65", 3, 4),
         ("ml_dsa_87", 5, 6), ("ml_kem_512", 7, 8),
         ("ml_kem_768", 11, 12), ("ml_kem_1024", 15, 16))
SECRETS = (("encapsulate", 9), ("decapsulate", 10),
           ("encapsulate", 13), ("decapsulate", 14),
           ("encapsulate", 17), ("decapsulate", 18))
# Spotlight order: v5 vocabulary rank, then category bytes
# (decapsulate before encapsulate, sign before verify).
SPOTLIGHT_ORDER = (("ml_dsa_44", "sign"), ("ml_dsa_44", "verify"),
                   ("ml_dsa_65", "sign"), ("ml_dsa_65", "verify"),
                   ("ml_dsa_87", "sign"), ("ml_dsa_87", "verify"),
                   ("ml_kem_512", "decapsulate"),
                   ("ml_kem_512", "encapsulate"),
                   ("ml_kem_768", "decapsulate"),
                   ("ml_kem_768", "encapsulate"),
                   ("ml_kem_1024", "decapsulate"),
                   ("ml_kem_1024", "encapsulate"))


def field(status, value, source=None, reason=None):
    """One producer-shaped metadata field."""
    return {"status": status, "value": value,
            "source": source, "reason": reason}


def unknown_field():
    """One unestablished metadata field, producer-shaped."""
    return field("unknown", None)


def object_row(number, label, class_code, birth, creation="generate_pair"):
    """One healthy PQC object row, producer-shaped.

    Established class/key type/parameter set come from the successful
    creation; token stays unknown while requested (the workload asks
    session keys); nothing was ever queried back.
    """
    key_type = LABEL_KEY_TYPE[label]
    param = LABEL_PARAM_CODE[label]
    requested = {"class": field("value", class_code),
                 "key_type": field("value", key_type),
                 "token": field("value", 0),
                 "value_len": unknown_field(),
                 "modulus_bits": unknown_field(),
                 "ec_params": unknown_field(),
                 "parameter_set": field("value", param)}
    established = {"class": field("value", class_code,
                                  source="creation_success"),
                   "key_type": field("value", key_type,
                                     source="creation_success"),
                   "token": unknown_field(),
                   "value_len": unknown_field(),
                   "modulus_bits": unknown_field(),
                   "ec_params": unknown_field(),
                   "parameter_set": field("value", param,
                                          source="creation_success")}
    queries = {"class": "not_queried", "key_type": "not_queried",
               "token": "not_queried", "value_len": "not_queried",
               "modulus_bits": "not_queried", "ec_params": "not_queried",
               "parameter_set": "not_queried"}
    return {"object": number, "session": 1, "origin": "created",
            "creation": creation, "birth": dict(birth),
            "lifetime": "destroyed", "lifetime_reason": None,
            "attribution": "valid", "attribution_reason": None,
            "requested": requested, "established": established,
            "queries": dict(queries), "label": label,
            "successful_references": 1,
            "successful_key_references": 1, "accessing_sessions": 0}


def secret_row(number, creation, birth):
    """One healthy shared-secret object row, producer-shaped."""
    requested = {"class": field("value", 4),
                 "key_type": field("value", 16),
                 "token": field("value", 0),
                 "value_len": field("value", 32),
                 "modulus_bits": unknown_field(),
                 "ec_params": unknown_field(),
                 "parameter_set": unknown_field()}
    established = {"class": field("value", 4,
                                  source="creation_success"),
                   "key_type": field("value", 16,
                                     source="creation_success"),
                   "token": unknown_field(),
                   "value_len": field("value", 32,
                                      source="creation_success"),
                   "modulus_bits": unknown_field(),
                   "ec_params": unknown_field(),
                   "parameter_set": unknown_field()}
    queries = {"class": "not_queried", "key_type": "not_queried",
               "token": "not_queried", "value_len": "not_queried",
               "modulus_bits": "not_queried", "ec_params": "not_queried",
               "parameter_set": "not_queried"}
    return {"object": number, "session": 1, "origin": "created",
            "creation": creation, "birth": dict(birth),
            "lifetime": "destroyed", "lifetime_reason": None,
            "attribution": "valid", "attribution_reason": None,
            "requested": requested, "established": established,
            "queries": dict(queries), "label": "generic_256",
            "successful_references": 0,
            "successful_key_references": 0, "accessing_sessions": 0}


def objects():
    """All eighteen healthy object rows: twelve PQC keys plus the six
    KEM shared secrets. Both halves of each pair share one birth."""
    rows = []
    pair_birth = 0
    for label, public, private in PAIRS:
        pair_birth += 1
        birth = {"start_ns": 1_000 * pair_birth,
                 "end_ns": 1_000 * pair_birth + 7}
        rows.append(object_row(public, label, 2, birth))
        rows.append(object_row(private, label, 3, birth))
    for index, (creation, number) in enumerate(SECRETS):
        birth = {"start_ns": 90_000 + index,
                 "end_ns": 90_000 + index + 3}
        rows.append(secret_row(number, creation, birth))
    rows.sort(key=lambda row: row["object"])
    return rows


def key_row(number, operation, label, sizes):
    """One healthy PQC key row, producer-shaped: the exact frozen
    fifteen keys, the operation's exact role, unit operations, and a
    single started/completed terminal."""
    row = {"instance": "i0", "object": number, "category": operation,
           "role": OP_ROLE[operation], "metadata_at_use": label,
           "unit": "operations", "started": 1, "completed": 1,
           "failed": 0, "cancelled": 0, "unknown": 0, "active": 0,
           "key_join_lost": 0,
           "inferred_family": {"status": "inferred",
                               "value": FAMILY[label],
                               "completions": 1}}
    if sizes:
        row["inferred_size"] = {
            "status": "inferred", "completions": 1,
            "detail": {"kind": "pqc_set", "parameter_set": label,
                       "octets": OCTETS[label],
                       "evidence": EVIDENCE[operation]}}
    else:
        row["inferred_size"] = {"status": "unknown", "detail": None,
                                "completions": 0}
    return row


def key_rows(sizes):
    """All twelve healthy key rows in producer order (by object):
    verify on the public half, sign on the private half, encapsulate
    on the public half, decapsulate on the private half."""
    rows = []
    for label, public, private in PAIRS:
        if label.startswith("ml_dsa"):
            rows.append(key_row(public, "verify", label, sizes))
            rows.append(key_row(private, "sign", label, sizes))
        else:
            rows.append(key_row(public, "encapsulate", label, sizes))
            rows.append(key_row(private, "decapsulate", label, sizes))
    rows.sort(key=lambda row: row["object"])
    return rows


def unknown_row():
    """The healthy unknown keygen row, producer-shaped: the nine
    frozen keys with the two keygen mechanism ids in first-seen
    order (the DSA keygens run before the KEM keygens) and no
    overflow count (absent when zero, per the v10 contract)."""
    return {"category": "generate_key_pair", "reason": "not_applicable",
            "unit": "operations", "completed": 6, "failed": 0,
            "cancelled": 0, "unknown": 0, "active": 0,
            "mechanisms": [{"id": 28, "count": 3},
                           {"id": 15, "count": 3}]}


def inventory(sizes):
    """One healthy leg inventory: section version 10, eighteen
    objects, the full twelve-row matrix plus its keygen row. The
    loss disclosure mirrors the real artifact: partial status,
    an outcome gap, one real top-level gap row, real edge
    coverage and the real (all-clean) top budgets."""
    return {
        "semantic_edges": [{
            "coverage": copy.deepcopy(REAL_EDGE_COVERAGE),
            "mechanisms": [
                {"mechanism": 15, "name": "CKM_ML_KEM_KEY_PAIR_GEN",
                 "calls": 3, "errors": 0},
                {"mechanism": 23, "name": "CKM_ML_KEM",
                 "calls": 6, "errors": 0},
                {"mechanism": 28, "name": "CKM_ML_DSA_KEY_PAIR_GEN",
                 "calls": 3, "errors": 0},
                {"mechanism": 29, "name": "CKM_ML_DSA",
                 "calls": 12, "errors": 0}]}],
        "gaps": [copy.deepcopy(REAL_TOP_GAP_JOINT)],
        "gaps_suppressed": 0,
        "budgets": copy.deepcopy(REAL_TOP_BUDGETS),
        "object_observations": {
            "version": 10, "revision": 1, "status": "partial",
            "reason": "authority_lost",
            "sessions": [{"session": 1, "origin": "opened",
                          "status": "lost"}],
            "objects": objects(),
            "key_operations": key_rows(sizes),
            "unknown_key_operations": [unknown_row()],
            "unattributed": [],
            "gaps": {"rows": [{"reason": "outcome_lost", "repeats": 1,
                               "subject": "model"}],
                     "suppressed": 0},
            "budgets": {
                "key_rows": {"limit": 65536, "occupied": 12,
                             "refused": 0},
                "object_rows": {"limit": 65536, "occupied": 18,
                                "refused": 0},
                "unknown_rows": {"occupied": 1},
                "encoded_bytes": 34522,
                "allocation_refused": False,
                "refusal_reason": "none"}}}


def text_row(number, operation, label, sizes):
    """One healthy verbose key line, producer-shaped: the operation's
    exact role, the family fragment, and the length set (sizes leg)
    or the size-unknown hint (nosizes leg)."""
    role = OP_ROLE[operation]
    family = "ML-KEM" if label.startswith("ml_kem") else "ML-DSA"
    line = (f"  key row i0 object {number} {operation} {role} ({label}): "
            f"probably {family} (from mechanism); ")
    if sizes:
        line += f"{DISPLAY[label]} (from {LENGTH_NOUN[operation]} length)"
    else:
        line += "size unknown (needs --key-sizes)"
    return line


def spotlight():
    """The healthy verbose spotlight, producer-shaped: one verbose
    segment per (parameter set, operation) pair in spotlight order."""
    segments = [f"{DISPLAY[label]} {operation}: 1 completed, "
                f"0 returned errors, 0 active"
                for label, operation in SPOTLIGHT_ORDER]
    return "  pqc keys: " + ", ".join(segments)


def verbose(sizes):
    """One healthy verbose text: twelve key lines plus the spotlight."""
    lines = []
    for label, public, private in PAIRS:
        if label.startswith("ml_dsa"):
            lines.append(text_row(public, "verify", label, sizes))
            lines.append(text_row(private, "sign", label, sizes))
        else:
            lines.append(text_row(public, "encapsulate", label, sizes))
            lines.append(text_row(private, "decapsulate", label, sizes))
    lines.append(spotlight())
    return "\n".join(lines) + "\n"


def run_judge_full(sizes_inv, sizes_text, nosizes_inv, nosizes_text,
                   sizes_log=TRUTH_LOG, nosizes_log=TRUTH_LOG,
                   sizes_exit="0", nosizes_exit="0",
                   sizes_inventory_exit="0", nosizes_inventory_exit="0",
                   missing=()):
    """Run the judge CLI on fabricated legs; return (rc, summary, rows).

    `missing` names tmp files to leave unwritten (e.g. "sizes.json")
    to simulate unreadable inputs; `rows` is the parsed results.jsonl
    (None when the judge wrote none).
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        payloads = {
            "sizes.log": sizes_log,
            "nosizes.log": nosizes_log,
            "sizes.json": json.dumps(sizes_inv),
            "nosizes.json": json.dumps(nosizes_inv),
            "sizes.txt": sizes_text,
            "nosizes.txt": nosizes_text,
        }
        for name, payload in payloads.items():
            if name not in missing:
                (tmp / name).write_text(payload, encoding="utf-8")
        argv = [sys.executable, "-I", str(JUDGE),
               "--sizes-log", str(tmp / "sizes.log"),
               "--sizes-exit", sizes_exit,
               "--sizes-inventory", str(tmp / "sizes.json"),
               "--sizes-inventory-exit", sizes_inventory_exit,
               "--sizes-text", str(tmp / "sizes.txt"),
               "--nosizes-log", str(tmp / "nosizes.log"),
               "--nosizes-exit", nosizes_exit,
               "--nosizes-inventory", str(tmp / "nosizes.json"),
               "--nosizes-inventory-exit", nosizes_inventory_exit,
               "--nosizes-text", str(tmp / "nosizes.txt"),
               "--out-results", str(tmp / "results.jsonl"),
               "--out-summary", str(tmp / "summary.txt")]
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=60)
        rows = None
        results = tmp / "results.jsonl"
        if results.exists():
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        return completed.returncode, completed.stdout, rows


def run_judge(sizes_inv, sizes_text, nosizes_inv, nosizes_text,
              sizes_log=TRUTH_LOG, nosizes_log=TRUTH_LOG,
              sizes_exit="0", nosizes_exit="0",
              sizes_inventory_exit="0", nosizes_inventory_exit="0"):
    """Run the judge CLI on fabricated legs; return (rc, summary)."""
    rc, summary, _rows = run_judge_full(
        sizes_inv, sizes_text, nosizes_inv, nosizes_text,
        sizes_log=sizes_log, nosizes_log=nosizes_log,
        sizes_exit=sizes_exit, nosizes_exit=nosizes_exit,
        sizes_inventory_exit=sizes_inventory_exit,
        nosizes_inventory_exit=nosizes_inventory_exit)
    return rc, summary


def result_for(rows, cell):
    """The one result row for a cell name."""
    found = [row for row in rows if row["cell"] == cell]
    assert len(found) == 1, f"want one {cell} row"
    return found[0]


def populated_inventory(sizes):
    """A loss-free leg inventory: populated status with reason
    none, no section gaps, clean section budgets, the session
    closed (not lost), no top-level gaps, and clean edge
    coverage. Every field is a producer-possible shape (the
    registry starts gap-free, coverage always carries both
    keys); the top budgets are the real all-clean object."""
    inv = inventory(sizes)
    oo = inv["object_observations"]
    oo["status"] = "populated"
    oo["reason"] = "none"
    oo["sessions"] = [{"session": 1, "origin": "opened",
                       "status": "closed"}]
    oo["gaps"] = {"rows": [], "suppressed": 0}
    inv["gaps"] = []
    inv["gaps_suppressed"] = 0
    inv["semantic_edges"][0]["coverage"] = dict(CLEAN_COVERAGE)
    return inv


def load_judge_module():
    """Import the judge script as a module (it has no import-time
    side effects beyond compiling its regexes)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pqc_cell_compare", JUDGE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def relabel(inv, text, sizes, operation, old, new):
    """Relabel one matrix pair consistently (row, detail and text).

    Same-family only (the family and length noun stay valid); the
    matrix pair is what breaks. The object binding breaks with it
    (the row's label no longer names its object's label), so this
    twin proves the matrix check fires alongside the binding check.
    """
    assert FAMILY[old] == FAMILY[new]
    inv = copy.deepcopy(inv)
    row = next(item for item in
               inv["object_observations"]["key_operations"]
               if item["category"] == operation
               and item["metadata_at_use"] == old)
    row["metadata_at_use"] = new
    if sizes:
        row["inferred_size"]["detail"]["parameter_set"] = new
        row["inferred_size"]["detail"]["octets"] = OCTETS[new]
    lines = []
    for line in text.splitlines():
        if (line.startswith("  key row ")
                and f" {operation} " in line
                and f"({old})" in line):
            line = line.replace(f"({old})", f"({new})")
            line = line.replace(DISPLAY[old], DISPLAY[new])
        lines.append(line)
    return inv, "\n".join(lines) + "\n"


def find_row(inv, operation, label):
    """The one key row for an (operation, parameter set) pair."""
    rows = [item for item in
            inv["object_observations"]["key_operations"]
            if item["category"] == operation
            and item["metadata_at_use"] == label]
    assert len(rows) == 1, f"want one ({operation}, {label}) row"
    return rows[0]


def find_object(inv, number):
    """The one object row for a capture-local object id."""
    rows = [item for item in inv["object_observations"]["objects"]
            if item["object"] == number]
    assert len(rows) == 1, f"want one object {number}"
    return rows[0]


class JudgeTwins(unittest.TestCase):
    def test_healthy_both_legs_pass(self):
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        self.assertIn("pqc-workload-truth: PASS", summary)
        self.assertIn("pqc-sizes-rows: PASS", summary)
        self.assertIn("pqc-nosizes-rows: PASS", summary)

    def test_relabel_sign_mutation_fails_sizes_leg(self):
        inv, text = relabel(inventory(True), verbose(True), True,
                            "sign", "ml_dsa_87", "ml_dsa_44")
        rc, summary = run_judge(inv, text,
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("pqc-nosizes-rows: PASS", summary)
        self.assertIn("matrix pairs missing", summary)
        self.assertIn("matrix pairs duplicated", summary)

    def test_relabel_sign_mutation_fails_nosizes_leg(self):
        inv, text = relabel(inventory(False), verbose(False), False,
                            "sign", "ml_dsa_87", "ml_dsa_44")
        rc, summary = run_judge(inventory(True), verbose(True),
                                inv, text)
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: PASS", summary)
        self.assertIn("pqc-nosizes-rows: FAIL", summary)
        self.assertIn("matrix pairs missing", summary)
        self.assertIn("matrix pairs duplicated", summary)

    def test_swapped_family_labels_fail(self):
        inv = copy.deepcopy(inventory(True))
        rows = inv["object_observations"]["key_operations"]
        first = next(item for item in rows
                     if item["category"] == "sign"
                     and item["metadata_at_use"] == "ml_dsa_44")
        second = next(item for item in rows
                      if item["category"] == "encapsulate"
                      and item["metadata_at_use"] == "ml_kem_512")
        first["metadata_at_use"], second["metadata_at_use"] = \
            second["metadata_at_use"], first["metadata_at_use"]
        for row in (first, second):
            row["inferred_family"]["value"] = \
                FAMILY[row["metadata_at_use"]]
            row["inferred_size"]["detail"]["parameter_set"] = \
                row["metadata_at_use"]
            row["inferred_size"]["detail"]["octets"] = \
                OCTETS[row["metadata_at_use"]]
        text = verbose(True)
        text = text.replace("(ml_dsa_44)", "(@@@)")
        text = text.replace("(ml_kem_512)", "(ml_dsa_44)")
        text = text.replace("(@@@)", "(ml_kem_512)")
        rc, summary = run_judge(inv, text,
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("matrix pairs missing", summary)
        self.assertIn("matrix pairs unexpected", summary)

    def test_verbose_row_must_match_its_matrix_pair(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " sign " in line and "(ml_dsa_87)" in line:
                lines[index] = line.replace("(ml_dsa_87)",
                                            "(ml_dsa_44)")
                lines[index] = lines[index].replace("ML-DSA-87",
                                                    "ML-DSA-44")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("text pairs missing", summary)

    def test_dropped_row_fails(self):
        inv = copy.deepcopy(inventory(True))
        rows = inv["object_observations"]["key_operations"]
        rows[:] = [row for row in rows
                   if not (row["category"] == "sign"
                           and row["metadata_at_use"] == "ml_dsa_87")]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want 12", summary)
        self.assertIn("matrix pairs missing", summary)

    def test_wrong_truth_fails(self):
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False),
                                sizes_log="WORKLOAD_EXIT ok=1\n")
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-workload-truth: FAIL", summary)
        self.assertIn("ground-truth line", summary)
        self.assertIn("lengths line", summary)

    def test_workload_exit_nonzero_fails_truth(self):
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False),
                                sizes_exit="1")
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-workload-truth: FAIL", summary)
        self.assertIn("workload exit=1", summary)

    def test_wrong_role_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "encapsulate", "ml_kem_512")["role"] = "key"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("role", summary)

    def test_verify_as_other_role_fails(self):
        inv = copy.deepcopy(inventory(False))
        find_row(inv, "verify", "ml_dsa_65")["role"] = "other"
        rc, summary = run_judge(inventory(True), verbose(True),
                                inv, verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-nosizes-rows: FAIL", summary)
        self.assertIn("role", summary)

    def test_swapped_public_private_objects_fail(self):
        inv = copy.deepcopy(inventory(True))
        sign = find_row(inv, "sign", "ml_dsa_44")
        verify = find_row(inv, "verify", "ml_dsa_44")
        sign["object"], verify["object"] = \
            verify["object"], sign["object"]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("class", summary)

    def test_swapped_kem_objects_fail(self):
        inv = copy.deepcopy(inventory(True))
        enc = find_row(inv, "encapsulate", "ml_kem_768")
        dec = find_row(inv, "decapsulate", "ml_kem_768")
        enc["object"], dec["object"] = dec["object"], enc["object"]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("class", summary)

    def test_dangling_object_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "sign", "ml_dsa_44")["object"] = 999
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("joins no object", summary)

    def test_object_label_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_object(inv, 1)["label"] = "ml_dsa_65"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("object label", summary)

    def test_object_key_type_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        established = find_object(inv, 7)["established"]
        established["key_type"]["value"] = 74
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("key_type", summary)

    def test_object_param_code_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        established = find_object(inv, 12)["established"]
        established["parameter_set"]["value"] = 3
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("parameter_set", summary)

    def test_pair_birth_split_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_object(inv, 2)["birth"]["end_ns"] += 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("birth", summary)

    def test_missing_pqc_object_fails(self):
        inv = copy.deepcopy(inventory(True))
        objects = inv["object_observations"]["objects"]
        objects[:] = [row for row in objects if row["object"] != 1]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("joins no object", summary)
        self.assertIn("want 2", summary)

    def test_extra_object_fails(self):
        inv = copy.deepcopy(inventory(True))
        extra = copy.deepcopy(find_object(inv, 9))
        extra["object"] = 19
        inv["object_observations"]["objects"].append(extra)
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want 18", summary)
        self.assertIn("secret", summary)

    def test_malformed_row_missing_key_fails(self):
        inv = copy.deepcopy(inventory(True))
        del find_row(inv, "sign", "ml_dsa_44")["role"]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys", summary)

    def test_malformed_row_extra_key_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "decapsulate", "ml_kem_1024")["bogus"] = 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys", summary)

    def test_extra_duplicate_row_fails(self):
        inv = copy.deepcopy(inventory(True))
        rows = inv["object_observations"]["key_operations"]
        rows.append(copy.deepcopy(find_row(inv, "sign", "ml_dsa_44")))
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want 12", summary)
        self.assertIn("duplicated", summary)

    def test_extra_foreign_category_row_fails(self):
        inv = copy.deepcopy(inventory(True))
        rows = inv["object_observations"]["key_operations"]
        rows[:] = [row for row in rows
                   if not (row["category"] == "sign"
                           and row["metadata_at_use"] == "ml_dsa_87")]
        foreign = copy.deepcopy(find_row(inv, "sign", "ml_dsa_44"))
        foreign["category"] = "encrypt"
        foreign["inferred_family"] = {"status": "unknown",
                                      "value": None, "completions": 0}
        foreign["inferred_size"] = {"status": "unknown",
                                    "detail": None, "completions": 0}
        rows.append(foreign)
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("category", summary)

    def test_bad_counters_fail(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "sign", "ml_dsa_44")["started"] = 0
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("started", summary)

    def test_split_instance_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "sign", "ml_dsa_44")["instance"] = "i1"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want one shared instance", summary)

    def test_family_label_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        row = find_row(inv, "sign", "ml_dsa_44")
        row["inferred_family"]["value"] = "ml_kem"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("family", summary)

    def test_size_octets_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        row = find_row(inv, "sign", "ml_dsa_44")
        row["inferred_size"]["detail"]["octets"] = 9999
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("size", summary)

    def test_nosizes_size_inferred_fails(self):
        inv = copy.deepcopy(inventory(False))
        row = find_row(inv, "sign", "ml_dsa_44")
        row["inferred_size"] = {"status": "inferred", "completions": 1,
                                "detail": {"kind": "pqc_set",
                                           "parameter_set": "ml_dsa_44",
                                           "octets": 2420,
                                           "evidence": "sign_output"}}
        rc, summary = run_judge(inventory(True), verbose(True),
                                inv, verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-nosizes-rows: FAIL", summary)
        self.assertIn("size", summary)

    def test_text_wrong_role_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " encapsulate " in line and "(ml_kem_512)" in line:
                lines[index] = line.replace("encapsulation_key", "key")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("role", summary)

    def test_text_family_mismatch_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " sign " in line and "(ml_dsa_44)" in line:
                lines[index] = line.replace("probably ML-DSA",
                                            "probably ML-KEM")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("family", summary)

    def test_text_extra_row_fails(self):
        text = verbose(True) + text_row(2, "sign", "ml_dsa_44", True) + "\n"
        rc, summary = run_judge(inventory(True), text,
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want 12", summary)

    def test_text_malformed_row_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " sign " in line and "(ml_dsa_87)" in line:
                lines[index] = "  key row garbled"
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("malformed", summary)
        self.assertIn("text pairs missing", summary)

    def test_nosizes_text_without_size_unknown_fails(self):
        lines = verbose(False).splitlines()
        for index, line in enumerate(lines):
            if line.startswith("  key row "):
                lines[index] = line.replace(
                    "; size unknown (needs --key-sizes)", "")
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False),
                                "\n".join(lines) + "\n")
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-nosizes-rows: FAIL", summary)
        self.assertIn("size unknown", summary)

    def test_mechanism_wrong_calls_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["semantic_edges"][0]["mechanisms"]
        next(row for row in mechs
             if row["mechanism"] == 23)["calls"] = 5
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanism 23", summary)

    def test_mechanism_extra_row_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["semantic_edges"][0]["mechanisms"].append(
            {"mechanism": 99, "name": "CKM_NOISE",
             "calls": 1, "errors": 1})
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want 4", summary)
        self.assertIn("mechanism 99", summary)

    def test_no_semantic_edges_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["semantic_edges"] = []
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("no semantic_edges", summary)

    def test_mechanism_listed_twice_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["semantic_edges"][0]["mechanisms"]
        mechs.append(dict(next(row for row in mechs
                               if row["mechanism"] == 23)))
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("listed twice", summary)

    def test_mechanism_missing_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["semantic_edges"][0]["mechanisms"]
        mechs[:] = [row for row in mechs if row["mechanism"] != 15]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanism 15", summary)

    def test_unknown_row_missing_unit_fails(self):
        inv = copy.deepcopy(inventory(True))
        del inv["object_observations"]["unknown_key_operations"][0]["unit"]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys", summary)

    def test_unknown_mechanism_order_swap_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["object_observations"]["unknown_key_operations"][0][
            "mechanisms"]
        mechs[:] = list(reversed(mechs))
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanisms", summary)

    def test_unknown_further_nonzero_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["object_observations"]["unknown_key_operations"][0][
            "further_mechanism_terminals"] = 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("further_mechanism_terminals", summary)

    def test_spotlight_missing_segment_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if line.startswith("  pqc keys: "):
                lines[index] = line.replace(
                    "ML-KEM-1024 decapsulate: 1 completed, "
                    "0 returned errors, 0 active, ", "")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("spotlight lacks", summary)

    def test_spotlight_extra_segment_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if line.startswith("  pqc keys: "):
                lines[index] = line + ", FOO bar: 9"
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("spotlight has extra", summary)

    def test_wrong_section_version_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["object_observations"]["version"] = 9
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("version", summary)

    def test_bad_instance_shape_fails(self):
        inv = copy.deepcopy(inventory(True))
        for row in inv["object_observations"]["key_operations"]:
            row["instance"] = "q0"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("want iN like", summary)

    def test_invalid_label_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_row(inv, "sign", "ml_dsa_44")["metadata_at_use"] = "bogus"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("metadata_at_use", summary)

    def test_unknown_wrong_completed_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["object_observations"]["unknown_key_operations"][0][
            "completed"] = 5
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("unknown row", summary)

    def test_mechanism_wrong_name_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["semantic_edges"][0]["mechanisms"]
        next(row for row in mechs
             if row["mechanism"] == 23)["name"] = "CKM_NOISE"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanism 23", summary)

    def test_mechanism_errors_nonzero_fails(self):
        inv = copy.deepcopy(inventory(True))
        mechs = inv["semantic_edges"][0]["mechanisms"]
        next(row for row in mechs
             if row["mechanism"] == 29)["errors"] = 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanism 29", summary)

    def test_inventory_exit_nonzero_fails_leg(self):
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False),
                                sizes_inventory_exit="1")
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("inventory exit=1", summary)

    def test_missing_workload_exit_line_fails_truth(self):
        log = ("GROUND_TRUTH mldsa_gen=3 mldsa_sign=3 mldsa_verify=3 "
               "mlkem_gen=3 mlkem_enc=3 mlkem_dec=3\n"
               "LENGTHS mldsa44=2420 mldsa65=3309 mldsa87=4627 "
               "mlkem512=768 mlkem768=1088 mlkem1024=1568\n")
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False),
                                sizes_log=log)
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-workload-truth: FAIL", summary)
        self.assertIn("WORKLOAD_EXIT", summary)

    def test_spotlight_missing_line_fails(self):
        lines = [line for line in verbose(True).splitlines()
                 if not line.startswith("  pqc keys: ")]
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("spotlight", summary)

    def test_secret_object_mislabeled_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_object(inv, 9)["label"] = "foo"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("secret", summary)

    def test_pair_same_class_fails(self):
        inv = copy.deepcopy(inventory(True))
        established = find_object(inv, 2)["established"]
        established["class"]["value"] = 2
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("pair classes", summary)

    def test_pair_birth_shared_across_labels_fails(self):
        inv = copy.deepcopy(inventory(True))
        first = find_object(inv, 1)["birth"]
        find_object(inv, 3)["birth"] = dict(first)
        find_object(inv, 4)["birth"] = dict(first)
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("share one birth", summary)

    def test_malformed_object_missing_key_fails(self):
        inv = copy.deepcopy(inventory(True))
        del find_object(inv, 1)["session"]
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys", summary)

    def test_malformed_object_extra_key_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_object(inv, 1)["bogus"] = 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys extra", summary)

    def test_unknown_extra_row_fails(self):
        inv = copy.deepcopy(inventory(True))
        rows = inv["object_observations"]["unknown_key_operations"]
        rows.append(copy.deepcopy(rows[0]))
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("unknown rows", summary)

    def test_unknown_row_extra_key_fails(self):
        inv = copy.deepcopy(inventory(True))
        inv["object_observations"]["unknown_key_operations"][0][
            "bogus"] = 1
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("keys extra", summary)

    def test_object_provenance_mismatch_fails(self):
        inv = copy.deepcopy(inventory(True))
        find_object(inv, 1)["attribution"] = "downgraded"
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("provenance", summary)

    def test_duplicate_object_fails(self):
        inv = copy.deepcopy(inventory(True))
        extra = copy.deepcopy(find_object(inv, 9))
        inv["object_observations"]["objects"].append(extra)
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("listed twice", summary)

    def test_text_cross_family_pair_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " sign " in line and "(ml_dsa_87)" in line:
                lines[index] = line.replace("(ml_dsa_87)",
                                            "(ml_kem_512)")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("text pairs missing", summary)
        self.assertIn("text pairs unexpected", summary)

    def test_text_length_fragment_missing_fails(self):
        lines = verbose(True).splitlines()
        for index, line in enumerate(lines):
            if " sign " in line and "(ml_dsa_44)" in line:
                lines[index] = line.replace(
                    " (from signature length)", "")
        rc, summary = run_judge(inventory(True),
                                "\n".join(lines) + "\n",
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("length set", summary)

    def test_missing_inventory_fails_leg(self):
        # The unreadable-inventory guard: without its fail.add the
        # leg returns early with no problems recorded and passes.
        rc, summary, _rows = run_judge_full(
            inventory(True), verbose(True),
            inventory(False), verbose(False),
            missing=("sizes.json",))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("pqc-nosizes-rows: PASS", summary)
        self.assertIn("unreadable", summary)

    def test_judge_error_fails_leg_with_results(self):
        # The judge-error catch: a malformed edge must fail loudly
        # with results still written, never as a bare traceback
        # with no results file.
        inv = copy.deepcopy(inventory(True))
        inv["semantic_edges"] = [42]
        rc, summary, rows = run_judge_full(
            inv, verbose(True), inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("judge error", summary)
        self.assertIsNotNone(rows)
        self.assertFalse(result_for(rows, "pqc-sizes-rows")["pass"])
        self.assertTrue(result_for(rows, "pqc-nosizes-rows")["pass"])

    def test_partial_leg_reports_partial_qualification(self):
        # The healthy cell discloses partial/authority_lost with an
        # outcome_lost gap: the rows stay exact (PASS) but the run
        # is partial, with the typed reason in the closed prefix.
        rc, summary, rows = run_judge_full(
            inventory(True), verbose(True),
            inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        for cell in ("pqc-workload-truth", "pqc-sizes-rows",
                     "pqc-nosizes-rows"):
            found = result_for(rows, cell)
            self.assertTrue(found["pass"], summary)
            self.assertEqual(found["qualification"], "partial",
                             summary)
        self.assertTrue(
            result_for(rows, "pqc-sizes-rows")["detail"].startswith(
                "partial (status/partial/authority_lost): "), summary)
        self.assertTrue(
            result_for(rows, "pqc-workload-truth")["detail"].startswith(
                "partial (sizes/status/partial/authority_lost, "
                "nosizes/status/partial/authority_lost): "), summary)

    def test_populated_leg_reports_qualified(self):
        # A loss-free run (populated status, no gaps, clean
        # budgets) is the only shape that qualifies.
        rc, summary, rows = run_judge_full(
            populated_inventory(True), verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        for cell in ("pqc-workload-truth", "pqc-sizes-rows",
                     "pqc-nosizes-rows"):
            found = result_for(rows, cell)
            self.assertTrue(found["pass"], summary)
            self.assertEqual(found["qualification"], "qualified",
                             summary)

    def test_edge_loss_reports_partial_qualification(self):
        # A lossy semantic edge (beyond the expected setup
        # boundary) makes its leg partial; the clean leg stays
        # qualified while the run-joining truth row goes partial.
        inv = populated_inventory(True)
        inv["semantic_edges"][0]["coverage"] = {
            "lossy": True, "reasons": ["semantic_loss"]}
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (edge/semantic_loss): "), summary)
        self.assertEqual(result_for(
            rows, "pqc-nosizes-rows")["qualification"],
            "qualified", summary)
        self.assertEqual(result_for(
            rows, "pqc-workload-truth")["qualification"],
            "partial", summary)

    def test_setup_coverage_stays_qualified(self):
        # Setup-only pre-boundary loss uses the real producer
        # shape (lossy with exactly the boundary reason) and is
        # the documented benign case: a run carrying only it
        # still qualifies.
        inv = populated_inventory(True)
        inv["semantic_edges"][0]["coverage"] = dict(SETUP_COVERAGE)
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        for cell in ("pqc-workload-truth", "pqc-sizes-rows",
                     "pqc-nosizes-rows"):
            self.assertEqual(result_for(rows, cell)["qualification"],
                             "qualified", summary)

    def test_budget_refusal_reports_partial_qualification(self):
        # Refused rows are omitted associations: the leg passes on
        # its exact rows but reports partial with the typed budget.
        inv = populated_inventory(True)
        inv["object_observations"]["budgets"]["key_rows"]["refused"] = 2
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (budget/key_rows_refused): "), summary)

    def test_suppressed_gaps_report_partial_qualification(self):
        # Suppressed gap rows hide loss detail the judge cannot
        # audit: the leg passes on its exact rows but reports
        # partial.
        inv = populated_inventory(True)
        inv["object_observations"]["gaps"]["suppressed"] = 3
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (gap/suppressed): "), summary)

    def test_gap_row_reports_partial_qualification(self):
        # A model gap row beside a populated status is still
        # disclosed loss: the leg passes on its exact rows but
        # reports partial with the typed gap.
        inv = populated_inventory(True)
        inv["object_observations"]["gaps"]["rows"] = [
            {"reason": "outcome_lost", "repeats": 1,
             "subject": "model"}]
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (gap/outcome_lost): "), summary)

    def test_top_level_gap_reports_partial_qualification(self):
        # A top-level inventory gap (here the real Joint-loss row)
        # is disclosed run coverage loss even beside a clean
        # section: the leg passes but reports partial.
        inv = populated_inventory(True)
        inv["gaps"] = [copy.deepcopy(REAL_TOP_GAP_JOINT)]
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (root-gap/joint_seal_h3_loss_history_loss): "),
            summary)

    def test_top_level_suppressed_reports_partial_qualification(self):
        # Suppressed top-level gap rows hide loss detail the judge
        # cannot audit: the leg passes but reports partial.
        inv = populated_inventory(True)
        inv["gaps_suppressed"] = 2
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (root-gap/suppressed): "), summary)

    def test_completeness_note_stays_qualified(self):
        # The producer's explicit completeness note ("attribution
        # complete", documented as a note, not a loss) is the one
        # top-level gap row that does not void qualification.
        inv = populated_inventory(True)
        inv["gaps"] = [copy.deepcopy(COMPLETENESS_NOTE)]
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        for cell in ("pqc-workload-truth", "pqc-sizes-rows",
                     "pqc-nosizes-rows"):
            self.assertEqual(result_for(rows, cell)["qualification"],
                             "qualified", summary)

    def test_unattributed_reports_partial_qualification(self):
        # Calls the producer could not attribute to a key (here a
        # record_lost counter row in the exact emitter shape)
        # void qualification even beside exact PQC rows.
        inv = populated_inventory(True)
        inv["object_observations"]["unattributed"] = [
            {"reason": "record_lost", "count": 3}]
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (unattributed/record_lost): "), summary)

    def test_lost_session_reports_partial_qualification(self):
        # A lost session ended with a model gap (here the real
        # session row): unaudited loss, so the leg passes but
        # reports partial.
        inv = populated_inventory(True)
        inv["object_observations"]["sessions"] = [
            {"session": 1, "origin": "opened", "status": "lost"}]
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (session/1/lost): "), summary)

    def test_populated_reason_mismatch_reports_partial(self):
        # Reason "none" holds only when populated: a populated
        # section carrying another reason is contradictory
        # disclosure, so the leg passes but reports partial.
        inv = populated_inventory(True)
        inv["object_observations"]["reason"] = "authority_lost"
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (status/populated/authority_lost): "), summary)

    def test_top_budget_refusal_reports_partial_qualification(self):
        # A refused top-level budget (here the real budgets with
        # two refused edge rows) is omitted coverage: the leg
        # passes on its exact rows but reports partial.
        inv = populated_inventory(True)
        inv["budgets"]["edges"]["refused"] = 2
        rc, summary, rows = run_judge_full(
            inv, verbose(True),
            populated_inventory(False), verbose(False))
        self.assertEqual(rc, 0, summary)
        found = result_for(rows, "pqc-sizes-rows")
        self.assertTrue(found["pass"], summary)
        self.assertEqual(found["qualification"], "partial", summary)
        self.assertTrue(found["detail"].startswith(
            "partial (top-budget/edges/refused): "), summary)

    def test_malformed_disclosure_is_partial(self):
        # Totality with exact reasons: every malformed disclosure
        # shape — and every CLI-awkward loss shape — reports
        # partial with its exact typed reason instead of raising
        # (a raise would skip the results file and void the
        # wrapper's failure attribution). Pinning the exact
        # reason (not just "partial") kills dropped-guard
        # mutants even when a later arm still says partial.
        judge = load_judge_module()
        valid = populated_inventory(True)
        self.assertEqual(valid["semantic_edges"][0]["coverage"],
                         CLEAN_COVERAGE)

        def apply(mutate):
            inv = copy.deepcopy(valid)
            mutate(inv)
            return inv

        def set_path(*path_and_value):
            *path, value = path_and_value

            def mutate(inv):
                target = inv
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return mutate

        def del_path(*path):
            def mutate(inv):
                target = inv
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]
            return mutate

        def str_lost_session(inv):
            row = inv["object_observations"]["sessions"][0]
            row["session"] = "1"
            row["status"] = "lost"

        oo = "object_observations"
        raw = [
            ("none", None, ("partial", "inventory_unreadable")),
            ("scalar", 42, ("partial", "inventory_malformed")),
            ("inventory_list", [],
             ("partial", "inventory_malformed")),
            ("empty", {}, ("partial", "section_malformed")),
            ("section_list", {"object_observations": []},
             ("partial", "section_malformed")),
        ]
        table = [
            ("reason_deleted",
             ("partial", "status/populated/None"),
             del_path(oo, "reason")),
            ("gaps_none", ("partial", "gaps_malformed"),
             set_path(oo, "gaps", None)),
            ("gaps_list", ("partial", "gaps_malformed"),
             set_path(oo, "gaps", [])),
            ("gaps_rows_dict", ("partial", "gaps_malformed"),
             set_path(oo, "gaps", {"rows": {}, "suppressed": 0})),
            ("gaps_row_none", ("partial", "gap/malformed"),
             set_path(oo, "gaps",
                      {"rows": [None], "suppressed": 0})),
            ("gaps_row_noreason", ("partial", "gap/malformed"),
             set_path(oo, "gaps",
                      {"rows": [{"repeats": 1, "subject": "model"}],
                       "suppressed": 0})),
            ("gaps_suppressed_str", ("partial", "gaps_malformed"),
             set_path(oo, "gaps", "suppressed", "0")),
            ("gaps_suppressed_true", ("partial", "gaps_malformed"),
             set_path(oo, "gaps", "suppressed", True)),
            ("gaps_suppressed_missing", ("partial", "gaps_malformed"),
             del_path(oo, "gaps", "suppressed")),
            ("budgets_none", ("partial", "budgets_malformed"),
             set_path(oo, "budgets", None)),
            ("budget_block_none",
             ("partial", "budget/key_rows_malformed"),
             set_path(oo, "budgets", "key_rows", None)),
            ("budget_block_missing",
             ("partial", "budget/object_rows_malformed"),
             del_path(oo, "budgets", "object_rows")),
            ("budget_refused_str",
             ("partial", "budget/key_rows_malformed"),
             set_path(oo, "budgets", "key_rows", "refused", "0")),
            ("budget_refused_true",
             ("partial", "budget/key_rows_malformed"),
             set_path(oo, "budgets", "key_rows", "refused", True)),
            ("budget_refused_missing",
             ("partial", "budget/key_rows_malformed"),
             del_path(oo, "budgets", "key_rows", "refused")),
            ("unattributed_none",
             ("partial", "unattributed_malformed"),
             set_path(oo, "unattributed", None)),
            ("unattributed_dict",
             ("partial", "unattributed_malformed"),
             set_path(oo, "unattributed", {})),
            ("unattributed_row_nondict",
             ("partial", "unattributed_malformed"),
             set_path(oo, "unattributed", [42])),
            ("unattributed_row_noreason",
             ("partial", "unattributed_malformed"),
             set_path(oo, "unattributed", [{"count": 1}])),
            ("unattributed_row_reason_int",
             ("partial", "unattributed_malformed"),
             set_path(oo, "unattributed",
                      [{"reason": 7, "count": 1}])),
            ("sessions_none", ("partial", "sessions_malformed"),
             set_path(oo, "sessions", None)),
            ("sessions_dict", ("partial", "sessions_malformed"),
             set_path(oo, "sessions", {})),
            ("session_row_nondict",
             ("partial", "sessions_malformed"),
             set_path(oo, "sessions", [7])),
            ("session_status_other",
             ("partial", "session/1/malformed"),
             set_path(oo, "sessions", 0, "status", "bogus")),
            ("session_status_missing",
             ("partial", "session/1/malformed"),
             del_path(oo, "sessions", 0, "status")),
            ("session_id_str_lost",
             ("partial", "session/?/lost"),
             str_lost_session),
            ("top_gaps_missing", ("partial", "root-gaps_malformed"),
             del_path("gaps")),
            ("top_gaps_dict", ("partial", "root-gaps_malformed"),
             set_path("gaps", {})),
            ("top_gap_row_none", ("partial", "root-gap/malformed"),
             set_path("gaps", [None])),
            ("top_gap_row_bare", ("partial", "root-gap/malformed"),
             set_path("gaps", [{}])),
            ("top_gap_row_subject_only",
             ("partial", "root-gap/PID custody lost"),
             set_path("gaps", [{"subject": "PID custody lost"}])),
            ("top_suppressed_str",
             ("partial", "root-gaps_malformed"),
             set_path("gaps_suppressed", "0")),
            ("top_suppressed_true",
             ("partial", "root-gaps_malformed"),
             set_path("gaps_suppressed", True)),
            ("top_suppressed_missing",
             ("partial", "root-gaps_malformed"),
             del_path("gaps_suppressed")),
            ("top_budgets_missing",
             ("partial", "top-budgets_malformed"),
             del_path("budgets")),
            ("top_budgets_list",
             ("partial", "top-budgets_malformed"),
             set_path("budgets", [])),
            ("top_budget_block_missing",
             ("partial", "top-budget/edges/malformed"),
             del_path("budgets", "edges")),
            ("top_budget_block_none",
             ("partial", "top-budget/edges/malformed"),
             set_path("budgets", "edges", None)),
            ("top_budget_counter_missing",
             ("partial", "top-budget/edges/refused/malformed"),
             del_path("budgets", "edges", "refused")),
            ("top_budget_counter_str",
             ("partial", "top-budget/edges/refused/malformed"),
             set_path("budgets", "edges", "refused", "0")),
            ("top_budget_counter_true",
             ("partial", "top-budget/edges/refused/malformed"),
             set_path("budgets", "edges", "refused", True)),
            ("exhausted_true",
             ("partial",
              "top-budget/instance_negative_state/exhausted"),
             set_path("budgets", "instance_negative_state",
                      "exhausted", True)),
            ("exhausted_str",
             ("partial",
              "top-budget/instance_negative_state/exhausted/"
              "malformed"),
             set_path("budgets", "instance_negative_state",
                      "exhausted", "false")),
            ("exhausted_missing",
             ("partial",
              "top-budget/instance_negative_state/exhausted/"
              "malformed"),
             del_path("budgets", "instance_negative_state",
                      "exhausted")),
            ("preadmission_pruned",
             ("partial", "top-budget/native_preadmission/pruned"),
             set_path("budgets", "native_preadmission",
                      "pruned", 1)),
            ("preadmission_str",
             ("partial",
              "top-budget/native_preadmission/malformed"),
             set_path("budgets", "native_preadmission", "x")),
            ("coverage_absent", ("partial", "edge/coverage_missing"),
             del_path("semantic_edges", 0, "coverage")),
            ("coverage_none", ("partial", "edge/coverage_missing"),
             set_path("semantic_edges", 0, "coverage", None)),
            ("coverage_empty", ("partial", "edge/lossy_malformed"),
             set_path("semantic_edges", 0, "coverage", {})),
            ("coverage_scalar",
             ("partial", "edge/coverage_malformed"),
             set_path("semantic_edges", 0, "coverage", 42)),
            ("lossy_missing", ("partial", "edge/lossy_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"reasons": []})),
            ("lossy_int", ("partial", "edge/lossy_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": 0, "reasons": []})),
            ("lossy_str", ("partial", "edge/lossy_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": "false", "reasons": []})),
            ("reasons_missing",
             ("partial", "edge/reasons_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False})),
            ("reasons_str", ("partial", "edge/reasons_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False, "reasons": "x"})),
            ("reasons_none", ("partial", "edge/reasons_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False, "reasons": None})),
            ("reasons_item_int",
             ("partial", "edge/reasons_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": True, "reasons": [42]})),
            ("reasons_item_none",
             ("partial", "edge/reasons_malformed"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": True, "reasons": [None]})),
            ("lossy_without_reasons", ("partial", "edge/lossy"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": True, "reasons": []})),
            ("contradictory_clean",
             ("partial", "edge/coverage_contradictory"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False,
                       "reasons": ["before_semantic_boundary"]})),
            ("contradictory_nocalls",
             ("partial", "edge/coverage_contradictory"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": True, "reasons": ["no_calls"]})),
            ("contradictory_mixed",
             ("partial", "edge/coverage_contradictory"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False,
                       "reasons": ["before_semantic_boundary",
                                   "no_calls"]})),
            ("edge_nondict", ("partial", "edge/edge_malformed"),
             set_path("semantic_edges", 0, 42)),
            ("outsider_mixed", ("partial", "edge/semantic_loss"),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": True,
                       "reasons": ["before_semantic_boundary",
                                   "semantic_loss"]})),
            ("fresh_no_calls", ("qualified", None),
             set_path("semantic_edges", 0, "coverage",
                      {"lossy": False, "reasons": ["no_calls"]})),
            ("setup_real_shape", ("qualified", None),
             set_path("semantic_edges", 0, "coverage",
                      dict(SETUP_COVERAGE))),
            ("preadmission_null", ("qualified", None),
             set_path("budgets", "native_preadmission", None)),
            ("note_only", ("qualified", None),
             set_path("gaps", [copy.deepcopy(COMPLETENESS_NOTE)])),
        ]
        # Every gated top-budget counter refuses exactly: the
        # (block, counter) list is an independent copy of the
        # producer's refused/loss-bearing budget contract, so a
        # dropped spec entry fails its case.
        for block, counter in [
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
                ("native_preadmission", "pruned")]:
            table.append(
                (f"top_budget_{block}_{counter}",
                 ("partial", f"top-budget/{block}/{counter}"),
                 set_path("budgets", block, counter, 1)))
        for name, inv, expected in raw:
            self.assertEqual(judge.leg_qualification(inv), expected,
                             name)
        for name, expected, mutate in table:
            self.assertEqual(
                judge.leg_qualification(apply(mutate)), expected,
                name)
        self.assertEqual(judge.leg_qualification(valid),
                         ("qualified", None))


if __name__ == "__main__":
    unittest.main()
