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
    objects, the full twelve-row matrix plus its keygen row."""
    return {
        "semantic_edges": [{"mechanisms": [
            {"mechanism": 15, "name": "CKM_ML_KEM_KEY_PAIR_GEN",
             "calls": 3, "errors": 0},
            {"mechanism": 23, "name": "CKM_ML_KEM",
             "calls": 6, "errors": 0},
            {"mechanism": 28, "name": "CKM_ML_DSA_KEY_PAIR_GEN",
             "calls": 3, "errors": 0},
            {"mechanism": 29, "name": "CKM_ML_DSA",
             "calls": 12, "errors": 0}]}],
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


def run_judge(sizes_inv, sizes_text, nosizes_inv, nosizes_text,
              sizes_log=TRUTH_LOG, nosizes_log=TRUTH_LOG,
              sizes_exit="0", nosizes_exit="0",
              sizes_inventory_exit="0", nosizes_inventory_exit="0"):
    """Run the judge CLI on fabricated legs; return (rc, summary)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "sizes.log").write_text(sizes_log, encoding="utf-8")
        (tmp / "nosizes.log").write_text(nosizes_log, encoding="utf-8")
        (tmp / "sizes.json").write_text(json.dumps(sizes_inv),
                                        encoding="utf-8")
        (tmp / "nosizes.json").write_text(json.dumps(nosizes_inv),
                                          encoding="utf-8")
        (tmp / "sizes.txt").write_text(sizes_text, encoding="utf-8")
        (tmp / "nosizes.txt").write_text(nosizes_text, encoding="utf-8")
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
        return completed.returncode, completed.stdout


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
        self.assertIn("instance", summary)

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
             "calls": 1, "errors": 0})
        rc, summary = run_judge(inv, verbose(True),
                                inventory(False), verbose(False))
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: FAIL", summary)
        self.assertIn("mechanism", summary)

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
        self.assertIn("spotlight", summary)

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
        self.assertIn("instance", summary)

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


if __name__ == "__main__":
    unittest.main()
