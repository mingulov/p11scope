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


def key_row(number, operation, label, sizes):
    """One healthy PQC key row, sizes-shaped or nosizes-shaped."""
    row = {"instance": "i0", "object": number, "category": operation,
           "completed": 1, "failed": 0, "metadata_at_use": label,
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


def inventory(sizes):
    """One healthy leg inventory: the full matrix plus its keygen row."""
    rows = []
    number = 1
    for operation, sets in OPERATIONS:
        for label in sets:
            rows.append(key_row(number, operation, label, sizes))
            number += 1
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
            "key_operations": rows,
            "unknown_key_operations": [
                {"category": "generate_key_pair", "completed": 6,
                 "reason": "not_applicable",
                 "mechanisms": [{"id": 15, "count": 3},
                               {"id": 28, "count": 3}],
                 "further_mechanism_terminals": 0}]}}


def text_row(number, operation, label, sizes):
    """One healthy verbose key line, producer-shaped."""
    family = "ML-KEM" if label.startswith("ml_kem") else "ML-DSA"
    line = (f"  key row i0 object {number} {operation} key ({label}): "
            f"probably {family} (from mechanism); {DISPLAY[label]}")
    if sizes:
        line += f" (from {LENGTH_NOUN[operation]} length)"
    return line


def verbose(sizes):
    """One healthy verbose text: twelve key lines plus the spotlight."""
    lines = []
    number = 1
    for operation, sets in OPERATIONS:
        for label in sets:
            lines.append(text_row(number, operation, label, sizes))
            number += 1
    lines.append("  pqc keys: ML-DSA-44 ML-DSA-65 ML-DSA-87 "
                 "ML-KEM-512 ML-KEM-768 ML-KEM-1024")
    return "\n".join(lines) + "\n"


def run_judge(sizes_inv, sizes_text, nosizes_inv, nosizes_text,
              sizes_log=TRUTH_LOG, nosizes_log=TRUTH_LOG):
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
               "--sizes-exit", "0",
               "--sizes-inventory", str(tmp / "sizes.json"),
               "--sizes-inventory-exit", "0",
               "--sizes-text", str(tmp / "sizes.txt"),
               "--nosizes-log", str(tmp / "nosizes.log"),
               "--nosizes-exit", "0",
               "--nosizes-inventory", str(tmp / "nosizes.json"),
               "--nosizes-inventory-exit", "0",
               "--nosizes-text", str(tmp / "nosizes.txt"),
               "--out-results", str(tmp / "results.jsonl"),
               "--out-summary", str(tmp / "summary.txt")]
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=60)
        return completed.returncode, completed.stdout


def relabel(inv, text, sizes, operation, old, new):
    """Relabel one matrix pair consistently (row, detail and text).

    Same-family only (the family and length noun stay valid); the
    matrix pair is what breaks.
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

    def test_relabel_sign_mutation_fails_nosizes_leg(self):
        inv, text = relabel(inventory(False), verbose(False), False,
                            "sign", "ml_dsa_87", "ml_dsa_44")
        rc, summary = run_judge(inventory(True), verbose(True),
                                inv, text)
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-sizes-rows: PASS", summary)
        self.assertIn("pqc-nosizes-rows: FAIL", summary)

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

    def test_wrong_truth_fails(self):
        rc, summary = run_judge(inventory(True), verbose(True),
                                inventory(False), verbose(False),
                                sizes_log="WORKLOAD_EXIT ok=1\n")
        self.assertEqual(rc, 1, summary)
        self.assertIn("pqc-workload-truth: FAIL", summary)


if __name__ == "__main__":
    unittest.main()
