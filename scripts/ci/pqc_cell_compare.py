#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Judge the PQC CI cell (scripts/ci/pqc-cell.sh).

Both legs run the same workload (ML-DSA-44/65/87 + ML-KEM-512/768/1024,
each generated once and used once) under `inventory --pid
--key-operations`, once with `--key-sizes` and once without. This judge
requires, per leg: the workload's exact known counts and FIPS lengths;
the four PQC mechanism rows with exact call counts; twelve per-key rows
whose metadata label, inferred family and (sizes leg) inferred parameter
set name the exact set; six generate_key_pair completions and no other
unknown row; no before_semantic_boundary gap; and the verbose text
showing family + parameter set on every PQC key row plus the `pqc keys:`
spotlight with all six sets. Anything missing fails: no skip counts as
a pass.

Usage:
  pqc_cell_compare.py --sizes-log F --sizes-exit N --sizes-inventory F
      --sizes-text F --nosizes-log F --nosizes-exit N --nosizes-inventory F
      --nosizes-text F --out-results F --out-summary F
"""

import json
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
WANT_OP_COMPLETED = {"sign": 3, "verify": 3, "encapsulate": 3, "decapsulate": 3}
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
WANT_SPOTLIGHT = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                  "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")


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
    for mid, (name, calls) in WANT_MECHS.items():
        row = mechs.get(mid)
        if row is None:
            fail.add(leg, f"mechanism {mid} ({name}) missing")
            continue
        if row.get("name") != name:
            fail.add(leg, f"mechanism {mid} name {row.get('name')!r}, want {name!r}")
        if row.get("calls") != calls:
            fail.add(leg, f"mechanism {mid} calls={row.get('calls')}, want {calls}")
        if row.get("errors") != 0:
            fail.add(leg, f"mechanism {mid} errors={row.get('errors')}, want 0")
    for mid, row in sorted(mechs.items(), key=lambda kv: str(kv[0])):
        if row.get("errors") != 0:
            fail.add(leg, f"mechanism {mid} errors={row.get('errors')}, want 0")


def check_key_rows(fail, leg, inv, sizes):
    oo = inv.get("object_observations", {})
    rows = [r for r in oo.get("key_operations", [])
            if r.get("category") in PQC_OPS]
    if len(rows) != 12:
        fail.add(leg, f"{len(rows)} PQC key rows, want 12")
    done = {}
    for row in rows:
        done[row.get("category")] = done.get(row.get("category"), 0) + row.get("completed", 0)
    for op, want in sorted(WANT_OP_COMPLETED.items()):
        if done.get(op, 0) != want:
            fail.add(leg, f"{op} completed={done.get(op, 0)}, want {want}")
    seen_labels = set()
    for row in rows:
        where = (f"{leg} row {row.get('instance')}/{row.get('object')}/"
                 f"{row.get('category')}")
        if row.get("failed") != 0:
            fail.add(leg, f"{where} failed={row.get('failed')}, want 0")
        label = row.get("metadata_at_use")
        if label not in LABEL_FAMILY:
            fail.add(leg, f"{where} metadata_at_use={label!r}, want a PQC set")
            continue
        seen_labels.add(label)
        fam = row.get("inferred_family", {})
        if fam.get("status") != "inferred" or fam.get("value") != LABEL_FAMILY[label]:
            fail.add(leg, f"{where} family={fam!r}, want inferred "
                           f"{LABEL_FAMILY[label]}")
        size = row.get("inferred_size", {})
        if sizes:
            detail = size.get("detail") or {}
            if (size.get("status") != "inferred"
                    or detail.get("kind") != "pqc_set"
                    or detail.get("parameter_set") != label
                    or detail.get("octets") != LABEL_OCTETS[label]
                    or detail.get("evidence") != OP_EVIDENCE[row.get("category")]):
                fail.add(leg, f"{where} size={size!r}, want inferred {label}")
        elif size.get("status") != "unknown" or size.get("detail") is not None:
            fail.add(leg, f"{where} size={size!r}, want unknown without detail")
    if seen_labels != set(LABEL_FAMILY):
        fail.add(leg, f"labels seen {sorted(seen_labels)}, want all six sets")
    unknown = oo.get("unknown_key_operations", [])
    if len(unknown) != 1:
        fail.add(leg, f"{len(unknown)} unknown rows, want exactly the keygen row")
    else:
        row = unknown[0]
        if (row.get("category") != "generate_key_pair"
                or row.get("completed") != 6
                or row.get("reason") != "not_applicable"):
            fail.add(leg, f"unknown row {row!r}, want 6 not_applicable keygens")


def gap_reasons(holders):
    reasons = []
    for gaps in holders:
        rows = gaps.get("rows", []) if isinstance(gaps, dict) else gaps
        for gap in rows or []:
            if isinstance(gap, dict):
                reasons.append(str(gap.get("reason", "")))
            else:
                reasons.append(str(gap))
    return reasons


def check_gaps(fail, leg, inv):
    holders = [inv.get("gaps", []),
               inv.get("object_observations", {}).get("gaps", [])]
    for reason in gap_reasons(holders):
        if "before_semantic_boundary" in reason:
            fail.add(leg, "before_semantic_boundary gap present: "
                          "ops ran before attach")


def check_text(fail, leg, text_path, sizes):
    lines = Path(text_path).read_text(encoding="utf-8").splitlines()
    key_rows = [ln for ln in lines if ln.startswith("  key row ")]
    pqc_rows = [ln for ln in key_rows
                if any(f" {op} " in ln for op in PQC_OPS)]
    if len(pqc_rows) != 12:
        fail.add(leg, f"text has {len(pqc_rows)} PQC key rows, want 12")
    for ln in pqc_rows:
        if "(ml_kem_" not in ln and "(ml_dsa_" not in ln:
            fail.add(leg, f"text row lacks a PQC label: {ln[:120]}")
        if ("probably ML-KEM (from mechanism)" not in ln
                and "probably ML-DSA (from mechanism)" not in ln):
            fail.add(leg, f"text row lacks a PQC family: {ln[:120]}")
        if sizes and ("(from ciphertext length)" not in ln
                      and "(from signature length)" not in ln):
            fail.add(leg, f"text row lacks a length set: {ln[:120]}")
    spot = [ln for ln in lines if ln.startswith("  pqc keys: ")]
    if len(spot) != 1:
        fail.add(leg, f"{len(spot)} `pqc keys:` lines, want 1")
    else:
        for display in WANT_SPOTLIGHT:
            if display not in spot[0]:
                fail.add(leg, f"spotlight lacks {display}")


def judge_leg(fail, leg, args, sizes):
    # A judge bug must fail loudly with results written, never as a bare
    # traceback with no results file (the wrapper then reports only that
    # the file is missing).
    try:
        inv = load_inventory(fail, leg, args[f"{leg}_inventory"],
                             int(args[f"{leg}_inventory_exit"]))
        if inv is None:
            return
        check_mechanisms(fail, leg, inv)
        check_key_rows(fail, leg, inv, sizes)
        check_gaps(fail, leg, inv)
        check_text(fail, leg, args[f"{leg}_text"], sizes)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        fail.add(leg, f"judge error: {exc!r}")


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
        judge_leg(sizes_fail, "sizes", args, True)
        nosizes_fail = Failures()
        judge_leg(nosizes_fail, "nosizes", args, False)
    except (OSError, ValueError) as exc:
        print(f"pqc_cell_compare: harness error: {exc}", file=sys.stderr)
        return 2
    rows = [
        {"cell": "pqc-workload-truth", "pass": truth_fail.ok(),
         "qualification": "qualified",
         "detail": ("both legs ran 3+3 PQC keypairs with exact counts and "
                    "FIPS lengths" if truth_fail.ok()
                    else "; ".join(truth_fail.problems))},
        {"cell": "pqc-sizes-rows", "pass": sizes_fail.ok(),
         "qualification": "qualified",
         "detail": ("12 key rows carry family + template label + length set; "
                    "6 keygens; 4 mechanism rows exact; no pre-boundary gap"
                    if sizes_fail.ok()
                    else "; ".join(sizes_fail.problems))},
        {"cell": "pqc-nosizes-rows", "pass": nosizes_fail.ok(),
         "qualification": "qualified",
         "detail": ("12 key rows carry family + template label; 6 keygens; "
                    "4 mechanism rows exact; no pre-boundary gap"
                    if nosizes_fail.ok()
                    else "; ".join(nosizes_fail.problems))},
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
