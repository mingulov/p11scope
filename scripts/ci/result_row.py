#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""The one strict validator for cell results.jsonl rows.

Every verdict gate (the per-run `check-cell-results.py` and the
cross-run `check-intermittent-bounds.py`) judges rows through this
module, so the row contract can never diverge between gates again.
A row is exactly the keys `cell/pass/qualification/detail` plus an
optional `proof` object; `cell` is a nonempty string, `pass` a
boolean, `qualification` a closed verdict, `detail` a string.
`proof` is present if and only if the qualification is one of the
two exact-proof verdicts, and its shape is validated strictly
(exact keys, exact types, positive counts): verdicts decide over
these typed proof records with exact equality, never over the
human `detail` prose.
"""

QUALIFIED = {
    "qualified",
    "command-contract",
    "owned-provider-counts",
    "owned-provider-counts-with-runner-noise",
    "owned-provider-counts-with-66-discovery-gap",
    "owned-provider-counts-with-ambient-gap",
    "owned-edge-usage-counts",
    "provider-info-exact",
    "prearm-exactness",
    "verdict-consistency",
    "semantic-names",
    "failed",
}
VALID_QUALIFICATIONS = QUALIFIED | {"nonqualifying", "expected-failure"}

# Qualifications whose verdict carries machine proof, with the exact
# proof shape each requires. Only these two may carry `proof`.
PROOF_QUALS = frozenset({"owned-edge-usage-counts", "provider-info-exact"})


def _is_int(value):
    # type() is bool-proof: isinstance(True, int) is True, and a
    # boolean count must never validate.
    return type(value) is int


def proof_problems(qualification, proof):
    """Problems with a row's proof record (empty when valid)."""
    if qualification not in PROOF_QUALS:
        if proof is None:
            return []
        return ["proof present on %s, want no proof" % qualification]
    if proof is None:
        return ["missing %s proof" % qualification]
    if not isinstance(proof, dict):
        return ["invalid %s proof: must be an object" % qualification]
    if qualification == "owned-edge-usage-counts":
        if set(proof) != {"edge_total", "caller_count"}:
            return ["invalid owned-edge-usage-counts proof: exact keys edge_total/caller_count"]
        if not _is_int(proof["edge_total"]) or proof["edge_total"] <= 0:
            return ["invalid owned-edge-usage-counts proof: edge_total positive integer"]
        if not _is_int(proof["caller_count"]) or proof["caller_count"] <= 0:
            return ["invalid owned-edge-usage-counts proof: caller_count positive integer"]
        return []
    if set(proof) != {
        "manufacturer",
        "library_major",
        "library_minor",
        "token_rows",
        "mechanism_rows",
        "slots",
    }:
        return ["invalid provider-info-exact proof: exact keys manufacturer/library/token/mechanism/slots"]
    maker = proof["manufacturer"]
    if not isinstance(maker, str) or not maker:
        return ["invalid provider-info-exact proof: manufacturer nonempty string"]
    for key in ("library_major", "library_minor"):
        if not _is_int(proof[key]) or not 0 <= proof[key] <= 255:
            return ["invalid provider-info-exact proof: %s byte 0..255" % key]
    for key in ("token_rows", "mechanism_rows", "slots"):
        if not _is_int(proof[key]) or proof[key] <= 0:
            return ["invalid provider-info-exact proof: %s positive integer" % key]
    return []


def validate_row(row):
    """Problems with one results row (empty when schema-valid).

    The row contract: exactly cell/pass/qualification/detail plus
    the optional proof object; nonempty string cell; boolean pass;
    closed qualification; string detail; proof exactly where the
    qualification requires it, with its strict shape. Callers add
    their own location (line number, run/kernel) to each problem.
    """
    if not isinstance(row, dict):
        return ["row is not an object"]
    if set(row) != {"cell", "pass", "qualification", "detail"} and set(
        row
    ) != {"cell", "pass", "qualification", "detail", "proof"}:
        return ["row must have exactly cell/pass/qualification/detail"]
    if not isinstance(row["cell"], str) or not row["cell"]:
        return ["cell must be a nonempty string"]
    if not isinstance(row["pass"], bool):
        return ["pass must be a boolean for %s" % row["cell"]]
    qualification = row["qualification"]
    if not isinstance(qualification, str) or not qualification:
        return ["qualification must be a nonempty string for %s" % row["cell"]]
    if qualification not in VALID_QUALIFICATIONS:
        return ["unknown qualification %r for %s" % (qualification, row["cell"])]
    if not isinstance(row["detail"], str):
        return ["detail must be a string for %s" % row["cell"]]
    return [
        "%s for %s" % (problem, row["cell"])
        for problem in proof_problems(qualification, row.get("proof"))
    ]
