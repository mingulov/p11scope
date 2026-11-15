#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Validate a cell-script results.jsonl file.

Each line must be one JSON object with exactly the keys cell, pass,
qualification and detail. Qualification is a closed set: qualified,
command-contract, owned-provider-counts,
owned-provider-counts-with-runner-noise,
owned-provider-counts-with-66-discovery-gap,
owned-provider-counts-with-ambient-gap, owned-edge-usage-counts,
prearm-exactness, verdict-consistency, semantic-names and failed are
qualified and every qualified row must pass (with owned-edge-usage-counts
requiring its proof fields in detail); nonqualifying smoke may pass or
fail but every nonqualifying row must be allow-listed and the allow-list
must equal the nonqualifying set; expected-failure must equal its
declared list and an expected failure that passes is a failure. An
--intermittent-failure cell fails only sometimes with a known signature:
its row must appear and may be a passing qualified row or a non-passing
expected-failure row, never a failed row or an unexpected pass. Every
--require cell must appear, so a dropped row fails.

Usage:
  python3 -I scripts/ci/check-cell-results.py RESULTS.JSONL [--expected-failure CELL ...] [--intermittent-failure CELL ...] [--allow-nonqualifying CELL ...] [--require CELL ...]
"""

import json
import re
import sys
from pathlib import Path


def fail(message):
    print(f"check-cell-results: {message}", file=sys.stderr)
    return 1


QUALIFIED = {"qualified", "command-contract", "owned-provider-counts",
             "owned-provider-counts-with-runner-noise",
             "owned-provider-counts-with-66-discovery-gap",
             "owned-provider-counts-with-ambient-gap",
             "owned-edge-usage-counts", "prearm-exactness",
             "verdict-consistency", "semantic-names", "failed"}
VALID_QUALIFICATIONS = QUALIFIED | {"nonqualifying", "expected-failure"}
OWNED_EDGE_USAGE_DETAIL = re.compile(
    r"owned per-edge usage and streamed edge totals match the independent ledger "
    r"total ([0-9]+) over ([0-9]+) workload callers; "
    r"per-caller attribution is by caller pid"
)


def has_owned_edge_usage_proof(detail):
    match = OWNED_EDGE_USAGE_DETAIL.search(detail)
    return match is not None and int(match.group(1)) > 0 and int(match.group(2)) > 0


def main(argv):
    expected = []
    intermittent = []
    allowed_smoke = []
    required = []
    positional = []
    iterator = iter(argv)
    for token in iterator:
        if token == "--expected-failure":
            try:
                expected.append(next(iterator))
            except StopIteration:
                return fail("--expected-failure needs a cell name")
        elif token == "--intermittent-failure":
            try:
                intermittent.append(next(iterator))
            except StopIteration:
                return fail("--intermittent-failure needs a cell name")
        elif token == "--allow-nonqualifying":
            try:
                allowed_smoke.append(next(iterator))
            except StopIteration:
                return fail("--allow-nonqualifying needs a cell name")
        elif token == "--require":
            try:
                required.append(next(iterator))
            except StopIteration:
                return fail("--require needs a cell name")
        elif token.startswith("-"):
            return fail(f"unknown option: {token}")
        else:
            positional.append(token)
    if len(positional) != 1:
        return fail("usage: check-cell-results.py RESULTS.JSONL [--expected-failure CELL ...] [--intermittent-failure CELL ...] [--allow-nonqualifying CELL ...] [--require CELL ...]")
    path = Path(positional[0])
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return fail(f"missing results file: {path}")
    except OSError as error:
        return fail(f"cannot read {path}: {error}")
    rows = []
    seen = set()
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            problems.append(f"line {number}: invalid JSON: {error}")
            continue
        if not isinstance(row, dict):
            problems.append(f"line {number}: row is not an object")
            continue
        if set(row) != {"cell", "pass", "qualification", "detail"}:
            problems.append(f"line {number}: row must have exactly cell/pass/qualification/detail")
            continue
        cell = row["cell"]
        passed = row["pass"]
        qualification = row["qualification"]
        detail = row["detail"]
        if not isinstance(cell, str) or not cell:
            problems.append(f"line {number}: cell must be a nonempty string")
            continue
        if cell in seen:
            problems.append(f"line {number}: duplicate cell {cell}")
            continue
        seen.add(cell)
        if not isinstance(passed, bool):
            problems.append(f"line {number}: pass must be a boolean for {cell}")
            continue
        if not isinstance(qualification, str) or not qualification:
            problems.append(f"line {number}: qualification must be a nonempty string for {cell}")
            continue
        if qualification not in VALID_QUALIFICATIONS:
            problems.append(f"line {number}: unknown qualification {qualification!r} for {cell}")
            continue
        if not isinstance(detail, str):
            problems.append(f"line {number}: detail must be a string for {cell}")
            continue
        rows.append(row)
    if not rows and not problems:
        return fail("no result rows")
    for row in rows:
        cell = row["cell"]
        passed = row["pass"]
        qualification = row["qualification"]
        detail = row["detail"][:200]
        if qualification == "expected-failure":
            status = "EXPECTED-FAIL" if not passed else "UNEXPECTED-PASS"
            print(f"{status} {cell} {detail}")
            if passed:
                problems.append(f"unexpected pass for expected failure {cell}")
        elif qualification == "nonqualifying":
            status = "PASS" if passed else "SMOKE"
            print(f"{status} {cell} {detail}")
            if cell not in set(allowed_smoke):
                problems.append(f"nonqualifying cell not in allow list: {cell}")
        else:
            missing_proof = (
                qualification == "owned-edge-usage-counts"
                and not has_owned_edge_usage_proof(row["detail"])
            )
            status = "PASS" if (passed and not missing_proof) else "FAIL"
            print(f"{status} {cell} {detail}")
            if not passed:
                problems.append(f"failed qualified cell {cell}")
            if qualification == "failed" and passed:
                problems.append(f"inconsistent row for {cell}: pass with failed qualification")
            if missing_proof:
                problems.append(f"missing owned-edge-usage-counts proof fields for {cell}")
    actual = sorted(row["cell"] for row in rows if row["qualification"] == "expected-failure")
    wanted = sorted(set(expected))
    if len(wanted) != len(expected):
        problems.append("duplicate --expected-failure names")
    if len(set(intermittent)) != len(intermittent):
        problems.append("duplicate --intermittent-failure names")
    both = sorted(set(intermittent) & set(expected))
    if both:
        problems.append("cells declared both expected and intermittent: " + ", ".join(both))
    # Intermittent cells may land either way: never part of the exact
    # expected-failure set, but their rows must be present.
    actual = [cell for cell in actual if cell not in set(intermittent)]
    missing_intermittent = sorted(set(intermittent) - seen)
    if missing_intermittent:
        problems.append("missing intermittent cells: " + ", ".join(missing_intermittent))
    if len(set(allowed_smoke)) != len(allowed_smoke):
        problems.append("duplicate --allow-nonqualifying names")
    if len(set(required)) != len(required):
        problems.append("duplicate --require names")
    if actual != wanted:
        missing = sorted(set(wanted) - set(actual))
        extra = sorted(set(actual) - set(wanted))
        if missing:
            problems.append("missing expected failures: " + ", ".join(missing))
        if extra:
            problems.append("undeclared expected failures: " + ", ".join(extra))
    actual_smoke = {row["cell"] for row in rows if row["qualification"] == "nonqualifying"}
    missing_smoke = sorted(set(allowed_smoke) - actual_smoke)
    if missing_smoke:
        problems.append("missing nonqualifying: " + ", ".join(missing_smoke))
    missing_required = sorted(set(required) - seen)
    if missing_required:
        problems.append("missing required cells: " + ", ".join(missing_required))
    if problems:
        for problem in problems:
            print(f"check-cell-results: {problem}", file=sys.stderr)
        return 1
    landed = sum(
        1 for row in rows
        if row["cell"] in set(intermittent) and row["qualification"] == "expected-failure"
    )
    if intermittent:
        print(f"check-cell-results: {len(rows)} rows ok ({len(actual)} expected failures, "
              f"{landed} of {len(set(intermittent))} intermittent failures)")
    else:
        print(f"check-cell-results: {len(rows)} rows ok ({len(actual)} expected failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
