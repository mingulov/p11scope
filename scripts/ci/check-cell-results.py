#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate a cell-script results.jsonl file.

Each line must be one JSON object with exactly the keys cell, pass,
qualification and detail. A row is qualified unless its qualification is
nonqualifying or expected-failure. Every qualified row must pass. The set
of expected-failure cells must equal the declared list; an expected
failure that passes is a failure (the fix must be recorded by removing
it from the list). Nonqualifying smoke may pass or fail without failing
the job; when --allow-nonqualifying is given, only the listed cells may
be nonqualifying, so a qualified cell cannot hide a failure behind smoke.

Usage:
  python3 -I scripts/ci/check-cell-results.py RESULTS.JSONL [--expected-failure CELL ...] [--allow-nonqualifying CELL ...]
"""

import json
import sys
from pathlib import Path


def fail(message):
    print(f"check-cell-results: {message}", file=sys.stderr)
    return 1


def main(argv):
    expected = []
    allowed_smoke = []
    positional = []
    iterator = iter(argv)
    for token in iterator:
        if token == "--expected-failure":
            try:
                expected.append(next(iterator))
            except StopIteration:
                return fail("--expected-failure needs a cell name")
        elif token == "--allow-nonqualifying":
            try:
                allowed_smoke.append(next(iterator))
            except StopIteration:
                return fail("--allow-nonqualifying needs a cell name")
        elif token.startswith("-"):
            return fail(f"unknown option: {token}")
        else:
            positional.append(token)
    if len(positional) != 1:
        return fail("usage: check-cell-results.py RESULTS.JSONL [--expected-failure CELL ...] [--allow-nonqualifying CELL ...]")
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
            if allowed_smoke and cell not in set(allowed_smoke):
                problems.append(f"nonqualifying cell not in allow list: {cell}")
        else:
            status = "PASS" if passed else "FAIL"
            print(f"{status} {cell} {detail}")
            if not passed:
                problems.append(f"failed qualified cell {cell}")
            if qualification == "failed" and passed:
                problems.append(f"inconsistent row for {cell}: pass with failed qualification")
    actual = sorted(row["cell"] for row in rows if row["qualification"] == "expected-failure")
    wanted = sorted(set(expected))
    if len(wanted) != len(expected):
        problems.append("duplicate --expected-failure names")
    if len(set(allowed_smoke)) != len(allowed_smoke):
        problems.append("duplicate --allow-nonqualifying names")
    if actual != wanted:
        missing = sorted(set(wanted) - set(actual))
        extra = sorted(set(actual) - set(wanted))
        if missing:
            problems.append("missing expected failures: " + ", ".join(missing))
        if extra:
            problems.append("undeclared expected failures: " + ", ".join(extra))
    if problems:
        for problem in problems:
            print(f"check-cell-results: {problem}", file=sys.stderr)
        return 1
    print(f"check-cell-results: {len(rows)} rows ok ({len(actual)} expected failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
