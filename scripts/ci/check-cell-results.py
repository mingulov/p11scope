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

import importlib.util
import json
import re
import subprocess
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
    known_results = []
    known_runner = []
    known_host = []
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
        elif token == "--known-failing-results":
            try:
                known_results.append(next(iterator))
            except StopIteration:
                return fail("--known-failing-results needs a path")
        elif token == "--known-failing-runner":
            try:
                known_runner.append(next(iterator))
            except StopIteration:
                return fail("--known-failing-runner needs a runner")
        elif token == "--known-failing-host":
            try:
                known_host.append(next(iterator))
            except StopIteration:
                return fail("--known-failing-host needs a host")
        elif token == "--require":
            try:
                required.append(next(iterator))
            except StopIteration:
                return fail("--require needs a cell name")
        elif token.startswith("-"):
            return fail(f"unknown option: {token}")
        else:
            positional.append(token)
    if len(known_results) != len(known_runner) or len(known_results) != len(known_host) or len(known_results) > 1:
        return fail("--known-failing-results, --known-failing-runner and --known-failing-host must appear together at most once")
    if len(positional) != 1:
        return fail("usage: check-cell-results.py RESULTS.JSONL [--expected-failure CELL ...] [--intermittent-failure CELL ...] [--allow-nonqualifying CELL ...] [--require CELL ...] [--known-failing-results PATH --known-failing-runner RUNNER --known-failing-host HOST]")
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
    typed_selection = []
    if known_results:
        selected_seen = set()
        for group in (required, expected, intermittent, allowed_smoke):
            for cell in group:
                if cell in selected_seen:
                    problems.append(f"typed selection overlap: {cell}")
                    continue
                selected_seen.add(cell)
                typed_selection.append(cell)
        if not typed_selection:
            problems.append("typed selection is empty")
        outside_selection = sorted(set(seen) - set(typed_selection))
        if outside_selection:
            problems.append("rows outside the typed selection: " + ", ".join(outside_selection))
    if rows and known_results:
        emit_error = emit_known_failing_results(
            rows, Path(known_results[0]), known_runner[0], known_host[0], typed_selection, path.parent)
        if emit_error is not None:
            problems.append(emit_error)
        else:
            checker = Path(__file__).resolve().parents[2] / "scripts" / "check-known-failing.py"
            judged = subprocess.run(
                [sys.executable, "-I", str(checker), "--results", str(known_results[0])],
                text=True)
            if judged.returncode != 0:
                problems.append("known-failing ledger judgment failed")
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


def ignored_test_files():
    registry_path = Path(__file__).resolve().parents[2] / "tests" / "ignored-tests.json"
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    files = {}
    ambiguous = set()
    for site in registry.get("sites", []):
        if not isinstance(site, dict):
            continue
        test = site.get("path")
        file_name = site.get("file")
        if not isinstance(test, str) or not isinstance(file_name, str):
            continue
        if test in files and files[test] != file_name:
            ambiguous.add(test)
        files.setdefault(test, file_name)
    for test in ambiguous:
        files.pop(test, None)
    return files


def known_failing_checker_module():
    path = Path(__file__).resolve().parents[2] / "scripts/check-known-failing.py"
    spec = importlib.util.spec_from_file_location("known_failing_checker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cell_sidecar_signature(result_dir, cell):
    if result_dir is None:
        return None, None
    path = result_dir / f"{cell}.typed-failure.json"
    if not path.exists():
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, f"typed failure record for {cell} is missing or invalid JSON"
    checker = known_failing_checker_module()
    problems = checker.signature_problems(value)
    if isinstance(value, dict) and "branch" not in value:
        problems.append("signature lacks a typed branch")
    if problems:
        return None, f"typed failure record for {cell} is not a typed signature: " + "; ".join(problems)
    return value, None


def emit_known_failing_results(rows, output, runner, host, selected_cells, result_dir=None):
    """Write typed selection/results for an independently declared cell set."""
    if not runner.startswith("cell:") or len(runner) <= len("cell:"):
        return "known-failing runner for cell results must be cell:<script>"
    if host not in {"fedora", "fedora-sm1", "vng", "github"}:
        return "known-failing host is not in the closed host vocabulary"
    if not selected_cells:
        return "typed selection is empty"
    if len(set(selected_cells)) != len(selected_cells):
        return "typed selection is duplicated"
    root = Path(__file__).resolve().parents[2]
    test_files = ignored_test_files()
    runner_path = runner[len("cell:"):]
    runner_file_ok = bool(runner_path) and not runner_path.startswith("/") and (root / runner_path).is_file()

    def identity(cell):
        path = test_files.get(cell)
        if path is None:
            if not runner_file_ok:
                return None
            path = runner_path
        return {"path": path, "test": cell, "invocation": []}

    selection = []
    for cell in selected_cells:
        item = identity(cell)
        if item is None:
            return f"cannot type the source path for cell {cell}: not in ignored-tests and runner file is absent"
        selection.append(item)

    results = []
    covered = set()
    for row in rows:
        cell = row["cell"]
        item = identity(cell)
        if item is None:
            return f"cannot type the source path for cell {cell}: not in ignored-tests and runner file is absent"
        covered.add(cell)
        qualification = row["qualification"]
        sidecar, sidecar_error = cell_sidecar_signature(result_dir, cell)
        if sidecar_error is not None:
            return sidecar_error
        if qualification == "nonqualifying":
            if sidecar is not None:
                return f"nonqualifying cell {cell} carries a typed failure record"
            state = "not_applicable"
            signature = {"cell": cell, "qualification": qualification}
        elif row["pass"]:
            if sidecar is not None:
                return f"passing cell {cell} carries a typed failure record"
            state = "passed"
            signature = None
        else:
            state = "failed"
            signature = sidecar if sidecar is not None else {"cell": cell, "qualification": qualification}
        results.append({**item, "state": state, "signature": signature})
    selected = set(selected_cells)
    complete = covered == selected and len(covered) == len(results)
    document = {
        "schema": "p11scope/known-failing-results/v1",
        "runner": runner,
        "host": host,
        "complete": complete,
        "selection": selection,
        "results": results,
    }
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except OSError as error:
        return f"cannot write typed known-failing results: {error}"
    return None


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
