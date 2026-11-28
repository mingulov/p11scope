#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Mechanical guard-removal sweep over the canary/G4/G5 oracle guards.

Parses scripts/check-capture-evidence.py with ast, enumerates EVERY guard
statement (assert, require/uint/guard-helper bare calls, raise) in the
scope-owned oracle functions, removes each one in turn in a temp copy
(replaced by `pass`, so the mutant is exactly "this guard is gone"), and
runs the committed canary suite: the checker self-test plus the three
checker-touching test classes at both widths. Each removal must make some
test fail. A surviving removal fails the sweep and names the line.

Scope boundary (reviewed, keep in sync with the code below):
- Swept bodies: the oracle/comparison/transcription helpers and the
  surface/table/shape/canary validators (SCOPE_FUNCTIONS), all of
  validate_canary, and the validate_induced head plus its G4/G5
  branches. G1/G2/G3 branches are excluded: other gates.
- NOT swept here: module-level derivation asserts (fixed-input
  construction invariants, killed by data mutants), shared cross-gate
  helpers (exact_common, exact_counters, exact_profile_v3_selection,
  exact_capture_modules, exact_metrics_schema, uint, entry_skips bodies;
  their call sites in scope ARE swept), test assertions, fixture
  builders, and data (constant/set/tuple changes stay in the hand
  mutation sweep: AST guard removal cannot express them).

Usage:
  python3 -I tests/python/test_guard_removal_sweep.py [-v] [--workers N]
  python3 -I tests/python/test_guard_removal_sweep.py --list
  python3 -I tests/python/test_guard_removal_sweep.py --guard INDEX [--suite ...]

Bare or -v runs the unittest wrapper below (the sweep as one typed
test); explicit sweep flags keep the direct CLI.
"""

import argparse
import ast
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-capture-evidence.py"
FIXTURE = ROOT / "crates" / "discover" / "tests" / "fixture" / "version_matrix.c"
TESTFILE = ROOT / "tests" / "python" / "test_canary_evidence.py"

# Scope-owned oracle functions, in file order. Nested helpers defined
# inside them (take, anchored, pinned_line, defines) are descended into,
# and bare calls to those nested names count as guards.
SCOPE_FUNCTIONS = (
    "apply_fixture_patches",
    "first_byte_difference",
    "matrix_fixture_bytes_match_live",
    "fixture_bytes_comparison_has_no_normaliser",
    "matrix_fixture_path",
    "matrix_fixture_transcription_matches_source",
    "matrix_shape",
    "surface_signature",
    "table_signature",
    "version_canary_scan_shape",
    "exact_shape",
    "exact_matrix_observation",
    "exact_canary_surface_records",
    "exact_table_row",
    "exact_scan_baseline_row",
    "exact_scan_extra_row",
    "exact_matrix_table_rows",
    "exact_canary_discovery_skips",
    "validate_canary",
    "validate_induced",
)

# validate_induced lane branches outside this lane's gate.
INDUCED_EXCLUDE_LANES = ("G1", "G2", "G3")

# Bare Name-calls that are validation stages, besides nested helpers
# (take, anchored, pinned_line). matrix_fixture_path is deliberately
# absent: it returns a value and is never a guard.
CALL_NAMES = {
    "require",
    "uint",
    "matrix_fixture_bytes_match_live",
    "matrix_fixture_transcription_matches_source",
    "fixture_bytes_comparison_has_no_normaliser",
}
CALL_PREFIXES = ("exact_", "validate_")

CANARY_TEST_CLASSES = (
    "MatrixBuildFlagsTests",
    "VersionCanaryPrefixTests",
    "OwnedMetricsOracleTests",
)

SUITE_TIMEOUT = 600


class SweepError(Exception):
    """The sweep itself is broken (not a survivor)."""


def guard_call_name(node, nested_defs):
    """The guard name if this Expr is a bare guard call, else None."""
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
        return None
    func = node.value.func
    if not isinstance(func, ast.Name):
        return None
    name = func.id
    if name in CALL_NAMES or name in nested_defs:
        return name
    if name.startswith(CALL_PREFIXES):
        return name
    return None


def is_guard_stmt(node, nested_defs):
    return (
        isinstance(node, (ast.Assert, ast.Raise))
        or guard_call_name(node, nested_defs) is not None
    )


def nested_def_names(func_node):
    names = set()
    for node in ast.walk(func_node):
        if node is not func_node and isinstance(node, ast.FunctionDef):
            names.add(node.name)
    return names


# Names that must always be bare statements (never valid in an
# expression). exact_/validate_ and nested helpers are exempt: some also
# return values (skips = exact_canary_discovery_skips(...)), and only
# their bare calls are guards. Their validation effect is covered by the
# guards inside their own bodies, which are swept when in scope.
ALWAYS_BARE = {
    "require",
    "uint",
    "matrix_fixture_bytes_match_live",
    "matrix_fixture_transcription_matches_source",
    "fixture_bytes_comparison_has_no_normaliser",
}


def forbid_guard_calls_in_expressions(func_node):
    """An always-bare guard call inside an expression would be silently
    missed, so fail loudly instead."""
    parents = {}
    for node in ast.walk(func_node):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ALWAYS_BARE:
                parent = parents.get(node)
                if not (isinstance(parent, ast.Expr) and parent.value is node):
                    raise SweepError(
                        f"{func_node.name}:{node.lineno}: guard call "
                        f"{node.func.id} is not a bare statement"
                    )


def collect_guards(func_node):
    """All guard statements in a scope function: (lineno, end, kind, head).
    If statements are descended into, never enumerated: removing the leaf
    guard (replaced by `pass`) is exactly "this guard is gone"."""
    nested_defs = nested_def_names(func_node)
    forbid_guard_calls_in_expressions(func_node)
    guards = []

    def visit(stmts):
        for stmt in stmts:
            if is_guard_stmt(stmt, nested_defs):
                kind = (
                    "assert" if isinstance(stmt, ast.Assert)
                    else "raise" if isinstance(stmt, ast.Raise)
                    else "call:" + guard_call_name(stmt, nested_defs)
                )
                guards.append((stmt.lineno, stmt.end_lineno, kind))
            elif isinstance(stmt, ast.FunctionDef):
                visit(stmt.body)
            elif isinstance(stmt, ast.If):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.While)):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, ast.With):
                visit(stmt.body)
            elif isinstance(stmt, ast.Try):
                visit(stmt.body)
                visit(stmt.orelse)
                visit(stmt.finalbody)
                for handler in stmt.handlers:
                    visit(handler.body)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    visit(case.body)

    visit(func_node.body)
    # No other statement may share the guard's lines (single-line
    # compounds like `for x in y: require(z)` would corrupt the mutant).
    spans = [
        (n.lineno, n.end_lineno) for n in ast.walk(func_node)
        if isinstance(n, ast.stmt)
    ]
    for lineno, end, kind in guards:
        for start, stop in spans:
            if stop < lineno or start > end:
                continue
            if start <= lineno and stop >= end:
                continue  # ancestor block: fine
            raise SweepError(
                f"{func_node.name}:{lineno}: guard {kind} shares lines with "
                f"another statement ({start}-{stop})"
            )
    return guards


def induced_excluded_spans(func_node):
    """Line spans of the G1/G2/G3 branch bodies in validate_induced."""
    chain = None
    for stmt in func_node.body:
        if isinstance(stmt, ast.If):
            chain = stmt
            break
    if chain is None:
        raise SweepError("validate_induced has no lane branch chain")
    excluded = []
    seen = []
    node = chain
    while True:
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "lane"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
        ):
            raise SweepError("validate_induced lane chain has an odd test")
        lane = test.comparators[0].value
        seen.append(lane)
        if lane in INDUCED_EXCLUDE_LANES:
            excluded.append((node.body[0].lineno, node.body[-1].end_lineno))
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            node = node.orelse[0]
        else:
            break
    if seen != ["G1", "G2", "G3", "G4"]:
        raise SweepError(f"validate_induced lane chain changed: {seen}")
    return excluded


def enumerate_guards(source):
    tree = ast.parse(source)
    funcs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            funcs[node.name] = node
    guards = []
    for name in SCOPE_FUNCTIONS:
        if name not in funcs:
            raise SweepError(f"scope function {name} is gone")
        excluded = (
            induced_excluded_spans(funcs[name]) if name == "validate_induced"
            else []
        )
        for lineno, end, kind in collect_guards(funcs[name]):
            if any(start <= lineno and end <= stop for start, stop in excluded):
                continue
            guards.append((name, lineno, end, kind))
    return guards


def remove_guard(source_lines, guard):
    """Replace the guard's line range with `pass` at its indent."""
    _, lineno, end, _ = guard
    indent = source_lines[lineno - 1][
        : len(source_lines[lineno - 1]) - len(source_lines[lineno - 1].lstrip())
    ]
    return source_lines[: lineno - 1] + [f"{indent}pass\n"] + source_lines[end:]


def run(cmd, cwd, env, timeout):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, env=env,
        )
    except subprocess.TimeoutExpired:
        return None, timeout
    return proc.returncode, None


def stage_layout(checker_text, base):
    work = Path(tempfile.mkdtemp(prefix="guard-sweep-", dir=str(base)))
    scripts = work / "scripts"
    fixture_dir = work / "crates" / "discover" / "tests" / "fixture"
    scripts.mkdir(parents=True)
    fixture_dir.mkdir(parents=True)
    (scripts / "check-capture-evidence.py").write_text(checker_text, encoding="utf-8")
    shutil.copy(FIXTURE, fixture_dir / FIXTURE.name)
    return work


def run_suites(checker_text, base, suites):
    """Run the committed canary suite against a checker text.

    Returns (killed, detail): killed when some suite fails (rc != 0).
    A timeout or harness error raises SweepError.
    """
    work = stage_layout(checker_text, base)
    checker = work / "scripts" / "check-capture-evidence.py"
    results = []
    try:
        if suites in ("all", "selftest"):
            # cwd=ROOT: the self-test reads tree-relative producer
            # sources; the checker and fixture under test resolve via
            # __file__ to the temp layout.
            rc, _ = run(
                [sys.executable, "-I", str(checker), "--self-test"],
                cwd=str(ROOT),
                env={**os.environ, "TMPDIR": str(work)},
                timeout=SUITE_TIMEOUT,
            )
            if rc is None:
                raise SweepError("self-test timed out")
            results.append(("selftest", rc))
        if suites in ("all", "canary"):
            for bits in (64, 32):
                rc, _ = run(
                    [sys.executable, "-I", str(TESTFILE),
                     "--target-bits", str(bits), *CANARY_TEST_CLASSES],
                    cwd=str(ROOT),
                    env={**os.environ, "TMPDIR": str(work),
                         "P11SCOPE_CAPTURE_CHECKER_OVERRIDE": str(checker)},
                    timeout=SUITE_TIMEOUT,
                )
                if rc is None:
                    raise SweepError(f"canary{bits} timed out")
                results.append((f"canary{bits}", rc))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    failed = [name for name, rc in results if rc != 0]
    detail = ",".join(f"{name}={rc}" for name, rc in results)
    return bool(failed), detail


def main(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--guard", type=int, default=None)
    parser.add_argument("--suite", choices=("all", "selftest", "canary"),
                        default="all")
    args, _ = parser.parse_known_args(argv)
    source = CHECKER.read_text(encoding="utf-8")
    source_lines = source.splitlines(keepends=True)
    try:
        guards = enumerate_guards(source)
    except SweepError as error:
        print(f"sweep broken: {error}")
        return 2
    print(f"enumerated {len(guards)} guards in {len(SCOPE_FUNCTIONS)} functions")
    if args.list:
        for index, (func, lineno, end, kind) in enumerate(guards):
            head = source_lines[lineno - 1].strip()[:72]
            print(f"{index:3d} {func}:{lineno}-{end} {kind} :: {head}")
        return 0
    base = Path(os.environ.get("TMPDIR", "/tmp"))
    base.mkdir(parents=True, exist_ok=True)
    if args.guard is not None and not 0 <= args.guard < len(guards):
        print(f"no guard {args.guard} (0-{len(guards) - 1})")
        return 2
    selected = (
        [guards[args.guard]] if args.guard is not None else guards
    )
    # Baselines: the committed suite must be green before any removal,
    # and the temp layout must run it green unmutated.
    try:
        killed, detail = run_suites(source, base, args.suite)
    except SweepError as error:
        print(f"sweep broken: {error}")
        return 2
    if killed:
        print(f"baseline is red ({detail}): fix the suite before sweeping")
        return 2
    print(f"baseline green ({detail})")
    workers = args.workers or min(16, os.cpu_count() or 8)
    if args.guard is not None:
        workers = 1

    def one(guard):
        mutated = "".join(remove_guard(source_lines, guard))
        try:
            ast.parse(mutated)
        except SyntaxError as error:
            return (guard, "ERROR", f"mutant is not syntax: {error}")
        try:
            killed, detail = run_suites(mutated, base, args.suite)
        except SweepError as error:
            return (guard, "ERROR", str(error))
        if killed:
            return (guard, "KILLED", detail)
        return (guard, "SURVIVED", detail)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_of = {pool.submit(one, guard): guard for guard in selected}
        for future in concurrent.futures.as_completed(future_of):
            guard, status, detail = future.result()
            results.append((guard, status, detail))
            func, lineno, _, kind = guard
            extra = f" ({detail})" if args.verbose else ""
            print(f"{func}:{lineno} {kind}: {status}{extra}", flush=True)
    results.sort(key=lambda item: selected.index(item[0]))
    bad = [(g, s, d) for g, s, d in results if s != "KILLED"]
    print("----")
    for (func, lineno, _, kind), status, detail in bad:
        print(f"{status} {func}:{lineno} {kind} ({detail})")
    print(f"killed {len(results) - len(bad)}/{len(results)}; "
          f"survivors/errors: {len(bad)}")
    return 1 if bad else 0


class GuardRemovalSweepTests(unittest.TestCase):
    def test_all_guards_killed(self):
        self.assertEqual(main([]), 0)


# Sweep flags keep the direct CLI; anything else (bare, -v, unittest
# selectors) runs the unittest wrapper so the typed runner records the
# sweep as one test with terminal records.
_CLI_FLAGS = ("--workers", "--guard", "--suite", "--list", "--verbose")

if __name__ == "__main__":
    if any(arg.split("=")[0] in _CLI_FLAGS for arg in sys.argv[1:]):
        sys.exit(main(sys.argv[1:]))
    unittest.main()
