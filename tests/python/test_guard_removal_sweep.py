#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Mechanical guard-removal sweep over the canary/G4/G5 oracle guards.

Parses scripts/check-capture-evidence.py with ast, derives the swept
function scope MECHANICALLY as the call-graph closure from the lane
entry points (validate_canary, validate_induced) plus the functions
called by unconditional module-level statements (import-time
derivation), enumerates EVERY guard statement (assert,
require/uint/guard-helper bare calls, raise) in that scope, removes
each one in turn in a temp copy (replaced by `pass`, so the mutant is
exactly "this guard is gone"), and runs the committed canary suite:
the checker self-test plus the three checker-touching test classes at
both widths. Each removal must make some test fail. A surviving removal
fails the sweep and names the line. There is no hand-named function
list: a validator the entries can reach is swept, whatever its name.

Scope boundary (mechanical, keep in sync with the code below):
- Roots: the lane entries, functions called by unconditional
  module-level statements (import-time derivation; main() is excluded
  by construction, called only under `if __name__`), and the
  fixture-oracle family by naming convention.
- Closure members under the lane-domain naming convention get
  per-guard removal checks (this lane owns their diagnostic
  precision). Every other closure member is a platform validator this
  lane uses but does not own: allowlisted with external callers
  printed as supporting evidence. Their internals belong to owning
  lanes (own tests, own staging, own messages); this lane pins their
  behavior on its paths instead: every platform stage called from a
  swept function is itself a swept call-site guard (it cannot be
  dropped silently), and the lane's black-box negatives prove refusal
  of invalid lane inputs through them.
- validate_induced's own statements keep the shared head/tail plus the
  lane branches that reach exact_matrix_observation (the matrix-oracle
  seam); other lane branches are other gates. The kept/dropped
  partition is printed by --list for audit.
- NOT swept here: test assertions, fixture builders, CLI handling, and
  data (constant/set/tuple changes stay in the hand data sweep: AST
  guard removal cannot express them).

Usage:
  python3 -I tests/python/test_guard_removal_sweep.py [-v] [--workers N]
  python3 -I tests/python/test_guard_removal_sweep.py --list
  python3 -I tests/python/test_guard_removal_sweep.py --guard INDEX [--suite ...]
"""

import argparse
import ast
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check-capture-evidence.py"
FIXTURE = ROOT / "crates" / "discover" / "tests" / "fixture" / "version_matrix.c"
TESTFILE = ROOT / "tests" / "python" / "test_canary_evidence.py"

# Lane entry points whose call-graph closure is swept. Nested helpers
# defined inside swept functions are descended into, and bare calls to
# those nested names count as guards.
ENTRY_POINTS = ("validate_canary", "validate_induced")

# Fixture-drift oracle family (self-test-time oracles over fixed inputs,
# killed by committed drift rows): swept as roots by naming convention,
# since the entries never call them. The convention is load-bearing.
ORACLE_PREFIXES = ("matrix_fixture_", "fixture_bytes_")

# Lane-domain naming convention: closure members under these names get
# per-guard removal checks (this lane owns their diagnostic precision);
# every other closure member gets a whole-function weakening check
# instead (behavioral coverage without owning another lane's staging).
# Nothing is unverified either way: a survivor in either tier fails.
LANE_PREFIXES = (
    "validate_canary",
    "validate_induced",
    "validate_object_canary_",
    "exact_canary_",
    "exact_matrix_",
    "exact_scan_",
    "exact_shape",
    "exact_table_",
    "version_canary_",
    "matrix_fixture_",
    "fixture_bytes_",
    "apply_fixture_",
    "first_byte_difference",
    "surface_signature",
    "table_signature",
    "matrix_shape",
    "expected_scan_agreement",
    "derive_matrix_",
)

# The matrix-oracle seam: validate_induced lane branches reaching it are
# this lane's (canary/G4/G5 validate the version-matrix provider through
# it); branches that never reach it are other gates.
MATRIX_SEAM = "exact_matrix_observation"

# Module entry points, named structurally (not scope members): the test
# suite entry seeds test-only code, and the CLI entry stays a gate even
# though self-test invokes it (otherwise every CLI-dispatched validator
# would misclassify as test-only). Calls from test-only code never make
# a helper shared: tests exercise gates; they are not gates.
TEST_ENTRY = "self_test"
MAIN_ENTRY = "main"

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


def local_callees(func_node, funcs):
    """Module-level function names called anywhere inside func_node."""
    names = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in funcs:
                names.add(node.func.id)
    return names


def module_level_roots(tree, funcs):
    """Functions called by unconditional module-level statements: the
    import-time derivation whose outputs the validators consume. Calls
    under `if`/`try`/etc. (like main()) are not derivation."""
    roots = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign,
                              ast.AugAssign, ast.Assert)):
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in funcs):
                    roots.add(node.func.id)
    return roots


def closure_scope(tree, funcs):
    """Swept roots and their transitive closure. Roots: the lane entries,
    functions called by unconditional module-level statements (import-time
    derivation), and the fixture-oracle family by naming convention. The
    closure from validate_induced follows only kept statements (shared
    head/tail plus matrix-reaching lane branches), so other gates'
    exclusive helpers never enter. Returns
    (roots, scope, dropped_spans, branch_labels)."""
    for name in ENTRY_POINTS:
        if name not in funcs:
            raise SweepError(f"entry point {name} is gone")
    if MATRIX_SEAM not in funcs:
        raise SweepError(f"matrix seam {MATRIX_SEAM} is gone")
    if TEST_ENTRY not in funcs:
        raise SweepError(f"test entry {TEST_ENTRY} is gone")
    family = {n for n in funcs if n.startswith(ORACLE_PREFIXES)}
    if not family:
        raise SweepError("fixture-oracle family is empty")
    roots = set(ENTRY_POINTS) | module_level_roots(tree, funcs) | family
    dropped, labels = induced_dropped_spans(funcs["validate_induced"], funcs)

    def seed_calls(stmts, spans):
        names = set()
        for sub in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id in funcs
                    and not any(start <= sub.lineno and sub.end_lineno <= stop
                                for start, stop in spans)):
                names.add(sub.func.id)
        return names

    seen, stack = set(roots), []
    for name in roots:
        spans = dropped if name == "validate_induced" else []
        stack.extend(seed_calls(funcs[name].body, spans) - seen)
    # Module-level unconditional statements seed derivation callers too.
    for stmt in tree.body:
        if isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign,
                              ast.AugAssign, ast.Assert)):
            stack.extend(seed_calls([stmt], []) - seen)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(local_callees(funcs[name], funcs) - seen)
    return roots, seen, dropped, labels


def caller_map(funcs):
    """Reverse call graph over module-level function definitions."""
    callers = {name: set() for name in funcs}
    for caller, node in funcs.items():
        for name in local_callees(node, funcs):
            callers[name].add(caller)
    return callers


def test_only(funcs, scope):
    """Functions provably called only from tests: the fixpoint seeded at
    the test entry over non-empty caller sets. Other lanes' validators
    stay gates even when self-test exercises them (main/CLI calls them
    too); a function with no callers at all never qualifies."""
    callers = caller_map(funcs)
    tests = {TEST_ENTRY}
    while True:
        more = {
            name for name in funcs
            if name not in scope
            and name not in tests
            and name != MAIN_ENTRY
            and callers[name]
            and callers[name] <= tests
        }
        if not more:
            return tests - {TEST_ENTRY}
        tests |= more


def lane_owned(name):
    """Lane-domain naming convention (see LANE_PREFIXES)."""
    return name.startswith(LANE_PREFIXES)


def shared_allowlist(funcs, scope):
    """Closure members outside the lane-domain convention: platform
    validators this lane uses but does not own. Each carries its
    external callers as supporting evidence (empty does not matter:
    the convention, not the callers, draws this line)."""
    for name in ENTRY_POINTS:
        if not lane_owned(name):
            raise SweepError(f"entry point {name} left the lane convention")
    callers = caller_map(funcs)
    tests = test_only(funcs, scope) | {TEST_ENTRY}
    allow = {}
    for name in sorted(scope):
        if lane_owned(name):
            continue
        outside = sorted(
            c for c in callers[name]
            if c not in scope and c not in tests
        )
        allow[name] = outside
    return allow


def induced_dropped_spans(func_node, funcs):
    """Line spans of validate_induced lane branches that never reach the
    matrix seam. Returns (dropped spans, kept/dropped branch labels)."""
    def reaches_seam(stmts):
        seen, stack = set(), []
        for sub in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id in funcs):
                stack.append(sub.func.id)
        while stack:
            callee = stack.pop()
            if callee in seen:
                continue
            seen.add(callee)
            if callee == MATRIX_SEAM:
                return True
            stack.extend(local_callees(funcs[callee], funcs) - seen)
        return False

    def is_lane_test(test):
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "lane"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
        )

    dropped, labels = [], []
    for stmt in func_node.body:
        if not isinstance(stmt, ast.If) or not is_lane_test(stmt.test):
            continue
        node = stmt
        while True:
            lane = node.test.comparators[0].value
            reaches = reaches_seam(node.body)
            labels.append((lane, reaches))
            if not reaches:
                dropped.append(
                    (node.body[0].lineno, node.body[-1].end_lineno))
            if (len(node.orelse) == 1
                    and isinstance(node.orelse[0], ast.If)
                    and is_lane_test(node.orelse[0].test)):
                node = node.orelse[0]
            else:
                break
        if node.orelse:
            reaches = reaches_seam(node.orelse)
            labels.append(("else", reaches))
            if not reaches:
                dropped.append(
                    (node.orelse[0].lineno, node.orelse[-1].end_lineno))
    return dropped, labels


def enumerate_guards(source):
    tree = ast.parse(source)
    funcs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            funcs[node.name] = node
    roots, scope, dropped, labels = closure_scope(tree, funcs)
    allow = shared_allowlist(funcs, scope)
    swept = scope - set(allow)
    guards = []
    for name in [n for n in funcs if n in swept]:
        excluded = dropped if name == "validate_induced" else []
        for lineno, end, kind in collect_guards(funcs[name]):
            if any(start <= lineno and end <= stop for start, stop in excluded):
                continue
            guards.append((name, lineno, end, kind))
    guards.sort(key=lambda g: (list(funcs).index(g[0]), g[1]))
    info = {"labels": labels, "allowlist": allow, "scope": scope,
            "roots": roots}
    return guards, info


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
        guards, info = enumerate_guards(source)
    except SweepError as error:
        print(f"sweep broken: {error}")
        return 2
    allow = info["allowlist"]
    funcs = {name for name, _, _, _ in guards}
    print(f"enumerated {len(guards)} guards in {len(funcs)} functions; "
          f"scope {len(info['scope'])} functions, "
          f"allowlist {len(allow)} shared helpers")
    print("induced lane branches: " + ", ".join(
        f"{lane}={'kept' if reaches else 'dropped'}"
        for lane, reaches in info["labels"]))
    if args.list:
        for index, (func, lineno, end, kind) in enumerate(guards):
            head = source_lines[lineno - 1].strip()[:72]
            print(f"{index:3d} {func}:{lineno}-{end} {kind} :: {head}")
        print("---- allowlist (shared: also called from outside the lane) ----")
        for name in sorted(allow):
            print(f"allow {name} <- {', '.join(allow[name])}")
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
