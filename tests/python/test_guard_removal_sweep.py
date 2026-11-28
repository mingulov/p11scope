#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Mechanical guard-removal sweep over the canary/G4/G5 oracle guards.

Parses scripts/check-capture-evidence.py with ast, derives the swept
function scope MECHANICALLY as the call-graph closure from the lane
entry points (validate_canary, validate_induced) plus the functions
called by unconditional module-level statements (import-time
derivation) and the fixture-oracle family by naming convention, then
collects EVERY guard statement (assert, require/uint/guard-helper
bare calls, raise) in that scope — including other lanes' branches
of validate_induced. Each collected guard is removed in turn in a
temp copy (replaced by `pass`, so the mutant is exactly "this guard
is gone") and run against the committed canary suite: the checker
self-test plus the three checker-touching test classes at both
widths. There is no hand-named function list and no silent
exemption: a validator the entries can reach is collected, whatever
its name.

Verdict per collected guard, all machine-checked every run:
- KILLED: some test fails on removal. Required for lane-domain
  guards (this lane owns their diagnostic precision).
- DISPOSITIONED: removal passes the suite (verdict-identical on the
  committed corpus, re-verified every run) and a committed row in
  guard_sweep_dispositions.py records why (staged overlap, owning
  context). Platform and other-gate guards may carry rows; lane
  guards may not — a lane-owned survivor fails naming it.
- Anything else fails naming it: an unaccounted survivor, a stale
  row (dispositioned guard now killed: promote to kill), an orphan
  row (no such guard: update or drop it), or a swept/collected
  mismatch (the self-check below).

Self-checks (loop rule: mechanical, no judgement): the run set must
equal the collected set; call edges include higher-order references
(a bare module-function Name in value position, e.g. map(f, ...),
counts as an edge); any dynamic dispatch the edges cannot resolve
(getattr/eval/exec/__import__/globals/locals/vars) fails closed
naming it.

Usage:
  python3 -I tests/python/test_guard_removal_sweep.py [-v] [--workers N]
  python3 -I tests/python/test_guard_removal_sweep.py --list
  python3 -I tests/python/test_guard_removal_sweep.py --guard INDEX [--suite ...]
"""

import argparse
import ast
import concurrent.futures
import hashlib
import importlib.util
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


def referenced_names(func_node, funcs):
    """Module-level function names referenced anywhere inside func_node:
    direct calls plus higher-order references in value position (map(f,
    ...), callbacks, aliases). Conservative: a bare Name may denote a
    call edge the direct-call walk would miss."""
    names = set()
    for node in ast.walk(func_node):
        if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                and node.id in funcs):
            names.add(node.id)
    return names


# Dynamic dispatch the static edges cannot resolve: fail closed.
DYNAMIC_DISPATCH = (
    "getattr",
    "eval",
    "exec",
    "__import__",
    "globals",
    "locals",
    "vars",
)


def fail_closed_dynamic(funcs, scope):
    """Any dynamic dispatch inside the swept scope fails naming it."""
    for name in sorted(scope):
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in DYNAMIC_DISPATCH:
                    raise SweepError(
                        f"{name}:{node.lineno}: dynamic dispatch "
                        f"{node.func.id}() cannot be edged statically"
                    )


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
    """Roots and their transitive closure over reference edges (direct
    calls plus higher-order Name references). Roots: the lane entries,
    functions called by unconditional module-level statements
    (import-time derivation), and the fixture-oracle family by naming
    convention. No statement filtering: G-branch callees enter like
    everything else (their guards route to other-gate dispositions).
    Returns (roots, scope)."""
    for name in ENTRY_POINTS:
        if name not in funcs:
            raise SweepError(f"entry point {name} is gone")
    family = {n for n in funcs if n.startswith(ORACLE_PREFIXES)}
    if not family:
        raise SweepError("fixture-oracle family is empty")
    roots = set(ENTRY_POINTS) | module_level_roots(tree, funcs) | family
    seen, stack = set(roots), []
    for name in roots:
        stack.extend(referenced_names(funcs[name], funcs) - seen)
    for stmt in tree.body:
        if isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign,
                              ast.AugAssign, ast.Assert)):
            for sub in ast.walk(stmt):
                if (isinstance(sub, ast.Name)
                        and isinstance(sub.ctx, ast.Load)
                        and sub.id in funcs
                        and sub.id not in seen):
                    stack.append(sub.id)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(referenced_names(funcs[name], funcs) - seen)
    return roots, seen


def lane_owned(name):
    """Lane-domain naming convention (see LANE_PREFIXES): routing rule
    for acceptance (per-guard kills required), never for enumeration."""
    return name.startswith(LANE_PREFIXES)


def induced_branch_spans(func_node, funcs):
    """Line spans of validate_induced lane branches that never reach the
    matrix seam, for routing their guards to other-gate dispositions
    (the guards are still collected and run like everything else).
    Returns (other-gate spans, branch labels). Fails closed when the
    lane dispatch is absent or nothing reaches the seam."""
    def reaches_seam(stmts):
        seen, stack = set(), []
        for sub in ast.walk(ast.Module(body=stmts, type_ignores=[])):
            if (isinstance(sub, ast.Name)
                    and isinstance(sub.ctx, ast.Load)
                    and sub.id in funcs):
                stack.append(sub.id)
        while stack:
            callee = stack.pop()
            if callee in seen:
                continue
            seen.add(callee)
            if callee == MATRIX_SEAM:
                return True
            stack.extend(referenced_names(funcs[callee], funcs) - seen)
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


def guard_head_id(source_lines, lineno):
    """Content hash of a guard's first line (edit-stable except for the
    guard's own text: rewording a guard orphans its disposition row)."""
    head = " ".join(source_lines[lineno - 1].split())
    return hashlib.sha1(head.encode("utf-8")).hexdigest()[:12]


def enumerate_guards(source):
    """Every guard in the closure scope, with routing and stable IDs.

    Returns (guards, info) where each guard is
    (func, lineno, end, kind, routing, guard_id) and info carries the
    scope, roots, branch labels and other-gate spans. Routing is
    other-gate (inside a non-matrix lane branch), lane-owned (lane
    convention), or platform. Fails closed on dynamic dispatch and on
    a vanished lane dispatch or seam."""
    tree = ast.parse(source)
    source_lines = source.splitlines(keepends=True)
    funcs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            funcs[node.name] = node
    roots, scope = closure_scope(tree, funcs)
    fail_closed_dynamic(funcs, scope)
    spans, labels = induced_branch_spans(funcs["validate_induced"], funcs)
    if not labels:
        raise SweepError("validate_induced has no lane dispatch to route")
    if not any(reaches for _, reaches in labels):
        raise SweepError("no induced lane branch reaches the matrix seam")
    guards = []
    for name in [n for n in funcs if n in scope]:
        for lineno, end, kind in collect_guards(funcs[name]):
            if name == "validate_induced" and any(
                    start <= lineno and end <= stop
                    for start, stop in spans):
                routing = "other-gate"
            elif lane_owned(name):
                routing = "lane-owned"
            else:
                routing = "platform"
            guards.append([name, lineno, end, kind, routing, None])
    guards.sort(key=lambda g: (list(funcs).index(g[0]), g[1]))
    seen = {}
    for guard in guards:
        func, lineno, _, kind = guard[0], guard[1], guard[2], guard[3]
        head = guard_head_id(source_lines, lineno)
        key = (func, kind, head)
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        guard[5] = f"{func}:{kind}:{head}:{occurrence}"
    info = {"labels": labels, "scope": scope, "roots": roots,
            "other_gate_spans": spans}
    return [tuple(guard) for guard in guards], info


DISPOSITIONS_FILE = "tests/python/guard_sweep_dispositions.py"

DISPOSITION_CATEGORIES = ("platform-overlap", "platform-untested",
                          "other-gate")


def load_dispositions():
    """Committed survivor dispositions: {guard_id: (category, cluster)}.
    Missing file means none recorded yet."""
    path = ROOT / DISPOSITIONS_FILE
    if not path.is_file():
        return {}, {}
    spec = importlib.util.spec_from_file_location(
        "guard_sweep_dispositions", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return dict(module.DISPOSITIONS), dict(module.CLUSTERS)


def remove_guard(source_lines, guard):
    """Replace the guard's line range with `pass` at its indent."""
    _, lineno, end, _, _, _ = guard
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
        dispositions, clusters = load_dispositions()
    except SweepError as error:
        print(f"sweep broken: {error}")
        return 2
    except (OSError, SyntaxError, AttributeError, TypeError) as error:
        print(f"sweep broken: cannot load dispositions: {error}")
        return 2
    by_routing = {}
    for guard in guards:
        by_routing.setdefault(guard[4], 0)
        by_routing[guard[4]] += 1
    print(f"enumerated {len(guards)} guards in "
          f"{len({name for name, _, _, _, _, _ in guards})} functions; "
          f"scope {len(info['scope'])} functions; "
          + ", ".join(f"{count} {routing}"
                      for routing, count in sorted(by_routing.items())))
    print("induced lane branches: " + ", ".join(
        f"{lane}={'matrix' if reaches else 'other-gate'}"
        for lane, reaches in info["labels"]))
    if args.list:
        for index, (func, lineno, end, kind, routing, gid) in enumerate(guards):
            head = source_lines[lineno - 1].strip()[:60]
            disp = dispositions.get(gid)
            mark = ("DISP+" if disp else "----")
            print(f"{index:3d} {func}:{lineno}-{end} {kind} "
                  f"[{routing}/{mark}] :: {head}")
        print(f"---- dispositions: {len(dispositions)} rows, "
              f"{len(clusters)} clusters ----")
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
            func, lineno, _, kind, _, _ = guard
            extra = f" ({detail})" if args.verbose else ""
            print(f"{func}:{lineno} {kind}: {status}{extra}", flush=True)
    # Self-check: the swept set must equal the collected set.
    if args.guard is None:
        ran = {guard[5] for guard, _, _ in results}
        collected = {guard[5] for guard in guards}
        if ran != collected:
            missing = sorted(collected - ran)
            extra = sorted(ran - collected)
            print(f"sweep broken: swept != collected "
                  f"(missing={missing} extra={extra})")
            return 2
    # Disposition file checks (schema, orphans, lane-owned rows).
    problems = []
    by_id = {guard[5]: guard for guard in guards}
    for gid, row in dispositions.items():
        if gid not in by_id:
            problems.append(f"orphan disposition row: {gid}")
            continue
        if not (isinstance(row, (tuple, list)) and len(row) == 3):
            problems.append(f"malformed disposition row: {gid}")
            continue
        category, cluster, note = row
        if category not in DISPOSITION_CATEGORIES:
            problems.append(f"bad category in row: {gid}")
        if cluster not in clusters:
            problems.append(f"unknown cluster in row: {gid}")
        if not note:
            problems.append(f"empty note in row: {gid}")
        routing = by_id[gid][4]
        if routing == "lane-owned":
            problems.append(f"lane-owned guard must be killed, not rowed: {gid}")
        elif category == "other-gate" and routing != "other-gate":
            problems.append(f"other-gate row on {routing} guard: {gid}")
        elif category in ("platform-overlap", "platform-untested") \
                and routing != "platform":
            problems.append(f"platform row on {routing} guard: {gid}")
    # Verdicts: killed, dispositioned, or failing (naming it).
    failures = []
    for guard, status, detail in results:
        func, lineno, _, kind, routing, gid = guard
        if status == "ERROR":
            failures.append(f"ERROR {func}:{lineno} {kind} ({detail})")
        elif status == "KILLED":
            if gid in dispositions:
                failures.append(
                    f"STALE-ROW {func}:{lineno} {kind}: now killed, "
                    "promote to kill (drop the row)")
        elif gid in dispositions:
            pass
        else:
            failures.append(
                f"SURVIVED {func}:{lineno} {kind} [{routing}] ({detail})")
    results.sort(key=lambda item: selected.index(item[0]))
    print("----")
    for problem in problems:
        print(problem)
    for failure in failures:
        print(failure)
    killed = sum(1 for _, status, _ in results if status == "KILLED")
    disped = sum(1 for guard, status, _ in results
                 if status != "KILLED" and guard[5] in dispositions)
    print(f"killed {killed}/{len(results)}; "
          f"dispositioned {disped}; problems {len(problems)}; "
          f"failures {len(failures)}")
    return 1 if (problems or failures) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
