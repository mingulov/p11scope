#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Fail once an intermittent cell has gone N runs without passing.

An --intermittent-failure declaration (scripts/ci/check-cell-results.py)
lets a cell land as a known-signature failure on any single run, with
no limit on how long that lasts. This gate bounds it: over the newest
--window workflow runs that carry run-tree result artifacts, every
listed cell must show at least one passing row on every listed kernel
leg. A (cell, kernel) pair with no pass in the window fails naming
the cell, its owning lanes and the window's run ids.

History comes from the workflow's own uploaded run-tree artifacts
(results.jsonl, 7-day retention): the newest completed runs across
branches, so the gate needs no ordering behind the current run-tree
matrix and judges with one run of lag. The declarations are
workflow-level, so a cell passing nowhere in the window is broken or
stale wherever it runs. Cancelled, skipped and still-running runs
contribute nothing. A self-skip is red, never a pass: no history
at all, no artifacts for a leg in the window, or a declared cell
that never ran all fail the gate (a dropped, renamed or
never-scheduled cell disables no bound), as does a window with no
positive row. A positive row is exactly `pass is true` with
qualification `qualified`; anything else, however shaped, is not
a pass.

Usage:
  python3 -I scripts/ci/check-intermittent-bounds.py --repo OWNER/REPO
      --cell CELL=LANE [--cell ...] [--window 10] [--workflow FILE]
      [--kernel K ...] [--history-json FILE]

--history-json judges a pre-fetched history instead of calling gh
(tests and offline runs): {"runs": [{"id":, "branch":, "results":
{kernel: [result rows] or null}}]}.
"""

import argparse
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# A gate must not mutate the tree it validates: importing the shared
# row validator must not drop __pycache__ into staged scripts.
sys.dont_write_bytecode = True
from result_row import duplicate_cells, parse_json_strict, validate_row  # noqa: E402

# The run-tree matrix legs (privileged-tests.yml); public-cli and
# witness-cli carry v7.4-rc3 too, run-tree does not.
DEFAULT_KERNELS = ("host", "v6.6.157", "v6.12.111", "v6.18.58", "v7.3.1")
ARTIFACT_PREFIX = "run-tree-"
RESULTS_PATH = "cells/results.jsonl"
LIST_SLACK = 20


def fail(message):
    print(f"check-intermittent-bounds: {message}", file=sys.stderr)
    return 1


def split_cell(value):
    cell, sep, lane = value.partition("=")
    if not sep or not cell or not lane:
        return None, None
    return cell, lane


def gh(args, timeout=120):
    try:
        proc = subprocess.run(["gh", *args], capture_output=True,
                              timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("gh is not installed")
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"gh timed out: {' '.join(args)}: {error}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"gh failed ({proc.returncode}): {' '.join(args)}: "
            f"{proc.stderr.decode('utf-8', 'replace')[:300]}")
    return proc.stdout


def list_runs(repo, workflow, limit):
    out = gh(["run", "list", "--repo", repo, "--workflow", workflow,
              "--limit", str(limit), "--json",
              "databaseId,headBranch,conclusion,createdAt"])
    try:
        runs = json.loads(out.decode("utf-8"))
    except ValueError as error:
        raise RuntimeError(f"unparseable run list: {error}")
    if not isinstance(runs, list):
        raise RuntimeError("unparseable run list: not a list")
    return runs


def run_artifacts(repo, run_id):
    out = gh(["api", f"repos/{repo}/actions/runs/{run_id}/artifacts",
              "--paginate", "--jq",
              ".artifacts[] | [.name, .archive_download_url, .expired] | @tsv"])
    found = {}
    for line in out.decode("utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, url, expired = parts
        if expired == "true":
            continue
        found[name] = url
    return found


def artifact_results(url):
    # Returns (rows, note): rows is None when the artifact carries
    # no usable evidence. An artifact with any schema-invalid row
    # is unusable as a whole (its source run already went red):
    # corrupt evidence never counts as a pass or a miss.
    blob = gh(["api", url])
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            try:
                raw = archive.read(RESULTS_PATH).decode("utf-8")
            except KeyError:
                return None, "results file absent"
    except zipfile.BadZipFile:
        raise RuntimeError("artifact zip is unparseable")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = parse_json_strict(line)
        except ValueError as error:
            return None, "line %d: invalid JSON: %s" % (number, error)
        problems = validate_row(row)
        if problems:
            return None, "line %d: %s" % (number, problems[0])
        rows.append(row)
    dups = duplicate_cells(rows)
    if dups:
        return None, "duplicate cell %r (one row per cell)" % (dups[0],)
    return rows, ""


def fetch_history(repo, workflow, window, kernels):
    history = []
    try:
        runs = list_runs(repo, workflow, window + LIST_SLACK)
    except RuntimeError as error:
        return None, str(error)
    for run in runs:
        if not isinstance(run, dict):
            continue
        if run.get("conclusion") not in ("success", "failure"):
            continue
        run_id = run.get("databaseId")
        if not isinstance(run_id, int):
            continue
        try:
            artifacts = run_artifacts(repo, run_id)
        except RuntimeError as error:
            return None, str(error)
        results = {}
        for kernel in kernels:
            url = artifacts.get(ARTIFACT_PREFIX + kernel)
            if url is None:
                results[kernel] = None
                continue
            try:
                rows, note = artifact_results(url)
            except (RuntimeError, ValueError) as error:
                return None, f"run {run_id} {kernel}: {error}"
            if rows is None:
                print(f"check-intermittent-bounds: SKIP run {run_id} "
                      f"{kernel}: unusable artifact ({note})")
            results[kernel] = rows
        if all(value is None for value in results.values()):
            continue
        history.append({"id": run_id, "branch": run.get("headBranch"),
                        "results": results})
        if len(history) >= window:
            break
    return history, ""


def load_history_json(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, f"cannot read {path}: {error}"
    try:
        document = parse_json_strict(text)
    except ValueError as error:
        return None, f"invalid history JSON: {error}"
    if not isinstance(document, dict) or not isinstance(
            document.get("runs"), list):
        return None, "history JSON must carry a runs list"
    history = []
    for run in document["runs"]:
        if not isinstance(run, dict) or not isinstance(
                run.get("results"), dict):
            return None, "history run must carry a results map"
        for kernel, rows in run["results"].items():
            if rows is None:
                continue
            if not isinstance(rows, list):
                return None, "history run %r kernel %r: results must be a list" % (
                    run.get("id"), kernel)
            for row in rows:
                problems = validate_row(row)
                if problems:
                    return None, "history run %r kernel %r: %s" % (
                        run.get("id"), kernel, problems[0])
            dups = duplicate_cells(rows)
            if dups:
                return None, "history run %r kernel %r: duplicate cell %r" % (
                    run.get("id"), kernel, dups[0])
        history.append(run)
    return history, ""


def is_positive(row):
    # A pass is exactly a schema-valid positive row: boolean true
    # with the qualified verdict. Anything else (failed,
    # expected-failure, nonqualifying, a non-boolean pass, missing
    # keys) is not a pass; malformed rows are refused, never
    # counted. In particular an unexpected pass
    # (pass+expected-failure) and an inconsistent row
    # (pass+failed) never reset the window.
    return (
        isinstance(row, dict)
        and row.get("pass") is True
        and row.get("qualification") == "qualified"
    )


def judge(history, cells, kernels, window):
    # Precondition: every row already passed the shared schema
    # validation at load (fetch_history skips corrupt artifacts
    # loudly; load_history_json refuses corrupt input). The judge
    # therefore decides presence and positivity only.
    lanes = {}
    for cell, lane in cells:
        lanes.setdefault(cell, []).append(lane)
    if not history:
        print("check-intermittent-bounds: no runs with run-tree "
              "artifacts in scope: cannot bound anything; refusing "
              "to pass on no evidence", file=sys.stderr)
        return 1
    window_runs = history[:window]
    print("check-intermittent-bounds: window: %s" % ", ".join(
        f"{run.get('id')} ({run.get('branch')})" for run in window_runs))
    failures = []
    for cell in sorted(lanes):
        for kernel in kernels:
            observed = []
            last_pass = None
            artifacts = 0
            for run in window_runs:
                rows = (run.get("results") or {}).get(kernel)
                if not isinstance(rows, list):
                    continue
                artifacts += 1
                for row in rows:
                    if row.get("cell") == cell:
                        observed.append(run.get("id"))
                        if is_positive(row) and last_pass is None:
                            last_pass = run.get("id")
            if not artifacts:
                failures.append(
                    f"{cell} on {kernel} has no run-tree artifacts in "
                    f"the window (lanes: {', '.join(lanes[cell])}): a "
                    f"missing leg disables no bound")
            elif not observed:
                failures.append(
                    f"{cell} on {kernel} never ran in the window "
                    f"(lanes: {', '.join(lanes[cell])}; runs: "
                    f"{', '.join(str(run.get('id')) for run in window_runs)}): "
                    f"a dropped or renamed cell disables no bound")
            elif last_pass is None:
                failures.append(
                    f"{cell} on {kernel} went {len(window_runs)} runs "
                    f"without passing (lanes: {', '.join(lanes[cell])}; "
                    f"runs: {', '.join(str(run.get('id')) for run in window_runs)})")
            else:
                print(f"check-intermittent-bounds: PASS {cell} on {kernel}: "
                      f"last pass {last_pass}")
    if failures:
        for failure in failures:
            print(f"check-intermittent-bounds: {failure}", file=sys.stderr)
        return 1
    print(f"check-intermittent-bounds: {len(lanes)} cells bounded over "
          f"{len(window_runs)} runs x {len(kernels)} kernels")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--workflow", default="privileged-tests.yml")
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--cell", action="append", default=[],
                        help="CELL=LANE (repeatable)")
    parser.add_argument("--kernel", action="append", default=[],
                        help="kernel leg (default: all run-tree legs)")
    parser.add_argument("--history-json", default=None)
    args = parser.parse_args(argv)
    if args.window < 1:
        return fail("--window must be at least 1")
    cells = []
    for value in args.cell:
        cell, lane = split_cell(value)
        if cell is None:
            return fail(f"bad --cell (want CELL=LANE): {value}")
        cells.append((cell, lane))
    if not cells:
        return fail("at least one --cell is required")
    kernels = tuple(args.kernel) if args.kernel else DEFAULT_KERNELS
    if args.history_json is not None:
        history, error = load_history_json(Path(args.history_json))
        if history is None:
            return fail(error)
    else:
        if not args.repo:
            return fail("--repo is required without --history-json")
        history, error = fetch_history(args.repo, args.workflow,
                                       args.window, kernels)
        if history is None:
            print(f"check-intermittent-bounds: {error}", file=sys.stderr)
            return 2
    return judge(history, cells, kernels, args.window)


if __name__ == "__main__":
    sys.exit(main())
