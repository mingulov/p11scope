#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One-kernel BPF load report from raw verifier-stats probe JSONL.

Reads the probe's own output (``record:"load"`` rows plus one
``probe-summary`` per file, as written inside the guest), prints one table
row per program with its processed count, and exits 0 only when every
non-auxiliary root loaded, carried verifier stats, and kept headroom.

With ``--budgets FILE`` each root is also compared against its pinned
per-kernel budget (``{"limit": L, "min_headroom_percent": M, "programs":
{"<root>": {"<kernel>": N}}}``): a root over budget, a budgeted root with
no row, or an observed root with no budget FAILs. Without it the gate is
loaded + stats + 5% headroom. A repeated root (doctor loads twice) keeps
its largest count. Auxiliary rows never supply coverage and are ignored.

With ``--object NAME`` every observed root is scored as ``NAME/<root>``
against budget keys of that form, and the budgeted-but-missing check is
scoped to ``NAME/`` keys, so two BPF objects sharing program names (the
Detailed and Inventory objects share ten) are gated from separate probe
files without mixing their counts.
"""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

DEFAULT_LIMIT = 1000000
DEFAULT_MIN_HEADROOM_PERCENT = 5.0


class ReportError(RuntimeError):
    pass


def read_jsonl(path):
    """Raw probe rows. Raises ReportError; never invents a row."""
    try:
        text = Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ReportError(f"{path}: cannot read input ({error})")
    lines = text.splitlines()
    if not lines:
        raise ReportError(f"{path}: empty input, no probe rows")
    rows = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            raise ReportError(f"{path}: blank line {number}")
        try:
            row = json.loads(line)
        except ValueError as error:
            raise ReportError(f"{path}: invalid JSON on line {number} ({error})")
        if type(row) is not dict or type(row.get("record")) is not str:
            raise ReportError(f"{path}: invalid record on line {number}")
        rows.append(row)
    loads = [row for row in rows if row["record"] == "load"]
    summaries = [row for row in rows if row["record"] == "probe-summary"]
    for row in rows:
        if row["record"] == "probe-error":
            raise ReportError(f"{path}: probe error ({row.get('reason')})")
        if row["record"] not in ("load", "probe-summary"):
            raise ReportError(f"{path}: unknown record {row['record']!r}")
    if not summaries:
        raise ReportError(f"{path}: no probe summary, the run never finished")
    if len(summaries) > 1:
        raise ReportError(f"{path}: {len(summaries)} probe summaries, expected one")
    summary = summaries[0]
    counted = len(loads) + sum(1 for row in rows if row["record"] == "probe-error")
    if summary.get("records") != counted:
        raise ReportError(
            f"{path}: summary counts {summary.get('records')} rows, file holds {counted}")
    if summary.get("write_failures") != 0 or summary.get("overflow") is not False:
        raise ReportError(f"{path}: probe output failed (summary {summary!r})")
    return loads


def checked_load(row):
    """The gated fields of one load row, strictly typed."""
    for key in ("root", "loaded", "errno", "stats_present", "processed", "limit"):
        if key not in row:
            raise ReportError(f"load row lacks {key!r}")
    root, loaded = row["root"], row["loaded"]
    stats, processed, limit = row["stats_present"], row["processed"], row["limit"]
    if type(root) is not str or not root:
        raise ReportError("load row has no root name")
    if loaded is not True and loaded is not False:
        raise ReportError(f"{root}: loaded is not a boolean")
    if type(row["errno"]) is not int:
        raise ReportError(f"{root}: errno is not an integer")
    if stats is not True and stats is not False:
        raise ReportError(f"{root}: stats_present is not a boolean")
    if type(processed) is not int or type(limit) is not int:
        raise ReportError(f"{root}: processed/limit are not integers")
    return {"root": root, "loaded": loaded, "errno": row["errno"],
            "stats": stats, "processed": processed, "limit": limit,
            "auxiliary": row.get("auxiliary")}


def read_budgets(path):
    try:
        document = json.loads(Path(path).read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ReportError(f"{path}: cannot read budgets ({error})")
    if type(document) is not dict or type(document.get("programs")) is not dict:
        raise ReportError(f"{path}: budgets need a programs mapping")
    limit = document.get("limit", DEFAULT_LIMIT)
    headroom = document.get("min_headroom_percent", DEFAULT_MIN_HEADROOM_PERCENT)
    if type(limit) is not int or limit <= 0:
        raise ReportError(f"{path}: bad budgets limit {limit!r}")
    if type(headroom) not in (int, float) or not 0 < headroom < 100:
        raise ReportError(f"{path}: bad min_headroom_percent {headroom!r}")
    programs = {}
    for root, per_kernel in document["programs"].items():
        if type(per_kernel) is not dict:
            raise ReportError(f"{path}: bad budgets entry for {root!r}")
        for kernel, budget in per_kernel.items():
            if type(budget) is not int or budget <= 0:
                raise ReportError(f"{path}: bad budget for {root} on {kernel}")
        programs[root] = dict(per_kernel)
    return {"limit": limit, "min_headroom_percent": float(headroom),
            "programs": programs}


def evaluate(loads, kernel, budgets, object_name=None):
    """Rows keyed by root plus an overall verdict. Duplicates keep the max."""
    prefix = f"{object_name}/" if object_name else ""
    by_root = {}
    for row in loads:
        parsed = checked_load(row)
        if parsed["auxiliary"] is not None:
            continue
        if parsed["root"] == "unresolved" and parsed["loaded"]:
            continue
        by_root.setdefault(prefix + parsed["root"], []).append(parsed)
    rows = []
    for root in sorted(by_root):
        entries = by_root[root]
        processed = max(entry["processed"] for entry in entries)
        limits = {entry["limit"] for entry in entries}
        budget = None
        if budgets is not None:
            budget = budgets["programs"].get(root, {}).get(kernel)
        row = {"root": root, "processed": processed,
               "limit": entries[0]["limit"] if len(limits) == 1 else -1,
               "budget": budget, "status": "PASS", "detail": "-"}
        if len(limits) != 1:
            row.update(status="FAIL", detail=f"limits disagree: {sorted(limits)}")
        elif row["limit"] <= 0 or processed < 0:
            row.update(status="FAIL",
                       detail=f"bad count processed={processed} limit={row['limit']}")
        elif any(not entry["loaded"] for entry in entries):
            errnos = sorted({entry["errno"] for entry in entries if not entry["loaded"]})
            row.update(status="FAIL", detail=f"refused errno={errnos[0]}")
        elif any(not entry["stats"] for entry in entries):
            row.update(status="FAIL",
                       detail=f"no verifier stats on {kernel}")
        else:
            minimum = (budgets["min_headroom_percent"] if budgets is not None
                       else DEFAULT_MIN_HEADROOM_PERCENT)
            headroom = (row["limit"] - processed) / row["limit"] * 100
            if budgets is not None and budget is None:
                row.update(status="FAIL", detail=f"no budget for {kernel}")
            elif budgets is not None and processed > budget:
                row.update(status="FAIL",
                           detail=f"processed {processed} over budget {budget}")
            elif headroom < minimum:
                row.update(status="FAIL",
                           detail=f"headroom {headroom:.2f}% below {minimum:g}%")
        rows.append(row)
    if budgets is not None:
        for root in sorted(budgets["programs"]):
            if prefix and not root.startswith(prefix):
                continue
            if kernel in budgets["programs"][root] and root not in by_root:
                rows.append({"root": root, "processed": None, "limit": None,
                             "budget": budgets["programs"][root][kernel],
                             "status": "FAIL", "detail": "missing from probe rows"})
        rows.sort(key=lambda row: row["root"])
    return rows


def headroom_text(row):
    if row["processed"] is None or row["limit"] is None or row["limit"] <= 0:
        return "-"
    return f"{(row['limit'] - row['processed']) / row['limit'] * 100:.2f}"


def format_table(rows, kernel, observer_sha256, errors):
    failed = bool(errors) or any(row["status"] != "PASS" for row in rows)
    if not rows and not errors:
        errors = [f"no probe rows on {kernel}"]
        failed = True
    lines = [f"# kernel={kernel} observer-sha256={observer_sha256} "
             f"result={'FAIL' if failed else 'PASS'}"]
    lines.extend(f"# error: {error}" for error in errors)
    lines.append("kernel program processed limit headroom_pct budget status detail")
    for row in rows:
        lines.append(f"{kernel} {row['root']} "
                     f"{row['processed'] if row['processed'] is not None else '-'} "
                     f"{row['limit'] if row['limit'] is not None else '-'} "
                     f"{headroom_text(row)} "
                     f"{row['budget'] if row['budget'] is not None else '-'} "
                     f"{row['status']} {row['detail']}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budgets", default=None,
                        help="pinned per-kernel budgets JSON (Task 2 file)")
    parser.add_argument("--object", default=None,
                        help="score roots as OBJECT/<root> against namespaced "
                             "budget keys (one BPF object per probe file)")
    parser.add_argument("--kernel", required=True, help="guest kernel release")
    parser.add_argument("--observer-sha256", default="unknown",
                        help="sha256 of the observer that produced the rows")
    parser.add_argument("jsonl", nargs="+", help="raw probe JSONL files")
    args = parser.parse_args(argv)
    errors, loads = [], []
    budgets = None
    if args.budgets is not None:
        try:
            budgets = read_budgets(args.budgets)
        except ReportError as error:
            errors.append(str(error))
    for path in args.jsonl:
        try:
            loads.extend(read_jsonl(path))
        except ReportError as error:
            errors.append(str(error))
    rows = []
    if not errors:
        try:
            rows = evaluate(loads, args.kernel, budgets, args.object)
        except ReportError as error:
            errors.append(str(error))
    sys.stdout.write(format_table(rows, args.kernel, args.observer_sha256, errors))
    failed = bool(errors) or any(row["status"] != "PASS" for row in rows)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
