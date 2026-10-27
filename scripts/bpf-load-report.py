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

With ``--object NAME`` loads are grouped by BTF id first and each
group is assigned to one object by its unique roots (Inventory-only
``p11_usage_entry_*``, Detailed-only image/instance roots, counter
``p11_counter_bank_*``); only the requested object's groups supply
coverage. Shared-only groups of known roots belong to Detailed (the
lone Detailed return), and to Inventory only when every root sits in
its program set; counter modes take only bank-carrying groups. A group
matching two objects or no known object FAILs naming its BTF id. Every
observed root is scored as ``NAME/<root>`` against budget keys of that
form, and the budgeted-but-missing check is scoped to ``NAME/`` keys,
so two BPF objects sharing program names (the Detailed and Inventory
objects share ten) are gated without mixing their counts, even from
one mixed probe file.

One refused shape is expected, never a failure: the 2-instruction
``bpf_loop`` (helper 181) capability probe that ``doctor`` runs for its
counter-modes footer. It is allowlisted by exact shape (fingerprint,
program type) and kernel-tied errno (EINVAL on v5.15.*, EACCES
elsewhere), reported as ``EXPECTED``; any other refused load still
fails.
"""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

DEFAULT_LIMIT = 1000000
DEFAULT_MIN_HEADROOM_PERCENT = 5.0

# Expected bpf_loop (helper 181) functional-probe shape: `call 181; exit`
# (src/attach.rs BPF_LOOP_PROBE_INSNS), plain kprobe type, never attached.
# doctor runs it for the counter-modes footer; 5.15 refuses the unknown
# helper (EINVAL) and 6.1 and later refuse the uninitialized registers
# (EACCES). The expected errno is tied to the kernel by
# bpf_loop_expected_errno(); any other errno fails like any other refused
# load. The fingerprint is pinned against the source bytes by the gate
# suite; any drift in shape fails too.
BPF_LOOP_PROBE_FNV1A64 = "27ef27a73ecc6270"
BPF_LOOP_PROBE_PROGRAM_TYPE = 2  # BPF_PROG_TYPE_KPROBE, linux/bpf.h.
BPF_LOOP_PROBE_INSN_COUNT = 2

# Object identity for BTF-grouped scoring (doctor loads Detailed and
# Inventory in one probed process; counter runs load a counter object
# plus a lone Detailed return). Each BTF id holds one object's loads;
# the group is assigned by the roots only that object has. Shared roots
# (the 13 defaults) never identify a group alone.
# Sources: src/attach.rs DEFAULT_PROGRAMS, src/attach/instance.rs
# INSTANCE_PROGRAMS, src/attach/selected_detailed.rs PROGRAMS,
# src/attach/counter_banks.rs PROGRAMS, and the 12 inventory budgets keys.
INVENTORY_UNIQUE_ROOTS = frozenset({
    "p11_usage_entry_lp64", "p11_usage_entry_ia32",
})
COUNTER_UNIQUE_ROOTS = frozenset({
    "p11_counter_bank_entry", "p11_counter_bank_return",
})
DETAILED_UNIQUE_ROOTS = frozenset({
    "p11_image_query", "p11_image_exec_release",
    "p11_inst_vma_map", "p11_inst_vma_unmap", "p11_inst_vma_copy",
    "p11_selected_bootstrap", "p11_selected_cgroup_migrate",
})
# Every root any shipped object loads (for foreign-group detection).
# The 13 defaults are shared by Detailed and counter; 10 of them are
# also shared by Inventory (which lacks p11_entry/p11_return/task_newtask).
KNOWN_SHARED_ROOTS = frozenset({
    "p11_entry", "p11_return", "task_newtask", "dl_debug_state",
    "function_list_entry", "function_list_return",
    "interface_list_entry", "interface_list_return",
    "interface_list_worker", "interface_entry", "interface_return",
    "sched_process_exec", "sched_process_exit",
})
KNOWN_ROOTS = (KNOWN_SHARED_ROOTS | INVENTORY_UNIQUE_ROOTS
               | COUNTER_UNIQUE_ROOTS | DETAILED_UNIQUE_ROOTS)
# Inventory's 12 loaded programs (for partial-group compatibility: a
# shared-only group whose roots all sit in this set is an Inventory
# partial that failed before its usage roots loaded).
INVENTORY_PROGRAMS = frozenset({
    "dl_debug_state", "function_list_entry", "function_list_return",
    "interface_entry", "interface_list_entry", "interface_list_return",
    "interface_list_worker", "interface_return",
    "p11_usage_entry_lp64", "p11_usage_entry_ia32",
    "sched_process_exec", "sched_process_exit",
})


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
    program_type = row.get("program_type")
    insn_count = row.get("insn_count")
    fingerprint = row.get("relocated_fnv1a64")
    btf_id = row.get("btf_id")
    return {"root": root, "loaded": loaded, "errno": row["errno"],
            "stats": stats, "processed": processed, "limit": limit,
            "auxiliary": row.get("auxiliary"),
            "btf_id": btf_id if type(btf_id) is int else 0,
            "program_type": program_type if type(program_type) is int else None,
            "insn_count": insn_count if type(insn_count) is int else None,
            "fingerprint": fingerprint if type(fingerprint) is str else None}


def assign_btf_group(entries):
    """One object's name for a BTF group, or None when shared-only.

    Returns (object, error) where object is "inventory", "counter",
    "detailed", or None, and error names an ambiguous (two objects) or
    foreign (no known root) group. Shared-only groups of known roots
    (the lone Detailed return, partial loads that failed before their
    unique roots) return (None, None); the caller decides by the
    requested object whether they belong.
    """
    roots = {entry["root"] for entry in entries}
    has_inventory = bool(roots & INVENTORY_UNIQUE_ROOTS)
    has_counter = bool(roots & COUNTER_UNIQUE_ROOTS)
    has_detailed = bool(roots & DETAILED_UNIQUE_ROOTS)
    hits = sum((has_inventory, has_counter, has_detailed))
    if hits > 1:
        kinds = sorted(kind for kind, has in
                       (("counter", has_counter),
                        ("detailed", has_detailed),
                        ("inventory", has_inventory)) if has)
        return None, f"matches two objects ({','.join(kinds)})"
    if has_inventory:
        return "inventory", None
    if has_counter:
        return "counter", None
    if has_detailed:
        return "detailed", None
    if not roots <= KNOWN_ROOTS:
        foreign = sorted(roots - KNOWN_ROOTS)
        return None, f"matches no object (foreign {','.join(foreign)})"
    return None, None


def bpf_loop_expected_errno(kernel):
    """The one errno the bpf_loop probe may refuse with on this kernel.

    5.15 kernels lack helper 181, so the verifier reports EINVAL for the
    unknown helper; 6.1 and later know the helper and refuse the
    uninitialized registers with EACCES. Any other errno is unexpected.
    """
    if kernel.startswith("v5.15."):
        return 22  # EINVAL: unknown helper 181.
    return 13  # EACCES: uninitialized registers.


def is_expected_bpf_loop_probe(entries, kernel):
    """True only when every entry is the exact allowlisted probe refusal."""
    if not entries:
        return False
    expected = bpf_loop_expected_errno(kernel)
    return all(entry["root"] == "unresolved"
               and entry["loaded"] is False
               and entry["program_type"] == BPF_LOOP_PROBE_PROGRAM_TYPE
               and entry["insn_count"] == BPF_LOOP_PROBE_INSN_COUNT
               and entry["fingerprint"] == BPF_LOOP_PROBE_FNV1A64
               and entry["errno"] == expected
               for entry in entries)


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


def select_object_loads(parsed_loads, object_name, group_errors):
    """Loads belonging to one object, grouped by BTF id.

    Unresolved refused loads (BTF id 0, the bpf_loop probe shape) pass
    through untouched for the allowlist. Every other load must carry a
    nonzero BTF id; its group is assigned by unique roots. Ambiguous
    (two objects) and foreign (no known root) groups append a FAIL
    naming the BTF id. Shared-only groups of known roots (the lone
    Detailed return; partial loads that failed before their unique
    roots) belong to Detailed, and to Inventory only when every root
    sits in Inventory's program set; counter objects always carry
    their bank roots, so shared-only groups never belong to them.
    """
    unresolved = [entry for entry in parsed_loads
                  if entry["root"] == "unresolved"]
    real = [entry for entry in parsed_loads
            if entry["root"] != "unresolved"]
    by_btf = {}
    for entry in real:
        by_btf.setdefault(entry["btf_id"], []).append(entry)
    selected = list(unresolved)
    want_counter = object_name.startswith("counter-")
    for btf_id in sorted(by_btf):
        entries = by_btf[btf_id]
        if btf_id == 0:
            roots = sorted({entry["root"] for entry in entries})
            group_errors.append(
                {"root": f"btf-{btf_id}-unknown",
                 "detail": f"matches no object (no BTF for {','.join(roots)})"})
            continue
        assigned, error = assign_btf_group(entries)
        if error is not None:
            group_errors.append(
                {"root": f"btf-{btf_id}-ambiguous"
                 if "two objects" in error else f"btf-{btf_id}-unknown",
                 "detail": f"btf {btf_id} {error}"})
            continue
        if assigned == "inventory":
            if object_name == "inventory":
                selected.extend(entries)
        elif assigned == "counter":
            if want_counter:
                selected.extend(entries)
        elif assigned == "detailed":
            if object_name == "detailed":
                selected.extend(entries)
        else:
            roots = {entry["root"] for entry in entries}
            if object_name == "detailed":
                selected.extend(entries)
            elif object_name == "inventory" and roots <= INVENTORY_PROGRAMS:
                selected.extend(entries)
            # Counter modes take only bank-carrying groups; shared-only
            # groups (the lone Detailed return) never belong to them.
    return selected


def evaluate(loads, kernel, budgets, object_name=None):
    """Rows keyed by root plus an overall verdict. Duplicates keep the max.

    With --object, loads are grouped by BTF id first: each group holds
    one object's programs, assigned by its unique roots. Only groups
    belonging to the requested object supply coverage, so an Inventory
    copy never masks a missing Detailed program and a lone Detailed
    return never inflates a counter table. Without --object the legacy
    by-name scoring applies (the focused unit tests use it).
    """
    prefix = f"{object_name}/" if object_name else ""
    parsed_loads = []
    for row in loads:
        parsed = checked_load(row)
        if parsed["auxiliary"] is not None:
            continue
        if parsed["root"] == "unresolved" and parsed["loaded"]:
            continue
        parsed_loads.append(parsed)
    group_errors = []
    if object_name is not None:
        parsed_loads = select_object_loads(parsed_loads, object_name,
                                            group_errors)
    by_root = {}
    for parsed in parsed_loads:
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
            if is_expected_bpf_loop_probe(entries, kernel):
                row.update(status="EXPECTED",
                           detail=f"expected bpf_loop probe refusal errno={errnos[0]}")
            else:
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
    for error in group_errors:
        rows.append({"root": error["root"], "processed": None, "limit": None,
                     "budget": None, "status": "FAIL",
                     "detail": error["detail"]})
    rows.sort(key=lambda row: row["root"])
    return rows


def headroom_text(row):
    if row["processed"] is None or row["limit"] is None or row["limit"] <= 0:
        return "-"
    return f"{(row['limit'] - row['processed']) / row['limit'] * 100:.2f}"


def format_table(rows, kernel, observer_sha256, errors):
    failed = (bool(errors)
              or any(row["status"] not in ("PASS", "EXPECTED") for row in rows))
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
    failed = (bool(errors)
              or any(row["status"] not in ("PASS", "EXPECTED") for row in rows))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
