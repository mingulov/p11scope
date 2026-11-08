#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record measured verifier costs as per-kernel budget cells.

Reads one kernel's measured processed counts from
scripts/bpf-load-report.py output tables and pins them into a
verifier-budgets file with the same margin rule as the existing cells:
ceil(measured * 115 / 100) in integer arithmetic, so an exact multiple
stays exact.

A pin past 75% of the limit is refused (BUD-1: growth past 75% needs
restructuring, never a mechanical pin); that refusal also keeps every
recorded pin inside the file's 95% headroom cap, which the budgets-cap
contract test still enforces on the file.

EXPECTED probe rows are skipped (the bpf_loop probe refusal carries no
budget); over-budget FAIL rows are measurements worth recording, but
any other FAIL (refused load, missing stats, bad count) aborts without
writing. Unknown programs, rows for another kernel, and zero counts
abort too. Without --update an existing column for the kernel aborts;
--update re-pins exactly the measured set. On any refusal the budgets
file is left unchanged.
"""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def fail(message):
    """Report a refusal on stderr and exit 1 without writing."""
    print(f"record-verifier-budgets.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_tables(paths, kernel):
    """Map each measured program to its processed count.

    A repeated program keeps its largest count, mirroring the report's
    own rule. EXPECTED rows are skipped; anything that is not a usable
    measurement aborts.
    """
    measured = {}
    for path in paths:
        try:
            text = Path(path).read_text(encoding="ascii")
        except OSError as error:
            fail(f"cannot read {path}: {error}")
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split()
            if fields[0] == "kernel" and fields[1:2] == ["program"]:
                continue
            if len(fields) < 7:
                fail(f"{path}:{number}: not a report row: {stripped!r}")
            row_kernel, program, raw_count = fields[0], fields[1], fields[2]
            status, detail = fields[6], " ".join(fields[7:])
            if row_kernel != kernel:
                fail(f"{path}:{number}: row is for {row_kernel}, "
                     f"not {kernel}")
            if status == "EXPECTED":
                continue
            try:
                count = int(raw_count)
            except ValueError:
                fail(f"{path}:{number}: bad count for {program}: "
                     f"{raw_count!r}")
            if status == "PASS":
                pass
            elif (status == "FAIL" and detail.startswith("processed ")
                    and " over budget " in detail):
                pass
            else:
                fail(f"{path}:{number}: {program} is not a measurement: "
                     f"{status} {detail}")
            if count <= 0:
                fail(f"{path}:{number}: {program} has no measured count: "
                     f"{count}")
            measured[program] = max(count, measured.get(program, 0))
    if not measured:
        fail("no measured rows found")
    return measured


def main(argv):
    parser = argparse.ArgumentParser(
        description="Pin measured verifier costs with the 15% margin rule.")
    parser.add_argument("--budgets", required=True,
                        help="verifier-budgets JSON file to update")
    parser.add_argument("--kernel", required=True,
                        help="kernel tag to record, e.g. v7.4-rc1")
    parser.add_argument("--measured", required=True, nargs="+",
                        help="report table files holding that kernel's rows")
    parser.add_argument("--update", action="store_true",
                        help="re-pin the measured set for a recorded kernel")
    args = parser.parse_args(argv)
    budgets_path = Path(args.budgets)
    try:
        document = json.loads(budgets_path.read_text(encoding="ascii"))
    except OSError as error:
        fail(f"cannot read {args.budgets}: {error}")
    except ValueError as error:
        fail(f"cannot parse {args.budgets}: {error}")
    limit = document.get("limit")
    programs = document.get("programs")
    if (not isinstance(limit, int) or isinstance(limit, bool)
            or limit <= 0):
        fail(f"{args.budgets}: limit {limit!r} is not a positive int")
    if not isinstance(programs, dict) or not programs:
        fail(f"{args.budgets}: programs is not a non-empty object")
    measured = parse_tables(args.measured, args.kernel)
    unknown = sorted(program for program in measured
                     if program not in programs)
    if unknown:
        fail(f"{args.budgets}: no budget key for "
             f"{', '.join(unknown)}")
    if not args.update:
        recorded = sorted(program for program, cells in programs.items()
                          if args.kernel in cells)
        if recorded:
            fail(f"{args.kernel} already has cells in {args.budgets} "
                 f"({len(recorded)} programs); pass --update to re-pin")
    pinned = {}
    for program in sorted(measured):
        budget = (measured[program] * 115 + 99) // 100
        if budget * 100 > limit * 75:
            fail(f"{program} {args.kernel}: pin {budget} is past 75% of "
                 f"limit {limit}; growth past 75% needs restructuring, "
                 "not a mechanical pin")
        pinned[program] = budget
    for program in sorted(pinned):
        old = programs[program].get(args.kernel)
        programs[program][args.kernel] = pinned[program]
        print(f"{program} {args.kernel}: "
              f"{old if old is not None else '-'} -> {pinned[program]}")
    budgets_path.write_text(json.dumps(document, indent=2) + "\n",
                            encoding="ascii")


if __name__ == "__main__":
    main(sys.argv[1:])
