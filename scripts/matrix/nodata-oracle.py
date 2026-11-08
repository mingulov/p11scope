#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""v0.7.0 no-data matrix oracle (stub): judges one live cell.

Full checks land with the implementation commit; this stub only parses
the cell receipt and reports PASS so the self-test can show RED first.
"""

import argparse
import sys


def build_parser():
    parser = argparse.ArgumentParser(description="judge one no-data matrix cell")
    parser.add_argument("--cell", required=True)
    parser.add_argument("--mode", required=True,
                        choices=["run", "profile", "trace", "inventory"])
    parser.add_argument("--scope", required=True,
                        choices=["pid", "cgroup", "system", "child"])
    parser.add_argument("--json", required=True)
    parser.add_argument("--stdout", required=True)
    parser.add_argument("--stderr", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--sysprovider", required=True)
    parser.add_argument("--min-calls", required=True, type=int)
    parser.add_argument("--exact", default=None)
    parser.add_argument("--caller", default=None)
    parser.add_argument("--caller-pid", default=None, type=int)
    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    print("cell=%s mode=%s scope=%s: stub oracle, no checks yet"
          % (args.cell, args.mode, args.scope))
    print("RESULT verdict=PASS calls=unknown endpoints=unknown "
          "caller=unknown note=stub")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
