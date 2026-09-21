#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Timestamp one text stream line by line.

Reads stdin (the observer's stderr via a FIFO), writes the raw lines
unchanged to --passthrough, and writes one JSON object per line to --out
with monotonic + wall receive timestamps. Lets the harness date the
`p11scope: discovery:` marker without touching the observer.

Stdlib only.
"""

import argparse
import json
import sys
import time


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--passthrough", required=True)
    args = parser.parse_args(argv)
    with open(args.out, "w", encoding="utf-8") as timed, open(
        args.passthrough, "w", encoding="utf-8", errors="replace"
    ) as raw:
        for line in sys.stdin:
            text = line.rstrip("\n")
            raw.write(line)
            raw.flush()
            timed.write(
                json.dumps(
                    {
                        "t_mono_ns": time.monotonic_ns(),
                        "t_wall_ns": time.time_ns(),
                        "line": text,
                    }
                )
                + "\n"
            )
            timed.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
