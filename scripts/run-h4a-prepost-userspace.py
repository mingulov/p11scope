#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manual qualified runner for the H4a pre/post userspace gate.

The gate needs root, both prebuilt release binaries, the Btrfs holder
population and a quiet host with /var/tmp/p11scope-ws-tmp/privileged.lock
held and no Cargo builds running. This wrapper checks the static
preconditions, then drives the suite through one invocation.

Qualified 6.16 shape: M=400 holders, K=40 cap, D=30s per run,
ROUNDS=10 (ABBA/BAAB, 20 samples/arm), POP rebuilt from the current
ledger. The K=8/M=100 example below is development shape only::

    # Development shape only (K=8/M=100):
    P11SCOPE_H4A_PRE_BIN=... P11SCOPE_H4A_POST_BIN=... P11SCOPE_H4A_POP=... \\
        P11SCOPE_H4A_K=8 P11SCOPE_H4A_M=100 \\
        python3 -I scripts/run-h4a-prepost-userspace.py
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ENV = (
    "P11SCOPE_H4A_PRE_BIN",
    "P11SCOPE_H4A_POST_BIN",
    "P11SCOPE_H4A_POP",
    "P11SCOPE_H4A_K",
    "P11SCOPE_H4A_M",
)


def main(argv):
    if os.geteuid() != 0:
        print("run-h4a-prepost-userspace: gate needs root", file=sys.stderr)
        return 1
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(f"H4a inputs missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    proc = subprocess.run(
        [sys.executable, "-I", "tests/python/test_h4a_prepost_userspace.py", *argv],
        cwd=ROOT,
    )
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
