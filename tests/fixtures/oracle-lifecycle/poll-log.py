#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recorded-process helper interposer that logs every liveness poll.

The hung-clients scenario points RECORDED_PROCESS_EXEC here, so each
`recorded_process_control active PID START` made by the product poll loops
appends `poll PID LABEL` to ORACLE_TEST_EVENT_LOG before the real helper's
output and status are passed through unchanged. The harness asserts the
exact poll/sleep sequence instead of timing it.
"""

import os
import subprocess
import sys

real = os.environ["ORACLE_TEST_REAL_HELPER"]
result = subprocess.run([sys.executable, "-I", real, *sys.argv[1:]], stdout=subprocess.PIPE, check=False)
if len(sys.argv) > 2 and sys.argv[1] == "active":
    label = result.stdout.decode("ascii", "replace").strip()
    with open(os.environ["ORACLE_TEST_EVENT_LOG"], "a", encoding="ascii") as log:
        log.write(f"poll {sys.argv[2]} {label}\n")
sys.stdout.buffer.write(result.stdout)
sys.stdout.flush()
raise SystemExit(result.returncode)
