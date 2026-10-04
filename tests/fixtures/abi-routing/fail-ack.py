#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native test shim that delegates every process-control action except ACK."""

import math
import os
from pathlib import Path
import subprocess
import sys
import time


def _slack(seconds):
    """Scale a hang-guard bound, as in test_lane13_evidence.py."""
    raw = os.environ.get("P11SCOPE_TEST_TIME_SCALE", "").strip() or "5.0"
    try:
        scale = float(raw)
    except ValueError:
        scale = math.nan
    if not math.isfinite(scale) or scale < 1:
        raise SystemExit("P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1")
    return seconds * scale


if Path(sys.argv[0]).name == "sudo":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "-n":
        arguments = arguments[1:]
    status = subprocess.run(arguments, check=False).returncode
    time.sleep(float(os.environ.get("ABI_ROUTING_SUDO_POST_WAIT", "0")))
    release = os.environ.get("ABI_ROUTING_SUDO_RELEASE_FILE", "")
    # Only the outer launch wrapper gates on the release file. Nested
    # facilitator calls through the same shim (lane-lib signals during
    # finalization) must never wait: finalization runs while the test is
    # stuck waiting for the wrapper, so gating them would deadlock the
    # failure path behind the full release bound.
    gated = (
        bool(release)
        and len(arguments) > 3
        and arguments[0] == "python3"
        and arguments[1] == "-I"
        and os.path.basename(arguments[2]) == "recorded-process-exec.py"
        and arguments[3] == "exec"
    )
    if gated:
        # Deterministic wrapper custody: stay alive until the test
        # publishes the release file, so the intermediate state (root
        # process cleared, wrapper still owned) is observable no matter
        # how slow one ownership poll is. A removed release directory
        # means the test gave up (a failed launch removes its tree),
        # so exit promptly instead of orphaning the full bound. The
        # bound only backstops a live test that never releases;
        # expiring it must fail loudly with a status no target produces.
        parent = os.path.dirname(os.path.abspath(release))
        parent_existed = os.path.isdir(parent)
        deadline = time.monotonic() + _slack(30)
        while not os.path.exists(release):
            if parent_existed and not os.path.isdir(parent):
                break
            if time.monotonic() >= deadline:
                print("sudo shim: release file never published", file=sys.stderr)
                raise SystemExit(99)
            time.sleep(0.01)
    raise SystemExit(status)

if len(sys.argv) > 1 and sys.argv[1] == "ack":
    mode = os.environ.get("ABI_ROUTING_ACK_MODE", "fail")
    if mode == "block":
        time.sleep(float(os.environ.get("ABI_ROUTING_ACK_BLOCK_SECONDS", "2")))
    elif mode == "fail":
        raise SystemExit(19)

real_helper = os.environ["ABI_ROUTING_REAL_HELPER"]
os.execv(sys.executable, [sys.executable, "-I", real_helper, *sys.argv[1:]])
