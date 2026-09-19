#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native test shim that delegates every process-control action except ACK."""

import os
from pathlib import Path
import subprocess
import sys
import time


if Path(sys.argv[0]).name == "sudo":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "-n":
        arguments = arguments[1:]
    status = subprocess.run(arguments, check=False).returncode
    time.sleep(float(os.environ.get("ABI_ROUTING_SUDO_POST_WAIT", "0")))
    raise SystemExit(status)

if len(sys.argv) > 1 and sys.argv[1] == "ack":
    mode = os.environ.get("ABI_ROUTING_ACK_MODE", "fail")
    if mode == "block":
        time.sleep(float(os.environ.get("ABI_ROUTING_ACK_BLOCK_SECONDS", "2")))
    elif mode == "fail":
        raise SystemExit(19)

real_helper = os.environ["ABI_ROUTING_REAL_HELPER"]
os.execv(sys.executable, [sys.executable, "-I", real_helper, *sys.argv[1:]])
