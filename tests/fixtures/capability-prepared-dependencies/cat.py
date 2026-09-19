#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import sys

if sys.argv[1:] == ["/proc/sys/kernel/perf_event_paranoid"]:
    print(4)
elif sys.argv[1:] == ["/proc/sys/kernel/yama/ptrace_scope"]:
    print(1)
else:
    os.execv("/bin/cat", ["cat", *sys.argv[1:]])
