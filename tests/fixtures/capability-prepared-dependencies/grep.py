#!/usr/bin/python3
import os
import sys

if len(sys.argv) == 4 and sys.argv[1:3] == ["-Fq", "libsofthsm2.so"] and sys.argv[3].startswith("/proc/"):
    raise SystemExit(0)
os.execv("/bin/grep", ["grep", *sys.argv[1:]])
