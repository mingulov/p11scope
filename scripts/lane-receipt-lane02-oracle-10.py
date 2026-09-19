#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 02 reclaim_verified_output oracle: chown a private root-owned observer output after verifying directory identity. Oracle extracted from scripts/verify-receipt-lane02.sh (lines 603-613)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 02 reclaim_verified_output oracle: chown a private root-owned observer output after verifying directory identity").print_help()
    raise SystemExit(0)

import os, stat, sys
directory, identity, name, uid, gid = sys.argv[1:]
fd_dir = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
s = os.fstat(fd_dir)
if f"{s.st_dev}:{s.st_ino}" != identity:
    raise SystemExit("row directory identity changed")
fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd_dir)
s = os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
    raise SystemExit("observer output is not a private root-owned regular file")
os.fchown(fd, int(uid), int(gid))
