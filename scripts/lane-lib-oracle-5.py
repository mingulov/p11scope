#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared lib process-session snapshot oracle snapshot_user_process_session: list session members with exe digests and argv. Oracle extracted from scripts/lib.sh (lines 599-669)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Shared lib process-session snapshot oracle snapshot_user_process_session: list session members with exe digests and argv").print_help()
    raise SystemExit(0)

import glob
import hashlib
import json
import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    if len(fields) < 20:
        raise ValueError("short proc stat")
    return int(fields[19]), int(fields[1]), int(fields[2]), int(fields[3])


sids = int(sys.argv[1])
if sids <= 0:
    raise SystemExit("invalid process session")
members = []
for path in glob.glob("/proc/[0-9]*"):
    pid = int(path.rsplit("/", 1)[1])
    try:
        starttime, ppid, actual_pgid, actual_sid = stat(pid)
    except (FileNotFoundError, ProcessLookupError):
        # No membership can be established for a process that vanished before
        # its first stat read. Once the target group is identified below, any
        # later disappearance is a hard error.
        continue
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot inspect process {pid}: {error}")
    if actual_sid != sids:
        continue
    try:
        def projection():
            digest = hashlib.sha256()
            with open(f"/proc/{pid}/exe", "rb") as source:
                for block in iter(lambda: source.read(131072), b""):
                    digest.update(block)
            raw_argv = open(f"/proc/{pid}/cmdline", "rb").read()
            if not raw_argv or not raw_argv.endswith(b"\0"):
                raise ValueError("malformed argv")
            argv = [item.decode("utf-8", "strict") for item in raw_argv[:-1].split(b"\0")]
            if not argv or not argv[0]:
                raise ValueError("empty argv")
            return digest.hexdigest(), argv

        digest, argv = projection()
        middle = stat(pid)
        final_digest, final_argv = projection()
        final = stat(pid)
    except (FileNotFoundError, OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"cannot close process-group member {pid}: {error}")
    if middle != (starttime, ppid, actual_pgid, actual_sid) or final != middle:
        raise SystemExit(f"process-session member {pid} changed during snapshot")
    if (final_digest, final_argv) != (digest, argv):
        raise SystemExit(f"process-group member {pid} execed during snapshot")
    members.append(
        {
            "pid": pid,
            "starttime": starttime,
            "ppid": ppid,
            "pgid": actual_pgid,
            "sid": actual_sid,
            "exe_sha256": digest,
            "argv": argv,
        }
    )
print(json.dumps(sorted(members, key=lambda member: member["pid"]), separators=(",", ":")))
