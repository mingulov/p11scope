# SPDX-License-Identifier: GPL-3.0-or-later
"""Record fixture custody, then exec in-place; no production ACK or supervisor."""

import json
import os
from pathlib import Path
import signal
import sys


phase, *command = sys.argv[1:]
pid = os.getpid()
generation = int(Path("/proc/self/stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
record = json.dumps({"pid": pid, "starttime": generation}) + "\n"
work = Path(os.environ["CASE_DIR"])
path = work / f".owned-{pid}-{generation}.json"
temporary = path.with_suffix(".tmp")
with temporary.open("x") as stream:
    stream.write(record)
temporary.replace(path)
os.environ["FIXTURE_OWN_PID"] = str(pid)
os.environ["FIXTURE_OWN_STARTTIME"] = str(generation)
if phase == os.environ.get("DELAY_PHASE"):
    temporary = work / "wrapper.stopped.tmp"
    temporary.write_text(record)
    temporary.replace(work / "wrapper.stopped")
    os.kill(pid, signal.SIGSTOP)
if phase == os.environ.get("EARLY_PHASE"):
    raise SystemExit(71)
os.execvpe(command[0], command, os.environ)
