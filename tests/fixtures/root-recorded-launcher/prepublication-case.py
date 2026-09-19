# SPDX-License-Identifier: GPL-3.0-or-later
"""Hold the actual one-shot fixture at its ownership-record publication."""

import json
import os
from pathlib import Path
import runpy
import sys
import time
from unittest import mock


work = Path(os.environ["CASE_DIR"])
original_open = Path.open


def before_publication(path, *args, **kwargs):
    if path.name.startswith(".owned-") and path.suffix == ".tmp":
        tail = Path("/proc/self/stat").read_bytes().rsplit(b") ", 1)[1].split()
        # Independent rescue evidence only. The drain never reads this file.
        record = {"pid": os.getpid(), "starttime": int(tail[19]), "ppid": int(tail[1])}
        temporary = work / "before-publication.tmp"
        temporary.write_text(json.dumps(record))
        temporary.replace(work / "before-publication.json")
        deadline = time.monotonic() + 8
        while not (work / "publication.release").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("publication fixture release deadline expired")
            time.sleep(0.005)
    return original_open(path, *args, **kwargs)


sys.argv = [sys.argv[1], "launcher", "/bin/true"]
with mock.patch.object(Path, "open", before_publication):
    runpy.run_path(sys.argv[0], run_name="__main__")
