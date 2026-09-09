#!/usr/bin/env python3
"""Record the harmless ABI resource sentinel and refuse without executing it."""

from pathlib import Path
import sys

from fixture_common import CONFIG, record, refuse


if sys.argv[1:] != ["-n", "true"]:
    refuse("unsupported sudo arguments")
record("sudo")
mutation = CONFIG.get("mutation")
if mutation:
    with Path(CONFIG[mutation]).open("a", encoding="utf-8") as stream:
        stream.write("\nfixture persistent mutation\n")
raise SystemExit(CONFIG.get("sudo_status", 73))
