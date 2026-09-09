#!/usr/bin/env python3
"""Answer only the selected rustc version query."""

import sys

from fixture_common import CONFIG, record, refuse


if sys.argv[1:] != ["--version"]:
    refuse("unsupported rustc arguments")
record("rustc_version")
status = CONFIG.get("rustc_version_status", 0)
if status:
    print("fixture rustc version refusal", file=sys.stderr)
    raise SystemExit(status)
print(CONFIG.get("rustc_version", "rustc 1.88.0 (fixture)"))
