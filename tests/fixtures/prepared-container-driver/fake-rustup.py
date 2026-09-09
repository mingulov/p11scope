#!/usr/bin/env python3
"""Return only the two explicitly admitted toolchain selections."""

import sys
from fixture_common import CONFIG, record, refuse


arguments = sys.argv[1:]
record("rustup")
if len(arguments) != 4 or arguments[:2] != ["which", "--toolchain"]:
    refuse("unsupported rustup arguments")
if arguments[2] not in ("1.88", "nightly-2026-05-20") or arguments[3] not in ("cargo", "rustc"):
    refuse("unsupported toolchain or executable")
print(CONFIG["tools"][arguments[2] + ":" + arguments[3]])
