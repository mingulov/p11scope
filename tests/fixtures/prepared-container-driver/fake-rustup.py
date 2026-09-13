#!/usr/bin/env python3
"""Return only the two explicitly admitted toolchain selections."""

import sys
from fixture_common import CONFIG, record, refuse


arguments = sys.argv[1:]
if arguments == ["--version"]:
    # The tool pinning layer identifies its executables by behaviour (it runs
    # `rustup --version` and requires a `rustup ` banner), so a stub standing
    # in for rustup must answer as rustup. Answer before record(): the probe
    # is a capability check, not a tool selection, so it must not appear in
    # the recorded call sequence.
    print("rustup 1.99.0 (p11scope test fixture)")
    raise SystemExit(0)
record("rustup")
if len(arguments) != 4 or arguments[:2] != ["which", "--toolchain"]:
    refuse("unsupported rustup arguments")
if arguments[2] not in ("1.88", "nightly-2026-05-20") or arguments[3] not in ("cargo", "rustc"):
    refuse("unsupported toolchain or executable")
print(CONFIG["tools"][arguments[2] + ":" + arguments[3]])
