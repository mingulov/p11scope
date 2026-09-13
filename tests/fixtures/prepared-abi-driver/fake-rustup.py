#!/usr/bin/env python3
"""Return only the four selected tool paths admitted by the ABI fixture."""

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
key = ":".join(arguments[2:])
if key not in CONFIG["tools"]:
    refuse("unsupported tool selection")
print(CONFIG["tools"][key])
