#!/usr/bin/env python3
"""Minimal product Cargo stand-in for the real-helper integration test."""

from pathlib import Path
import sys


if sys.argv[1:4] != ["build", "--locked", "--offline"]:
    raise SystemExit(64)
try:
    target = Path(sys.argv[sys.argv.index("--target-dir") + 1])
except (ValueError, IndexError):
    raise SystemExit(65)
target.joinpath("integrated-build").write_text("yes", encoding="utf-8")
