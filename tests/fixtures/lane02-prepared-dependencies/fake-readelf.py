#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled readelf for Lane02 setup before the fixture build refusal."""

import sys


if sys.argv[1:2] == ["-n"]:
    print("    Build ID: 0123456789abcdef")
    raise SystemExit(0)
raise SystemExit(94)
