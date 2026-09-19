#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled SoftHSM prerequisite for Lane02 integration tests."""

import sys


if sys.argv[1:] == ["--version"]:
    print("2.6.1")
    raise SystemExit(0)
raise SystemExit(95)
