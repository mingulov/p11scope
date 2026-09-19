# SPDX-License-Identifier: GPL-3.0-or-later
"""Tripwire for an inherited PYTHONPATH reaching an unisolated interpreter."""

from pathlib import Path

Path(__file__).with_name("sitecustomize-ran").write_text("executed")
