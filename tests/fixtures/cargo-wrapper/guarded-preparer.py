#!/usr/bin/env python3
"""Observe preparation arguments and forbid network in missing-archive tests."""

import json
import os
from pathlib import Path
import runpy
import sys
import urllib.request


base = Path(__file__).resolve().parents[2]
(base / "preparation.json").write_text(json.dumps({
    "argv": sys.argv[1:], "cwd": os.getcwd(), "isolated": sys.flags.isolated,
}) + "\n", encoding="utf-8")


def forbid_download(*_arguments, **_keywords):
    (base / "downloader-executed").touch()
    raise OSError("fixture downloader blocked")


urllib.request.urlopen = forbid_download
runpy.run_path(str(Path(__file__).with_name("actual-prepare-dependencies.py")), run_name="__main__")
