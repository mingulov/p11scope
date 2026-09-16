#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys


Path(os.environ["P11SCOPE_PRODUCT_BUILD_RECORD"]).with_name("preparation.json").write_text(
    json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(),
                "isolated": int(sys.flags.isolated)}, sort_keys=True), encoding="utf-8")
