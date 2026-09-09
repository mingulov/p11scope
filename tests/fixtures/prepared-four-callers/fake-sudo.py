#!/usr/bin/env python3
import sys
from fixture_common import CONFIG, record, refuse

if sys.argv[1:] != ["-n", "true"]:
    refuse("unsupported sudo arguments")
record("sudo")
raise SystemExit(CONFIG.get("sudo_status", 73))
