#!/usr/bin/env python3
"""Answer the compiler version query and refuse every compilation."""

import sys

from fixture_common import record


if sys.argv[1:] == ["-dumpfullversion", "-dumpversion"]:
    record("compiler_version")
    print("14.2.0")
    raise SystemExit(0)
record("compiler_refusal")
print("ABI fixture refusal: compiler execution blocked", file=sys.stderr)
raise SystemExit(89)
