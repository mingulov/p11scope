#!/usr/bin/env python3
"""Bench-overhead bounded-trace oracle: assert the --max-events truncation evidence shape of trace_bound.txt. Oracle extracted from scripts/bench-overhead.sh (lines 197-206)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Bench-overhead bounded-trace oracle: assert the --max-events truncation evidence shape of trace_bound.txt").print_help()
    raise SystemExit(0)

import json, sys

lines = [line.rstrip("\n") for line in open(sys.argv[1])]
events = [line for line in lines if line and not line.startswith(("CAPTURE ", "TRUNCATED ", "EVIDENCE ", "LOST "))]
assert any(line.startswith("CAPTURE ") for line in lines), lines
assert len(events) <= 1, events
assert sum(line.startswith("TRUNCATED at 1 events (--max-events)") for line in lines) == 1, lines
evidence = [line.removeprefix("EVIDENCE ") for line in lines if line.startswith("EVIDENCE ")]
assert len(evidence) == 1, evidence
assert json.loads(evidence[0])["trace_truncated"] is True, evidence[0]
