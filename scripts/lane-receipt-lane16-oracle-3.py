#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4 lane 16 structural oracle: assert the observed evidence row counts, losses, and pause shape for the mode. Oracle extracted from scripts/verify-receipt-lane16.sh (lines 429-442)."""
import argparse
import sys

if sys.argv[1:] in (["--help"], ["-h"]):
    argparse.ArgumentParser(description="Task 4 lane 16 structural oracle: assert the observed evidence row counts, losses, and pause shape for the mode").print_help()
    raise SystemExit(0)

import json, sys
d = json.load(open(sys.argv[1])); e = d["evidence"]; mode = sys.argv[2]
assert (e["table_entries"], e["slots"], e["attached_probes"]) == (68, 68, 136)
assert e["skipped"] == [{"name": "discovery subject", "reason": "discovery unavailable"}]
assert [e[k] for k in ("event_loss", "discovery_ring_loss", "discovery_state_failures", "discovery_read_failures", "discovery_truncated", "task_uprobe_link_losses")] == [0] * 6
assert all(row["module_ambiguous"] is False for row in d["functions"])
assert [e[k] for k in ("session_cancel_ambiguities", "auth_state_ambiguities", "fork_state_ambiguities")] == [0] * 3
assert [e[k] for k in ("in_flight_at_end", "pending_at_end")] == [0, 0]
assert e["child_still_running"] is False
if mode == "never":
    assert [e[k] for k in ("pause", "pause_attempts", "pause_confirmed", "pause_partial")] == ["none", 0, 0, 0]
else:
    assert e["pause"] == "sigstop" and e["pause_attempts"] == e["pause_confirmed"] >= 1 and e["pause_partial"] == 0
print(f"Lane 16 {mode} structural row: OK")
