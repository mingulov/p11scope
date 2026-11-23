#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Contract for the inventory-event-stdout cell judge.

The judge is the `event-stdout` judge of scripts/qualify_records.py,
which `inventory_event_stdout()` in scripts/qualify-public-cli.sh calls;
this suite runs it against synthetic streams and decides from its typed
verdict record. The totals cadence is anchored at
`started`, not at a pass number: on a slow attach the first pass
commits after the interval is already due, so the first totals
legitimately trails pass 0, while a totals before its due date is
rejected.

Run: python3 -I tests/python/test_event_stdout_judge.py -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "qualify-public-cli.sh"
SCHEMA = "p11scope/inventory-events/v1"
INTERVAL_NS = 2_000_000_000


RECORDS = ROOT / "scripts" / "qualify_records.py"
RUN_ID = "test-run"


def row(seq, at_ns, kind, event):
    return {"schema": SCHEMA, "seq": seq, "at_ns": at_ns, "kind": kind, "event": event}


def marker(pass_no):
    return {
        "pass": pass_no,
        "scanned": 1,
        "maps_matched": 0,
        "native_callers": 0,
        "scan_callers": 1,
        "totals": {"callers": 1, "modules": 1, "edges": 1},
        "new_gaps": 0,
        "suppressed_delta": 0,
        "gaps_suppressed": 0,
    }


def totals(pass_no):
    return {
        "pass": pass_no,
        "passes": pass_no + 1,
        "callers": 1,
        "modules": 1,
        "edges": 1,
        "stdout_lost": {"lines": 0, "bytes": 0},
    }


COMPLETE = {"status": "complete", "lines_lost": 0, "bytes_lost": 0, "reason": "none"}
TRUNCATED = {"status": "truncated", "lines_lost": 2, "bytes_lost": 310, "reason": "broken_pipe"}


def report(passes, event_output=COMPLETE):
    return {
        "schema": "p11scope/inventory/v1",
        "observation": {"passes": passes},
        "callers": [{}],
        "modules": [{}],
        "edges": [{}],
        "event_output": dict(event_output),
    }


def run_judge(stream, full_report):
    """Run the loader's event-stdout judge; the result carries the parsed
    verdict record as `.verdict`."""
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        subprocess.run([sys.executable, "-I", str(RECORDS), "stamp", "inventory-event-stdout.stamp",
                        RUN_ID, "inventory-event-stdout"], cwd=tmp, check=True)
        with (tmpdir / "event-stdout.jsonl").open("w", encoding="utf-8") as handle:
            for entry in stream:
                handle.write(json.dumps(entry) + "\n")
        (tmpdir / "event-stdout.json").write_text(
            json.dumps(full_report), encoding="utf-8"
        )
        (tmpdir / "event-epipe.json").write_text(
            json.dumps(report(1, TRUNCATED)), encoding="utf-8"
        )
        (tmpdir / "event-epipe.head").write_bytes(b"{" + b"x" * 199)
        result = subprocess.run(
            [sys.executable, "-I", str(RECORDS), "event-stdout", "--stamp", "inventory-event-stdout.stamp",
             "--run-id", RUN_ID, "--verdict", "verdict.json", "--jsonl", "event-stdout.jsonl",
             "--full-report", "event-stdout.json", "--epipe-report", "event-epipe.json",
             "--epipe-head", "event-epipe.head", "--rc1", "0", "--rc2", "1"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=60,
        )
        result.verdict = json.loads((tmpdir / "verdict.json").read_text(encoding="utf-8"))
        return result


STARTED = 1_000_000_000_000


class EventStdoutJudgeTests(unittest.TestCase):
    def test_slow_attach_totals_at_pass_0_accepted(self):
        commit = STARTED + 2_700_000_000
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", totals(0)),
            row(3, commit + 100_000_000, "ended", {"stdout_lost": {"lines": 0, "bytes": 0}, "passes": 1}),
        ]
        result = run_judge(stream, report(1))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fast_attach_totals_at_pass_1_accepted(self):
        commit0 = STARTED + 1_400_000_000
        commit1 = STARTED + 2_700_000_000
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit0, "pass_committed", marker(0)),
            row(2, commit1, "pass_committed", marker(1)),
            row(3, commit1, "totals", totals(1)),
            row(4, commit1 + 100_000_000, "ended", {"stdout_lost": {"lines": 0, "bytes": 0}, "passes": 2}),
        ]
        result = run_judge(stream, report(2))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_totals_before_the_due_date_rejected(self):
        commit = STARTED + 1_000_000_000
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", totals(0)),
            row(3, commit + 100_000_000, "ended", {"stdout_lost": {"lines": 0, "bytes": 0}, "passes": 1}),
        ]
        result = run_judge(stream, report(1))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.verdict["rule"], "event.totals-cadence", result.stdout)

    def test_totals_disagreeing_with_its_marker_rejected(self):
        commit = STARTED + 2_700_000_000
        bad = totals(0)
        bad["callers"] = 9
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", bad),
            row(3, commit + 100_000_000, "ended", {"stdout_lost": {"lines": 0, "bytes": 0}, "passes": 1}),
        ]
        result = run_judge(stream, report(1))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.verdict["rule"], "event.totals-marker", result.stdout)


if __name__ == "__main__":
    unittest.main()
