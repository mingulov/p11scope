#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract for the inventory-event-stdout cell judge.

The judge lives inline in scripts/qualify-public-cli.sh
(`inventory_event_stdout()`); this suite extracts that exact heredoc and
runs it against synthetic streams. The totals cadence is anchored at
`started`, not at a pass number: on a slow attach the first pass
commits after the interval is already due, so the first totals
legitimately trails pass 0, while a totals before its due date is
rejected.

Run: python3 -I tests/python/test_event_stdout_judge.py -v
"""

import json
import os
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


def extract_judge():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    start = next(
        i for i, line in enumerate(lines) if line == "inventory_event_stdout() {"
    )
    heredoc = next(i for i in range(start, len(lines)) if "<<'PY'" in lines[i])
    end = next(i for i in range(heredoc + 1, len(lines)) if lines[i] == "PY")
    block = "\n".join(lines[heredoc + 1 : end]) + "\n"
    assert SCHEMA in block and "event-epipe.stderr" in block, (
        "extracted the wrong heredoc"
    )
    return block


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
    }


def report(passes):
    return {
        "schema": "p11scope/inventory/v1",
        "observation": {"passes": passes},
        "callers": [0],
        "modules": [0],
        "edges": [0],
    }


def run_judge(stream, full_report):
    judge = extract_judge()
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "judge.py").write_text(judge, encoding="utf-8")
        with (tmpdir / "event-stdout.jsonl").open("w", encoding="utf-8") as handle:
            for entry in stream:
                handle.write(json.dumps(entry) + "\n")
        (tmpdir / "event-stdout.json").write_text(
            json.dumps(full_report), encoding="utf-8"
        )
        (tmpdir / "event-epipe.json").write_text(
            json.dumps(report(1)), encoding="utf-8"
        )
        (tmpdir / "event-epipe.head").write_bytes(b"{" + b"x" * 199)
        (tmpdir / "event-epipe.stderr").write_text(
            "p11scope: inventory event log stdout shed 2 lines\n", encoding="utf-8"
        )
        env = dict(
            os.environ,
            full_out=str(tmpdir / "event-stdout.json"),
            epipe_out=str(tmpdir / "event-epipe.json"),
            rc1="0",
            rc2="1",
        )
        return subprocess.run(
            [sys.executable, "-I", "judge.py"],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )


STARTED = 1_000_000_000_000


class EventStdoutJudgeTests(unittest.TestCase):
    def test_slow_attach_totals_at_pass_0_accepted(self):
        commit = STARTED + 2_700_000_000
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", totals(0)),
            row(3, commit + 100_000_000, "ended", {"passes": 1}),
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
            row(4, commit1 + 100_000_000, "ended", {"passes": 2}),
        ]
        result = run_judge(stream, report(2))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_totals_before_the_due_date_rejected(self):
        commit = STARTED + 1_000_000_000
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", totals(0)),
            row(3, commit + 100_000_000, "ended", {"passes": 1}),
        ]
        result = run_judge(stream, report(1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('row["at_ns"] - last_at', result.stderr)

    def test_totals_disagreeing_with_its_marker_rejected(self):
        commit = STARTED + 2_700_000_000
        bad = totals(0)
        bad["callers"] = 9
        stream = [
            row(0, STARTED, "started", {"started_ns": STARTED}),
            row(1, commit, "pass_committed", marker(0)),
            row(2, commit, "totals", bad),
            row(3, commit + 100_000_000, "ended", {"passes": 1}),
        ]
        result = run_judge(stream, report(1))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('marker["totals"]', result.stderr)


if __name__ == "__main__":
    unittest.main()
