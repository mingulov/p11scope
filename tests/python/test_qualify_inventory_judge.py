#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The C1b judge prints inspect's skipped list and member statuses on partial."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/qualify-inventory-c1b.sh"


def judge_source():
    """The judge python block, extracted by its heredoc markers."""
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index('python3 -I - "$OBS" "$CELLS" <<\'EOF\'')
    body = text[start:].splitlines(keepends=True)[1:]
    end = body.index("EOF\n")
    return "".join(body[:end])


def write_cell(obs, status):
    (obs / "cap.nprocs").write_text("501\n", encoding="utf-8")
    (obs / "cap.rc").write_text("inspect rc=0\ninventory rc=0\n", encoding="utf-8")
    (obs / "cap.ready").write_text("READY pid=100\n", encoding="utf-8")
    (obs / "cap.paths").write_text("/mod/libsofthsm2.so\n", encoding="utf-8")
    (obs / "cap.json").write_text(
        json.dumps({"callers": [], "modules": {}, "edges": [], "gaps": []}),
        encoding="utf-8",
    )
    skipped = (
        [{"pid": 7, "subject": "deep scan", "reason": "snapshot unavailable"}]
        if status == "partial"
        else []
    )
    (obs / "cap.inspect.json").write_text(
        json.dumps(
            {
                "scan": {
                    "status": status,
                    "enumerated": 501,
                    "limit": 64,
                    "deep_scanned": 64,
                    "maps_matched": 400,
                    "unexamined": 0,
                    "unexamined_objects": 0,
                    "snapshots_unavailable": 1,
                    "attribution_losses": {},
                },
                "skipped": skipped,
                "processes": [
                    {"pid": 7, "status": "unreadable", "reason": "maps denied"},
                    {"pid": 8, "status": "scanned"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (obs / "cap.stderr").write_text("", encoding="utf-8")


def run_judge(obs):
    return subprocess.run(
        [sys.executable, "-I", "-", str(obs), "cap"],
        input=judge_source(),
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


class QualifyInventoryJudgeTests(unittest.TestCase):
    def test_partial_scan_prints_skipped_list_and_member_statuses(self):
        with tempfile.TemporaryDirectory(prefix="p11scope c1b judge ") as tmp:
            obs = Path(tmp)
            write_cell(obs, "partial")
            result = run_judge(obs)
        self.assertIn("inspect skipped (1)", result.stdout)
        self.assertIn("snapshot unavailable", result.stdout)
        self.assertIn("inspect member statuses", result.stdout)
        self.assertIn("unreadable", result.stdout)
        self.assertIn("maps denied", result.stdout)

    def test_complete_scan_prints_no_partial_diagnosis(self):
        with tempfile.TemporaryDirectory(prefix="p11scope c1b judge ") as tmp:
            obs = Path(tmp)
            write_cell(obs, "complete")
            result = run_judge(obs)
        self.assertNotIn("inspect skipped", result.stdout)
        self.assertNotIn("inspect member statuses", result.stdout)
        self.assertNotIn("inspect unattributed members", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
