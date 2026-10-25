# SPDX-License-Identifier: GPL-3.0-or-later
"""Dying session members never fail the snapshot: python3 -I tests/python/test_process_session_dying_members.py."""

import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def stat_bytes(pid, state="S", ppid=1, pgid=41, sid=41, starttime=100):
    fields = [state, str(ppid), str(pgid), str(sid)] + ["0"] * 15 + [str(starttime)]
    return f"{pid} (fixture) ".encode() + " ".join(fields).encode()


LIVE_STAT = stat_bytes(41)
ZOMBIE_STAT = stat_bytes(41, state="Z")
LIVE_STAT_42 = stat_bytes(42, ppid=41)
EXE_BYTES = b"executable"
CMDLINE_BYTES = b"fixture\0"


class ScriptedProc:
    """Serve a scripted open() sequence, then plausible live content."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def opened(self, path, mode):
        self.calls.append(path)
        if self.script:
            payload = self.script.pop(0)
            if isinstance(payload, Exception):
                raise payload
            return io.BytesIO(payload)
        if path.endswith("/stat"):
            pid = int(path.split("/")[2])
            return io.BytesIO(stat_bytes(pid))
        if path.endswith("/exe"):
            return io.BytesIO(EXE_BYTES)
        return io.BytesIO(CMDLINE_BYTES)


class DyingMemberSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Execute the production oracle; do not duplicate its snapshot logic.
        source = (
            Path(__file__).resolve().parents[2] / "scripts/lane-lib-oracle-5.py"
        ).read_text()
        cls.source = compile(source, "scripts/lane-lib-oracle-5:oracle", "exec")

    def run_oracle(self, pids, script):
        proc = ScriptedProc(script)
        output = io.StringIO()
        with (
            patch("sys.argv", ["snapshot", "41"]),
            patch("glob.glob", return_value=[f"/proc/{pid}" for pid in pids]),
            patch("builtins.open", side_effect=proc.opened),
            contextlib.redirect_stdout(output),
        ):
            try:
                exec(self.source, {})
            except SystemExit as failure:
                return ("failed", str(failure))
        return ("ok", json.loads(output.getvalue()))

    def test_zombie_member_is_omitted(self):
        status, members = self.run_oracle(
            [41],
            [
                ZOMBIE_STAT,
                FileNotFoundError(2, "No such file or directory"),
                ZOMBIE_STAT,
            ],
        )
        self.assertEqual((status, members), ("ok", []))

    def test_exiting_member_with_empty_cmdline_is_omitted(self):
        status, members = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                b"",
                ZOMBIE_STAT,
            ],
        )
        self.assertEqual((status, members), ("ok", []))

    def test_member_reaped_during_probe_is_omitted(self):
        status, members = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                b"",
                FileNotFoundError(2, "No such file or directory"),
            ],
        )
        self.assertEqual((status, members), ("ok", []))

    def test_zombie_leader_omitted_live_child_listed(self):
        status, members = self.run_oracle(
            [41, 42],
            [
                ZOMBIE_STAT,
                FileNotFoundError(2, "No such file or directory"),
                ZOMBIE_STAT,
                LIVE_STAT_42,
                EXE_BYTES,
                CMDLINE_BYTES,
                LIVE_STAT_42,
                EXE_BYTES,
                CMDLINE_BYTES,
                LIVE_STAT_42,
            ],
        )
        self.assertEqual(status, "ok")
        self.assertEqual([member["pid"] for member in members], [42])
        self.assertEqual(members[0]["argv"], ["fixture"])

    def test_live_member_with_empty_cmdline_still_fails(self):
        status, message = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                b"",
            ],
        )
        self.assertEqual(status, "failed")
        self.assertIn("cannot close process-group member 41: malformed argv", message)

    def test_mid_exec_member_still_fails(self):
        status, message = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                b"before\0",
                LIVE_STAT,
                EXE_BYTES,
                b"after\0",
                LIVE_STAT,
            ],
        )
        self.assertEqual(status, "failed")
        self.assertIn("process-group member 41 execed during snapshot", message)

    def test_changed_member_still_fails(self):
        status, message = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                CMDLINE_BYTES,
                stat_bytes(41, starttime=200),
            ],
        )
        self.assertEqual(status, "failed")
        self.assertIn("process-session member 41 changed during snapshot", message)

    def test_probe_rejects_pid_reuse(self):
        status, message = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                FileNotFoundError(2, "No such file or directory"),
                stat_bytes(41, starttime=200),
            ],
        )
        self.assertEqual(status, "failed")
        self.assertIn("cannot close process-group member 41", message)

    def test_live_member_listed_with_argv(self):
        status, members = self.run_oracle(
            [41],
            [
                LIVE_STAT,
                EXE_BYTES,
                CMDLINE_BYTES,
                LIVE_STAT,
                EXE_BYTES,
                CMDLINE_BYTES,
                LIVE_STAT,
            ],
        )
        self.assertEqual(status, "ok")
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]["argv"], ["fixture"])
        self.assertEqual(
            set(members[0]),
            {"pid", "starttime", "ppid", "pgid", "sid", "exe_sha256", "argv"},
        )


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
