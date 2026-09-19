# SPDX-License-Identifier: GPL-3.0-or-later
"""Process-session snapshot races: python3 -I tests/python/test_process_session_snapshot.py."""

import contextlib
import errno
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch


class ProcessSessionSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Execute the production oracle; do not duplicate its snapshot logic.
        source = (Path(__file__).resolve().parents[2] / "scripts/lane-lib-oracle-5.py").read_text()
        cls.source = compile(source, "scripts/lane-lib-oracle-5:oracle", "exec")

    def snapshot(self, failure_read=0, error=None):
        fields = ["S", "1", "41", "41"] + ["0"] * 15 + ["100"]
        files = {
            "/proc/41/stat": ("41 (fixture) " + " ".join(fields)).encode(),
            "/proc/41/exe": b"executable",
            "/proc/41/cmdline": b"fixture\0",
        }
        reads = 0

        def opened(path, mode):
            nonlocal reads
            reads += 1
            if reads == failure_read:
                raise error
            return io.BytesIO(files[path])

        output = io.StringIO()
        with patch("sys.argv", ["snapshot", "41"]), \
             patch("glob.glob", return_value=["/proc/41"]), \
             patch("builtins.open", side_effect=opened), \
             contextlib.redirect_stdout(output):
            try:
                exec(self.source, {})
            except SystemExit as failure:
                self.assertEqual(output.getvalue(), "")
                return str(failure)
        return json.loads(output.getvalue())

    def test_healthy_member_is_retained(self):
        members = self.snapshot()
        self.assertEqual(len(members), 1)
        self.assertEqual((members[0]["pid"], members[0]["sid"]), (41, 41))

    def test_only_initial_disappearance_is_tolerated(self):
        for number in (errno.ENOENT, errno.ESRCH):
            error = OSError(number, "injected disappearance")
            with self.subTest(errno=number, read=1):
                self.assertEqual(self.snapshot(1, error), [])
            # Once membership is known, exe/argv reads and stat rechecks
            # must all fail closed if the process disappears.
            for read in range(2, 8):
                with self.subTest(errno=number, read=read):
                    self.assertIn("cannot close process-group member 41",
                                  self.snapshot(read, error))

    def test_other_initial_errors_reject_snapshot(self):
        for error in (PermissionError(errno.EACCES, "denied"),
                      OSError(errno.EIO, "I/O"), ValueError("malformed proc stat")):
            with self.subTest(error=error):
                self.assertIn("cannot inspect process 41", self.snapshot(1, error))


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
