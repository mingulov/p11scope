# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""CI entry mapping for the stop-race cells (synthetic, no root).

Exercises `scripts/ci/stop-races.sh` without privileged runs: the
joint-row mapping (wedge signature, single-seal preclusion tag, clean
pass, unexpected pass, unmapped failure, missing test binary) via a
verbatim copy of the entry with stubbed qualify/id/library-test, and
the early prerequisite rows (non-root, missing observer) via the real
entry. The harness must also flag a ledger that appears between the
pre-kill check and the signal.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/stop-races.sh"
HARNESS = ROOT / "scripts/qualify-stop-races.sh"

SWEEP_CELLS = (
    "stop-race-sweep.profile-pid",
    "stop-race-sweep.profile-system",
    "stop-race-sweep.run",
    "stop-race-sweep.inventory-system",
    "system-newcomer-burst",
)


def script_token(pattern, name):
    match = re.search(pattern, SCRIPT.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, "cannot find %s in the CI entry" % name
    return match.group(1)


def joint_cell():
    return script_token(r"^JOINT_CELL=(\S+)\s*$", "the joint cell selector")


def wedge_signature():
    return script_token(r"^JOINT_WEDGE_SIGNATURE='([^']+)'\s*$", "the wedge signature")


def write_exe(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


STUB_QUALIFY = """#!/bin/sh
# Stub for the sweep/burst harness: five passing rows, no root.
set -u
OUT="$2"
cat > "$OUT/results.jsonl" <<'EOF'
%s
EOF
exit 0
""" % "\n".join(
    '{"cell":"%s","pass":true,"detail":"stub","qualification":"stub"}' % cell
    for cell in SWEEP_CELLS
)

STUB_ID = "#!/bin/sh\necho 0\n"

STUB_LIBTEST = """#!/bin/sh
# Stub library test: --list advertises the joint cell, --exact replays
# the fixture log on stdout (the entry redirects it to joint-cell.log).
set -u
if [ "${1:-}" = --list ]; then
  echo "$JOINT_CELL_STUB: test"
  exit 0
fi
printf '%s' "$STUB_LOG"
exit "$STUB_RC"
"""


def run_mapping(*, log, rc, expect_fail, libtest=True):
    """Run a verbatim copy of the entry with stubbed qualify/id/libtest."""
    cell = joint_cell()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        root = tmp / "root"
        (root / "scripts/ci").mkdir(parents=True)
        copy = root / "scripts/ci/stop-races.sh"
        copy.write_bytes(SCRIPT.read_bytes())
        copy.chmod(0o755)
        assert copy.read_bytes() == SCRIPT.read_bytes(), "entry copy drifted"
        qualify = root / "scripts/qualify-stop-races.sh"
        write_exe(qualify, STUB_QUALIFY)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        write_exe(bin_dir / "id", STUB_ID)
        env = dict(os.environ)
        env["PATH"] = str(bin_dir) + ":" + env.get("PATH", "")
        env["JOINT_EXPECTED_FAILURE"] = "1" if expect_fail else "0"
        env["STOP_RACES_TRIALS"] = "2"
        env["STOP_RACES_BURST_TRIALS"] = "1"
        if libtest:
            stub = tmp / "libtest"
            write_exe(stub, STUB_LIBTEST)
            env["P11SCOPE_LIBTEST"] = str(stub)
            env["JOINT_CELL_STUB"] = cell
            env["STUB_LOG"] = log
            env["STUB_RC"] = str(rc)
        else:
            env.pop("P11SCOPE_LIBTEST", None)
        out = tmp / "out"
        proc = subprocess.run(
            [str(copy), "/bin/true", str(out)],
            env=env, capture_output=True, text=True, timeout=30,
        )
        rows = []
        results = out / "results.jsonl"
        if results.exists():
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        joint = next((row for row in rows
                      if row.get("cell") == "joint-stop-after-last-waiter"), None)
        return proc, rows, joint


class CiStopRacesTests(unittest.TestCase):
    def test_wedge_signature_maps_expected_failure(self):
        log = "JOINT_STOP wp7-stop0: finish wedges without the fix: %s\n" % wedge_signature()
        proc, rows, joint = run_mapping(log=log, rc=1, expect_fail=True)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "expected-failure")
        self.assertEqual(len(rows), 6)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_preclusion_tag_maps_environment_precluded(self):
        log = ("P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded\n"
               "wp7-stop0: no joint feeds: not attempted\n")
        self.assertNotIn(wedge_signature(), log)
        proc, rows, joint = run_mapping(log=log, rc=1, expect_fail=True)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "environment-precluded")
        self.assertEqual(len(rows), 6)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_clean_pass_with_expect_zero_maps_qualified(self):
        proc, rows, joint = run_mapping(
            log="test result: ok. 1 passed\n", rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertTrue(joint["pass"])
        self.assertEqual(joint["qualification"], "qualified")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_unexpected_pass_with_expect_one_fails(self):
        proc, rows, joint = run_mapping(
            log="test result: ok. 1 passed\n", rc=0, expect_fail=True)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_failure_without_signature_fails(self):
        log = "test result: FAILED. assertion failed at line 1\n"
        self.assertNotIn(wedge_signature(), log)
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=1, expect_fail=True)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_missing_libtest_fails_the_joint_row(self):
        proc, rows, joint = run_mapping(log="", rc=0, expect_fail=True, libtest=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("P11SCOPE_LIBTEST", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_prereq_not_root_writes_a_row(self):
        if os.geteuid() == 0:
            self.skipTest("needs a non-root caller")
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "out"
            proc = subprocess.run(
                [str(SCRIPT), "/bin/true", str(out)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(proc.returncode, 77, proc.stdout + proc.stderr)
            results = out / "results.jsonl"
            self.assertTrue(results.exists(), "prerequisite row missing")
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            self.assertEqual(len(rows), 1, rows)
            self.assertEqual(rows[0]["cell"], "stop-races-prerequisites")
            self.assertFalse(rows[0]["pass"])
            self.assertEqual(rows[0]["qualification"], "environment-precluded")
            self.assertIn("root", rows[0]["detail"])

    def test_prereq_missing_observer_writes_a_row(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            write_exe(bin_dir / "id", STUB_ID)
            env = dict(os.environ)
            env["PATH"] = str(bin_dir) + ":" + env.get("PATH", "")
            out = tmp / "out"
            proc = subprocess.run(
                [str(SCRIPT), "/nonexistent-p11scope-observer-12345", str(out)],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(proc.returncode, 77, proc.stdout + proc.stderr)
            results = out / "results.jsonl"
            self.assertTrue(results.exists(), "prerequisite row missing")
            rows = [json.loads(line) for line in
                    results.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
            self.assertEqual(len(rows), 1, rows)
            self.assertEqual(rows[0]["cell"], "stop-races-prerequisites")
            self.assertFalse(rows[0]["pass"])
            self.assertEqual(rows[0]["qualification"], "environment-precluded")
            self.assertIn("observer", rows[0]["detail"])

    def test_harness_flags_a_ledger_that_appears_after_the_check(self):
        text = HARNESS.read_text(encoding="utf-8")
        self.assertTrue("ledger_race_possible" in text, "race flag missing")
        self.assertTrue("LEDGER " in text, "workload ledger marker missing")


if __name__ == "__main__":
    unittest.main()
