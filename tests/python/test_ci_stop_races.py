# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""CI entry mapping for the stop-race cells (synthetic, no root).

Exercises `scripts/ci/stop-races.sh` without privileged runs: the
joint-row mapping (wedge signature, single-seal preclusion tag,
unattributed no-feed tag, full-matrix clean pass, one-case short
matrix, linked-but-incomplete case, malformed completion marker,
inherited narrowing, unexpected pass, unmapped failure,
missing test binary) via a verbatim copy of the entry with stubbed
qualify/id/library-test, and the early prerequisite rows (non-root,
missing observer) via the real entry. The harness must also flag a
ledger that appears between the pre-kill check and the signal.
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

STUB_LIBTEST_UNIGNORED = """#!/bin/sh
# An unignored joint cell: plain --list advertises it, but the ignored
# listing (the set the entry executes) is empty.
set -u
if [ "${1:-}" = --list ]; then
  for arg in "$@"; do
    if [ "$arg" = --ignored ]; then
      exit 0
    fi
  done
  echo "$JOINT_CELL_STUB: test"
  exit 0
fi
printf '%s' "$STUB_LOG"
exit "$STUB_RC"
"""

STUB_LIBTEST_MATRIX_GUARD = """#!/bin/sh
# A joint cell that proves the entry forced the full matrix: it fails
# loudly when an inherited narrowing selector reaches it, else replays
# the fixture log.
set -u
if [ "${1:-}" = --list ]; then
  echo "$JOINT_CELL_STUB: test"
  exit 0
fi
if [ -n "${WP7_STOP_PREPS:-}" ] || [ -n "${WP7_STOP_OFFSETS:-}" ]; then
  echo "narrowing leaked into the qualifying entry"
  exit 1
fi
printf '%s' "$STUB_LOG"
exit "$STUB_RC"
"""


def full_matrix_log():
    """A passing 12-case matrix log: every pre-stop linkage tag plus
    its post-stop completion marker, each by exact name."""
    tags = "".join(
        "P11SCOPE_CELL_BRANCH=wp7-stop%d:linked\n" % i for i in range(12))
    done = "".join(
        "P11SCOPE_STOP_COMPLETE=wp7-stop%d\n" % i for i in range(12))
    return tags + done + ("test result: ok. 1 passed; 0 failed; 0 ignored; "
                          "0 measured; 0 filtered out; finished in 180.00s\n")


def one_case_log():
    """A passing one-case log: only the first linked case tag is present."""
    return ("P11SCOPE_CELL_BRANCH=wp7-stop0:linked\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 15.00s\n")


def linked_but_incomplete_log():
    """Twelve linkage tags, but case 7 never completed its stop."""
    tags = "".join(
        "P11SCOPE_CELL_BRANCH=wp7-stop%d:linked\n" % i for i in range(12))
    done = "".join(
        "P11SCOPE_STOP_COMPLETE=wp7-stop%d\n" % i for i in range(12)
        if i != 7)
    return tags + done + ("test result: ok. 1 passed; 0 failed; 0 ignored; "
                          "0 measured; 0 filtered out; finished in 180.00s\n")


def malformed_completion_log():
    """Twelve linkage tags, but case 7's completion line is embedded
    in a diagnostic instead of standing as an exact line."""
    tags = "".join(
        "P11SCOPE_CELL_BRANCH=wp7-stop%d:linked\n" % i for i in range(12))
    done = "".join(
        "P11SCOPE_STOP_COMPLETE=wp7-stop%d\n" % i for i in range(7))
    done += ("JOINT_STOP wp7-stop7: P11SCOPE_STOP_COMPLETE=wp7-stop7 "
             "emitted late\n")
    done += "".join(
        "P11SCOPE_STOP_COMPLETE=wp7-stop%d\n" % i for i in range(8, 12))
    return tags + done + ("test result: ok. 1 passed; 0 failed; 0 ignored; "
                          "0 measured; 0 filtered out; finished in 180.00s\n")


def run_mapping(*, log, rc, expect_fail, libtest=True, list_mode="always",
                extra_env=None, stub_body=None):
    """Run a verbatim copy of the entry with stubbed qualify/id/libtest.

    expect_fail None leaves JOINT_EXPECTED_FAILURE unset (the default
    path); list_mode "unignored" hides the cell from the ignored
    listing while plain --list still advertises it; extra_env adds
    inherited variables (matrix narrowing); stub_body overrides the
    replay stub (the matrix guard).
    """
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
        if expect_fail is None:
            env.pop("JOINT_EXPECTED_FAILURE", None)
        else:
            env["JOINT_EXPECTED_FAILURE"] = "1" if expect_fail else "0"
        env["STOP_RACES_TRIALS"] = "2"
        env["STOP_RACES_BURST_TRIALS"] = "1"
        for key, value in (extra_env or {}).items():
            env[key] = value
        if libtest:
            stub = tmp / "libtest"
            if stub_body is None:
                stub_body = (STUB_LIBTEST_UNIGNORED if list_mode == "unignored"
                             else STUB_LIBTEST)
            write_exe(stub, stub_body)
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
            log=full_matrix_log(), rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertTrue(joint["pass"])
        self.assertEqual(joint["qualification"], "qualified")
        self.assertIn("linked joint stop", joint["detail"])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_one_case_pass_does_not_qualify_as_the_full_matrix(self):
        proc, rows, joint = run_mapping(
            log=one_case_log(), rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("wp7-stop", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_linked_but_incomplete_case_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=linked_but_incomplete_log(), rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("wp7-stop", joint["detail"])
        self.assertIn("7", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_malformed_completion_marker_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=malformed_completion_log(), rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("wp7-stop", joint["detail"])
        self.assertIn("7", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_qualifying_entry_ignores_inherited_matrix_narrowing(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False,
            extra_env={"WP7_STOP_PREPS": "0", "WP7_STOP_OFFSETS": "0"},
            stub_body=STUB_LIBTEST_MATRIX_GUARD)
        self.assertIsNotNone(joint, rows)
        self.assertTrue(joint["pass"])
        self.assertEqual(joint["qualification"], "qualified")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_unattributed_no_feed_run_fails_with_its_cause(self):
        log = ("P11SCOPE_CELL_BRANCH=wp7-stop4:no-feeds-unattributed\n"
               "wp7-stop4: no joint feeds and no S1 seal "
               "(unattributed linkage default); not attempted\n")
        self.assertNotIn(wedge_signature(), log)
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=1, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("unattributed", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

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

    def test_zero_selected_tests_fail_the_joint_row(self):
        log = ("running 0 tests\n\n"
               "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
               "0 filtered out; finished in 0.00s\n")
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_unignored_cell_fails_the_joint_row(self):
        proc, rows, joint = run_mapping(
            log="test result: ok. 1 passed\n", rc=0, expect_fail=False,
            list_mode="unignored")
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("missing from test binary", joint["detail"])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_unset_expected_failure_defaults_to_clean_pass_qualified(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=None)
        self.assertIsNotNone(joint, rows)
        self.assertTrue(joint["pass"])
        self.assertEqual(joint["qualification"], "qualified")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_wedge_signature_under_expect_zero_names_the_wedge(self):
        log = "JOINT_STOP wp7-stop0: finish wedges without the fix: %s\n" % wedge_signature()
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=1, expect_fail=False)
        self.assertIsNotNone(joint, rows)
        self.assertFalse(joint["pass"])
        self.assertEqual(joint["qualification"], "failed")
        self.assertIn("wedge", joint["detail"].lower())
        self.assertNotIn("without the wedge signature", joint["detail"])
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
