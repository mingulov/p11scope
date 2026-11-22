# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""CI entry mapping for the stop-race cells (synthetic, no root).

Exercises `scripts/ci/stop-races.sh` without privileged runs: the
joint row through the shared fail-closed validator
(scripts/ci/joint_stop_verdict.py; its per-class table lives in
test_joint_stop_verdict.py) end to end, with logs in the real pinned
libtest framing (wedge, S1 preclusion, unattributed no-feed cause,
full-matrix pass, short, incomplete, malformed and mixed matrices,
competing terminal errors, signal exits, malformed or non-terminal
summaries, receipt-only passes, inherited narrowing, unexpected pass,
unmapped failure, missing test binary), via a verbatim copy of the
entry and the validator with stubbed qualify/id/library-test, and the
early prerequisite rows (non-root, missing observer) via the real
entry. The harness must also flag a ledger that appears between the
pre-kill check and the signal.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/stop-races.sh"
VERDICT = ROOT / "scripts/ci/joint_stop_verdict.py"
HARNESS = ROOT / "scripts/qualify-stop-races.sh"

sys.path.insert(0, str(ROOT / "tests/python"))
from joint_stop_logs import (  # noqa: E402
    FAILED_SUMMARY, S1_ERROR, UNATTRIBUTED_ERROR, case_head,
    case_outcome, frame, matrix_body, s1_body, unattributed_body,
    wedge_body,
)

# The Rust cell's terminal wedge text (src/inventory/
# joint_stop_races_privileged_tests.rs, check_stop_outcome).
WEDGE_TEXT = "Published then WoundDown"

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

STUB_LIBTEST_SIGNAL = """#!/bin/sh
# Replays the fixture log, then dies by the named signal.
set -u
if [ "${1:-}" = --list ]; then
  echo "$JOINT_CELL_STUB: test"
  exit 0
fi
printf '%s' "$STUB_LOG"
kill -s "$STUB_SIGNAL" $$
"""


def full_matrix_log():
    """A passing 12-case matrix log in the real framing: each case's
    linkage tag, offset diagnostic and post-stop completion marker."""
    return frame(matrix_body(), True)


def one_case_log():
    """A passing one-case log: only the first case ran."""
    return frame(matrix_body(range(1)), True)


def linked_but_incomplete_log():
    """Twelve linked cases, but case 7 never completed its stop."""
    body = [line for line in matrix_body()
            if line != "P11SCOPE_STOP_COMPLETE=wp7-stop7"]
    return frame(body, True)


def malformed_completion_log():
    """Case 7's completion line is embedded in a diagnostic instead of
    standing as an exact line."""
    body = [("JOINT_STOP wp7-stop7: P11SCOPE_STOP_COMPLETE=wp7-stop7 "
             "emitted late") if line == "P11SCOPE_STOP_COMPLETE=wp7-stop7"
            else line for line in matrix_body()]
    return frame(body, True)


def failed_log(body):
    return frame(body, False)


def run_mapping(*, log, rc, expect_fail, libtest=True, list_mode="always",
                extra_env=None, stub_body=None, verdict=True):
    """Run a verbatim copy of the entry with stubbed qualify/id/libtest.

    expect_fail None leaves JOINT_EXPECTED_FAILURE unset (the default
    path); list_mode "unignored" hides the cell from the ignored
    listing while plain --list still advertises it; extra_env adds
    inherited variables (matrix narrowing, the signal name); stub_body
    overrides the replay stub; verdict False leaves the validator out
    of the copied tree.
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
        if verdict:
            (root / "scripts/ci/joint_stop_verdict.py").write_bytes(
                VERDICT.read_bytes())
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
    def assert_row(self, proc, rows, joint, qualification, reason=None,
                   exit_code=None):
        """The joint row carries qualification and the validator's
        bracketed reason; the suite exit follows the row."""
        self.assertIsNotNone(joint, rows)
        self.assertEqual(len(rows), 6, rows)
        self.assertEqual(joint["qualification"], qualification, joint)
        self.assertEqual(joint["pass"], qualification == "qualified", joint)
        if reason is not None:
            self.assertIn("[%s]" % reason, joint["detail"], joint)
        if exit_code is None:
            exit_code = 1 if qualification == "failed" else 0
        self.assertEqual(proc.returncode, exit_code, proc.stdout + proc.stderr)

    def test_wedge_signature_maps_expected_failure(self):
        log = failed_log(wedge_body())
        self.assertIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "expected-failure", "wedge")

    def test_preclusion_tag_maps_environment_precluded(self):
        log = failed_log(s1_body())
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "environment-precluded",
                        "s1-first-case")

    def test_clean_pass_with_expect_zero_maps_qualified(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "qualified", "full-matrix")
        self.assertIn("linked joint stop", joint["detail"])

    def test_one_case_pass_does_not_qualify_as_the_full_matrix(self):
        proc, rows, joint = run_mapping(
            log=one_case_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "matrix-short")
        self.assertIn("wp7-stop", joint["detail"])

    def test_linked_but_incomplete_case_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=linked_but_incomplete_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "sequence")
        self.assertIn("wp7-stop", joint["detail"])
        self.assertIn("7", joint["detail"])

    def test_malformed_completion_marker_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=malformed_completion_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-malformed")
        self.assertIn("wp7-stop", joint["detail"])
        self.assertIn("7", joint["detail"])

    def test_qualifying_entry_ignores_inherited_matrix_narrowing(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False,
            extra_env={"WP7_STOP_PREPS": "0", "WP7_STOP_OFFSETS": "0"},
            stub_body=STUB_LIBTEST_MATRIX_GUARD)
        self.assert_row(proc, rows, joint, "qualified", "full-matrix")

    def test_unattributed_no_feed_run_fails_with_its_cause(self):
        log = failed_log(unattributed_body(4))
        self.assertNotIn(WEDGE_TEXT, log)
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "no-feed-unattributed")
        self.assertIn("unattributed", joint["detail"])

    def test_old_collapsed_s1_tag_without_receipt_fails(self):
        # The archived probe tag with the collapsed message (no
        # producer-seal receipt) is ambiguous, never environmental.
        log = failed_log(s1_body(error="Error: wp7-stop0: no joint feeds "
                                 "from the linked session; not attempted"))
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "receipt-mismatch")
        self.assertIn("ambiguous", joint["detail"])

    def test_embedded_s1_tag_does_not_preclude(self):
        log = failed_log([
            "JOINT_STOP wp7-stop0: P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded "
            "emitted late", S1_ERROR.format(k=0)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-malformed")

    def test_suffixed_s1_lookalike_does_not_preclude(self):
        log = failed_log([
            "P11SCOPE_CELL_BRANCH=wp7-stop7:s1-precluded-suspected",
            S1_ERROR.format(k=7)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-malformed")

    def test_s1_after_seven_linked_completions_fails(self):
        # Seven cases linked and completed, then an S1 tag: preclusion
        # holds only before any linked case.
        log = failed_log(s1_body(7))
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "s1-after-linked")
        self.assertIn("before any linked case", joint["detail"])

    def test_s1_with_linked_tags_fails(self):
        log = failed_log(s1_body(1))
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "s1-after-linked")
        self.assertIn("mixed", joint["detail"])

    def test_s1_without_receipt_fails(self):
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
                          "Error: wp7-stop0: q1 fixture failed"])
        self.assertNotIn(WEDGE_TEXT, log)
        self.assertNotIn("producers unlinked", log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "receipt-mismatch")
        self.assertIn("ambiguous", joint["detail"])

    def test_s1_with_unattributed_mixed_fails(self):
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
                          "P11SCOPE_CELL_BRANCH=wp7-stop1:no-feeds-unattributed",
                          UNATTRIBUTED_ERROR.format(k=1)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "sequence")

    def test_s1_with_wedge_mixed_fails_under_expect_one(self):
        log = failed_log(s1_body() + [
            "JOINT_STOP wp7-stop0: finish wedges: %s" % WEDGE_TEXT])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "error-not-terminal")

    def test_pass_with_s1_tag_fails(self):
        log = frame(matrix_body() + [
            "P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded"], True)
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "sequence")

    def test_pass_with_first_case_s1_tag_fails(self):
        log = frame(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded"], True)
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "pass-with-no-feed")
        self.assertIn("never precludes", joint["detail"])

    def test_two_passed_does_not_qualify(self):
        log = frame(matrix_body(), True, summary=(
            "test result: ok. 2 passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 180.00s"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-counts")

    def test_out_of_range_s1_tag_does_not_preclude(self):
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop12:s1-precluded",
                          S1_ERROR.format(k=12)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-malformed")

    def test_unattributed_embedded_maps_to_generic_fail(self):
        log = failed_log([
            "JOINT_STOP wp7-stop4: P11SCOPE_CELL_BRANCH=wp7-stop4:"
            "no-feeds-unattributed emitted late",
            UNATTRIBUTED_ERROR.format(k=4)])
        self.assertNotIn(WEDGE_TEXT, log)
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-malformed")

    def test_s1_tag_with_mismatched_receipt_case_fails(self):
        # Case-0 tag with a case-7 terminal error: the tag and its
        # receipt name different cases, so the preclusion is unproven.
        log = failed_log(s1_body(error=S1_ERROR.format(k=7)))
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "receipt-mismatch")

    def test_lone_later_s1_preclusion_fails(self):
        # A case-7 tag and error with no earlier records: the
        # qualifying entry runs the matrix in order and the first
        # error ends it, so a lone later preclusion is impossible.
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop7:s1-precluded",
                          S1_ERROR.format(k=7)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "sequence")

    def test_s1_receipt_inside_diagnostic_fails(self):
        # Case-0 tag with the receipt substring inside a diagnostic
        # line instead of standing as the full terminal error.
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
                          "JOINT_STOP wp7-stop0: diagnostic "
                          + S1_ERROR.format(k=0)[len("Error: "):] + " seen",
                          "Error: wp7-stop0: q1 fixture failed"])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "receipt-stray")

    def test_s1_with_conflicting_unattributed_receipt_fails(self):
        # Case-0 tag and error plus a contradictory unattributed
        # error without its tag: the run claims both seals.
        log = failed_log(s1_body() + [UNATTRIBUTED_ERROR.format(k=0)])
        self.assertNotIn(WEDGE_TEXT, log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "error-count")

    def test_mixed_unattributed_wedge_fails_under_expect_one(self):
        # Explicit unattributed tag and receipt plus a wedge-text
        # diagnostic: under expectation this is the unattributed
        # cause, never an expected failure.
        log = failed_log(unattributed_body(4)[:-1] + [
            "JOINT_STOP wp7-stop4: diagnostic %s seen" % WEDGE_TEXT,
            UNATTRIBUTED_ERROR.format(k=4)])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "no-feed-unattributed")

    def test_malformed_pass_summary_fails(self):
        # Full 12-case matrix but a malformed libtest summary: the
        # pass count carries a suffix and failures are nonzero.
        log = frame(matrix_body(), True, summary=(
            "test result: ok. 1 passed_suspected; 9 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 180.00s"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-malformed")

    def test_pass_followed_by_failed_terminal_fails(self):
        # A valid summary followed by a failed terminal result: one
        # terminal summary only.
        log = frame(matrix_body(), True, tail=[FAILED_SUMMARY])
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-duplicate")

    def test_garbage_after_the_ignored_count_fails(self):
        log = frame(matrix_body(), True, summary=(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 9 failed; "
            "garbage"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-malformed")

    def test_error_after_a_healthy_summary_fails(self):
        log = frame(matrix_body(), True,
                    tail=["Error: joint cleanup failed"])
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-not-terminal")

    def test_s1_receipt_then_a_later_different_error_fails(self):
        # The real-framed S1 pair, then a different terminal error
        # before the same footer: competing errors never preclude.
        log = failed_log(s1_body() + [
            "Error: wp7-stop0: joint cleanup failed"])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "error-count")

    def test_unprefixed_s1_receipt_then_a_different_error_fails(self):
        log = failed_log(["P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
                          S1_ERROR.format(k=0)[len("Error: "):],
                          "Error: wp7-stop0: joint cleanup failed"])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "receipt-stray")

    def test_s1_log_with_a_non_libtest_status_fails(self):
        # A clean S1 control log with exit 137 (the child status a
        # SIGKILL leaves): never a libtest failure.
        proc, rows, joint = run_mapping(
            log=failed_log(s1_body()), rc=137, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "exit-status")

    def test_s1_log_with_a_real_signal_exit_fails(self):
        proc, rows, joint = run_mapping(
            log=failed_log(s1_body()), rc=0, expect_fail=False,
            stub_body=STUB_LIBTEST_SIGNAL, extra_env={"STUB_SIGNAL": "KILL"})
        self.assert_row(proc, rows, joint, "failed", "exit-status")
        self.assertIn("137", joint["detail"])

    def test_receipt_only_pass_fails_for_both_causes(self):
        for receipt in (UNATTRIBUTED_ERROR.format(k=0),
                        S1_ERROR.format(k=0)):
            for line, reason in ((receipt, "error-count"),
                                 (receipt[len("Error: "):], "receipt-stray")):
                with self.subTest(line=line):
                    log = frame(matrix_body() + [line], True)
                    proc, rows, joint = run_mapping(
                        log=log, rc=0, expect_fail=False)
                    self.assert_row(proc, rows, joint, "failed", reason)

    def test_wedge_arm_refuses_an_unrelated_terminal_error(self):
        # A linked case, a diagnostic with the wedge text, then an
        # unrelated terminal error: under expectation that is a
        # failure, not the wedge.
        log = failed_log(case_head(0) + case_outcome(0) + [
            "JOINT_STOP wp7-stop0: diagnostic %s" % WEDGE_TEXT,
            "Error: wp7-stop0: q1 fixture failed"])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_missing_validator_fails_the_joint_row(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False, verdict=False)
        self.assert_row(proc, rows, joint, "failed")
        self.assertIn("validator", joint["detail"])

    def test_unexpected_pass_with_expect_one_fails(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "unexpected-pass")

    def test_failure_without_signature_fails(self):
        log = failed_log(matrix_body(range(2)) + case_head(2) + [
            "Error: offset 5: two-owner reconciliation failed: entered 2"])
        self.assertNotIn(WEDGE_TEXT, log)
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_zero_selected_tests_fail_the_joint_row(self):
        log = ("\nrunning 0 tests\n\n"
               "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
               "0 filtered out; finished in 0.00s\n\n")
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "header")

    def test_unignored_cell_fails_the_joint_row(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False,
            list_mode="unignored")
        self.assert_row(proc, rows, joint, "failed")
        self.assertIn("missing from test binary", joint["detail"])

    def test_unset_expected_failure_defaults_to_clean_pass_qualified(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=None)
        self.assert_row(proc, rows, joint, "qualified", "full-matrix")

    def test_wedge_signature_under_expect_zero_names_the_wedge(self):
        log = failed_log(wedge_body())
        self.assertNotIn("s1-precluded", log)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "wedge-unexpected")
        self.assertIn("wedge", joint["detail"].lower())
        self.assertNotIn("without the wedge signature", joint["detail"])

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
