# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""CI entry mapping for the stop-race cells (synthetic, no root).

Exercises `scripts/ci/stop-races.sh` without privileged runs: the
joint row through the shared fail-closed validator
(scripts/ci/joint_stop_verdict.py; its per-class table lives in
test_joint_stop_verdict.py) end to end. Each log is the real pinned
libtest framing around the cell's single verdict record (wedge, S1
preclusion, unattributed no-feed cause, full-matrix pass, short,
incomplete, misplaced and contradictory records, signal exits,
malformed or non-terminal summaries, receipt-only passes, inherited
narrowing, unexpected pass, unmapped failure, missing test binary),
replayed through a verbatim copy of the entry and the validator with
stubbed qualify/id/library-test, and the early prerequisite rows
(non-root, missing observer) via the real entry. The harness must also
flag a ledger that appears between the pre-kill check and the signal.
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
    FAILED_SUMMARY, S1_RECEIPT, UNATTRIBUTED_RECEIPT,
    case_failed_record, case_record, frame,
    healthy_outcome, log_for, no_feed_record, offset_of, passing,
    precluded, precluded_record, qualified_record, record, record_line,
    wedge_outcome, wedge_record, wedged,
)


def edited(rec, change):
    change(rec)
    return rec


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
    """A passing 12-case matrix log: the qualified record."""
    return passing()


def one_case_log():
    """A passing record that holds only the first case."""
    return log_for(edited(qualified_record(),
                          lambda r: r.update(cases=r["cases"][:1])))


def linked_but_incomplete_log():
    """Twelve linked cases, but case 7 never completed its stop."""
    rec = qualified_record()
    rec["cases"][7]["completed"] = False
    return log_for(rec)


def malformed_completion_log():
    """The record glued behind a diagnostic instead of opening its line."""
    rec = qualified_record()
    return log_for(rec).replace(
        "\n" + record_line(rec), "\nJOINT_STOP wp7-stop7: " + record_line(rec))


def failed_log(rec):
    return log_for(rec, ok=False)


def text_only_log(lines, ok=False):
    """Free text with no verdict record (the old grammar's evidence)."""
    return frame(lines, ok)


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
        proc, rows, joint = run_mapping(log=wedged(), rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "expected-failure", "wedge")

    def test_preclusion_tag_maps_environment_precluded(self):
        proc, rows, joint = run_mapping(log=precluded(), rc=101,
                                        expect_fail=True)
        self.assert_row(proc, rows, joint, "environment-precluded",
                        "s1-first-case")

    def test_clean_pass_with_expect_zero_maps_qualified(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "qualified", "full-matrix")
        self.assertIn("stop cases completed", joint["detail"])

    def test_one_case_pass_does_not_qualify_as_the_full_matrix(self):
        proc, rows, joint = run_mapping(
            log=one_case_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "qualified-count")
        self.assertIn("1 of 12", joint["detail"])

    def test_linked_but_incomplete_case_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=linked_but_incomplete_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "completion")
        self.assertIn("wp7-stop7", joint["detail"])

    def test_malformed_completion_marker_does_not_qualify(self):
        proc, rows, joint = run_mapping(
            log=malformed_completion_log(), rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-misplaced")

    def test_qualifying_entry_ignores_inherited_matrix_narrowing(self):
        proc, rows, joint = run_mapping(
            log=full_matrix_log(), rc=0, expect_fail=False,
            extra_env={"WP7_STOP_PREPS": "0", "WP7_STOP_OFFSETS": "0"},
            stub_body=STUB_LIBTEST_MATRIX_GUARD)
        self.assert_row(proc, rows, joint, "qualified", "full-matrix")

    def test_unattributed_no_feed_run_fails_with_its_cause(self):
        log = failed_log(no_feed_record(4, "no-feeds-unattributed"))
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "no-feed-unattributed")
        self.assertIn("unattributed", joint["detail"])

    def test_old_collapsed_s1_tag_without_receipt_fails(self):
        # A preclusion whose receipt is the archived collapsed message
        # is ambiguous, never environmental.
        rec = precluded_record()
        rec["terminal"]["receipt"] = "no joint feeds from the linked session"
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "no-feed-binding")

    def test_embedded_s1_tag_does_not_preclude(self):
        # The old free-text tag and receipt alone carry no verdict.
        log = text_only_log([
            "JOINT_STOP wp7-stop0: P11SCOPE_CELL_BRANCH=wp7-stop0:s1-precluded",
            "Error: wp7-stop0: %s; not attempted" % S1_RECEIPT])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-missing")

    def test_suffixed_s1_lookalike_does_not_preclude(self):
        rec = precluded_record()
        rec["cases"][0]["branch"] = "s1-precluded-suspected"
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-schema")

    def test_s1_after_seven_linked_completions_fails(self):
        proc, rows, joint = run_mapping(log=failed_log(no_feed_record(7)),
                                        rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "s1-after-linked")
        self.assertIn("after linked cases", joint["detail"])

    def test_s1_with_linked_tags_fails(self):
        proc, rows, joint = run_mapping(log=failed_log(no_feed_record(1)),
                                        rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "s1-after-linked")

    def test_s1_without_receipt_fails(self):
        rec = precluded_record()
        rec["terminal"]["receipt"] = ""
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "no-feed-binding")

    def test_s1_with_unattributed_mixed_fails(self):
        rec = no_feed_record(1, "no-feeds-unattributed")
        rec["cases"][0] = case_record(0, "s1-precluded")
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-branch")

    def test_s1_with_wedge_mixed_fails_under_expect_one(self):
        rec = precluded_record()
        rec["terminal"] = {"kind": "wedge", "case": 0}
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "wedge-binding")

    def test_pass_with_s1_tag_fails(self):
        rec = qualified_record()
        rec["cases"][3] = case_record(3, "s1-precluded")
        proc, rows, joint = run_mapping(log=log_for(rec), rc=0,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-branch")

    def test_pass_with_first_case_s1_tag_fails(self):
        rec = record([case_record(0, "s1-precluded")], {"kind": "qualified"})
        proc, rows, joint = run_mapping(log=log_for(rec), rc=0,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "terminal-case")

    def test_two_passed_does_not_qualify(self):
        log = passing(summary=(
            "test result: ok. 2 passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 180.00s"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-counts")

    def test_out_of_range_s1_tag_does_not_preclude(self):
        rec = precluded_record()
        rec["cases"][0].update(index=12, name="wp7-stop12", prep=3)
        rec["terminal"]["case"] = 12
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-sequence")

    def test_unattributed_embedded_maps_to_generic_fail(self):
        log = text_only_log([
            "JOINT_STOP wp7-stop4: P11SCOPE_CELL_BRANCH=wp7-stop4:"
            "no-feeds-unattributed emitted late",
            "Error: wp7-stop4: %s; not attempted" % UNATTRIBUTED_RECEIPT])
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-missing")

    def test_s1_tag_with_mismatched_receipt_case_fails(self):
        # Case-0 S1 with a terminal naming case 7: unbound preclusion.
        rec = precluded_record()
        rec["terminal"]["case"] = 7
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "terminal-case")

    def test_lone_later_s1_preclusion_fails(self):
        # A lone case-7 record: the matrix opens case 0 first.
        rec = no_feed_record(7)
        rec["cases"] = rec["cases"][7:]
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-sequence")

    def test_s1_receipt_inside_diagnostic_fails(self):
        # The receipt in free text never turns a case failure into a
        # preclusion: only the record's terminal counts.
        rec = case_failed_record(0, "drive", error="q1 fixture failed")
        log = frame(["JOINT_STOP wp7-stop0: diagnostic %s seen" % S1_RECEIPT,
                     "", record_line(rec)], False)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_s1_with_conflicting_unattributed_receipt_fails(self):
        rec = precluded_record()
        rec["terminal"]["receipt"] = UNATTRIBUTED_RECEIPT
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "no-feed-binding")

    def test_mixed_unattributed_wedge_fails_under_expect_one(self):
        rec = no_feed_record(4, "no-feeds-unattributed")
        rec["terminal"] = {"kind": "wedge", "case": 4}
        proc, rows, joint = run_mapping(log=failed_log(rec), rc=101,
                                        expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "wedge-binding")

    def test_malformed_pass_summary_fails(self):
        log = passing(summary=(
            "test result: ok. 1 passed_suspected; 9 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 180.00s"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-malformed")

    def test_pass_followed_by_failed_terminal_fails(self):
        log = passing(tail=[FAILED_SUMMARY])
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-duplicate")

    def test_garbage_after_the_ignored_count_fails(self):
        log = passing(summary=(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 9 failed; "
            "garbage"))
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-malformed")

    def test_error_after_a_healthy_summary_fails(self):
        log = passing(tail=["Error: joint cleanup failed"])
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-not-terminal")

    def test_s1_receipt_then_a_later_different_error_fails(self):
        # A second record after the preclusion: the cell prints one.
        log = log_for(precluded_record()).replace(
            "\nError: ", "\n" + record_line(case_failed_record(
                0, "drive", error="joint cleanup failed")) + "\nError: ", 1)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "record-duplicate")

    def test_unprefixed_s1_receipt_then_a_different_error_fails(self):
        rec = case_failed_record(0, "drive", error="joint cleanup failed")
        log = frame([S1_RECEIPT, "", record_line(rec)], False)
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_s1_log_with_a_non_libtest_status_fails(self):
        proc, rows, joint = run_mapping(
            log=precluded(), rc=137, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "exit-status")

    def test_s1_log_with_a_real_signal_exit_fails(self):
        proc, rows, joint = run_mapping(
            log=precluded(), rc=0, expect_fail=False,
            stub_body=STUB_LIBTEST_SIGNAL, extra_env={"STUB_SIGNAL": "KILL"})
        self.assert_row(proc, rows, joint, "failed", "exit-status")
        self.assertIn("137", joint["detail"])

    def test_receipt_only_pass_fails_for_both_causes(self):
        for rec in (precluded_record(),
                    no_feed_record(0, "no-feeds-unattributed")):
            with self.subTest(cause=rec["terminal"]["cause"]):
                proc, rows, joint = run_mapping(
                    log=log_for(rec, ok=True), rc=0, expect_fail=False)
                self.assert_row(proc, rows, joint, "failed",
                                "terminal-status")

    def test_wedge_arm_refuses_an_unrelated_terminal_error(self):
        proc, rows, joint = run_mapping(
            log=failed_log(case_failed_record(0, "drive",
                                              error="q1 fixture failed")),
            rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_wedge_evidence_anywhere_in_an_s1_log_refuses(self):
        # A preclusion is case 0 alone, unlinked and undriven: a
        # collected outcome, a linked branch or an earlier case refuses.
        linked = precluded_record()
        linked["cases"][0].update(branch="linked", no_feed=None)
        earlier = no_feed_record(1)
        earlier["terminal"]["kind"] = "precluded"
        driven = precluded_record()
        driven["cases"][0]["outcome"] = wedge_outcome(0)
        for label, rec, reason in (
                ("outcome", driven, "case-outcome"),
                ("linked", linked, "no-feed-binding"),
                ("earlier-case", earlier, "precluded-binding")):
            for expect in (False, True):
                with self.subTest(position=label, expect=expect):
                    proc, rows, joint = run_mapping(
                        log=failed_log(rec), rc=101, expect_fail=expect)
                    self.assert_row(proc, rows, joint, "failed", reason)

    def test_wedge_arm_refuses_a_successful_or_malformed_terminal(self):
        k = 5
        success = wedge_record(k)
        success["cases"][k]["outcome"] = healthy_outcome(offset_of(k))
        at_q = wedge_record(k)
        at_q["cases"][k]["outcome"]["api_a"] = 1
        undriven = wedge_record(k)
        undriven["cases"][k]["outcome"] = None
        for label, rec, reason in (
                ("success", success, "completion"),
                ("at-q-first", at_q, "wedge-binding"),
                ("undriven", undriven, "wedge-binding")):
            with self.subTest(case=label):
                proc, rows, joint = run_mapping(
                    log=failed_log(rec), rc=101, expect_fail=True)
                self.assert_row(proc, rows, joint, "failed", reason)

    def test_malformed_no_feed_branch_record_on_a_pass_refuses(self):
        for branch in ("no-feeds-unattributed:", "linked ", "S1"):
            with self.subTest(branch=branch):
                rec = qualified_record()
                rec["cases"][0]["branch"] = branch
                proc, rows, joint = run_mapping(
                    log=log_for(rec), rc=0, expect_fail=False)
                self.assert_row(proc, rows, joint, "failed", "record-schema")

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
        log = failed_log(case_failed_record(2))
        proc, rows, joint = run_mapping(log=log, rc=101, expect_fail=True)
        self.assert_row(proc, rows, joint, "failed", "case-failed")

    def test_zero_selected_tests_fail_the_joint_row(self):
        log = ("\nrunning 0 tests\n\n"
               "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
               "0 filtered out; finished in 0.00s\n\n")
        proc, rows, joint = run_mapping(log=log, rc=0, expect_fail=False)
        self.assert_row(proc, rows, joint, "failed", "summary-counts")

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
        proc, rows, joint = run_mapping(log=wedged(), rc=101,
                                        expect_fail=False)
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
