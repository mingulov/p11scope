#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Linked-control cells: full-script self-test through fakes.

Runs scripts/ci/key-operations-linked-control.sh end to end with a fake
observer, fake fixture, fake seed, fake discover and fake oracles
(selected per cell by the KEYOPS_SELFTEST_* knobs) and asserts the
results.jsonl rows for every scenario: pass, OPEN-6 expected-failure,
product-unavailable expected-failure, pid nonqualifying, s1 failure,
both no-manifest branches, both off-build branches and the 77/2 exits.
No SoftHSM, no privilege, no real observer. Run as a script:

    python3 -I tests/python/test_key_operations_linked_control.py -v
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/key-operations-linked-control.sh"

sys.path.insert(0, str(ROOT / "scripts/ci"))
import key_operations_checks as checks  # noqa: E402


def _restore_int_quit():
    """Restore default SIGINT/SIGQUIT in the script subtree (preexec_fn).

    A backgrounded launcher starts with SIGINT and SIGQUIT ignored, and a
    non-interactive bourne shell cannot trap an ignored signal back: the
    fake observer's SIGINT trap would stay dead and every cell would hang
    in its stop wait. The cells stop the observer with exactly one SIGINT,
    so the subtree needs the default disposition. Foreground CI steps
    already have it; this only repairs backgrounded launches.
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)

FAKE_OBSERVER = """#!/usr/bin/env python3
# Fake observer: seal line on stderr, canned doc on -o, SIGINT-stop.
# KEYOPS_SELFTEST_SCENARIO: populated | unavailable | unavailable-empty |
# unavailable-bootstrap | unavailable-bootstrap-gaps | diag-gaps-16 |
# diag-gaps-unreadable | garbage-doc | accept-with-token |
# refuse-CODE:MESSAGE | die-at-3 | exit-0-silent
# Python (not shell): an async-launched bourne shell cannot trap SIGINT
# back from the inherited ignore, while sigaction always can.
import os
import signal
import sys
import time

scenario = os.environ.get("KEYOPS_SELFTEST_SCENARIO", "unavailable")
args = sys.argv[1:]
out = args[args.index("-o") + 1]
if scenario.startswith("refuse-"):
    rest = scenario[len("refuse-"):]
    code, _, message = rest.partition(":")
    sys.stderr.write(message + "\\n")
    sys.exit(int(code))
if scenario == "exit-0-silent":
    sys.exit(0)
if scenario == "die-at-3":
    sys.stderr.write("p11scope: semantic lane ready; mechanisms and API results are recorded"
                     " from now on (key operations: planned for 0.6.0)\\n")
    sys.stderr.flush()
    time.sleep(3)
    sys.exit(3)
if scenario == "accept-with-token":
    sys.stderr.write("p11scope: journal-pair-unavailable-in-build: this build omits"
                     " the production journal object\\n")
sys.stderr.write("p11scope: semantic lane ready; mechanisms and API results are recorded"
                 " from now on (key operations: planned for 0.6.0)\\n")
sys.stderr.flush()
DOCS = {"populated": ("populated", "rev 1"),
        "unavailable-empty": ("unavailable", ""),
        "unavailable-bootstrap": ("unavailable", "bootstrap_unavailable"),
        "unavailable-bootstrap-gaps": ("unavailable", "bootstrap_unavailable"),
        "diag-gaps-16": ("unavailable", "journal_unavailable"),
        "diag-gaps-unreadable": ("unavailable", "journal_unavailable")}
status, reason = DOCS.get(scenario, ("unavailable", "journal_unavailable"))


def gaps_json():
    if scenario == "unavailable-bootstrap-gaps":
        return ('[{"subject": "Joint birth unavailable; retained S1", '
                '"reason": "joint_birth_claim_ImageTainted", "repeats": 2}]')
    if scenario == "diag-gaps-16":
        return ('[{"subject": "semantic admission refused", '
                '"reason": "semantic_unavailable:no_receipt", "repeats": 16}]')
    if scenario == "diag-gaps-unreadable":
        return '5'
    return '[]'


def write_doc():
    with open(out, "w", encoding="utf-8") as handle:
        if scenario == "garbage-doc":
            handle.write("NOT JSON{{{\\n")
            return
        handle.write('{"object_observations": {"status": "%s", "reason": "%s"},\\n'
                     ' "observation": {"lifecycle": {"ring_loss": 0}}, "gaps": %s}\\n'
                     % (status, reason, gaps_json()))


exit_code = int(os.environ.get("FAKE_OBS_EXIT", "0"))


def on_int(signum, frame):
    write_doc()
    sys.exit(exit_code)


signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGQUIT, signal.SIG_DFL)
signal.signal(signal.SIGINT, on_int)
time.sleep(float(os.environ.get("FAKE_OBSERVE_S", "300")))
write_doc()
sys.exit(exit_code)
"""

FAKE_FIXTURE = """#!/bin/sh
echo '{"seq":1,"kind":"header","time_ns":1}'
echo '{"seq":2,"kind":"ready","time_ns":2}'
go=$(dd bs=1 count=1 2>/dev/null)
[ "$go" = G ] || exit 3
echo '{"seq":3,"kind":"sign","time_ns":3}'
echo '{"seq":4,"kind":"done","time_ns":4}'
fin=$(dd bs=1 count=1 2>/dev/null)
[ "$fin" = F ] || exit 3
exit 0
"""

FAKE_GATED = """#!/bin/sh
echo READY
exec sleep 300
"""

FAKE_ORACLE = """import os, sys
if sys.argv[1:2] == ["--s1"]:
    code = int(os.environ.get("FAKE_S1_EXIT", "0"))
    text = os.environ.get("FAKE_S1_TEXT", "s1 ok")
else:
    code = int(os.environ.get("FAKE_EXIT", "0"))
    text = os.environ.get("FAKE_TEXT", "compare ok")
print(text)
sys.exit(code)
"""

FAKE_LEDGER_CHECK = """import os, sys
sys.exit(int(os.environ.get("FAKE_LEDGER_EXIT", "0")))
"""

FAKE_DISCOVER = """#!/bin/sh
out=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then out=$arg; fi
    prev=$arg
done
echo '{"fake": true}' > "$out"
"""


class LinkedControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-keyops-linked-")
        self.directory = Path(self.temporary.name)
        self.fakes = self.directory / "fakes"
        self.fakes.mkdir()
        self.write_fake("observer", FAKE_OBSERVER, executable=True)
        self.write_fake("fixture", FAKE_FIXTURE, executable=True)
        self.write_fake("gated", FAKE_GATED, executable=True)
        self.write_fake("oracle.py", FAKE_ORACLE)
        self.write_fake("ledger-check.py", FAKE_LEDGER_CHECK)
        self.write_fake("discover", FAKE_DISCOVER, executable=True)
        (self.directory / "manifest.json").write_text('{"fake": true}')

    def tearDown(self):
        self.temporary.cleanup()

    def write_fake(self, name, content, executable=False):
        path = self.fakes / name
        path.write_text(content)
        if executable:
            path.chmod(0o755)
        return str(path)

    def run_script(self, scenarios, extra_env=None, with_off=True):
        outdir = self.directory / "out"
        env = dict(os.environ)
        env.update({
            "KEYOPS_SELFTEST_NO_PRIV": "1",
            "KEYOPS_SELFTEST_FIXTURE_BIN": str(self.fakes / "fixture"),
            "KEYOPS_SELFTEST_GATED_BIN": str(self.fakes / "gated"),
            "KEYOPS_SELFTEST_QUALIFY": str(self.fakes / "oracle.py"),
            "KEYOPS_SELFTEST_LEDGER_CHECK": str(self.fakes / "ledger-check.py"),
            "KEYOPS_SELFTEST_DISCOVER": str(self.fakes / "discover"),
            "KEYOPS_SELFTEST_MANIFEST": str(self.directory / "manifest.json"),
            "KEYOPS_SELFTEST_SCENARIO_LINKED_SYSTEM":
                scenarios.get("linked-system", "unavailable"),
            "KEYOPS_SELFTEST_SCENARIO_LINKED_PID":
                scenarios.get("linked-pid", "unavailable"),
            "KEYOPS_SELFTEST_SCENARIO_FLAG_OFF_S1":
                scenarios.get("flag-off-s1", "unavailable"),
            "KEYOPS_SELFTEST_SCENARIO_FLAG_OFF_S1_SETTLE10":
                scenarios.get("flag-off-s1-settle10", "unavailable"),
            "KEYOPS_SELFTEST_SCENARIO_NO_MANIFEST":
                scenarios.get("flag-without-manifest", "unavailable"),
            "KEYOPS_SELFTEST_SCENARIO_OFF_BUILD":
                scenarios.get("off-build-refusal",
                              "refuse-1:p11scope: journal-pair-unavailable-in-build: off"),
            "SETTLE_S": "0",
            "ADMIT_TIMEOUT_S": "2",
            "REFUSE_WAIT_S": "3",
            "FIXTURE_TIMEOUT_S": "30",
            "DURATION": "60",
            "TMPDIR": str(self.directory),
        })
        env.pop("P11SCOPE_OFF", None)
        if with_off:
            env["P11SCOPE_OFF"] = str(self.fakes / "observer")
        env.update(extra_env or {})
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=300, env=env,
            preexec_fn=_restore_int_quit)
        rows = []
        results = outdir / "results.jsonl"
        if results.exists():
            rows = [json.loads(line) for line in
                    results.read_text().splitlines()]
        return proc, outdir, {row["cell"]: row for row in rows}

    def test_all_pass(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual(set(rows), {"linked-system", "linked-pid",
                                    "flag-off-s1", "flag-off-s1-settle10",
                                    "flag-without-manifest",
                                    "off-build-refusal"})
        self.assertEqual(
            (rows["linked-system"]["pass"], rows["linked-system"]["qualification"]),
            (True, "qualified"))
        self.assertEqual(
            (rows["linked-pid"]["pass"], rows["linked-pid"]["qualification"]),
            (True, "qualified"))
        self.assertEqual(
            (rows["flag-off-s1"]["pass"], rows["flag-off-s1"]["qualification"]),
            (True, "qualified"))
        self.assertIn("settle 0", rows["flag-off-s1"]["detail"])
        diag = rows["flag-off-s1-settle10"]
        self.assertEqual((diag["pass"], diag["qualification"]),
                         (True, "qualified"))
        self.assertIn("0 no_receipt", diag["detail"])
        self.assertIn("known issue", diag["detail"])
        self.assertIn("accepted", rows["flag-without-manifest"]["detail"])
        self.assertEqual(rows["flag-without-manifest"]["qualification"], "qualified")
        self.assertIn("R-58", rows["off-build-refusal"]["detail"])
        for row in rows.values():
            self.assertEqual(set(row), {"cell", "pass", "qualification", "detail"})

    def test_populated_oracle_refusal_is_failed_row(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_EXIT": "1",
                       "FAKE_TEXT": "refused: simulated shape text"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("oracle refused the populated linked shape", row["detail"])
        self.assertIn("simulated shape text", row["detail"])
        sample = outdir / "linked-sample.json"
        self.assertTrue(sample.exists())
        self.assertEqual(json.loads(sample.read_text())["object_observations"]["status"],
                         "populated")

    def test_journal_unavailable_is_stale_pin_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "unavailable", "linked-pid": "populated"},
            extra_env={"FAKE_EXIT": "1",
                       "FAKE_TEXT": "observer status unavailable with reason journal_unavailable"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("stale pin", row["detail"])
        self.assertIn("journal_unavailable", row["detail"])
        self.assertTrue((outdir / "linked-sample.json").exists())

    def test_corrupt_observer_doc_is_failed_row(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "garbage-doc", "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("missing or unparsable", row["detail"])
        # The harness records the row and continues: later cells run.
        self.assertEqual(set(rows), {"linked-system", "linked-pid",
                                    "flag-off-s1", "flag-off-s1-settle10",
                                    "flag-without-manifest",
                                    "off-build-refusal"})

    def test_bootstrap_without_gaps_is_failed_row(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "unavailable-bootstrap",
             "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("bootstrap_unavailable", row["detail"])
        self.assertIn("no gaps", row["detail"])
        self.assertTrue((outdir / "linked-sample.json").exists())

    def test_bootstrap_with_gaps_records_gap_text(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "unavailable-bootstrap-gaps",
             "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("bootstrap_unavailable", row["detail"])
        self.assertIn("Joint birth unavailable; retained S1", row["detail"])
        self.assertIn("joint_birth_claim_ImageTainted", row["detail"])
        self.assertTrue((outdir / "linked-sample.json").exists())

    def test_pid_journal_is_stale_pin_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "unavailable"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "failed"))
        self.assertIn("stale pin", pid_row["detail"])
        self.assertIn("journal_unavailable", pid_row["detail"])

    def test_pid_bootstrap_is_nonqualifying(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated",
             "linked-pid": "unavailable-bootstrap"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "nonqualifying"))
        self.assertIn("before the seal", pid_row["detail"])
        self.assertIn("bootstrap_unavailable", pid_row["detail"])
        self.assertIn("while no Joint feed exists", pid_row["detail"])

    def test_pid_populated_pass_nonzero_exit_is_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_OBS_EXIT": "1"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "failed"))
        self.assertIn("not the pinned signature", pid_row["detail"])
        sys_row = rows["linked-system"]
        self.assertEqual((sys_row["pass"], sys_row["qualification"]),
                         (False, "failed"))
        self.assertIn("not the pinned signature", sys_row["detail"])

    def test_pid_populated_refusal_is_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_EXIT": "1",
                       "FAKE_TEXT": "refused: pid shape text"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "failed"))
        self.assertIn("oracle refused", pid_row["detail"])
        self.assertIn("pid shape text", pid_row["detail"])

    def test_pid_populated_refusal_nonzero_exit_is_failed_with_text(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_EXIT": "1",
                       "FAKE_TEXT": "refused: pid exit1 text",
                       "FAKE_OBS_EXIT": "1"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "failed"))
        self.assertIn("pid exit1 text", pid_row["detail"])

    def test_nonzero_exit_is_not_the_pinned_signature(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "unavailable", "linked-pid": "populated"},
            extra_env={"FAKE_OBS_EXIT": "1",
                       "FAKE_S1_EXIT": "1",
                       "FAKE_S1_TEXT": ("S1 child API returns are not exactly"
                                        " 66 current observations")})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("not the pinned signature", row["detail"])
        s1_row = rows["flag-off-s1"]
        self.assertEqual((s1_row["pass"], s1_row["qualification"]),
                         (False, "failed"))
        self.assertIn("settle 0", s1_row["detail"])

    def test_oracle_pass_on_unavailable_is_stale(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "unavailable", "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("went stale", row["detail"])

    def test_refused_start_with_exit_zero_fails(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": ("refuse-0:p11scope: "
                              "journal-pair-unavailable-in-build: off"),
             "linked-pid": "populated"})
        self.assertEqual(proc.returncode, 1)
        row = rows["linked-system"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("flow failed", row["detail"])

    def test_sudo_preserves_token_conf(self):
        text = SCRIPT.read_text()
        self.assertIn('SUDO="sudo -n --preserve-env=SOFTHSM2_CONF"', text)

    def test_old_oracle_text_is_not_expected_failure(self):
        text = SCRIPT.read_text()
        self.assertNotIn("not exactly 65 current observations", text)

    def test_s1_failure_fails(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_S1_EXIT": "1",
                       "FAKE_S1_TEXT": "s1 topology mismatch"})
        self.assertEqual(proc.returncode, 1)
        row = rows["flag-off-s1"]
        self.assertEqual((row["pass"], row["qualification"]), (False, "failed"))
        self.assertIn("s1 topology mismatch", row["detail"])
        self.assertIn("settle 0", row["detail"])

    def test_s1_65_text_is_failed_row(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_S1_EXIT": "1",
                       "FAKE_S1_TEXT": ("S1 child API returns are not exactly"
                                        " 65 current observations")})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        row = rows["flag-off-s1"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("65 current observations", row["detail"])

    def test_s1_66_text_is_failed_row(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"FAKE_S1_EXIT": "1",
                       "FAKE_S1_TEXT": ("S1 child API returns are not exactly"
                                        " 66 current observations")})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        row = rows["flag-off-s1"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("66 current observations", row["detail"])

    def test_flag_off_s1_forces_settle_zero(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated"},
            extra_env={"SETTLE_S": "10"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        row = rows["flag-off-s1"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (True, "qualified"))
        self.assertIn("settle 0", row["detail"])

    def test_settle10_diagnostic_reports_gaps_as_known_issue(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "flag-off-s1-settle10": "diag-gaps-16"},
            extra_env={"FAKE_S1_EXIT": "1",
                       "FAKE_S1_TEXT": "S1 terminal semantic drain or continuity is unproven"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        diag = rows["flag-off-s1-settle10"]
        self.assertEqual((diag["pass"], diag["qualification"]),
                         (True, "qualified"))
        self.assertIn("16 no_receipt", diag["detail"])
        self.assertIn("known issue", diag["detail"])
        s1_row = rows["flag-off-s1"]
        self.assertEqual((s1_row["pass"], s1_row["qualification"]),
                         (False, "failed"))

    def test_settle10_diagnostic_zero_gaps_is_qualified(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "flag-off-s1-settle10": "unavailable"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        diag = rows["flag-off-s1-settle10"]
        self.assertEqual((diag["pass"], diag["qualification"]),
                         (True, "qualified"))
        self.assertIn("0 no_receipt", diag["detail"])

    def test_settle10_diagnostic_flow_failure_is_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "flag-off-s1-settle10": "refuse-9:boom"})
        self.assertEqual(proc.returncode, 1)
        diag = rows["flag-off-s1-settle10"]
        self.assertEqual((diag["pass"], diag["qualification"]),
                         (False, "failed"))
        self.assertIn("flow failed", diag["detail"])

    def test_settle10_unreadable_gaps_is_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "flag-off-s1-settle10": "diag-gaps-unreadable"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        diag = rows["flag-off-s1-settle10"]
        self.assertEqual((diag["pass"], diag["qualification"]),
                         (False, "failed"))
        self.assertIn("unreadable", diag["detail"])

    def test_no_manifest_refusal_and_off_nonqualifying(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "flag-without-manifest": "refuse-2:p11scope: need a manifest"},
            with_off=False)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        row = rows["flag-without-manifest"]
        self.assertEqual((row["pass"], row["qualification"]), (True, "qualified"))
        self.assertIn("refused before any output file opened", row["detail"])
        self.assertIn("exit 2", row["detail"])
        off = rows["off-build-refusal"]
        self.assertEqual((off["pass"], off["qualification"]),
                         (False, "nonqualifying"))

    def test_off_build_accepted_s1(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "populated",
             "off-build-refusal": "accept-with-token"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        row = rows["off-build-refusal"]
        self.assertEqual((row["pass"], row["qualification"]), (True, "qualified"))
        self.assertIn("completed S1 capture", row["detail"])

    def test_off_build_observer_flag_cells(self):
        token = ("refuse-1:p11scope: journal-pair-unavailable-in-build: "
                 "this build omits the production journal object")
        proc, outdir, rows = self.run_script(
            {"linked-system": token, "linked-pid": token,
             "flag-off-s1": "unavailable",
             "flag-without-manifest": "refuse-2:p11scope: need a manifest",
             "off-build-refusal": token})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        for cell in ("linked-system", "linked-pid"):
            row = rows[cell]
            self.assertEqual((row["pass"], row["qualification"]),
                             (True, "expected-failure"), cell)
            self.assertIn("refused at start", row["detail"], cell)
        self.assertEqual(rows["flag-off-s1"]["qualification"], "qualified")
        self.assertEqual(rows["flag-without-manifest"]["qualification"],
                         "qualified")
        self.assertEqual(rows["off-build-refusal"]["qualification"],
                         "qualified")

    def test_flow_failures_are_failed_rows(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "populated", "linked-pid": "refuse-9:boom",
             "flag-off-s1": "unavailable",
             "flag-without-manifest": "exit-0-silent",
             "off-build-refusal": "die-at-3"})
        self.assertEqual(proc.returncode, 1)
        pid_row = rows["linked-pid"]
        self.assertEqual((pid_row["pass"], pid_row["qualification"]),
                         (False, "failed"))
        self.assertIn("flow failed", pid_row["detail"])
        self.assertTrue((outdir / "linked-pid-flow.stderr").exists())
        noman = rows["flag-without-manifest"]
        self.assertEqual((noman["pass"], noman["qualification"]),
                         (False, "failed"))
        self.assertIn("exited 0 within", noman["detail"])
        off = rows["off-build-refusal"]
        self.assertEqual((off["pass"], off["qualification"]), (False, "failed"))
        self.assertIn("observer exited before admission", off["detail"])
        self.assertEqual(rows["linked-system"]["qualification"], "qualified")
        self.assertEqual(rows["flag-off-s1"]["qualification"], "qualified")

    def test_no_manifest_stop_failure_is_failed(self):
        proc, outdir, rows = self.run_script(
            {"linked-system": "refuse-9:boom", "linked-pid": "refuse-9:boom",
             "flag-off-s1": "refuse-9:boom",
             "flag-without-manifest": "unavailable"},
            extra_env={"FAKE_OBS_EXIT": "3"})
        self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
        row = rows["flag-without-manifest"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("stop failed: exit 3", row["detail"])

    def test_bad_numeric_env_is_usage_error(self):
        outdir = self.directory / "outbad"
        env = dict(os.environ, KEYOPS_SELFTEST_NO_PRIV="1", DURATION="abc",
                   TMPDIR=str(self.directory))
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("positive integer", proc.stderr)

    def test_missing_module_is_77(self):
        outdir = self.directory / "out77"
        env = dict(os.environ, KEYOPS_SELFTEST_NO_PRIV="1",
                   MODULE="/nonexistent-provider.so",
                   TMPDIR=str(self.directory))
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 77)

    def test_usage_errors(self):
        proc = subprocess.run(["sh", str(SCRIPT)],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        proc = subprocess.run(
            ["sh", str(SCRIPT), "/nonexistent-observer",
             str(self.directory / "out")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)

    def test_default_paths_exist(self):
        for rel in ("scripts/qualify-key-operations.py",
                    "scripts/key-operation-ledger.py",
                    "tests/fixtures/key-operations/rsa-ledger.c",
                    "tests/fixtures/public-cli/gated.c",
                    "scripts/ci/key_operations_checks.py",
                    "scripts/ci/key_operations_fixture.py",
                    "scripts/ci/run_default_signals.py"):
            self.assertTrue((ROOT / rel).exists(), rel)

    def test_signal_launcher_restores_int_for_async_child(self):
        import signal as sig_mod
        import time as time_mod
        stub = self.directory / "trap-tester.sh"
        # A childless wait: `read` on a held stdin blocks with no
        # grandchild to inherit the stdout pipe (a `sleep` child would
        # outlive the stub and wedge communicate()).
        stub.write_text('#!/bin/sh\ntrap "echo TRAPPED; exit 0" INT\nread x || true\n')
        stub.chmod(0o755)
        helper = str(ROOT / "scripts/ci/run_default_signals.py")

        def launch(command):
            # Async `&` children get stdin=/dev/null unless redirected, so
            # the blocking `read` needs an explicitly held pipe.
            read_fd, write_fd = os.pipe()
            try:
                proc = subprocess.Popen(
                    ["sh", "-c",
                     f"{command} <&{read_fd} & echo STARTED $!; wait $!"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True,
                    pass_fds=(read_fd,))
            finally:
                os.close(read_fd)
            line = proc.stdout.readline().strip()
            self.assertTrue(line.startswith("STARTED "), line)
            proc.held_stdin_write = write_fd
            return proc, int(line.split()[1])

        def close_held(proc):
            try:
                os.close(proc.held_stdin_write)
            except OSError:
                pass

        # Premise: an async child ignores SIGINT, so its trap stays dead.
        # Dash installs the ignore post-fork; poll for it briefly instead
        # of a single read that can catch mid-setup (SigIgn 0000/0004).
        proc, pid = launch(f'"{stub}"')
        try:
            deadline = time_mod.time() + 5
            status = ""
            while True:
                try:
                    with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
                        status = handle.read()
                except FileNotFoundError:
                    break
                if "SigIgn:\t0000000000000006" in status:
                    break
                if time_mod.time() >= deadline:
                    break
                time_mod.sleep(0.05)
            self.assertIn("SigIgn:\t0000000000000006", status)
            os.kill(pid, sig_mod.SIGINT)
            time_mod.sleep(1)
            os.kill(pid, 0)  # Still alive: the trap never installed.
        finally:
            try:
                os.kill(pid, sig_mod.SIGTERM)
            except ProcessLookupError:
                pass
            close_held(proc)
            proc.communicate(timeout=10)
        # With the helper, an async exec target observes default
        # SIGINT/SIGQUIT and its handler fires. A Python target: it captures
        # its own entry mask before installing anything, so the mask
        # assertion below is the helper's doing, not self-restore; the
        # handler is installed before ENTRYMASK is printed so the SIGINT
        # below always lands on the handler instead of the default.
        target = self.directory / "trap-target.py"
        target.write_text(
            "#!/usr/bin/env python3\n"
            "import signal, sys, time\n"
            "mask = open('/proc/self/status').read()\n"
            "line = next(l for l in mask.splitlines() if l.startswith('SigIgn:'))\n"
            "entry = line.split()[1]\n"
            "signal.signal(signal.SIGINT,\n"
            "              lambda s, f: (print('TRAPPED'), sys.exit(0)))\n"
            "print('ENTRYMASK', entry, flush=True)\n"
            "time.sleep(30)\n")
        target.chmod(0o755)
        proc = subprocess.Popen(
            ["sh", "-c",
             f'"{sys.executable}" -I "{helper}" "{target}" & echo STARTED $!; wait $!'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)
        try:
            started = mask_line = None
            for _ in range(2):
                line = proc.stdout.readline().strip()
                if line.startswith("STARTED "):
                    started = int(line.split()[1])
                elif line.startswith("ENTRYMASK "):
                    mask_line = line
            self.assertIsNotNone(started)
            self.assertIsNotNone(mask_line)
            entry_mask = int(mask_line.split()[1], 16)
            self.assertEqual(entry_mask & 0x6, 0,
                             f"helper left INT/QUIT ignored: {mask_line}")
            os.kill(started, sig_mod.SIGINT)
            out, _ = proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("TRAPPED", out)


class LossVocabularyTests(unittest.TestCase):
    """The s1 loss subjects fail the shared zero-loss gate by subject.

    The linked script only reads object_observations today, so these
    pin the shared checker directly: each subject must fail with the
    current reason text and with a reason that names no events_lost
    token (the batch-4 review probe).
    """

    def doc(self, gaps):
        return {"object_observations": {"status": "unavailable",
                                       "reason": "journal_unavailable"},
                "observation": {"lifecycle": {"ring_loss": 0}},
                "gaps": gaps}

    def test_s1_events_lost_subject_fails_zero_loss_gate(self):
        current = ("the EVENTS ring was full; the kernel refused records "
                   "before the drain could read them "
                   "(kernel reserve failures; exact count in events_lost)")
        without_token = ("the EVENTS ring was full; the kernel refused "
                         "records before the drain could read them")
        for reason in (current, without_token):
            gap = {"subject": "native capture events lost", "reason": reason}
            ok, detail = checks.check_no_loss_gap(self.doc(gaps=[gap]))
            self.assertFalse(ok, reason)
            self.assertIn("loss gap", detail)

    def test_s1_events_loss_unknown_subject_fails_zero_loss_gate(self):
        current = ("the EVENTS ring-loss counter could not be read; "
                   "events_lost may undercount until a later good read "
                   "restores the exact cumulative total")
        probe = "the EVENTS ring-loss counter could not be read"
        for reason in (current, probe):
            gap = {"subject": "native capture events loss unknown",
                   "reason": reason}
            ok, detail = checks.check_no_loss_gap(self.doc(gaps=[gap]))
            self.assertFalse(ok, reason)
            self.assertIn("loss gap", detail)


if __name__ == "__main__":
    unittest.main()
