#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Churn cells: full-script self-test through fakes, plus check units.

Runs scripts/ci/key-operations-system.sh end to end with a self-stopping
fake observer, fake fixture/seed/caller/discover, a fake GNU time on PATH
and fake oracles, and asserts the churn-on/churn-twin/churn-on-ledger rows
for every scenario: pass, planted ring loss (with twin attribution both
ways), planted loss gap, incomplete stop, churn shortfalls and the 77/2
exits. Also unit-tests scripts/ci/key_operations_checks.py, including the
proof that benign custody notes never match the loss vocabulary. No
SoftHSM, no privilege, no real observer. Run as a script:

    python3 -I tests/python/test_key_operations_system.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/key-operations-system.sh"

sys.path.insert(0, str(ROOT / "scripts/ci"))
import key_operations_checks as checks  # noqa: E402


FAKE_OBSERVER = """#!/bin/sh
# Fake observer: seal line, self-stop after FAKE_OBSERVE_S, canned doc.
# KEYOPS_SELFTEST_SCENARIO: clean | ring-loss | loss-gap | dirty-stop |
# oo-populated | garbage-doc (each: unavailable oo except oo-populated).
out=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then out=$arg; fi
    prev=$arg
done
scenario=${KEYOPS_SELFTEST_SCENARIO:-clean}
case $scenario in
    refuse-*)
        rest=${scenario#refuse-}
        code=${rest%%:*}
        echo "${rest#*:}" >&2
        exit "$code"
        ;;
esac
echo "p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: planned for 0.6.0)" >&2
sleep "${FAKE_OBSERVE_S:-8}"
ring=0
gaps="[]"
status=unavailable
reason=journal_unavailable
case $scenario in
    ring-loss) ring=1 ;;
    loss-gap)
        gaps='[{"subject": "discovery ring loss", "reason": "the ring was not serviced during the collection"}]' ;;
    oo-populated)
        status=populated
        reason="rev 1" ;;
    garbage-doc)
        echo "NOT JSON{{{" > "$out"
        exit "${FAKE_OBS_EXIT:-0}" ;;
esac
if [ "$scenario" = dirty-stop ]; then
    echo "p11scope: cleanup incomplete, 3 links uncertain" >&2
fi
cat > "$out" <<EOF
{"object_observations": {"status": "$status", "reason": "$reason"},
 "observation": {"lifecycle": {"ring_loss": $ring}}, "gaps": $gaps}
EOF
exit "${FAKE_OBS_EXIT:-0}"
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

FAKE_GENCALLS = """#!/bin/sh
ledger=$5
i=0
n=${GENCALLS_CALLS:-10}
while [ "$i" -lt "$n" ]; do
    echo "{\\"kind\\":\\"call\\",\\"seq\\":$i,\\"fn\\":\\"C_Digest\\",\\"rv\\":0,\\"t0\\":1,\\"t1\\":2}"
    i=$((i + 1))
done > "$ledger"
exit "${GENCALLS_EXIT:-0}"
"""

FAKE_TIME = """#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case $1 in
        -o) out=$2; shift 2;;
        -*) shift;;
        *) break;;
    esac
done
"$@"
code=$?
cat > "$out" <<EOF
	Maximum resident set size (kbytes): 123456
	Percent of CPU this job got: 42%
EOF
exit "$code"
"""

FAKE_ORACLE = """import os, sys
code = int(os.environ.get("FAKE_EXIT", "0"))
print(os.environ.get("FAKE_TEXT", "compare ok"))
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


class SystemScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="p11scope-keyops-system-")
        self.directory = Path(self.temporary.name)
        self.fakes = self.directory / "fakes"
        self.fakes.mkdir()
        for name, content in (
                ("observer", FAKE_OBSERVER), ("fixture", FAKE_FIXTURE),
                ("gated", FAKE_GATED), ("gen-calls", FAKE_GENCALLS),
                ("time", FAKE_TIME), ("discover", FAKE_DISCOVER)):
            path = self.fakes / name
            path.write_text(content)
            path.chmod(0o755)
        (self.fakes / "oracle.py").write_text(FAKE_ORACLE)
        (self.fakes / "ledger-check.py").write_text(FAKE_LEDGER_CHECK)
        (self.directory / "manifest.json").write_text('{"fake": true}')

    def tearDown(self):
        self.temporary.cleanup()

    def run_script(self, on="clean", twin="clean", extra_env=None):
        outdir = self.directory / "out"
        env = dict(os.environ)
        env.update({
            "PATH": str(self.fakes) + ":" + env.get("PATH", ""),
            "KEYOPS_SELFTEST_NO_PRIV": "1",
            "KEYOPS_SELFTEST_FIXTURE_BIN": str(self.fakes / "fixture"),
            "KEYOPS_SELFTEST_GATED_BIN": str(self.fakes / "gated"),
            "KEYOPS_SELFTEST_GENCALLS_BIN": str(self.fakes / "gen-calls"),
            "KEYOPS_SELFTEST_QUALIFY": str(self.fakes / "oracle.py"),
            "KEYOPS_SELFTEST_LEDGER_CHECK": str(self.fakes / "ledger-check.py"),
            "KEYOPS_SELFTEST_DISCOVER": str(self.fakes / "discover"),
            "KEYOPS_SELFTEST_MANIFEST": str(self.directory / "manifest.json"),
            "KEYOPS_SELFTEST_SCENARIO_ON": on,
            "KEYOPS_SELFTEST_SCENARIO_TWIN": twin,
            "SETTLE_S": "0",
            "ADMIT_TIMEOUT_S": "2",
            "FIXTURE_TIMEOUT_S": "30",
            "DURATION": "3",
            "TMPDIR": str(self.directory),
        })
        env.update(extra_env or {})
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=300, env=env)
        rows = []
        results = outdir / "results.jsonl"
        if results.exists():
            rows = [json.loads(line) for line in
                    results.read_text().splitlines()]
        return proc, outdir, {row["cell"]: row for row in rows}

    def test_all_pass(self):
        proc, outdir, rows = self.run_script(
            extra_env={"FAKE_EXIT": "1", "FAKE_TEXT": "unavailable: none"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual(set(rows), {"churn-on", "churn-twin", "churn-on-ledger"})
        self.assertEqual((rows["churn-on"]["pass"],
                          rows["churn-on"]["qualification"]), (True, "qualified"))
        self.assertEqual((rows["churn-twin"]["pass"],
                          rows["churn-twin"]["qualification"]), (True, "qualified"))
        self.assertIn("123456", rows["churn-on"]["detail"])
        self.assertIn("42%", rows["churn-on"]["detail"])
        ledger = rows["churn-on-ledger"]
        self.assertEqual((ledger["pass"], ledger["qualification"]),
                         (True, "expected-failure"))
        self.assertIn("journal_unavailable", ledger["detail"])
        self.assertTrue((outdir / "churn-linked-sample.json").exists())

    def test_ledger_compared_pass(self):
        proc, outdir, rows = self.run_script("oo-populated")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        ledger = rows["churn-on-ledger"]
        self.assertEqual((ledger["pass"], ledger["qualification"]),
                         (True, "qualified"))

    def test_ring_loss_fails_with_clean_twin_attribution(self):
        proc, outdir, rows = self.run_script("ring-loss", "clean")
        self.assertEqual(proc.returncode, 1)
        row = rows["churn-on"]
        self.assertEqual((row["pass"], row["qualification"]), (False, "failed"))
        self.assertIn("ring_loss == 1", row["detail"])
        self.assertIn("twin clean, loss belongs to the flag run", row["detail"])
        self.assertEqual(rows["churn-twin"]["qualification"], "qualified")

    def test_ring_loss_both_runs_is_ambient(self):
        proc, outdir, rows = self.run_script("ring-loss", "ring-loss")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("twin also loses", rows["churn-on"]["detail"])
        self.assertEqual(rows["churn-twin"]["qualification"], "failed")

    def test_off_build_flag_run_is_nonqualifying(self):
        token = ("refuse-1:p11scope: journal-pair-unavailable-in-build: "
                 "this build omits the production journal object")
        proc, outdir, rows = self.run_script(token, "clean")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertEqual((rows["churn-on"]["pass"],
                          rows["churn-on"]["qualification"]),
                         (False, "nonqualifying"))
        self.assertIn("R-58", rows["churn-on"]["detail"])
        self.assertEqual((rows["churn-on-ledger"]["pass"],
                          rows["churn-on-ledger"]["qualification"]),
                         (False, "nonqualifying"))
        self.assertEqual(rows["churn-twin"]["qualification"], "qualified")

    def test_loss_gap_fails(self):
        proc, outdir, rows = self.run_script("loss-gap", "clean")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("loss gap", rows["churn-on"]["detail"])

    def test_corrupt_observer_doc_is_failed_row(self):
        proc, outdir, rows = self.run_script("garbage-doc", "clean")
        self.assertEqual(proc.returncode, 1)
        row = rows["churn-on-ledger"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("missing or unparsable", row["detail"])
        # The harness records the row and continues: every row lands.
        self.assertEqual(set(rows),
                         {"churn-on", "churn-twin", "churn-on-ledger"})

    def test_nonzero_exit_is_not_the_pinned_signature(self):
        proc, outdir, rows = self.run_script(
            "clean", "clean", extra_env={"FAKE_OBS_EXIT": "1"})
        self.assertEqual(proc.returncode, 1)
        row = rows["churn-on-ledger"]
        self.assertEqual((row["pass"], row["qualification"]),
                         (False, "failed"))
        self.assertIn("not the pinned signature", row["detail"])

    def test_sudo_preserves_token_conf(self):
        text = SCRIPT.read_text()
        self.assertIn('SUDO="sudo -n --preserve-env=SOFTHSM2_CONF"', text)

    def test_incomplete_stop_fails(self):
        proc, outdir, rows = self.run_script("dirty-stop", "clean")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("cleanup incomplete", rows["churn-on"]["detail"])

    def test_caller_failure_fails(self):
        proc, outdir, rows = self.run_script(
            extra_env={"GENCALLS_EXIT": "3", "GENCALLS_CALLS": "0"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("caller churn failed", rows["churn-on"]["detail"])

    def test_exec_floor_shortfall_fails(self):
        proc, outdir, rows = self.run_script(
            extra_env={"EXEC_FLOOR_PER_S": "1000000"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("exec churn shortfall", rows["churn-on"]["detail"])

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
        outdir = self.directory / "outbad"
        env = dict(os.environ, KEYOPS_SELFTEST_NO_PRIV="1", DURATION="0",
                   TMPDIR=str(self.directory))
        proc = subprocess.run(
            ["sh", str(SCRIPT), str(self.fakes / "observer"), str(outdir)],
            capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("positive integer", proc.stderr)

    def test_default_paths_exist(self):
        for rel in ("scripts/qualify-key-operations.py",
                    "scripts/key-operation-ledger.py",
                    "tests/fixtures/key-operations/rsa-ledger.c",
                    "tests/fixtures/public-cli/gated.c",
                    "tests/fixtures/joint-throughput/gen-calls.c",
                    "scripts/ci/key_operations_checks.py",
                    "scripts/ci/key_operations_fixture.py"):
            self.assertTrue((ROOT / rel).exists(), rel)


class CheckHelperTests(unittest.TestCase):
    def doc(self, ring_loss=0, gaps=None, status="unavailable",
            reason="journal_unavailable"):
        return {"object_observations": {"status": status, "reason": reason},
                "observation": {"lifecycle": {"ring_loss": ring_loss}},
                "gaps": gaps if gaps is not None else []}

    def test_ring_loss(self):
        ok, detail = checks.check_ring_loss(self.doc())
        self.assertTrue(ok)
        self.assertIn("== 0", detail)
        ok, detail = checks.check_ring_loss(self.doc(ring_loss=1))
        self.assertFalse(ok)
        self.assertIn("== 1", detail)
        ok, detail = checks.check_ring_loss({})
        self.assertFalse(ok)
        self.assertIn("missing", detail)

    def test_no_loss_gap(self):
        ok, _ = checks.check_no_loss_gap(self.doc())
        self.assertTrue(ok)
        gap = {"subject": "discovery ring loss",
               "reason": "the ring was not serviced"}
        ok, detail = checks.check_no_loss_gap(self.doc(gaps=[gap]))
        self.assertFalse(ok)
        self.assertIn("loss gap", detail)
        gap = {"subject": "truncated collection", "reason": "overflow at 99%"}
        ok, _ = checks.check_no_loss_gap(self.doc(gaps=[gap]))
        self.assertFalse(ok)

    def test_real_loss_subjects_match(self):
        for subject in ("semantic capture loss", "semantic calls lost",
                        "native count refresh loss",
                        "leader task link loss",
                        "semantic batch dropped without lane authority"):
            gap = {"subject": subject, "reason": "cell pressure"}
            ok, detail = checks.check_no_loss_gap(self.doc(gaps=[gap]))
            self.assertFalse(ok, subject)
            self.assertIn("loss gap", detail)

    def test_real_loss_reasons_match(self):
        reasons = (
            # src/attach/inventory/capture.rs lifecycle-ring rule.
            "the lifecycle ring lost records (DISCOVERY ring loss 6 -> 8): "
            "2 may be among them",
            # caller_registry.rs capture-loss note.
            "EVENTS ring lost 4 records",
            # capture.rs short-record lifecycle loss.
            "a lifecycle record was lost: short DISCOVERY record",
        )
        for reason in reasons:
            gap = {"subject": "capture discovery", "reason": reason}
            ok, detail = checks.check_no_loss_gap(self.doc(gaps=[gap]))
            self.assertFalse(ok, reason)
            self.assertIn("loss gap", detail)

    def test_benign_gaps_never_match(self):
        benign = [
            {"subject": "native capture scope custody unproven",
             "reason": "PID custody lost: the PID target exited"},
            {"subject": "native capture scope custody unproven",
             "reason": "PID custody was lost: the target exited"},
            {"subject": "first-burst shed",
             "reason": "predates the semantic lane; shed 12"},
            {"subject": "inventory capture failed",
             "reason": "the process could not be read; unknown, not absent"},
            {"subject": "native owner lost",
             "reason": "scan failed: owner unreadable"},
            {"subject": "semantic calls unrouted",
             "reason": "1 calls shed without a route (pending=1)"},
            {"subject": "semantic batch refused for a foreign domain",
             "reason": "domain ended before the batch"},
        ]
        ok, _ = checks.check_no_loss_gap(self.doc(gaps=benign))
        self.assertTrue(ok)

    def test_stop(self):
        ok, _ = checks.check_stop(0, "all done", self.doc())
        self.assertTrue(ok)
        ok, detail = checks.check_stop(3, "", self.doc())
        self.assertFalse(ok)
        self.assertIn("exit 3", detail)
        ok, detail = checks.check_stop(0, "cleanup incomplete, 1 uncertain",
                                       self.doc())
        self.assertFalse(ok)
        self.assertIn("cleanup incomplete", detail)
        ok, _ = checks.check_stop(0, "", None)
        self.assertFalse(ok)

    def test_object_observations(self):
        self.assertEqual(checks.object_observations(self.doc()),
                         ("unavailable", "journal_unavailable"))
        self.assertEqual(
            checks.object_observations(self.doc(status="populated", reason="rev 1")),
            ("populated", "rev 1"))
        self.assertEqual(checks.object_observations({}), ("missing", ""))


if __name__ == "__main__":
    unittest.main()
