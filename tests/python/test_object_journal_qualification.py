# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged qualification-oracle tests: argument handling, READY/GO and
deadline behavior, ledger comparison and rejection/mutation cells.

All live BPF measurements stay UNRUN: the driver path runs only against the
repository stub provider, which replays the frozen ledger with scripted
faults. Each oracle mutation (fabricated bootstrap, removed BEGIN, erased
loss, leaked private key) must fail closed."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True

ORACLE = ROOT / "scripts" / "qualify-object-journal.py"
FIXTURES = ROOT / "tests" / "fixtures" / "object-journal"
LEDGER = FIXTURES / "provider-ledger.json"
STUB = FIXTURES / "stub-provider.py"


def run_oracle(*argv, timeout=60):
    return subprocess.run(
        [sys.executable, str(ORACLE), *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_stub(ledger_path, out_path, *extra, stdin_text="GO\n", timeout=60):
    return subprocess.run(
        [sys.executable, str(STUB), "--ledger", str(ledger_path), "--out", str(out_path), *extra],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class LedgerTests(unittest.TestCase):
    def test_ledger_is_frozen_and_complete(self):
        ledger = json.loads(LEDGER.read_bytes())
        self.assertEqual(ledger["schema"], "p11scope/object-journal-ledger/v1")
        invocations = ledger["invocations"]
        records = ledger["records"]
        # Counts pinned separately: API calls are not journal records.
        self.assertEqual(ledger["counts"]["api_calls"], len(invocations))
        self.assertEqual(ledger["counts"]["journal_records"], len(records))
        self.assertGreater(len(records), len(invocations))
        # Coverage: creation, use, destruction, success and error terminals.
        effects = {effect for call in invocations for effect in call["effects"]}
        self.assertTrue({"created", "used", "destroyed"} <= effects)
        terminals = {call["terminal"] for call in invocations}
        self.assertEqual(terminals, {"success", "error"})
        # A long-open call: its END arrives after another call's records.
        begins = {}
        long_open = False
        for record in records:
            if record["kind"] == "BEGIN":
                begins[record["seq"]] = record["ordinal"]
            elif record["kind"] == "END" and record["seq"] in begins:
                if record["ordinal"] > begins[record["seq"]] + 1:
                    intervening = [
                        other
                        for other in records
                        if begins[record["seq"]] < other["ordinal"] < record["ordinal"]
                        and other["seq"] != record["seq"]
                    ]
                    long_open = long_open or bool(intervening)
        self.assertTrue(long_open, "ledger holds a long-open call")
        # Ordinals are dense from 1 with nonzero identity words.
        self.assertEqual([record["ordinal"] for record in records], list(range(1, len(records) + 1)))
        for record in records:
            self.assertGreater(record["thread"], 0)
            self.assertGreater(record["sequence"], 0)


class ArgTests(unittest.TestCase):
    def test_plan_only_prints_matrix(self):
        proc = run_oracle("--plan-only")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for profile in ("1k", "10k", "100k"):
            self.assertIn(profile, proc.stdout)
        self.assertIn("60", proc.stdout)

    def test_check_requires_files(self):
        proc = run_oracle("--check", "--observed", "no-such.json", "--ledger", str(LEDGER))
        self.assertEqual(proc.returncode, 2)

    def test_unknown_profile_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--ledger",
                str(LEDGER),
                "--out",
                out,
                "--profile",
                "1m",
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("profile", proc.stderr)

    def test_bad_deadline_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--ledger",
                str(LEDGER),
                "--out",
                out,
                "--deadline-seconds",
                "0",
            )
            self.assertEqual(proc.returncode, 2)


class ReadyGoTests(unittest.TestCase):
    def test_stub_ready_go_round_trip_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--provider-arg=--ledger",
                "--provider-arg",
                str(LEDGER),
                "--provider-arg=--out",
                "--provider-arg",
                out,
                "--ledger",
                str(LEDGER),
                "--out",
                out,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PASS", proc.stdout)
            observed = json.loads(Path(out).read_bytes())
            self.assertEqual(observed["counts"], json.loads(LEDGER.read_bytes())["counts"])

    def test_malformed_ready_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--provider-arg=--ledger",
                "--provider-arg",
                str(LEDGER),
                "--provider-arg=--out",
                "--provider-arg",
                out,
                "--provider-arg=--ready",
                "--provider-arg",
                "garbage",
                "--ledger",
                str(LEDGER),
                "--out",
                out,
            )
            self.assertEqual(proc.returncode, 3)
            self.assertIn("READY", proc.stderr)

    def test_stall_hits_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--provider-arg=--ledger",
                "--provider-arg",
                str(LEDGER),
                "--provider-arg=--out",
                "--provider-arg",
                out,
                "--provider-arg=--stall",
                "--provider-arg",
                "30",
                "--ledger",
                str(LEDGER),
                "--out",
                out,
                "--deadline-seconds",
                "2",
            )
            self.assertEqual(proc.returncode, 3)
            self.assertIn("deadline", proc.stderr)


class CompareTests(unittest.TestCase):
    def check(self, *stub_extra):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        out = str(Path(temp.name) / "observed.json")
        stub = run_stub(LEDGER, out, *stub_extra)
        self.assertEqual(stub.returncode, 0, stub.stderr)
        return run_oracle("--check", "--observed", out, "--ledger", str(LEDGER))

    def test_clean_observed_passes(self):
        proc = self.check()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_fabricated_bootstrap_rejected(self):
        proc = self.check("--mutate", "fabricate-bootstrap")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BOOTSTRAP_MISMATCH", proc.stdout)

    def test_removed_begin_rejected(self):
        proc = self.check("--mutate", "drop-begin")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("JOURNAL_COUNT_MISMATCH", proc.stdout)

    def test_erased_loss_rejected(self):
        proc = self.check("--mutate", "erase-loss")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RECORD_MISMATCH", proc.stdout)

    def test_leaked_key_rejected(self):
        proc = self.check("--mutate", "leak-key")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("KEY_MATERIAL_LEAK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
