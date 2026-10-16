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


def run_profiled(tmp, provider, provider_args, *oracle_args, timeout=60):
    out = str(Path(tmp) / "observed.json")
    argv = ["--run", "--provider", str(provider)]
    for arg in provider_args:
        argv.append(f"--provider-arg={arg}")
    argv += ["--ledger", str(LEDGER), "--out", out, *oracle_args]
    return run_oracle(*argv, timeout=timeout), out


FAKE_PROVIDER = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--fake-profile", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "fake-provider", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
if args.fake_profile:
    rate, duration = (int(part) for part in args.fake_profile.split(","))
    observed["profile"] = {"rate": rate, "duration": duration}
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""


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


class IndependenceTests(unittest.TestCase):
    """C13: PASS must prove observation-plus-comparison agreement, never a
    serialization round-trip, and every comparison binds to one frozen
    ledger read."""

    def test_two_runs_differ_in_bytes_but_both_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            first = str(Path(temp) / "first.json")
            second = str(Path(temp) / "second.json")
            self.assertEqual(run_stub(LEDGER, first).returncode, 0)
            self.assertEqual(run_stub(LEDGER, second).returncode, 0)
            raw_first = Path(first).read_bytes()
            raw_second = Path(second).read_bytes()
            self.assertNotEqual(raw_first, raw_second, "fresh stamps each run")
            for path in (first, second):
                proc = run_oracle("--check", "--observed", path, "--ledger", str(LEDGER))
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            observed = json.loads(raw_first)
            self.assertIn("run_id", observed)
            self.assertIn("ledger_digest", observed)
            self.assertTrue(
                all(isinstance(call.get("observed_at"), int) for call in observed["invocations"])
            )
            self.assertTrue(
                all(
                    isinstance(record.get("observed_at"), int)
                    for record in observed["records"]
                )
            )

    def test_stale_output_fails_against_current_ledger(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = json.loads(LEDGER.read_bytes())
            ledger["records"][0] = {**ledger["records"][0], "seq": 7}
            other = Path(temp) / "ledger-b.json"
            other.write_text(json.dumps(ledger, sort_keys=True))
            observed_path = str(Path(temp) / "observed.json")
            self.assertEqual(run_stub(LEDGER, observed_path).returncode, 0)
            proc = run_oracle("--check", "--observed", observed_path, "--ledger", str(other))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("LEDGER_UNBOUND", proc.stdout)

    def test_current_output_fails_against_stale_ledger(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = json.loads(LEDGER.read_bytes())
            ledger["records"][0] = {**ledger["records"][0], "seq": 7}
            other = Path(temp) / "ledger-b.json"
            other.write_text(json.dumps(ledger, sort_keys=True))
            observed_path = str(Path(temp) / "observed.json")
            self.assertEqual(run_stub(other, observed_path).returncode, 0)
            proc = run_oracle("--check", "--observed", observed_path, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("LEDGER_UNBOUND", proc.stdout)


class PacingTests(unittest.TestCase):
    """N6: the profile rate and duration pace the run; the oracle verifies
    the observed pace instead of ignoring it."""

    def stub_args(self, tmp):
        out = str(Path(tmp) / "observed.json")
        return ["--ledger", str(LEDGER), "--out", out], out

    def test_run_honors_requested_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            provider_args, out = self.stub_args(temp)
            proc, _ = run_profiled(temp, STUB, provider_args, "--rate", "100", "--duration", "5")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            observed = json.loads(Path(out).read_bytes())
            self.assertEqual(observed["profile"], {"rate": 100, "duration": 5})
            stamps = [call["observed_at"] for call in observed["invocations"]]
            stamps += [record["observed_at"] for record in observed["records"]]
            self.assertEqual(len(stamps), 15)
            self.assertLessEqual(max(stamps) - min(stamps), 5_000_000_000)

    def test_profile_name_selects_default_rate(self):
        with tempfile.TemporaryDirectory() as temp:
            provider_args, out = self.stub_args(temp)
            proc, _ = run_profiled(temp, STUB, provider_args, "--profile", "10k")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            observed = json.loads(Path(out).read_bytes())
            self.assertEqual(observed["profile"]["rate"], 10000)

    def test_infeasible_pace_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            provider_args, _ = self.stub_args(temp)
            proc, _ = run_profiled(temp, STUB, provider_args, "--rate", "1", "--duration", "1")
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
            self.assertIn("pace infeasible", proc.stderr)

    def test_unpaced_provider_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "fake-provider.py"
            fake.write_text(FAKE_PROVIDER)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(fake), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PACING_MISSING", proc.stdout)

    def test_wrong_profile_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "fake-provider.py"
            fake.write_text(FAKE_PROVIDER)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(fake), "--ledger", str(LEDGER), "--out", out, "--fake-profile", "1,60"],
                "--rate",
                "100",
                "--duration",
                "5",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PROFILE_MISMATCH", proc.stdout)

    def crafted(self, tmp, profile, stamps):
        ledger = json.loads(LEDGER.read_bytes())
        observed = json.loads(json.dumps(ledger))
        import hashlib

        observed["ledger_digest"] = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
        observed["key_material"] = None
        observed["profile"] = profile
        stamp_iter = iter(stamps)
        for call in observed["invocations"]:
            call["observed_at"] = next(stamp_iter)
        for record in observed["records"]:
            record["observed_at"] = next(stamp_iter)
        path = str(Path(tmp) / "observed.json")
        Path(path).write_text(json.dumps(observed))
        return run_oracle("--check", "--observed", path, "--ledger", str(LEDGER))

    def test_compressed_stamps_fail_check(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = self.crafted(temp, {"rate": 100, "duration": 5}, range(0, 15_000, 1_000))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PACING_TOO_FAST", proc.stdout)

    def test_span_beyond_duration_fails_check(self):
        with tempfile.TemporaryDirectory() as temp:
            stamps = [step * 1_000_000_000 for step in range(15)]
            proc = self.crafted(temp, {"rate": 1000, "duration": 5}, stamps)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PACING_SPAN_EXCEEDED", proc.stdout)

    def test_missing_stamps_fail_check(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = json.loads(LEDGER.read_bytes())
            observed = json.loads(json.dumps(ledger))
            import hashlib

            observed["ledger_digest"] = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
            observed["key_material"] = None
            observed["profile"] = {"rate": 100, "duration": 5}
            path = str(Path(temp) / "observed.json")
            Path(path).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", path, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PACING_INCOMPLETE", proc.stdout)


class EmptyTests(unittest.TestCase):
    """N6: an empty observation set is a qualification FAIL, never a
    vacuous PASS."""

    def test_empty_observations_fail(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temp:
            ledger = json.loads(LEDGER.read_bytes())
            observed = {
                "schema": "p11scope/object-journal-ledger/v1",
                "bootstrap": ledger["bootstrap"],
                "invocations": [],
                "records": [],
                "counts": {"api_calls": 0, "journal_records": 0},
                "key_material": None,
                "ledger_digest": hashlib.sha256(LEDGER.read_bytes()).hexdigest(),
            }
            path = str(Path(temp) / "observed.json")
            Path(path).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", path, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("EMPTY_OBSERVATION_SET", proc.stdout)

    def test_empty_against_empty_ledger_fails(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temp:
            empty_ledger = {
                "schema": "p11scope/object-journal-ledger/v1",
                "bootstrap": {"witness": "absence-appearance", "cut": 0},
                "invocations": [],
                "records": [],
                "counts": {"api_calls": 0, "journal_records": 0},
            }
            ledger_path = Path(temp) / "empty-ledger.json"
            ledger_path.write_text(json.dumps(empty_ledger))
            observed = dict(empty_ledger)
            observed["key_material"] = None
            observed["ledger_digest"] = hashlib.sha256(ledger_path.read_bytes()).hexdigest()
            observed_path = str(Path(temp) / "observed.json")
            Path(observed_path).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", observed_path, "--ledger", str(ledger_path))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("EMPTY_OBSERVATION_SET", proc.stdout)


if __name__ == "__main__":
    unittest.main()
