# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged qualification-oracle tests: argument handling, READY/GO and
deadline behavior, ledger comparison and rejection/mutation cells.

All live BPF measurements stay UNRUN: the driver path runs only against the
repository stub provider, which replays the frozen ledger with scripted
faults. Each oracle mutation (fabricated bootstrap, removed BEGIN, erased
loss, leaked private key) must fail closed."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
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


def run_profiled(tmp, provider, provider_args, *oracle_args, timeout=60, ledger=LEDGER):
    out = str(Path(tmp) / "observed.json")
    argv = ["--run", "--provider", str(provider)]
    for arg in provider_args:
        argv.append(f"--provider-arg={arg}")
    argv += ["--ledger", str(ledger), "--out", out, *oracle_args]
    return run_oracle(*argv, timeout=timeout), out


def stub_module():
    """The stub provider's pure observation builders, for generating a
    consistent bigger ledger (the oracle still independently verifies
    every field, count and delivery)."""
    spec = importlib.util.spec_from_file_location("stub_provider", STUB)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_full_window_ledger(tmp, rate, duration):
    """A ledger holding exactly rate*duration observations: the stock
    15 plus whole call/BEGIN/END/return quads (3 observations each)."""
    total = rate * duration
    assert total > 15 and (total - 15) % 3 == 0, "whole quads past the stock 15"
    ledger = json.loads(LEDGER.read_bytes())
    stub = stub_module()
    calls = max(event["seq"] for event in ledger["trace"] if event.get("op") == "call")
    records = len(ledger["records"])
    for _ in range((total - 15) // 3):
        calls += 1
        call = {"op": "call", "seq": calls, "function": "C_CreateObject"}
        begun = {"op": "record", "kind": "BEGIN", "seq": calls, "thread": 11, "sequence": 1}
        ended = {"op": "record", "kind": "END", "seq": calls, "thread": 11, "sequence": 2}
        ret = {"op": "return", "seq": calls, "rv": "OK", "effects": ["created"]}
        ledger["trace"] += [call, begun, ended, ret]
        ledger["invocations"].append(stub.observe_invocation(call, ret, None, 0))
        for event in (begun, ended):
            records += 1
            ledger["records"].append(stub.observe_record(event, records, 0))
    ledger["counts"] = {"api_calls": len(ledger["invocations"]), "journal_records": len(ledger["records"])}
    assert len(ledger["invocations"]) + len(ledger["records"]) == total
    path = Path(tmp) / "ledger-full.json"
    path.write_text(json.dumps(ledger, sort_keys=True))
    return path


FAKE_PROVIDER = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
parser.add_argument("--fake-profile", default=None)
parser.add_argument("--fake-stamps", default=None)
parser.add_argument("--fake-sleep", type=float, default=0.0)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "fake-provider", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
if args.fake_sleep:
    time.sleep(args.fake_sleep)
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed.pop("trace", None)
if args.fake_profile:
    rate, duration = (int(part) for part in args.fake_profile.split(","))
    observed["profile"] = {"rate": rate, "duration": duration}
if args.fake_stamps:
    start, step = (int(part) for part in args.fake_stamps.split(","))
    stamp = start
    for call in observed["invocations"]:
        call["observed_at"] = stamp
        stamp += step
    for record in observed["records"]:
        record["observed_at"] = stamp
        stamp += step
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

EMPTY_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "empty-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
"""

BURST_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "burst-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
time.sleep(0.2)
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed["profile"] = {"rate": int(args.rate), "duration": int(args.duration)}
observed.pop("trace", None)
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

PACED_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "paced-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
rate = int(args.rate)
first = True
for call in ledger["invocations"]:
    if not first:
        time.sleep(1.0 / rate)
    first = False
    print(json.dumps({"progress": "call", "seq": call["seq"]}), flush=True)
    assert sys.stdin.readline().strip() == "ACK"
for record in ledger["records"]:
    time.sleep(1.0 / rate)
    print(json.dumps({"progress": "record", "ordinal": record["ordinal"]}), flush=True)
    assert sys.stdin.readline().strip() == "ACK"
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed["profile"] = {"rate": 1, "duration": 60}
observed.pop("trace", None)
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

PARTIAL_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "partial-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
for call in ledger["invocations"][:3]:
    print(json.dumps({"progress": "call", "seq": call["seq"]}), flush=True)
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed.pop("trace", None)
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

GARBAGE_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "garbage-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
print("NOT-A-PROGRESS-LINE", flush=True)
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed.pop("trace", None)
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

TWOBURST_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "twoburst-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
lines = (
    [{"progress": "call", "seq": call["seq"]} for call in ledger["invocations"][:3]]
    + [{"progress": "record", "ordinal": record["ordinal"]}
       for record in ledger["records"][:4]]
    + [{"progress": "call", "seq": call["seq"]} for call in ledger["invocations"][3:]]
    + [{"progress": "record", "ordinal": record["ordinal"]}
       for record in ledger["records"][4:]]
)
for line in lines[:7]:
    print(json.dumps(line), flush=True)
time.sleep(1.0)
for line in lines[7:]:
    print(json.dumps(line), flush=True)
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed["run_token"] = args.run_token
observed.pop("trace", None)
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""

FLOOD_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "flood-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
for seq in range(1, 60001):
    print(json.dumps({"progress": "call", "seq": seq}), flush=True)
time.sleep(30)
"""

NO_TOKEN_CHILD = """#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
parser = argparse.ArgumentParser()
parser.add_argument("--ledger", required=True)
parser.add_argument("--out", required=True)
parser.add_argument("--rate", default=None)
parser.add_argument("--duration", default=None)
parser.add_argument("--run-token", default=None)
args = parser.parse_args()
raw = open(args.ledger, "rb").read()
ledger = json.loads(raw.decode("utf-8"))
print(json.dumps({"schema": "p11scope/object-journal-ready/v1",
                  "provider": "no-token-child", "pid": os.getpid(),
                  "abi": ledger["provider"]["abi"],
                  "ledger_digest": hashlib.sha256(raw).hexdigest()}), flush=True)
assert sys.stdin.readline().strip() == "GO"
observed = json.loads(json.dumps(ledger))
observed["key_material"] = None
observed["ledger_digest"] = hashlib.sha256(raw).hexdigest()
observed.pop("trace", None)
rate = int(args.rate)
observed["profile"] = {"rate": rate, "duration": int(args.duration)}
stamp = 1_000_000_000
step = 1_000_000_000 // rate
for call in observed["invocations"]:
    call["observed_at"] = stamp
    stamp += step
for record in observed["records"]:
    record["observed_at"] = stamp
    stamp += step
open(args.out, "w").write(json.dumps(observed, sort_keys=True))
"""


def canonical(observed):
    """Observed output with run-volatile fields stripped: two replays of
    the same trace compare equal iff the stub computed the same
    semantics."""

    def strip(value):
        if isinstance(value, dict):
            return {
                key: strip(item)
                for key, item in value.items()
                if key not in ("observed_at", "sampled_at", "run_id", "ledger_digest")
            }
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return strip(observed)


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

    def test_flood_without_ack_reads_hits_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "flood-child.py"
            child.write_text(FLOOD_CHILD)
            out = str(Path(temp) / "observed.json")
            start = time.monotonic()
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "60",
                "--deadline-seconds",
                "1",
            )
            elapsed = time.monotonic() - start
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
            self.assertIn("provider deadline", proc.stderr)
            self.assertLess(
                elapsed, 15, "the controller enforced its deadline with no outer kill"
            )


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
            self.assertIn("not a qualified profile", proc.stdout)
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
            self.assertIn("STREAM_POPULATION_MISMATCH", proc.stdout)

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

    def test_short_replay_fails_qualified_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            provider_args, _ = self.stub_args(temp)
            proc, _ = run_profiled(
                temp,
                STUB,
                provider_args,
                "--rate",
                "100",
                "--duration",
                "60",
                "--qualify-profile",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PROFILE_POPULATION_MISMATCH", proc.stdout)
            self.assertIn("PROFILE_WINDOW_SHORT", proc.stdout)
            self.assertNotIn("profile complete", proc.stdout)

    def test_paced_full_window_passes_qualified_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = write_full_window_ledger(temp, 10, 3)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                STUB,
                ["--ledger", str(ledger), "--out", out],
                "--rate",
                "10",
                "--duration",
                "3",
                "--qualify-profile",
                ledger=ledger,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("profile complete", proc.stdout)


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


class TraceReplayTests(unittest.TestCase):
    """Carryover 8: the stub replays the trace/request stream into
    observations it computes itself; it never copies the ledger's
    expected semantic fields."""

    def replay(self, tmp, ledger_dict):
        ledger_path = Path(tmp) / "ledger.json"
        ledger_path.write_text(json.dumps(ledger_dict, sort_keys=True))
        out = str(Path(tmp) / "observed.json")
        proc = run_stub(ledger_path, out)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(Path(out).read_bytes())

    def test_trace_mutations_are_detectable_in_observations(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            base = self.replay(temp, frozen)
            # (a) Flip a return's rv in the trace: the derived terminal flips.
            mutated = json.loads(json.dumps(frozen))
            for event in mutated["trace"]:
                if event["op"] == "return" and event["seq"] == 1:
                    event["rv"] = "GENERAL_ERROR"
            observed = self.replay(temp, mutated)
            base_terminals = [call["terminal"] for call in base["invocations"]]
            mutated_terminals = [call["terminal"] for call in observed["invocations"]]
            self.assertEqual(base_terminals[0], "success")
            self.assertEqual(mutated_terminals[0], "error")
            # (b) Drop a record event: the journal observation shrinks with
            # recomputed ordinals.
            mutated = json.loads(json.dumps(frozen))
            for index, event in enumerate(mutated["trace"]):
                if event["op"] == "record" and event["kind"] == "BEGIN":
                    del mutated["trace"][index]
                    break
            observed = self.replay(temp, mutated)
            self.assertEqual(len(observed["records"]), len(base["records"]) - 1)
            self.assertEqual(
                [record["ordinal"] for record in observed["records"]],
                list(range(1, len(base["records"]))),
            )
            # (c) Equalize the probe's bracketed epochs: the derived
            # witness stops proving absence.
            mutated = json.loads(json.dumps(frozen))
            mutated["trace"][0]["epoch"] = [42, 42]
            observed = self.replay(temp, mutated)
            self.assertEqual(base["bootstrap"]["witness"], "absence-appearance")
            self.assertNotEqual(observed["bootstrap"]["witness"], "absence-appearance")
            # End to end: trace-mutated output fails against the frozen ledger.
            import hashlib

            observed["ledger_digest"] = hashlib.sha256(LEDGER.read_bytes()).hexdigest()
            path = str(Path(temp) / "mutated.json")
            Path(path).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", path, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("BOOTSTRAP_MISMATCH", proc.stdout)

    def test_stub_ignores_expected_answer_fields(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            base = self.replay(temp, frozen)
            # Mutate ONLY the expected answer fields; the trace is untouched.
            mutated = json.loads(json.dumps(frozen))
            mutated["invocations"][0]["terminal"] = "error"
            mutated["records"][0]["seq"] = 7
            mutated["bootstrap"]["cut"] = 999
            observed = self.replay(temp, mutated)
            self.assertEqual(
                canonical(observed),
                canonical(base),
                "trace-identical replays agree semantically",
            )
            # ... so the replayed output fails against the mutated ledger:
            # the stub did not follow the expected fields.
            ledger_path = Path(temp) / "ledger-mut.json"
            ledger_path.write_text(json.dumps(mutated, sort_keys=True))
            out = str(Path(temp) / "replayed.json")
            Path(out).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", out, "--ledger", str(ledger_path))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("INVOCATION_MISMATCH", proc.stdout)


class TraceIdentityTests(unittest.TestCase):
    """N12: duplicate trace identities and invalid pairing/order refuse
    loudly rather than collapsing; the oracle fails such traces."""

    def ledger_with_trace(self, tmp, trace):
        ledger = json.loads(LEDGER.read_bytes())
        ledger["trace"] = trace
        path = Path(tmp) / "ledger.json"
        path.write_text(json.dumps(ledger, sort_keys=True))
        return path

    def test_duplicate_call_seq_refused(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            trace = list(frozen["trace"])
            dup = next(event for event in trace if event["op"] == "call")
            trace.append(dict(dup))
            ledger_path = self.ledger_with_trace(temp, trace)
            out = str(Path(temp) / "observed.json")
            proc = run_stub(ledger_path, out)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("duplicate", proc.stderr)

    def test_duplicate_return_seq_refused(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            trace = list(frozen["trace"])
            dup = next(event for event in trace if event["op"] == "return")
            trace.append(dict(dup))
            ledger_path = self.ledger_with_trace(temp, trace)
            out = str(Path(temp) / "observed.json")
            proc = run_stub(ledger_path, out)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("duplicate", proc.stderr)

    def test_misordered_pair_refused(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            trace = list(frozen["trace"])
            call_index = next(
                index for index, event in enumerate(trace) if event["op"] == "call"
            )
            ret_index = next(
                index for index, event in enumerate(trace) if event["op"] == "return"
            )
            trace[call_index], trace[ret_index] = trace[ret_index], trace[call_index]
            ledger_path = self.ledger_with_trace(temp, trace)
            out = str(Path(temp) / "observed.json")
            proc = run_stub(ledger_path, out)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("misordered", proc.stderr)

    def test_unpaired_return_refused(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            trace = list(frozen["trace"])
            trace.append({"op": "return", "seq": 99, "rv": "OK", "effects": []})
            ledger_path = self.ledger_with_trace(temp, trace)
            out = str(Path(temp) / "observed.json")
            proc = run_stub(ledger_path, out)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("unpaired", proc.stderr)

    def test_duplicate_trace_fails_run(self):
        frozen = json.loads(LEDGER.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            trace = list(frozen["trace"])
            dup = next(event for event in trace if event["op"] == "call")
            trace.append(dict(dup))
            ledger_path = self.ledger_with_trace(temp, trace)
            out = str(Path(temp) / "observed.json")
            proc = run_oracle(
                "--run",
                "--provider",
                str(STUB),
                "--provider-arg=--ledger",
                "--provider-arg",
                str(ledger_path),
                "--provider-arg=--out",
                "--provider-arg",
                out,
                "--ledger",
                str(ledger_path),
                "--out",
                out,
                "--rate",
                "100",
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("PASS", proc.stdout)

    def test_duplicate_invocation_seq_fails_check(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            stub = run_stub(LEDGER, out)
            self.assertEqual(stub.returncode, 0, stub.stderr)
            observed = json.loads(Path(out).read_bytes())
            observed["invocations"][2]["seq"] = observed["invocations"][1]["seq"]
            Path(out).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", out, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("DUPLICATE_INVOCATION", proc.stdout)

    def test_duplicate_record_ordinal_fails_check(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            stub = run_stub(LEDGER, out)
            self.assertEqual(stub.returncode, 0, stub.stderr)
            observed = json.loads(Path(out).read_bytes())
            observed["records"][3]["ordinal"] = observed["records"][1]["ordinal"]
            Path(out).write_text(json.dumps(observed))
            proc = run_oracle("--check", "--observed", out, "--ledger", str(LEDGER))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("DUPLICATE_RECORD", proc.stdout)


class FreshnessTests(unittest.TestCase):
    """Carryover 14: output freshness binds to the current run via a nonce
    the child must echo, and pace is controller-measured, never trusted
    from child timestamps."""

    def test_empty_child_on_stale_output_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            out = str(Path(temp) / "observed.json")
            # A known-passing stale file sits at the output path: a full
            # paced run's output, left behind by an earlier invocation.
            stale_run, _ = run_profiled(
                temp, STUB, ["--ledger", str(LEDGER), "--out", out], "--rate", "100"
            )
            self.assertEqual(stale_run.returncode, 0, stale_run.stdout + stale_run.stderr)
            stale = run_oracle("--check", "--observed", out, "--ledger", str(LEDGER))
            self.assertEqual(stale.returncode, 0, stale.stdout + stale.stderr)
            # An empty READY/GO child that writes nothing must FAIL, never
            # inherit the stale PASS.
            empty = Path(temp) / "empty-child.py"
            empty.write_text(EMPTY_CHILD)
            proc = run_oracle(
                "--run",
                "--provider",
                sys.executable,
                "--provider-arg",
                str(empty),
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
                "--rate",
                "100",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("STALE_OUTPUT", proc.stdout)

    def test_synthetic_timestamps_fail_run(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "fake-provider.py"
            fake.write_text(FAKE_PROVIDER)
            out = str(Path(temp) / "observed.json")
            # Fresh output echoing this run's token, written after 0.2 s
            # with stamps spanning 14 s: the old timestamp arithmetic
            # passed this; controller measurement must fail it.
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [
                    str(fake),
                    "--ledger",
                    str(LEDGER),
                    "--out",
                    out,
                    "--fake-profile",
                    "1,60",
                    "--fake-stamps",
                    "1000000000,1000000000",
                    "--fake-sleep",
                    "0.2",
                ],
                "--rate",
                "1",
                "--duration",
                "60",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("STREAM_POPULATION_MISMATCH", proc.stdout)

    def test_missing_token_echo_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "no-token-child.py"
            child.write_text(NO_TOKEN_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "5",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("RUN_TOKEN_MISMATCH", proc.stdout)

    def test_run_ignores_child_profile_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            # An honestly paced provider passes even while its echoed
            # profile claim lies: controller measurement, not the child's
            # word, decides. (The old sleep-then-dump premise encoded the
            # idle-substitute defect; honest pacing now streams progress.)
            paced = Path(temp) / "paced-child.py"
            paced.write_text(PACED_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(paced), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "10",
                "--duration",
                "60",
                "--deadline-seconds",
                "10",
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("PASS", proc.stdout)


class PaceStreamingTests(unittest.TestCase):
    """Carryover 6: pacing comes from controller-observed delivery timing
    (inter-arrival times of streamed progress at the controller) plus the
    required population/duration — total child lifetime never substitutes
    for paced delivery."""

    def test_burst_after_sleep_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "burst-child.py"
            child.write_text(BURST_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "60",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("STREAM_POPULATION_MISMATCH", proc.stdout)
            self.assertNotIn("PASS", proc.stdout)

    def test_partial_progress_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "partial-child.py"
            child.write_text(PARTIAL_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "60",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("STREAM_POPULATION_MISMATCH", proc.stdout)

    def test_malformed_progress_fails_run(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "garbage-child.py"
            child.write_text(GARBAGE_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "60",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("STREAM_MALFORMED", proc.stdout)

    def test_two_bursts_fail_run(self):
        with tempfile.TemporaryDirectory() as temp:
            child = Path(temp) / "twoburst-child.py"
            child.write_text(TWOBURST_CHILD)
            out = str(Path(temp) / "observed.json")
            proc, _ = run_profiled(
                temp,
                sys.executable,
                [str(child), "--ledger", str(LEDGER), "--out", out],
                "--rate",
                "100",
                "--duration",
                "60",
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("PACING_TOO_FAST", proc.stdout)

if __name__ == "__main__":
    unittest.main()
