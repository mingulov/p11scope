#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native-owner proof twins.

The oracle (scripts/joint-owner-proof-compare.py) compares per-owner
proof evidence in the pressure-live driver protocol (TARGET/READY/LEDGER
lines from tests/fixtures/pressure-live/driver.c) against snapshot rows:
exactly the expected owners, each with a complete burst and a completed
call; old and new providers both retained; the newcomer inside its
declared bound; pid->caller->instance->module joins on kernel (device,
inode) identity with a digest; key rows that never over-claim their
ledger; no ambient positives; the association bound.

Healthy and mutation twins run unignored; the live tests build the
tracked pressure-live driver and version-matrix provider with gcc, run a
small retain/late wave, and compare the real child outputs.
"""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "scripts" / "joint-owner-proof-compare.py"
DRIVER_SRC = ROOT / "tests" / "fixtures" / "pressure-live" / "driver.c"
MATRIX_SRC = ROOT / "crates" / "discover" / "tests" / "fixture" / "version_matrix.c"

SCHEMA = "p11scope/pressure-live-ledger/v1"
SHA_EARLY = "11" * 32
SHA_LATE = "22" * 32

try:
    _SPEC = importlib.util.spec_from_file_location(
        "joint_owner_proof_compare", ORACLE_PATH
    )
    ORACLE = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(ORACLE)
except OSError:
    ORACLE = None


def require_oracle(test):
    """Fail naming the missing production file (RED) or return the oracle."""
    if ORACLE is None:
        test.fail(f"oracle missing: {ORACLE_PATH} (implementation not present)")
    return ORACLE


def owner_text(pid, mode="retain", dev=(8, 1), ino=101, attempts=25,
               successful=25, complete=True, bursts=1, schema=SCHEMA,
               surfaces=("C_GetFunctionList",)):
    """One owner child stdout: TARGET lines, READY, LEDGER rows."""
    lines = []
    for surface in surfaces:
        lines.append("TARGET " + json.dumps(
            {"name": surface, "dev": list(dev), "ino": ino,
             "file_offset": 4096}))
    lines.append(f"READY pid={pid}")
    for burst in range(1, bursts + 1):
        lines.append("LEDGER " + json.dumps(
            {"schema": schema, "pid": pid, "mode": mode, "burst": burst,
             "complete": complete,
             "functions": [{"name": name, "attempts": attempts,
                            "successful": successful}
                           for name in surfaces]}))
    return "\n".join(lines) + "\n"


def write_owners(directory, specs):
    """Write owner files; specs map file name to owner stdout text."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    for name, text in specs.items():
        (path / name).write_text(text, encoding="utf-8")
    return str(path)


def population_snapshot(entries, extra_instances=(), extra_modules=(),
                        budgets=None, gaps=()):
    """Build a snapshot for entries of (pid, dev, ino, sha, attempts,
    successful); one caller, instance, module share and key row each."""
    callers = []
    instances = []
    key_rows = []
    modules = {}
    for index, (pid, dev, ino, sha, attempts, successful) in enumerate(entries):
        callers.append({"id": f"c{index}", "pid": pid})
        digest = (tuple(dev), ino, sha)
        if digest not in modules:
            modules[digest] = f"m{len(modules)}"
        mid = modules[digest]
        instances.append({"id": f"i{index}", "caller": f"c{index}",
                          "module": mid, "state": "observed", "reason": None,
                          "first_seen_ns": 1_000 + index,
                          "last_seen_ns": 2_000 + index})
        key_rows.append({"instance": f"i{index}", "started": attempts,
                         "completed": successful,
                         "failed": attempts - successful, "unknown": 0})
    module_rows = [{"id": mid,
                    "key": {"device": list(dev), "inode": ino, "sha256": sha},
                    "lifecycle": "mapped"}
                   for (dev, ino, sha), mid in modules.items()]
    snapshot = {"callers": callers, "instances": instances + list(extra_instances),
                "modules": module_rows + list(extra_modules),
                "key_rows": key_rows, "gaps": list(gaps)}
    if budgets is not None:
        snapshot["budgets"] = budgets
    return snapshot


def wave_specs(count=3, late_pid=None, ino_early=101, ino_late=102):
    """Small wave specs: retain owners on the early file, one late owner."""
    specs = {}
    pids = list(range(5000, 5000 + count))
    late = late_pid if late_pid is not None else pids[-1]
    for pid in pids:
        if pid == late:
            specs[f"owner-{pid}"] = owner_text(pid, mode="late", ino=ino_late)
        else:
            specs[f"owner-{pid}"] = owner_text(pid, ino=ino_early)
    return specs, pids, late


def wave_entries(pids, late, dev=(8, 1), ino_early=101, ino_late=102,
                 attempts=25, successful=25):
    entries = []
    for pid in pids:
        if pid == late:
            entries.append((pid, dev, ino_late, SHA_LATE, attempts,
                            successful))
        else:
            entries.append((pid, dev, ino_early, SHA_EARLY, attempts,
                            successful))
    return entries


def compare_wave(oracle, tmp, count=3, expect=3, newcomer=None):
    specs, pids, late = wave_specs(count=count)
    directory = write_owners(Path(tmp) / "owners", specs)
    if newcomer is not None:
        with open(os.path.join(directory, "newcomer.json"), "w",
                  encoding="utf-8") as stream:
            json.dump(newcomer, stream)
    snapshot = population_snapshot(wave_entries(pids, late))
    return oracle.compare(oracle.read_owners(directory), snapshot,
                          expect=expect)


class OwnerFileTwins(unittest.TestCase):
    def test_healthy_owner_parses(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242), encoding="utf-8")
            owner = oracle.read_owner(str(path))
        self.assertEqual(owner["pid"], 4242)
        self.assertEqual(owner["mode"], "retain")
        self.assertEqual(owner["successful"], 25)
        self.assertEqual(owner["target"], ((8, 1), 101))

    def test_mutation_missing_target_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = [line for line in owner_text(4242).splitlines()
                     if not line.startswith("TARGET ")]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a physical target"):
                oracle.read_owner(str(path))

    def test_mutation_disagreeing_targets_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            text = owner_text(4242, surfaces=("C_GetFunctionList",
                                              "C_GetInterfaceList"))
            lines = text.splitlines()
            second = json.loads(lines[1].split(" ", 1)[1])
            second["ino"] += 1
            lines[1] = "TARGET " + json.dumps(second)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "targets disagree"):
                oracle.read_owner(str(path))

    def test_mutation_missing_ready_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = [line for line in owner_text(4242).splitlines()
                     if not line.startswith("READY ")]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without READY"):
                oracle.read_owner(str(path))

    def test_mutation_disagreeing_ready_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            text = owner_text(4242) + "READY pid=4243\n"
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "READY pids disagree"):
                oracle.read_owner(str(path))

    def test_mutation_ledger_ready_pid_mismatch_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["pid"] = 4243
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError, "join refused"):
                oracle.read_owner(str(path))

    def test_mutation_incomplete_burst_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242, complete=False), encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a complete burst"):
                oracle.read_owner(str(path))

    def test_mutation_mixed_modes_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            text = owner_text(4242, bursts=2)
            lines = text.splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["mode"] = "late"
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError, "mixed owner modes"):
                oracle.read_owner(str(path))

    def test_mutation_no_completed_call_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242, successful=0), encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a completed call"):
                oracle.read_owner(str(path))

    def test_mutation_bad_schema_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242, schema="p11scope/other/v1"),
                            encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "ledger schema string mismatch"):
                oracle.read_owner(str(path))

    def test_mutation_unknown_surface_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["functions"][0]["name"] = "C_Invented"
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "function name invalid"):
                oracle.read_owner(str(path))

    def test_mutation_successful_exceeds_attempts_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["functions"][0]["successful"] = 26
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "successful out of range"):
                oracle.read_owner(str(path))

    def test_mutation_unexpected_line_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242) + "SUMMARY {}\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError, "unexpected owner"):
                oracle.read_owner(str(path))

    def test_mutation_duplicate_json_key_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text('READY pid=1\nREADY pid=1\n'
                            'LEDGER {"schema": "x", "schema": "y"}\n',
                            encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "duplicate JSON key"):
                oracle.read_owner(str(path))

    def test_mutation_line_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text("READY pid=1\n" + "x" * 4097 + "\n",
                            encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
                oracle.read_owner(str(path))

    def test_mutation_owner_file_byte_limit_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text("READY pid=1\n" + "\n" * 65536, encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError, "byte limit"):
                oracle.read_owner(str(path))

    def test_mutation_symlink_refused(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "owners" / "owner-1"
            real.parent.mkdir()
            real.write_text(owner_text(4242), encoding="utf-8")
            os.symlink(real, Path(tmp) / "owners" / "owner-2")
            with self.assertRaisesRegex(oracle.LedgerError, "regular file"):
                oracle.read_owners(str(real.parent))

    def test_mutation_subdirectory_refused(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            owners = Path(tmp) / "owners"
            owners.mkdir()
            (owners / "nested").mkdir()
            with self.assertRaisesRegex(oracle.LedgerError, "regular file"):
                oracle.read_owners(str(owners))

    def test_mutation_bad_mode_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["mode"] = "early"
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "ledger mode invalid"):
                oracle.read_owner(str(path))

    def test_mutation_burst_zero_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["burst"] = 0
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "ledger burst out of range"):
                oracle.read_owner(str(path))

    def test_mutation_complete_not_bool_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[-1].split(" ", 1)[1])
            row["complete"] = "yes"
            lines[-1] = "LEDGER " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "ledger complete invalid"):
                oracle.read_owner(str(path))

    def test_mutation_missing_ledger_row_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = [line for line in owner_text(4242).splitlines()
                     if not line.startswith("LEDGER ")]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a ledger row"):
                oracle.read_owner(str(path))

    def test_mutation_target_not_object_refused(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text("TARGET 5\nREADY pid=4242\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "target row must be an object"):
                oracle.read_owner(str(path))

    def test_mutation_ledger_not_object_refused(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            path.write_text(owner_text(4242).splitlines()[0] + "\n"
                            "READY pid=4242\nLEDGER []\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "ledger row must be an object"):
                oracle.read_owner(str(path))

    def test_mutation_bad_ready_line_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = [line if not line.startswith("READY ") else "READY 4242"
                     for line in owner_text(4242).splitlines()]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "READY line invalid"):
                oracle.read_owner(str(path))

    def test_mutation_ready_pid_zero_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = [line if not line.startswith("READY ") else "READY pid=0"
                     for line in owner_text(4242).splitlines()]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "READY pid out of range"):
                oracle.read_owner(str(path))

    def test_mutation_target_inode_zero_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-1"
            lines = owner_text(4242).splitlines()
            row = json.loads(lines[0].split(" ", 1)[1])
            row["ino"] = 0
            lines[0] = "TARGET " + json.dumps(row)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "target inode invalid"):
                oracle.read_owner(str(path))


class PopulationTwins(unittest.TestCase):
    def test_healthy_small_wave_passes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            result = compare_wave(oracle, tmp, count=3, expect=3)
        self.assertEqual(result["owners"], 3)
        self.assertEqual(result["modes"], ["late", "retain"])
        self.assertEqual(result["modules"], 2)
        self.assertFalse(result["newcomer"])
        self.assertEqual(result["associations"], 3)

    def test_healthy_257_wave_passes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs = {}
            pids = list(range(10000, 10257))
            for pid in pids[:-1]:
                specs[f"owner-{pid}"] = owner_text(pid, ino=101)
            specs[f"owner-{pids[-1]}"] = owner_text(pids[-1], mode="late",
                                                   ino=102)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(
                wave_entries(pids, pids[-1]))
            result = oracle.compare(oracle.read_owners(directory), snapshot)
        self.assertEqual(result["owners"], 257)
        self.assertEqual(result["associations"], 257)

    def test_healthy_newcomer_within_bound_passes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            result = compare_wave(
                oracle, tmp, count=3, expect=3,
                newcomer={"admit_ns": 1_000, "first_settled_ns": 2_000,
                          "bound_ns": 1_000})
        self.assertTrue(result["newcomer"])

    def test_healthy_ambient_without_positive_passes(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["callers"].append({"id": "c9", "pid": 9999})
            snapshot["instances"].append(
                {"id": "i9", "caller": "c9", "module": "m0",
                 "state": "observed", "reason": None, "first_seen_ns": 1_000,
                 "last_seen_ns": 2_000})
            result = oracle.compare(oracle.read_owners(directory), snapshot,
                                    expect=3)
        self.assertEqual(result["owners"], 3)

    def test_mutation_short_wave_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            specs.pop(f"owner-{pids[0]}")
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "expected 3 owners, found 2"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_default_count_is_257(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "expected 257 owners, found 3"):
                oracle.compare(oracle.read_owners(directory), snapshot)

    def test_mutation_repeated_pid_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            specs["owner-dup"] = owner_text(pids[0], ino=101)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            with self.assertRaisesRegex(oracle.LedgerError,
                                        f"repeated owner pid {pids[0]}"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=4)

    def test_mutation_all_retain_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs = {f"owner-{pid}": owner_text(pid, ino=101 + (pid % 2))
                     for pid in (5000, 5001, 5002)}
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(
                [(pid, (8, 1), 101 + (pid % 2),
                  SHA_EARLY if pid % 2 == 0 else SHA_LATE, 25, 25)
                 for pid in (5000, 5001, 5002)])
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a late owner"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_single_provider_span_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3, ino_late=101)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(
                wave_entries(pids, late, ino_late=101))
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "not both retained"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_newcomer_over_bound_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = Path(write_owners(Path(tmp) / "owners", specs))
            (directory / "newcomer.json").write_text(json.dumps(
                {"admit_ns": 1_000, "first_settled_ns": 2_001,
                 "bound_ns": 1_000}), encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "past its bound 1000"):
                oracle.read_owners(str(directory))

    def test_mutation_newcomer_causality_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = Path(write_owners(Path(tmp) / "owners", specs))
            (directory / "newcomer.json").write_text(json.dumps(
                {"admit_ns": 2_000, "first_settled_ns": 1_000,
                 "bound_ns": 1_000}), encoding="utf-8")
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "admission follows"):
                oracle.read_owners(str(directory))

    def test_mutation_owner_without_caller_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["callers"].pop(0)
            snapshot["instances"].pop(0)
            snapshot["key_rows"].pop(0)
            with self.assertRaisesRegex(oracle.LedgerError,
                                        f"owner pid {pids[0]} without a caller"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_owner_not_retained_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["instances"][2]["state"] = "retired"
            snapshot["instances"][2]["reason"] = "instance_retired"
            with self.assertRaisesRegex(oracle.LedgerError, "not retained"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_target_module_mismatch_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["modules"][0]["key"]["inode"] = 999
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "target disagrees"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_path_keyed_module_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["modules"][0] = {"id": "m0", "key": "/lib/x.so",
                                  "lifecycle": "mapped"}
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "module without identity key"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_missing_sha_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        del snapshot["modules"][1]["key"]["sha256"]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "module key without sha256"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_key_row_overclaims_completed_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"][0]["started"] = 30
            snapshot["key_rows"][0]["completed"] = 30
            with self.assertRaisesRegex(oracle.LedgerError, "over-claims"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_key_row_completes_without_starting_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"][0]["started"] = 1
            snapshot["key_rows"][0]["completed"] = 2
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without starting"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_missing_key_row_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"].pop(0)
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a key row"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_ambient_positive_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["callers"].append({"id": "c9", "pid": 9999})
            snapshot["instances"].append(
                {"id": "i9", "caller": "c9", "module": "m0",
                 "state": "observed", "reason": None, "first_seen_ns": 1_000,
                 "last_seen_ns": 2_000})
            snapshot["key_rows"].append(
                {"instance": "i9", "started": 1, "completed": 1,
                 "failed": 0, "unknown": 0})
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "claims a positive"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_orphan_module_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["modules"].append(
                {"id": "m9", "key": {"device": [8, 1], "inode": 999,
                                     "sha256": "cc" * 32},
                 "lifecycle": "mapped"})
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without an instance"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_duplicate_module_key_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["modules"][1]["key"] = dict(snapshot["modules"][0]["key"])
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "duplicate module key"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_duplicate_caller_pid_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["callers"][1]["pid"] = snapshot["callers"][0]["pid"]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "duplicate caller pid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_non_object_snapshot_row_refused(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["instances"][0] = ["i0"]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "must be an object"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_all_late_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs = {f"owner-{pid}": owner_text(pid, mode="late",
                                                ino=101 + (pid % 2))
                     for pid in (5000, 5001, 5002)}
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(
                [(pid, (8, 1), 101 + (pid % 2),
                  SHA_EARLY if pid % 2 == 0 else SHA_LATE, 25, 25)
                 for pid in (5000, 5001, 5002)])
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without a retain owner"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_key_row_fails_without_starting_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"][0]["started"] = 0
            snapshot["key_rows"][0]["completed"] = 0
            snapshot["key_rows"][0]["failed"] = 1
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "fails without starting"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_key_row_overclaims_started_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"][0]["started"] = 30
            snapshot["key_rows"][0]["completed"] = 25
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "over-claims started"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_key_row_overclaims_failed_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"][0]["failed"] = 1
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "over-claims failed"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_instance_missing_module_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["instances"][0]["module"] = "m9"
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "missing module"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_instance_missing_caller_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["instances"][0]["caller"] = "c9"
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "missing caller"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_key_row_missing_instance_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["key_rows"].append(
                {"instance": "i9", "started": 0, "completed": 0,
                 "failed": 0, "unknown": 0})
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "missing instance"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_owner_caller_with_two_instances_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["instances"].append(
                {"id": "i9", "caller": "c0", "module": "m1",
                 "state": "observed", "reason": None, "first_seen_ns": 1_000,
                 "last_seen_ns": 2_000})
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "without exactly one instance"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_association_bound_rejected(self):
        oracle = require_oracle(self)
        instances = [{"id": f"i{n}", "caller": "c0", "module": f"m{n}",
                      "state": "observed", "reason": None,
                      "first_seen_ns": 1_000 + n, "last_seen_ns": 2_000 + n}
                     for n in range(4097)]
        snapshot = {"callers": [{"id": "c0", "pid": 4242}],
                    "instances": instances,
                    "modules": [{"id": f"m{n}",
                                 "key": {"device": [8, 1], "inode": 1000 + n,
                                         "sha256": f"{n:064x}"},
                                 "lifecycle": "mapped"}
                                for n in range(4097)],
                    "key_rows": [], "gaps": []}
        with self.assertRaisesRegex(oracle.LedgerError, "association bound"):
            oracle.check_associations(snapshot)

    def test_mutation_budget_occupied_mismatch_rejected(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snapshot["budgets"] = {"instances": {"limit": 4096, "occupied": 5,
                                                 "refused": 0}}
            with self.assertRaisesRegex(oracle.LedgerError,
                                        "budget occupied 5 disagrees"):
                oracle.compare(oracle.read_owners(directory), snapshot,
                               expect=3)

    def test_mutation_instance_state_invalid_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["instances"][0]["state"] = "pending"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "instance state invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_duplicate_instance_id_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["instances"][1]["id"] = "i0"
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "duplicate instance id"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_key_count_negative_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["key_rows"][0]["unknown"] = -1
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "key row unknown out of range"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))

    def test_mutation_gap_subject_empty_rejected(self):
        oracle = require_oracle(self)
        _, pids, late = wave_specs(count=3)
        snapshot = population_snapshot(wave_entries(pids, late))
        snapshot["gaps"] = [{"subject": "", "reason": "x"}]
        with self.assertRaisesRegex(oracle.LedgerError,
                                    "gap subject invalid"):
            oracle.read_snapshot(io.StringIO(json.dumps(snapshot)))


class ComparisonCliTwins(unittest.TestCase):
    def write_pair(self, tmp, count=3, expect=3):
        specs, pids, late = wave_specs(count=count)
        directory = write_owners(Path(tmp) / "owners", specs)
        snapshot = population_snapshot(wave_entries(pids, late))
        snap = Path(tmp) / "snapshot.json"
        with open(snap, "w", encoding="utf-8") as stream:
            json.dump(snapshot, stream)
        return directory, str(snap), expect

    def test_cli_healthy_wave_passes(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            directory, snap, expect = self.write_pair(tmp)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), directory, snap,
                 "--owners", str(expect)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["owners"], 3)

    def test_cli_short_wave_refused(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            specs.pop(f"owner-{pids[0]}")
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snap = Path(tmp) / "snapshot.json"
            with open(snap, "w", encoding="utf-8") as stream:
                json.dump(snapshot, stream)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), directory, str(snap),
                 "--owners", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertRegex(completed.stderr,
                             r"comparison refused: expected 3 owners, found 2")

    def test_cli_string_payload_not_echoed(self):
        require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            specs, pids, late = wave_specs(count=3)
            specs[f"owner-{pids[0]}"] = owner_text(
                pids[0], schema="PIN=1234-secret")
            directory = write_owners(Path(tmp) / "owners", specs)
            snapshot = population_snapshot(wave_entries(pids, late))
            snap = Path(tmp) / "snapshot.json"
            with open(snap, "w", encoding="utf-8") as stream:
                json.dump(snapshot, stream)
            completed = subprocess.run(
                ["python3", "-I", str(ORACLE_PATH), directory, str(snap),
                 "--owners", "3"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 1)
            self.assertIn("comparison refused: ledger schema string mismatch",
                          completed.stderr)
            self.assertNotIn("PIN=1234-secret", completed.stderr)


class LiveWaveTests(unittest.TestCase):
    def build_wave(self, tmp):
        if not shutil.which("gcc"):
            self.skipTest("requires gcc; installs nothing")
        if not DRIVER_SRC.is_file():
            self.fail(f"fixture missing: {DRIVER_SRC} (implementation not present)")
        if not MATRIX_SRC.is_file():
            self.fail(f"fixture missing: {MATRIX_SRC} (implementation not present)")
        early = Path(tmp) / "early.so"
        late = Path(tmp) / "late.so"
        driver = Path(tmp) / "driver"
        build = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-DMATRIX_INTERFACES=1",
             "-o", str(early), str(MATRIX_SRC)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        shutil.copy(early, late)
        self.assertNotEqual(early.stat().st_ino, late.stat().st_ino)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(DRIVER_SRC), "-ldl", "-o", str(driver)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(build.returncode, 0, build.stderr)
        return early, late, driver

    def test_live_small_wave_compares(self):
        oracle = require_oracle(self)
        with tempfile.TemporaryDirectory() as tmp:
            early, late, driver = self.build_wave(tmp)
            owners = Path(tmp) / "owners"
            owners.mkdir()
            children = []
            for mode, provider in (("retain", early), ("retain", early),
                                   ("late", late)):
                child = subprocess.Popen(
                    [str(driver), str(provider), mode, "2", "-"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append((child, provider))
            outputs = []
            try:
                for child, provider in children:
                    stdout, stderr = child.communicate(timeout=60)
                    self.assertEqual(child.returncode, 0, stderr)
                    self.assertIn(f"READY pid={child.pid}", stdout)
                    outputs.append((child.pid, provider, stdout))
            finally:
                for child, _ in children:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)
            for pid, _, stdout in outputs:
                (owners / f"owner-{pid}").write_text(stdout, encoding="utf-8")
            population = oracle.read_owners(str(owners))
            self.assertEqual(len(population["owners"]), 3)
            for owner, (pid, provider, _) in zip(
                    sorted(population["owners"], key=lambda row: row["pid"]),
                    sorted(outputs, key=lambda row: row[0])):
                self.assertEqual(owner["pid"], pid)
                # Identity joins on the kernel-rendered (device, inode) from
                # /proc/self/maps; only the inode is comparable to stat (the
                # maps device domain differs on btrfs/overlay filesystems).
                self.assertEqual(owner["target"][1],
                                 provider.stat().st_ino)
                self.assertEqual(owner["successful"], 6)
            by_pid = {owner["pid"]: owner for owner in population["owners"]}
            entries = []
            for pid, _, _ in sorted(outputs, key=lambda row: row[0]):
                owner = by_pid[pid]
                dev, ino = owner["target"]
                entries.append((pid, dev, ino, SHA_EARLY if ino ==
                                early.stat().st_ino else SHA_LATE,
                                owner["attempts"], owner["successful"]))
            snapshot = population_snapshot(entries)
            result = oracle.compare(population, snapshot, expect=3)
            self.assertEqual(result["owners"], 3)
            self.assertEqual(result["modes"], ["late", "retain"])


if __name__ == "__main__":
    unittest.main()
