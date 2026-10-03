# SPDX-License-Identifier: GPL-3.0-or-later
"""Native lane-13 evidence ownership and cleanup tests."""

import argparse
import array
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import runpy


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/lane13-evidence"
RELEASE_FIXTURES = FIXTURES / "releases"
GATE = ROOT / "scripts/matrix/verify-knative.sh"
EvidenceFixture = runpy.run_path(
    str(ROOT / "tests/python/test_prepared_dependency_evidence.py")
)["EvidenceFixture"]
EBPF_OBJECT = None
RELEASES = (
    ("serving-crds.yaml", 411211,
     "b172ff4901ed50f8e4e09ff8616e54d22e264df7086ce8cb74f513a04812fe74"),
    ("serving-core.yaml", 521056,
     "be3f16c9c0ac9276cc173ef04871aaeac78537f9edb116310caa02f016e9cbc2"),
    ("kourier.yaml", 25361,
     "cded0c3c1d7669b1aa9f7484234b454ff3940a2b54a27d5ec4825c2d4003d01d"),
)
# Diagnostic inputs are sampled before decoding, and the rendered assertion is
# independently capped so escaping or multiple fields cannot exceed 8192 bytes.
READINESS_DIAGNOSTIC_TAIL_BYTES = 2048
READINESS_DIAGNOSTIC_FIELD_BYTES = 1024
READINESS_DIAGNOSTIC_MAX_BYTES = 8192
READINESS_DIAGNOSTIC_TRUNCATION = "; diagnostic_truncated=1"
# Wall-clock bounds here are of two kinds. SEMANTIC bounds are what a case
# asserts (a 0.05 s outer budget, a 200 ms readiness observation, a forced
# hold that must outlast a short timeout) and stay literal. SLACK bounds only
# wait for an event that must happen (a marker, an exit, an EOF); their expiry
# is a failure, so they scale with P11SCOPE_TEST_TIME_SCALE. A passing case
# never waits a SLACK bound out, so the default costs no time unloaded; it is
# sized so a full gate run at host load ~20 cannot exhaust it. Lifetimes that
# must outlast a whole case (decoys, controlled bodies, held port-forwards)
# scale with the same factor so their ordering against SLACK bounds holds.
DEFAULT_TIME_SCALE = 5.0


def _time_scale():
    raw = os.environ.get("P11SCOPE_TEST_TIME_SCALE", "").strip()
    if not raw:
        return DEFAULT_TIME_SCALE
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 1:
        raise SystemExit("P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1")
    return value


TIME_SCALE = _time_scale()


def slack(seconds):
    """Scale a wait-until bound whose expiry can only mean failure."""
    return seconds * TIME_SCALE


def scaled_whole_seconds(seconds):
    """Scale a process lifetime that must outlast SLACK waits; whole seconds."""
    return str(math.ceil(seconds * TIME_SCALE))


TERMINAL_READINESS_TIMEOUT_SECONDS = slack(20)
# Cleanup keeps the original 2s settle slices but retries them to this total
# bound: under host load a SIGKILLed child can miss one slice without being
# wedged. A child unsettled past the bound still fails the same way.
CLEANUP_SETTLE_SECONDS = slack(10)


class Lane13InputLedgerTests(unittest.TestCase):
    """Actual-CLI tests for the maintained lane-13 source snapshot helper."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope lane13 ledger ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project with spaces"
        self.project.mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        (self.project / "scripts").mkdir()
        for name in ("lane13-input-ledger.py", "merge-checksum-ledgers.py", "_loader.py"):
            source = ROOT / "scripts" / name
            if source.exists():
                shutil.copy2(source, self.project / "scripts" / name)
        self.git = self.bin / "git"
        self.git.symlink_to(FIXTURES / "candidate-git.py")
        self.paths = (
            ".cargo/config.toml",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "build_support/bpf_tools.rs",
            "src/main.rs",
            "crates/demo/Cargo.toml",
            "third-party/sources.json",
            "third-party/patches/demo/ordered patch.diff",
            "scripts/lane13-input-ledger.py",
            "scripts/merge-checksum-ledgers.py",
            "scripts/helper with spaces.sh",
        )
        for relative in self.paths:
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(f"fixture {relative}\n", encoding="utf-8")
        self.generated_relative = "third-party/src/generated crate/src/lib.rs"
        generated = self.project / self.generated_relative
        generated.parent.mkdir(parents=True)
        generated.write_text("generated fixture\n", encoding="utf-8")
        self.generated = self.base / "generated ledger.sha256"
        self.generated.write_text(
            f"{hashlib.sha256(generated.read_bytes()).hexdigest()}  {self.generated_relative}\n",
            encoding="utf-8",
        )
        self.output = self.base / "source snapshot.sha256"
        self.facts = self.base / "facts log"
        self.config = self.base / "git inventory.json"
        self.config.write_text(json.dumps({
            "root": str(self.project),
            "delegate": False,
            "tracked_paths": list(self.paths),
        }), encoding="utf-8")

    def run_helper(self, phase="start", generated=None, output=None, facts=None):
        return subprocess.run(
            [
                sys.executable, "-I", str(self.project / "scripts/lane13-input-ledger.py"),
                "snapshot", "--phase", phase,
                "--generated-ledger", str(generated or self.generated),
                "--output", str(output or self.output),
                "--facts", str(facts or self.facts),
            ],
            cwd=self.project,
            env=os.environ | {
                "PATH": f"{self.bin}:/usr/bin:/bin",
                "D2_CANDIDATE_INPUTS": str(self.config),
            },
            text=True,
            capture_output=True,
            timeout=slack(5),
        )

    def test_snapshot_hashes_fixed_tracked_inventory_and_merges_generated_rows(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.output.read_text(encoding="utf-8").splitlines()
        expected_paths = sorted((*self.paths, self.generated_relative), key=os.fsencode)
        self.assertEqual([row[66:] for row in rows], expected_paths)
        self.assertIn("scripts/helper with spaces.sh", [row[66:] for row in rows])
        self.assertIn("build_support/bpf_tools.rs", [row[66:] for row in rows])
        facts = self.facts.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            facts,
            [f"input_ledger_start={row[:64]} path={row[66:]}" for row in rows],
        )

    def test_snapshot_refuses_empty_missing_duplicate_and_existing_outputs(self):
        cases = {
            "empty": "",
            "missing": f"{'0' * 64}  third-party/src/missing.rs\n",
            "duplicate": self.generated.read_text(encoding="utf-8") * 2,
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                generated = self.base / f"{name}.sha256"
                generated.write_text(content, encoding="utf-8")
                output = self.base / f"{name}.out"
                facts = self.base / f"{name}.facts"
                result = self.run_helper(generated=generated, output=output, facts=facts)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertFalse(facts.exists())
        self.output.write_text("foreign\n", encoding="utf-8")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "foreign\n")

    def test_snapshot_refuses_missing_non_obsolete_tracked_input(self):
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["tracked_paths"].append("scripts/missing-maintained-input.sh")
        self.config.write_text(json.dumps(config), encoding="utf-8")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "tracked input scripts/missing-maintained-input.sh cannot be inspected",
            result.stderr,
        )
        self.assertFalse(self.output.exists())


class OwnedCommunicationTimeout(RuntimeError):
    def __init__(self, result):
        super().__init__(result.stderr)
        self.result = result


class ControlledBodySetupError(RuntimeError):
    pass


class Lane13EvidenceTests(unittest.TestCase):
    # Class-level caches: compiling port-forward.c and listing tracked files
    # once per class instead of once per method. Both latencies prove nothing
    # about lane 13; per-method runs multiplied load-flake exposure (a 5 s
    # bound racing cc fork+exec+compile under full-suite contention).
    _tracked_ls_files = None
    _port_forward_binary = None
    _class_temp = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._class_temp = tempfile.TemporaryDirectory(prefix="p11scope-lane13-class-")
        cls.addClassCleanup(cls._class_temp.cleanup)
        # Hang guard only: neither bound is part of the lane-13 contract.
        cls._tracked_ls_files = subprocess.run(
            ["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z", "--",
             ".cargo", "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml",
             "build_support", "src", "crates", "scripts", "spike", "third-party",
             ":(exclude)third-party/aya/**",
             ":(exclude)third-party/aya-obj/**"],
            check=True, stdout=subprocess.PIPE, timeout=120,
        ).stdout
        binary = Path(cls._class_temp.name) / "port-forward"
        subprocess.run(
            ["/usr/bin/cc", "-O0", "-o", str(binary),
             str(FIXTURES / "port-forward.c")],
            check=True,
            timeout=120,
        )
        cls._port_forward_binary = binary

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="p11scope-lane13-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.outside_temp = tempfile.TemporaryDirectory(prefix="p11scope-lane13-foreign-")
        self.outside = Path(self.outside_temp.name)
        self.processes = []
        self.budget_started = None
        self.evidence_roots = []
        self.owned_launches = {}
        self.accepted_sessions = set()
        self.settlement_errors = []
        self.settlement_diagnostics = []
        self.acknowledged_settlement_errors = 0
        self.before_pidfd_open = None
        self.retained_body_handles = {}
        self.controlled_bodies = {}
        self.cleaned = False
        self.state = self.root / "state"
        self.addCleanup(self.outside_temp.cleanup)
        self.addCleanup(self.cleanup_case)
        prepared_area = self.root / "prepared"
        prepared_area.mkdir()
        self.prepared = EvidenceFixture(prepared_area)
        self.project = self.prepared.root
        self.gate = self.project / "scripts/matrix/verify-knative.sh"
        tracked = type(self)._tracked_ls_files.split(b"\0")
        tracked_paths = []
        for raw in tracked:
            if not raw:
                continue
            relative_text = os.fsdecode(raw)
            relative = Path(relative_text)
            if relative_text not in tracked_paths:
                tracked_paths.append(relative_text)
            destination = self.project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(ROOT / relative, destination)
        for reached in (
            Path("scripts/recorded-process-exec.py"),
            Path("scripts/lane13-input-ledger.py"),
            # The release compiler is single-sourced from this root file,
            # which the ls-files pathspecs above do not cover.
            Path(".release-rust-version"),
        ):
            (self.project / reached).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / reached, self.project / reached)
            reached_text = str(reached)
            if reached_text not in tracked_paths:
                tracked_paths.append(reached_text)
        self.release_fixtures = self.project / "tests/fixtures/lane13-evidence/releases"
        shutil.copytree(RELEASE_FIXTURES, self.release_fixtures, dirs_exist_ok=True)
        self.corrupt_release_fixtures = self.root / "corrupt-releases"
        shutil.copytree(self.release_fixtures, self.corrupt_release_fixtures)
        for release_name, _, _ in RELEASES:
            corrupt = self.corrupt_release_fixtures / release_name
            body = bytearray(corrupt.read_bytes())
            offset = body.index(b"Copyright")
            body[offset] = ord("X")
            corrupt.write_bytes(body)
        self.fake_bin = self.root / "bin"
        self.provider = self.root / "provider"
        self.fake_bin.mkdir()
        self.state.mkdir()
        self.provider.mkdir()
        (self.provider / "libsofthsm2.so").write_bytes(b"fake provider bytes\n")
        self.dispatch = self.fake_bin / "dispatch"
        shutil.copy2(FIXTURES / "dispatch.sh", self.dispatch)
        self.dispatch.chmod(0o755)
        self.metadata_cargo = self.root / "metadata-cargo.py"
        shutil.copy2(FIXTURES / "prepared-metadata.py", self.metadata_cargo)
        for name in ("stable cargo", "stable rustc", "bpf cargo", "bpf rustc"):
            destination = self.prepared.tools / name
            destination.unlink()
            shutil.copy2(self.dispatch, destination)
            destination.chmod(0o755)
        self.port_forward = self.fake_bin / "kubectl"
        if self._testMethodName.startswith("test_prepared_"):
            shutil.copy2(self.dispatch, self.port_forward)
            self.port_forward.chmod(0o755)
        else:
            shutil.copy2(type(self)._port_forward_binary, self.port_forward)
            self.port_forward.chmod(0o755)
        for command in (
            "git", "cargo", "rustc", "rustup", "gcc", "curl", "docker", "kind",
            "sudo", "timeout", "readelf", "cp", "tar", "sha256sum",
            "python3", "mkdir", "cmp",
        ):
            (self.fake_bin / command).symlink_to("dispatch")
        for command in ("python3", "rustup"):
            path = self.fake_bin / command
            path.unlink()
            shutil.copy2(self.dispatch, path)
            path.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update({
            "PATH": f"{self.fake_bin}:/usr/bin:/bin",
            "P11SCOPE_MATRIX_TMPDIR": str(self.root / "work"),
            "D2_STATE": str(self.state),
            "D2_PROVIDER": str(self.provider),
            "D2_EBPF_OBJECT": str(EBPF_OBJECT),
            "D2_DISPATCH_PATH": str(self.dispatch),
            "D2_PORT_FORWARD_HELPER": str(self.port_forward),
            "D2_FIXTURES": str(FIXTURES),
            "D2_RELEASE_FIXTURES": str(self.release_fixtures),
            "D2_CORRUPT_RELEASE_FIXTURES": str(self.corrupt_release_fixtures),
            "D2_ORIGINAL_ROOT": str(ROOT),
            # Dispatch holds stay literal: a TERMed fixture shell leaves its
            # sleep behind, and cleanup waits that sleep out.
            "D2_HOLD_SECONDS": "4",
            # The native port-forward must outlive the body that uses it.
            "D2_PORT_FORWARD_SECONDS": scaled_whole_seconds(4),
            "P11SCOPE_TEST_TIME_SCALE": repr(TIME_SCALE),
            "D2_FOREIGN_TARGET": str(self.outside / "foreign-symlink-target"),
            "D2_SENTINEL_OVERWRITE": os.environ.get(
                "P11SCOPE_LANE13_SENTINEL_VARIANT", "0"
            ),
            "D2_UNTRACKED_FIXTURE": str(
                FIXTURES / (
                    "untracked-query-old.sh"
                    if os.environ.get("P11SCOPE_LANE13_UNTRACKED_VARIANT") == "old"
                    else "untracked-query-current.sh"
                )
            ),
            "D2_CANDIDATE_INPUTS": str(self.root / "candidate-inputs.json"),
            "D2_METADATA_CARGO": str(self.metadata_cargo),
            "P11SCOPE_FAKE_CARGO_CONFIG": str(self.prepared.config_path),
            "D2_STABLE_CARGO": str(self.prepared.tools / "stable cargo"),
            "D2_STABLE_RUSTC": str(self.prepared.tools / "stable rustc"),
            "D2_BPF_CARGO": str(self.prepared.tools / "bpf cargo"),
            "D2_BPF_RUSTC": str(self.prepared.tools / "bpf rustc"),
        })
        alternate = self.root / "alternate-root-metadata.json"
        alternate_metadata = json.loads(self.prepared.root_metadata.read_text(encoding="utf-8"))
        alternate_metadata["resolve"]["nodes"][0]["features"].append("redirected")
        alternate.write_text(json.dumps(alternate_metadata), encoding="utf-8")
        self.prepared.config.update({
            "lane13_cargo_config": str(self.project / ".cargo/config.toml"),
            "lane13_redirected_root_metadata": str(alternate),
        })
        self.prepared.write_config()
        mutation_config = self.root / "prepared-mutation.json"
        mutation_config.write_text(json.dumps({
            "generated": str(self.prepared.base.output / "src/lib.rs"),
            "recipe": str(self.project / "third-party/sources.json"),
            "patch": str(self.project / self.prepared.base.record["patches"][0]),
            "script": str(self.project / "scripts/prepared-dependency-evidence.py"),
            "selection": str(self.prepared.selection),
            "alternate_root_metadata": str(alternate),
            "cargo_config": str(self.project / ".cargo/config.toml"),
        }), encoding="utf-8")
        self.env["D2_MUTATION_CONFIG"] = str(mutation_config)
        (self.root / "candidate-inputs.json").write_text(json.dumps({
            "root": str(ROOT),
            "delegate": False,
            "tracked_paths": tracked_paths,
        }), encoding="utf-8")

    @staticmethod
    def read_process_snapshot(pid):
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        _, separator, tail = raw.rpartition(b") ")
        if not separator:
            raise ValueError("malformed proc stat")
        fields = tail.split()
        if len(fields) < 20:
            raise ValueError("short proc stat")
        return {
            "state": os.fsdecode(fields[0]),
            "identity": {
                "starttime": int(fields[19]),
                "ppid": int(fields[1]),
                "pgid": int(fields[2]),
                "sid": int(fields[3]),
            },
        }

    @classmethod
    def read_process_identity(cls, pid):
        return cls.read_process_snapshot(pid)["identity"]

    @classmethod
    def process_starttime(cls, pid):
        return cls.read_process_identity(pid)["starttime"]

    def assert_process_absent(self, pid, starttime):
        try:
            current = self.read_process_identity(pid)
        except (FileNotFoundError, ProcessLookupError):
            return
        self.assertNotEqual(current["starttime"], starttime, f"process {pid}/{starttime} remains")

    def fixture_records(self):
        ledger = self.state / "fixture-pids"
        if not ledger.exists():
            return []
        records = []
        expected = {
            "version", "record_id", "owner", "evidence", "kind", "pid",
            "starttime", "ppid", "pgid", "sid", "exe", "argv",
        }
        for number, line in enumerate(ledger.read_text().splitlines(), 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed fixture identity line {number}: {error}") from error
            if set(record) != expected or record["version"] != 1:
                raise ValueError(f"malformed fixture identity line {number}")
            if not all(
                isinstance(record[name], int) and record[name] > 0
                for name in ("pid", "starttime", "ppid", "pgid", "sid")
            ):
                raise ValueError(f"malformed fixture integers line {number}")
            if not all(
                isinstance(record[name], str) and record[name]
                for name in ("record_id", "owner", "evidence", "kind", "exe")
            ) or not isinstance(record["argv"], list) or not record["argv"] \
                    or not all(isinstance(item, str) for item in record["argv"]):
                raise ValueError(f"malformed fixture authority line {number}")
            launch = self.owned_launches.get(record["owner"])
            if launch is None or record["evidence"] != str(launch["evidence"]):
                raise ValueError(f"unknown fixture launch authority line {number}")
            if record["record_id"] != (
                f"{record['owner']}:{record['kind']}:{record['pid']}:{record['starttime']}"
            ):
                raise ValueError(f"mismatched fixture record id line {number}")
            if record["kind"] == "native-port-forward":
                if record["pid"] != record["pgid"] or record["pid"] != record["sid"]:
                    raise ValueError("native port-forward did not enter its own session")
                if record["exe"] != str(self.port_forward) \
                        or len(record["argv"]) != 6 or record["argv"][:5] != [
                            "kubectl", "port-forward", "-n", "kourier-system",
                            "svc/kourier-internal",
                        ] or not record["argv"][5].endswith(":80"):
                    raise ValueError("native port-forward argv does not match the controlled fixture")
            elif record["kind"] not in {
                "dispatch-sleep-build", "dispatch-terminal-readiness",
                "dispatch-terminal-signal", "dispatch-kubectl",
            }:
                raise ValueError(f"unknown fixture kind line {number}")
            records.append(record)
        if len({record["record_id"] for record in records}) != len(records):
            raise ValueError("duplicate fixture identity record")
        return records

    def body_records(self):
        records = []
        expected = {"pid", "starttime", "pgid", "sid", "argv"}
        for evidence in self.evidence_roots:
            pidfile = evidence / ".lane13-body.pid"
            if not pidfile.exists():
                continue
            try:
                record = json.loads(pidfile.read_text())
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError(f"malformed body identity in {pidfile}: {error}") from error
            launch = next(
                (item for item in self.owned_launches.values() if item["evidence"] == evidence),
                None,
            )
            if launch is None or set(record) != expected:
                raise ValueError(f"body identity lacks controlled launch authority in {pidfile}")
            if not all(isinstance(record[name], int) and record[name] > 0
                       for name in ("pid", "starttime", "pgid", "sid")):
                raise ValueError(f"malformed body integers in {pidfile}")
            if record["pid"] != record["pgid"] or record["pid"] != record["sid"]:
                raise ValueError(f"body identity is not its recorded session leader in {pidfile}")
            if not isinstance(record["argv"], list) or str(self.gate) not in record["argv"] \
                    or str(evidence / "stdout.log") not in record["argv"] \
                    or str(evidence / "stderr.log") not in record["argv"]:
                raise ValueError(f"body argv lacks controlled evidence authority in {pidfile}")
            records.append(record | {
                "record_id": f"body:{evidence}",
                "kind": "lane13-body",
                "ppid": launch["record"]["pid"],
                "source": pidfile,
            })
        return records

    def recorded_processes(self):
        records = self.fixture_records() + self.body_records()
        records.extend(launch["record"] | {
            "record_id": f"launch:{owner}",
            "kind": "owned-launch",
            "owner": owner,
        } for owner, launch in self.owned_launches.items())
        return records

    def _remember_settlement_errors(self, failures):
        self.settlement_errors.extend(failures)
        return failures

    def acknowledge_settlement_errors(self):
        self.acknowledged_settlement_errors = len(self.settlement_errors)

    @staticmethod
    def close_owned_child(process):
        if process.poll() is None:
            process.kill()
        deadline = time.monotonic() + CLEANUP_SETTLE_SECONDS
        while True:
            try:
                process.wait(timeout=2)
                return
            except subprocess.TimeoutExpired:
                if process.poll() is not None:
                    process.wait(timeout=0)
                    return
                if time.monotonic() >= deadline:
                    raise
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

    def start_decoy(self):
        process = subprocess.Popen(
            ["/bin/sleep", scaled_whole_seconds(20)], start_new_session=True
        )
        self.addCleanup(self.close_owned_child, process)
        return process

    def close_controlled_handle(self, descriptor):
        try:
            if self._pidfd_is_live(descriptor):
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + CLEANUP_SETTLE_SECONDS
                while not select.select([descriptor], [], [], 2)[0]:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("controlled original handle did not settle")
                    try:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                    except ProcessLookupError:
                        pass
        finally:
            os.close(descriptor)

    @staticmethod
    def _pidfd_is_live(descriptor):
        return not select.select([descriptor], [], [], 0)[0]

    def _reread_record(self, record):
        if record["kind"] == "native-port-forward" or record["kind"].startswith("dispatch-"):
            return next(
                (item for item in self.fixture_records()
                 if item["record_id"] == record["record_id"]),
                None,
            )
        if record["kind"] == "lane13-body":
            return next(
                (item for item in self.body_records()
                 if item["record_id"] == record["record_id"]),
                None,
            )
        return record

    @staticmethod
    def _identity_tuple(identity):
        return tuple(identity[key] for key in ("starttime", "ppid", "pgid", "sid"))

    def _identity_diagnostic(self, record, expected, snapshot, descriptor):
        ready = "unavailable" if descriptor is None else str(
            not self._pidfd_is_live(descriptor)
        ).lower()
        return (
            f"record={record['record_id']} pid={record['pid']} "
            f"expected={self._identity_tuple(expected)} "
            f"current={self._identity_tuple(snapshot['identity'])} "
            f"state={snapshot['state']} pinnedfd_ready={ready}"
        )

    def retain_body_handle(self, evidence):
        launch = next(
            (item for item in self.owned_launches.values() if item["evidence"] == evidence),
            None,
        )
        if launch is None or launch["process"].poll() is not None \
                or not self._pidfd_is_live(launch["pidfd"]):
            raise ValueError("body pin lacks a live controlled outer launch")
        record = next(
            (item for item in self.body_records() if item["source"].parent == evidence),
            None,
        )
        if record is None:
            raise ValueError("body pin lacks a durable controlled body record")
        existing = self.retained_body_handles.get(record["record_id"])
        if existing is not None:
            return existing
        outer_expected = {
            key: launch["record"][key] for key in ("starttime", "ppid", "pgid", "sid")
        }
        expected = {key: record[key] for key in ("starttime", "ppid", "pgid", "sid")}
        descriptor = None
        try:
            if self.read_process_identity(launch["record"]["pid"]) != outer_expected:
                raise ValueError("controlled outer identity changed before body pin")
            first = self.read_process_snapshot(record["pid"])
            if first["identity"] != expected or first["state"] == "Z":
                raise ValueError("body identity changed before pin")
            controlled = self.controlled_bodies.get(evidence)
            descriptor = (os.dup(controlled["pidfd"]) if controlled is not None
                          else os.pidfd_open(record["pid"]))
            second = self.read_process_snapshot(record["pid"])
            reread = self._reread_record(record)
            if second["identity"] != first["identity"] or second["state"] == "Z" \
                    or reread != record or not self._pidfd_is_live(descriptor):
                raise ValueError("body identity or record changed while pinning")
            if launch["process"].poll() is not None \
                    or not self._pidfd_is_live(launch["pidfd"]) \
                    or self.read_process_identity(launch["record"]["pid"]) != outer_expected:
                raise ValueError("controlled outer changed while pinning body")
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise
        retained = {"record": record, "pidfd": descriptor}
        self.retained_body_handles[record["record_id"]] = retained
        self.accepted_sessions.add(record["sid"])
        if controlled is not None:
            controlled["socket"].sendall(b"retained")
            if controlled["socket"].recv(16) != b"retained":
                raise ValueError("controlled outer did not acknowledge retained ownership")
        return retained

    def settle_recorded(self, defer_owned_process=None):
        failures = []
        for marker in ("terminal-signal-go", "terminal-communication-go"):
            try:
                (self.state / marker).write_text("release\n")
            except OSError as error:
                failures.append(f"release {marker}: {error}")
        records = []
        try:
            records.extend(self.fixture_records())
        except (OSError, ValueError, TypeError, KeyError) as error:
            failures.append(f"fixture identity inventory: {error}")
        try:
            body_inventory = self.body_records()
        except (OSError, ValueError, TypeError, KeyError) as error:
            failures.append(f"body identity inventory: {error}")
            body_inventory = []
        for record in body_inventory:
            retained = self.retained_body_handles.get(record["record_id"])
            if retained is not None and retained["record"] != record:
                failures.append(f"retained body record changed {record['record_id']}")
                continue
            records.append(record)
        recorded_ids = {record["record_id"] for record in records}
        records.extend(
            retained["record"] for retained in self.retained_body_handles.values()
            if retained["record"]["record_id"] not in recorded_ids
        )
        records.extend(launch["record"] | {
            "record_id": f"launch:{owner}",
            "kind": "owned-launch",
            "owner": owner,
        } for owner, launch in self.owned_launches.items()
                       if launch["process"] is not defer_owned_process)
        pinned = []
        seen = set()
        for record in records:
            # An unaccepted inventory record must not suppress a separately
            # accepted original handle for the same numeric process identity.
            identity = (record["record_id"], record["pid"], record["starttime"])
            if identity in seen:
                continue
            seen.add(identity)
            descriptor = None
            descriptor_published = False
            retained_body = self.retained_body_handles.get(record["record_id"])
            accepted = retained_body
            if record["kind"] == "owned-launch":
                accepted = self.owned_launches.get(record.get("owner"))
            if accepted is not None:
                descriptor = accepted["pidfd"]
                if not self._pidfd_is_live(descriptor):
                    continue
                self.accepted_sessions.add(accepted["record"]["sid"])
                # Settlement authority was established at original admission.
                # Publish before optional numeric observation, which can neither
                # revoke that authority nor describe an already exited original.
                pinned.append((record, descriptor, True))
                try:
                    snapshot = self.read_process_snapshot(record["pid"])
                    expected = {key: record[key] for key in ("starttime", "ppid", "pgid", "sid")}
                    if self._pidfd_is_live(descriptor) and snapshot["identity"] != expected:
                        self.settlement_diagnostics.append(
                            self._identity_diagnostic(record, expected, snapshot, descriptor)
                        )
                except (FileNotFoundError, ProcessLookupError):
                    if self._pidfd_is_live(descriptor):
                        failures.append(f"inspect {record['record_id']}: original live but proc absent")
                except (OSError, ValueError, TypeError, KeyError) as error:
                    failures.append(f"inspect {record['record_id']}: {error}")
                try:
                    if self._pidfd_is_live(descriptor):
                        signal.pidfd_send_signal(descriptor, signal.SIGTERM, None, 0)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    failures.append(f"signal {record['record_id']}: {error}")
                continue
            try:
                snapshot = self.read_process_snapshot(record["pid"])
                current = snapshot["identity"]
                expected = {key: record[key] for key in ("starttime", "ppid", "pgid", "sid")}
                if current != expected:
                    failures.append(
                        "identity mismatch before pin "
                        + self._identity_diagnostic(record, expected, snapshot, None)
                    )
                    continue
                if self.before_pidfd_open is not None:
                    self.before_pidfd_open(record)
                descriptor = os.pidfd_open(record["pid"])
                second = self.read_process_snapshot(record["pid"])
                try:
                    reread = self._reread_record(record)
                except (OSError, ValueError, TypeError, KeyError):
                    reread = None
                if second["identity"] != expected or reread != record:
                    diagnostic = self._identity_diagnostic(record, expected, second, descriptor)
                    os.close(descriptor)
                    failures.append(f"identity record changed before pin {diagnostic}")
                    continue
                pinned.append((record, descriptor, False))
                descriptor_published = True
                self.accepted_sessions.add(record["sid"])
                signal.pidfd_send_signal(descriptor, signal.SIGTERM, None, 0)
            except (FileNotFoundError, ProcessLookupError):
                if descriptor is not None and self._pidfd_is_live(descriptor):
                    failures.append(
                        f"process vanished while retained pidfd remained live {record['record_id']}"
                    )
                if descriptor is not None and not descriptor_published:
                    os.close(descriptor)
            except (OSError, ValueError, TypeError, KeyError) as error:
                failures.append(f"signal {record['record_id']}: {error}")
                if descriptor is not None and not descriptor_published:
                    os.close(descriptor)
        deadline = time.monotonic() + 1
        remaining = pinned
        while remaining and time.monotonic() < deadline:
            remaining = [item for item in remaining if self._pidfd_is_live(item[1])]
            if not remaining:
                break
            time.sleep(0.02)
        for record, descriptor, _ in remaining:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
            except (FileNotFoundError, ProcessLookupError):
                pass
            except OSError as error:
                failures.append(f"kill {record['record_id']}: {error}")
        deadline = time.monotonic() + slack(2)
        while remaining and time.monotonic() < deadline:
            remaining = [item for item in remaining if self._pidfd_is_live(item[1])]
            if remaining:
                time.sleep(0.02)
        for record, _, _ in remaining:
            failures.append(
                f"process {record['pid']}/{record['starttime']} remained live"
            )
        for _, descriptor, retained in pinned:
            if not retained:
                os.close(descriptor)
        return self._remember_settlement_errors(failures)

    def wait_for_session_writers(self):
        # A retired leader does not retire its children. In particular, a
        # final input-ledger helper can still create files after its shell
        # exits. Only observe sessions accepted through original launch or
        # validated process handles; this grants no additional kill authority.
        if not self.accepted_sessions:
            return []
        deadline = time.monotonic() + CLEANUP_SETTLE_SECONDS
        empty_inventories = 0
        while True:
            remaining = []
            try:
                for path in Path("/proc").iterdir():
                    if not path.name.isdecimal():
                        continue
                    descriptor = None
                    identity = None
                    try:
                        pid = int(path.name)
                        identity = self.read_process_snapshot(pid)["identity"]
                        if identity["sid"] not in self.accepted_sessions:
                            continue
                        descriptor = os.pidfd_open(pid)
                        if not self._pidfd_is_live(descriptor):
                            continue
                        second = self.read_process_snapshot(pid)["identity"]
                        if any(second[key] != identity[key] for key in ("starttime", "sid")):
                            return [f"session writer identity changed during inventory: {pid}"]
                        # A zombie main thread can still have a worker writing
                        # evidence. Pidfd readiness covers the whole thread group.
                        if self._pidfd_is_live(descriptor):
                            remaining.append((pid, identity["starttime"]))
                    except (FileNotFoundError, ProcessLookupError):
                        if descriptor is not None and self._pidfd_is_live(descriptor):
                            remaining.append((pid, identity["starttime"]))
                    finally:
                        if descriptor is not None:
                            os.close(descriptor)
            except (OSError, ValueError) as error:
                return [f"session writer inventory: {error}"]
            empty_inventories = 0 if remaining else empty_inventories + 1
            # Re-enumerate after an empty scan: a listed parent can fork and
            # disappear before its stat read while its new child is still live.
            if empty_inventories >= 2:
                return []
            if time.monotonic() >= deadline:
                return [f"owned session writers remained live: {remaining}"]
            time.sleep(0.02)

    def cleanup_case(self):
        if self.cleaned:
            return
        failures = []
        self.settle_recorded()
        for process in reversed(self.processes):
            try:
                process.communicate(timeout=slack(2))
            except subprocess.TimeoutExpired:
                try:
                    self.signal_owned_process(process, signal.SIGKILL)
                except (OSError, ValueError) as error:
                    failures.append(f"direct child {process.pid} kill failed: {error}")
                try:
                    process.communicate(timeout=slack(2))
                except subprocess.TimeoutExpired:
                    failures.append(f"direct child {process.pid} did not settle")
        failures.extend(self.wait_for_session_writers())
        failures.extend(self.settlement_errors[self.acknowledged_settlement_errors:])
        for launch in self.owned_launches.values():
            os.close(launch["pidfd"])
        for retained in self.retained_body_handles.values():
            os.close(retained["pidfd"])
        self.cleaned = True
        if failures:
            self.temp._finalizer.detach()
            self.fail(f"owned cleanup failed; retained {self.root}: {'; '.join(failures)}")
        self.temp.cleanup()

    def clear_state(self):
        for marker in (
            "cluster", "cluster-delete-called", "image-created", "image-cleaned",
            "image-removed", "partial-image-failed", "partial-cluster-failed",
            "cluster-node-observed", "cluster-replacement-failed", "mutate-head",
            "signal-after-root", "mkdir-signal", "portforward-ready",
            "terminal-signal-ready", "terminal-signal-go", "terminal-communication-go",
            "terminal-readiness-hold", "sleep-build-ready", "checker.calls",
            "input-compare-called", "git-compare-called",
            "release-applies", "release-deletion-observed", "last-release-path",
            "curl-argv.jsonl", "work-collision-path",
        ):
            try:
                (self.state / marker).unlink()
            except FileNotFoundError:
                pass
        (self.state / "calls").write_text("")
        (self.state / "git.calls").write_text("")

    def run_owned(self, arguments, env, timeout, hold_marker=None):
        process = self.start_owned(arguments, env)
        if hold_marker is not None:
            # A SEMANTIC budget covers the held phase, not setup: start it
            # only once the fixture has published that it entered its hold.
            # Setup is a SLACK wait; a missing marker is left for the caller
            # to assert after the bounded communication below.
            deadline = time.monotonic() + TERMINAL_READINESS_TIMEOUT_SECONDS
            while not hold_marker.exists() and process.poll() is None \
                    and time.monotonic() < deadline:
                time.sleep(0.01)
        self.budget_started = time.monotonic()
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as error:
            settlement = self.settle_recorded()
            try:
                stdout, stderr = process.communicate(timeout=slack(2))
            except subprocess.TimeoutExpired:
                self.signal_owned_process(process, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=slack(2))
            detail = "" if not settlement else "\n" + "\n".join(settlement)
            return subprocess.CompletedProcess(
                arguments, 124, stdout or error.stdout or "",
                (stderr or error.stderr or "")
                + "\nnative fixture communication timeout\n" + detail,
            )

    def start_owned(self, arguments, env, pass_fds=()):
        evidence = Path(env["P11SCOPE_LANE_EVIDENCE_DIR"])
        if not evidence.is_absolute():
            raise ValueError("owned evidence root must be absolute")
        if evidence not in self.evidence_roots:
            self.evidence_roots.append(evidence)
        self.prepared.config["prefix"] = str(evidence / "dependencies")
        self.prepared.write_config()
        owner = secrets.token_hex(16)
        launch_env = env.copy()
        launch_env["D2_OWNER_ID"] = owner
        process = subprocess.Popen(
            arguments, cwd=self.project, env=launch_env, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            pass_fds=pass_fds,
        )
        descriptor = None
        try:
            first = self.read_process_identity(process.pid)
            descriptor = os.pidfd_open(process.pid)
            second = self.read_process_identity(process.pid)
            if first != second or process.pid != first["pgid"] or process.pid != first["sid"]:
                raise ValueError("owned launch identity changed while pinning")
        except BaseException:
            try:
                process.kill()
                process.communicate(timeout=slack(2))
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            raise
        self.processes.append(process)
        self.owned_launches[owner] = {
            "process": process,
            "pidfd": descriptor,
            "evidence": evidence,
            "record": {"pid": process.pid, **first, "argv": list(arguments)},
        }
        self.accepted_sessions.add(first["sid"])
        return process

    def signal_owned_process(self, process, signal_number):
        launch = next(
            (item for item in self.owned_launches.values() if item["process"] is process),
            None,
        )
        if launch is None:
            raise ValueError("process lacks controlled launch authority")
        current = self.read_process_identity(process.pid)
        expected = {key: launch["record"][key]
                    for key in ("starttime", "ppid", "pgid", "sid")}
        if current != expected:
            raise ValueError("owned launch identity changed before signal")
        signal.pidfd_send_signal(launch["pidfd"], signal_number, None, 0)

    def finish_owned(self, process, timeout, finalize_timeout=None):
        if finalize_timeout is None:
            finalize_timeout = slack(2)
        try:
            return process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            settlement = self.settle_recorded(defer_owned_process=process)
            finalization_timeout = False
            try:
                stdout, stderr = process.communicate(timeout=finalize_timeout)
            except subprocess.TimeoutExpired:
                finalization_timeout = True
                settlement.extend(self.settle_recorded())
                stdout, stderr = process.communicate(timeout=finalize_timeout)
            detail = "" if not settlement else "\n" + "\n".join(settlement)
            if finalization_timeout:
                detail += "\nowned outer finalization timeout"
            result = subprocess.CompletedProcess(
                process.args, 124, stdout or error.stdout or "",
                (stderr or error.stderr or "")
                + "\nnative fixture communication timeout\n" + detail,
            )
            raise OwnedCommunicationTimeout(result)

    def reap_controlled_body_after_final_read(self, process, descriptor, body, sender):
        self.signal_owned_process(process, signal.SIGSTOP)
        try:
            sender(descriptor, signal.SIGKILL, None, 0)
            deadline = time.monotonic() + slack(2)
            while self._pidfd_is_live(descriptor) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(self._pidfd_is_live(descriptor))
        finally:
            self.signal_owned_process(process, signal.SIGCONT)
        outer_stdout, outer_stderr = process.communicate(timeout=slack(2))
        self.assertEqual(process.returncode, 0, outer_stderr)
        self.assertIn(f"controlled child settled {body['pid']}", outer_stdout)

    def run_lane(self, mode, name=None, timeout=None, extra_env=None, hold_marker=None):
        self.clear_state()
        evidence = self.root / (name or mode)
        env = self.env | {
            "D2_MODE": mode,
            "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence),
        }
        env.update(extra_env or {})
        if timeout is None:
            timeout = slack(20)
        if hold_marker is not None:
            hold_marker = self.state / hold_marker
        output = self.run_owned(["sh", str(self.gate)], env, timeout, hold_marker)
        return output, evidence

    def start_controlled_body(self, label, ignore_term=False, fault="none"):
        evidence = self.root / label
        ready = self.root / f"{label}-ready"
        release = self.root / f"{label}-release"
        with ExitStack() as setup:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            setup.callback(child.close)
            self.addCleanup(parent.close)
            parent.settimeout(slack(5))
            argv = ["/usr/bin/python3", "-I", str(FIXTURES / "controlled-body.py"),
                    "outer", "--control-fd", str(child.fileno()),
                    "--evidence", str(evidence), "--gate", str(self.gate),
                    "--stdout-log", str(evidence / "stdout.log"),
                    "--stderr-log", str(evidence / "stderr.log"),
                    "--ready", str(ready), "--release", str(release), "--fault", fault]
            if ignore_term:
                argv.append("--ignore-term")
            proc = self.start_owned(
                argv, self.env | {"P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
                pass_fds=(child.fileno(),),
            )
            child.close()
            try:
                parent.sendall(b"start")
                data, ancillary, flags, _ = parent.recvmsg(32, socket.CMSG_SPACE(4))
                descriptors = []
                for level, kind, payload in ancillary:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        received = array.array("i")
                        received.frombytes(payload)
                        for descriptor in received:
                            self.addCleanup(self.close_controlled_handle, descriptor)
                            descriptors.append(descriptor)
                if flags or len(descriptors) != 1:
                    raise ValueError("controlled original handle transfer failed")
                controlled = {"pidfd": descriptors[0], "pid": int(data),
                              "socket": parent, "process": proc}
                self.controlled_bodies[evidence] = controlled
                parent.sendall(b"owned")
                deadline = time.monotonic() + slack(5)
                while not ready.exists() and time.monotonic() < deadline:
                    if proc.poll() is not None:
                        stdout, stderr = self.finish_owned(proc, slack(2))
                        raise ControlledBodySetupError(
                            f"controlled outer exit={proc.returncode}\n{stdout}\n{stderr}"
                        )
                    time.sleep(0.01)
                if not ready.exists():
                    raise ControlledBodySetupError("controlled body publication timeout")
                record = next(
                    item for item in self.body_records() if item["source"].parent == evidence
                )
                if record["pid"] != controlled["pid"]:
                    raise ValueError("controlled body record does not match transferred original")
            except BaseException:
                # Closing the private channel asks the outer to settle its own
                # child; registered original handles independently cover failure.
                parent.close()
                try:
                    # Popen still owns this direct child; no late proc read is
                    # needed to terminate it on a setup exception.
                    proc.terminate()
                finally:
                    self.finish_owned(proc, slack(3))
                raise
        return proc, evidence, evidence / ".lane13-body.pid", release, record

    def start_recorded_hold(self, label):
        """One recorded direct child, held after publication with no descendants."""
        evidence = self.root / label
        program = r'''
import json
import os
from pathlib import Path
import socket
import sys

control = socket.socket(fileno=int(sys.argv[1]))
pid = os.getpid()
fields = Path("/proc/self/stat").read_bytes().rpartition(b") ")[2].split()
owner = os.environ["D2_OWNER_ID"]
kind = "dispatch-sleep-build"
record = {
    "version": 1, "record_id": f"{owner}:{kind}:{pid}:{int(fields[19])}",
    "owner": owner, "evidence": os.environ["P11SCOPE_LANE_EVIDENCE_DIR"],
    "kind": kind, "pid": pid, "starttime": int(fields[19]),
    "ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]),
    "exe": os.path.realpath("/proc/self/exe"),
    "argv": [os.fsdecode(arg) for arg in Path("/proc/self/cmdline").read_bytes().split(b"\0") if arg],
}
with (Path(os.environ["D2_STATE"]) / "fixture-pids").open("w") as ledger:
    ledger.write(json.dumps(record, separators=(",", ":")) + "\n")
    ledger.flush()
    os.fsync(ledger.fileno())
control.sendall(b"ready")
# No natural exit or further filesystem writes while the parent holds us.
control.recv(1)
'''
        with ExitStack() as setup:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            setup.callback(child.close)
            self.addCleanup(parent.close)
            parent.settimeout(slack(5))
            proc = self.start_owned(
                ["/usr/bin/python3", "-I", "-c", program, str(child.fileno())],
                self.env | {"P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
                pass_fds=(child.fileno(),),
            )
            child.close()
            self.assertEqual(parent.recv(5), b"ready",
                             "controlled fixture did not publish its owned identity")
            self.assertIsNone(proc.poll(), "controlled fixture exited before identity test")
            record, = self.fixture_records()
            self.assertEqual(record["pid"], proc.pid)
            self.assertEqual(self.read_process_identity(proc.pid), {
                key: record[key] for key in ("starttime", "ppid", "pgid", "sid")
            })
        return proc, parent, record

    def facts(self, evidence):
        return (evidence / "facts.log").read_text()

    def work_path(self, recorded):
        path = Path(recorded)
        return path if path.is_absolute() else self.project / path

    def calls(self):
        return (self.state / "calls").read_text()

    def terminal_readiness_diagnostic(self, launched, process, evidence):
        truncated = False

        def tail(path):
            nonlocal truncated
            try:
                with path.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    start = max(0, size - READINESS_DIAGNOSTIC_TAIL_BYTES)
                    stream.seek(start)
                    raw = stream.read(READINESS_DIAGNOSTIC_TAIL_BYTES)
            except FileNotFoundError:
                return ["absent"]
            except OSError as error:
                return [f"unavailable: {error}"]
            lines = raw.decode("utf-8", errors="replace").splitlines()[-12:]
            if start:
                truncated = True
                lines.insert(0, f"byte_tail_truncated={start}")
            return lines

        def bounded_json(value):
            nonlocal truncated
            encoded = json.dumps(value, sort_keys=True).encode("utf-8")
            if len(encoded) <= READINESS_DIAGNOSTIC_FIELD_BYTES:
                return encoded.decode("utf-8")
            truncated = True
            suffix = b"...[field_truncated=1]"
            prefix = encoded[:READINESS_DIAGNOSTIC_FIELD_BYTES - len(suffix)]
            return prefix.decode("utf-8", errors="ignore") + suffix.decode("ascii")

        returncode = process.poll()
        try:
            process_state = self.read_process_snapshot(process.pid)["state"]
        except (FileNotFoundError, ProcessLookupError):
            process_state = "absent"
        except (OSError, ValueError) as error:
            process_state = f"unavailable: {error}"
        call_tail = tail(self.state / "calls")
        body_diagnostics = {
            name: tail(evidence / name)
            for name in (".lane13-body.pid", "stdout.log", "stderr.log", "facts.log")
        }
        try:
            phase_markers = [
                name for name in (
                    "terminal-readiness-hold", "terminal-signal-ready", "fixture-pids",
                    "input-compare-called", "checker.calls", "portforward-ready",
                ) if (self.state / name).exists()
            ]
        except OSError as error:
            phase_markers = [f"unavailable:{error}"]
        diagnostic = (
            f"terminal readiness missing; elapsed_after_launch="
            f"{time.monotonic() - launched:.6f}s; "
            f"outer_process=pid:{process.pid},state:{process_state},exit:{returncode}; "
            f"fixture_call_tail={bounded_json(call_tail)}; "
            f"body_diagnostics={bounded_json(body_diagnostics)}; "
            f"phase_markers={','.join(phase_markers) if phase_markers else 'none'}"
        )
        if truncated:
            diagnostic += READINESS_DIAGNOSTIC_TRUNCATION
        encoded = diagnostic.encode("utf-8")
        if len(encoded) <= READINESS_DIAGNOSTIC_MAX_BYTES:
            return diagnostic
        suffix = READINESS_DIAGNOSTIC_TRUNCATION.encode("utf-8")
        prefix = encoded[:READINESS_DIAGNOSTIC_MAX_BYTES - len(suffix)]
        return prefix.decode("utf-8", errors="ignore") + READINESS_DIAGNOSTIC_TRUNCATION

    def assert_no_cargo_call(self):
        self.assertFalse(any(line.startswith("cargo ") for line in self.calls().splitlines()))

    def assert_no_collision_body(self):
        self.assert_no_cargo_call()
        self.assertFalse((self.state / "checker.calls").exists())
        work_parent = Path(self.env["P11SCOPE_MATRIX_TMPDIR"])
        self.assertFalse(work_parent.exists() and any(work_parent.iterdir()))

    @staticmethod
    def tree_receipt(root):
        receipt = []
        if not root.exists():
            return receipt
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root))
            metadata = path.lstat()
            if path.is_symlink():
                value = f"link:{os.readlink(path)}"
            elif path.is_file():
                value = f"file:{hashlib.sha256(path.read_bytes()).hexdigest()}"
            else:
                value = "directory"
            receipt.append((relative, metadata.st_mode & 0o7777, value))
        return receipt

    def test_script_contract(self):
        gate = GATE.read_text()
        self.assertLess(gate.index('mkdir -p "${WORK%/*}"'), gate.index('mkdir "$WORK"'))
        self.assertEqual(
            gate.count("python3 scripts/check-capture-evidence.py lane13-knative-metrics"), 1
        )
        for marker in (
            "P11SCOPE_LANE13_BODY", "P11SCOPE_LANE13_TOKEN",
            "P11SCOPE_LANE13_TOKEN is private lane state", "LANE13_BODY_STARTTIME",
            "LANE13_BODY_SIGNAL", "lane13_container_absent",
            "len(items) != len(set(items))", "for item in sorted(items):",
            "git diff --cached --quiet", "scripts/lane13-input-ledger.py snapshot",
            "RepoDigests", "diff_ids", "dev_ino",
        ):
            self.assertIn(marker, gate)
        self.assertNotIn("knative scale-from-zero: ALL OK", gate)
        self.assertNotIn('kill "$launcher"', gate)
        signal_check = gate.index('[ "$LANE13_BODY_SIGNAL_STATUS" -eq 0 ] || lane13_outer_status=1')
        status_write = gate.rindex("printf '%s\\n' \"$lane13_outer_status\" > \"$EVIDENCE/status\"")
        self.assertLess(gate.rindex("trap 'lane13_outer_signal 1' INT"), signal_check)
        self.assertLess(gate.rindex("trap 'lane13_outer_signal 1' TERM"), signal_check)
        self.assertLess(signal_check, status_write)
        retained = gate.rindex("if ! lane13_validate_retained_root; then lane13_outer_status=1; fi")
        self.assertLess(retained, status_write)

    def test_prepared_metadata_failures_stop_before_privilege_runtime_and_work(self):
        for context in ("root", "bpf"):
            with self.subTest(context=context):
                self.prepared.config.pop("root_status", None)
                self.prepared.config.pop("bpf_status", None)
                self.prepared.config[f"{context}_status"] = 42
                output, evidence = self.run_lane(
                    f"prepared-{context}-failure", f"prepared-{context}-failure"
                )
                self.assertNotEqual(output.returncode, 0)
                calls = self.calls().splitlines()
                forbidden = ("sudo ", "docker ", "kind ", "gcc ")
                self.assertFalse(any(line.startswith(forbidden) for line in calls), calls)
                self.assertFalse(any(" build " in f" {line} " for line in calls), calls)
                work_base = self.env["P11SCOPE_MATRIX_TMPDIR"]
                self.assertFalse(any(line.startswith("mkdir ") and work_base in line
                                     for line in calls), calls)
                facts = self.facts(evidence)
                self.assertIn("input_ledger_phase=unavailable-start", facts)
                self.assertNotIn("prepared_recheck_status=", facts)
                self.assertFalse((evidence / "source.start.sha256").exists())
                self.assertFalse(any(path.name.startswith("dependencies.final.")
                                     for path in evidence.iterdir()))

    def test_prepared_stale_input_is_refused_before_privilege_runtime_and_work(self):
        generated = self.prepared.base.output / "src/lib.rs"
        original = generated.read_bytes()
        self.prepared.config["root_mutations"] = [{
            "path": str(generated), "action": "append", "content": "stale during capture\n",
        }]
        output, evidence = self.run_lane("prepared-stale-capture")
        self.assertNotEqual(output.returncode, 0)
        calls = self.calls().splitlines()
        self.assertFalse(any(line.startswith(("sudo ", "docker ", "kind ", "gcc "))
                             for line in calls), calls)
        self.assertFalse(any(" build " in f" {line} " for line in calls), calls)
        self.assertFalse((evidence / "source.start.sha256").exists())
        self.assertIn("input_ledger_phase=unavailable-start", self.facts(evidence))
        generated.write_bytes(original)
        self.prepared.config.pop("root_mutations")

    def test_prepared_initial_and_final_queries_bracket_all_resource_cleanup(self):
        self.prepared.config.pop("root_status", None)
        self.prepared.config.pop("bpf_status", None)
        output, evidence = self.run_lane("normal", "prepared-final-recheck")
        self.assertNotEqual(output.returncode, 0)
        invocations = self.prepared.invocations()
        self.assertEqual(
            [("initial" if index < 2 else "final", row["context"])
             for index, row in enumerate(invocations)],
            [("initial", "root"), ("initial", "bpf"), ("final", "root"), ("final", "bpf")],
        )
        calls = self.calls().splitlines()
        metadata_calls = [
            index for index, line in enumerate(calls)
            if line.startswith("stable cargo metadata") or line.startswith("bpf cargo metadata")
        ]
        self.assertEqual(len(metadata_calls), 4, calls)
        final_metadata = metadata_calls[2:]
        cleanup_calls = [
            index for index, line in enumerate(calls)
            if line.startswith("kind get clusters") or line.startswith("docker image ls")
        ]
        self.assertTrue(cleanup_calls, calls)
        self.assertLess(max(cleanup_calls), min(final_metadata))
        for query in invocations[2:]:
            self.assertTrue(query["lane13_work_absent"], query)
            self.assertTrue(query["lane13_status_unpublished"], query)
        build = [line for line in calls if line.startswith("stable cargo build ")]
        self.assertEqual(len(build), 1, calls)
        self.assertEqual(
            build[0].split(),
            ["stable", "cargo", "build", "--locked", "--offline", "--release",
             "--workspace", "--target-dir", build[0].split()[-1]],
        )
        self.assertEqual(
            [line for line in calls if line.startswith("selected-build-rustc ")],
            [f"selected-build-rustc {self.prepared.tools / 'stable rustc'}"],
        )
        self.assertEqual(
            [line for line in calls if line.startswith("selected-build-")
             and not line.startswith("selected-build-rustc ")],
            [
                f"selected-build-stable-cargo {self.prepared.tools / 'stable cargo'}",
                f"selected-build-stable-rustc {self.prepared.tools / 'stable rustc'}",
                f"selected-build-bpf-cargo {self.prepared.tools / 'bpf cargo'}",
                f"selected-build-bpf-rustc {self.prepared.tools / 'bpf rustc'}",
            ],
        )
        for phase in ("initial", "final"):
            for context, cargo, rustc in (
                ("root", self.prepared.tools / "stable cargo",
                 self.prepared.tools / "stable rustc"),
                ("bpf", self.prepared.tools / "bpf cargo",
                 self.prepared.tools / "bpf rustc"),
            ):
                command = json.loads((evidence / f"dependencies.{phase}.{context}.command.json").read_text())
                query_context = json.loads((evidence / f"dependencies.{phase}.{context}.context.json").read_text())
                self.assertEqual(command["argv"], [
                    str(cargo), "metadata", "--locked", "--offline", "--all-features",
                    "--format-version", "1", "--manifest-path",
                    "Cargo.toml" if context == "root" else "crates/ebpf/Cargo.toml",
                ])
                self.assertEqual(query_context["environment"], {"RUSTC": str(rustc)})
        expected = {"source.start.sha256", "source.end.sha256", "git.start", "git.end"}
        for phase in ("initial", "final"):
            for context in ("root", "bpf"):
                for suffix in ("command.json", "context.json", "status", "stdout.json", "stderr"):
                    expected.add(f"dependencies.{phase}.{context}.{suffix}")
            expected.add(f"dependencies.{phase}.ledger.sha256")
            expected.add(f"dependencies.{phase}.receipt.json")
        self.assertTrue(expected.issubset({entry.name for entry in evidence.iterdir()}))
        facts = self.facts(evidence)
        self.assertIn("prepared_admission=complete", facts)
        self.assertIn("prepared_recheck_status=0", facts)
        self.assertIn("input_ledger_phase=complete", facts)

    def test_prepared_final_recheck_refuses_every_bound_input_mutation(self):
        targets = {
            "mutate-prepared-generated": self.prepared.base.output / "src/lib.rs",
            "mutate-prepared-recipe": self.project / "third-party/sources.json",
            "mutate-prepared-patch": self.project / self.prepared.base.record["patches"][0],
            "mutate-prepared-script": self.project / "scripts/prepared-dependency-evidence.py",
        }
        originals = {path: path.read_bytes() for path in targets.values()}
        original_selection = self.prepared.selection.read_bytes()
        modes = (*targets, "mutate-prepared-final-graph", "mutate-prepared-config-redirect")
        for mode in modes:
            with self.subTest(mode=mode):
                output, evidence = self.run_lane(mode)
                self.assertNotEqual(output.returncode, 0)
                facts = self.facts(evidence)
                self.assertIn("prepared_admission=complete", facts)
                self.assertRegex(facts, r"prepared_recheck_status=[1-9][0-9]*")
                self.assertIn("input_ledger_phase=failed-end", facts)
                self.assertFalse((evidence / "source.end.sha256").exists())
                if mode == "mutate-prepared-config-redirect":
                    self.assertEqual(self.prepared.selection.read_bytes(), original_selection)
                    self.assertTrue((self.project / ".cargo/config.toml").is_file())
                    final_root = json.loads(
                        (evidence / "dependencies.final.root.stdout.json").read_text()
                    )
                    self.assertIn(
                        "redirected", final_root["resolve"]["nodes"][0]["features"]
                    )
                for path, value in originals.items():
                    path.write_bytes(value)
                self.prepared.selection.write_bytes(original_selection)
                try:
                    (self.project / ".cargo/config.toml").unlink()
                except FileNotFoundError:
                    pass

    def test_private_and_public_injection_are_refused(self):
        for arguments, extra in (
            (["--lane13-private-body"], {
                "P11SCOPE_LANE13_BODY": "1", "P11SCOPE_LANE13_TOKEN": "forged"
            }),
            ([], {"P11SCOPE_LANE13_TOKEN": "caller-controlled"}),
        ):
            evidence = self.root / f"injection-{len(arguments)}"
            output = self.run_owned(
                ["sh", str(self.gate), *arguments],
                self.env | extra | {"P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
                5,
            )
            self.assertEqual(output.returncode, 2, output.stderr)
            self.assertFalse(evidence.exists())

    def test_untracked_consumed_input_is_named_refusal_before_resources(self):
        self.env["D2_UNTRACKED_FIXTURE"] = str(
            FIXTURES / "untracked-build-support.sh"
        )
        output, evidence = self.run_lane("untracked-consumed-input")
        self.assertNotEqual(output.returncode, 0)
        body_stderr = (evidence / "stderr.log").read_text()
        self.assertIn(
            "lane-13 consumed input is untracked", body_stderr,
            f"outer_stderr={output.stderr!r} calls={self.calls()!r}",
        )
        calls = self.calls()
        call_lines = calls.splitlines()
        self.assertFalse(any(line.startswith("cargo ") for line in call_lines))
        self.assertFalse(any(line.startswith("docker build") for line in call_lines))
        self.assertFalse(any(line.startswith("kind create cluster") for line in call_lines))
        self.assertFalse((self.state / "cluster").exists())
        self.assertFalse((self.state / "image-created").exists())
        work_base = self.env["P11SCOPE_MATRIX_TMPDIR"]
        self.assertFalse(
            any(line.startswith("mkdir ") and work_base in line
                for line in call_lines)
        )
        self.assertTrue(evidence.exists())
        facts = self.facts(evidence)
        self.assertIn("input_ledger_phase=unavailable-start", facts)
        self.assertNotIn("input_ledger_end=", facts)
        self.assertNotIn("Traceback", body_stderr)
        self.assertRegex((evidence / "status").read_text(), r"^[1-9][0-9]*\n$")

    def test_prepared_candidate_inventory_is_frozen_against_ambient_git_index(self):
        candidate_path = Path(self.env["D2_CANDIDATE_INPUTS"])
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        ambient = self.root / "ambient-index"
        ambient.mkdir()
        subprocess.run(["/usr/bin/git", "init", "-q", str(ambient)], check=True)
        ambient_input = ambient / "scripts/ambient-new.sh"
        ambient_input.parent.mkdir()
        ambient_input.write_text("ambient\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "-C", str(ambient), "add", "scripts/ambient-new.sh"],
            check=True,
        )
        candidate["root"] = str(ambient)
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        output = subprocess.run(
            [sys.executable, "-I", str(FIXTURES / "candidate-git.py"),
             "ls-files", "-z", "--", "scripts"],
            env=os.environ | {"D2_CANDIDATE_INPUTS": str(candidate_path)},
            check=True,
            stdout=subprocess.PIPE,
            timeout=slack(5),
        )
        observed = {
            os.fsdecode(item) for item in output.stdout.split(b"\0") if item
        }
        expected = {
            path for path in candidate["tracked_paths"]
            if path == "scripts" or path.startswith("scripts/")
        }
        self.assertEqual(observed, expected)
        self.assertNotIn("scripts/ambient-new.sh", observed)

    def test_prepared_candidate_avoids_obsolete_sources_and_keeps_recipe_inputs(self):
        candidate = json.loads(
            Path(self.env["D2_CANDIDATE_INPUTS"]).read_text(encoding="utf-8")
        )
        tracked = set(candidate["tracked_paths"])
        for obsolete in ("third-party/aya", "third-party/aya-obj"):
            self.assertFalse(any(
                path == obsolete or path.startswith(obsolete + "/")
                for path in tracked
            ))
        self.assertIn("third-party/sources.json", tracked)
        synthetic_recipe = json.loads(
            (self.project / "third-party/sources.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            [record["name"] for record in synthetic_recipe["packages"]],
            ["demo"],
        )
        self.assertTrue((self.prepared.base.output / ".p11scope-prepared.json").is_file())
        maintained_recipe = json.loads(
            (ROOT / "third-party/sources.json").read_text(encoding="utf-8")
        )
        maintained_patches = {
            patch
            for record in maintained_recipe["packages"]
            for patch in record["patches"]
        }
        self.assertTrue(maintained_patches)
        self.assertTrue(maintained_patches.issubset(tracked))
        for relative in maintained_patches:
            self.assertEqual(
                (self.project / relative).read_bytes(),
                (ROOT / relative).read_bytes(),
            )

    def test_start_ledger_failure_after_work_is_unavailable_and_nonpass(self):
        output, evidence = self.run_lane("start-ledger-failure")
        self.assertNotEqual(output.returncode, 0)
        facts = self.facts(evidence)
        self.assertNotIn("work_dev_ino=", facts)
        self.assertIn("input_ledger_phase=unavailable-start", facts)
        self.assertNotIn("input_ledger_end=", facts)
        self.assertFalse((self.state / "input-compare-called").exists())
        self.assertFalse((self.state / "git-compare-called").exists())
        self.assertFalse(any(" build " in f" {line} "
                             for line in self.calls().splitlines()))
        work = next(line.removeprefix("work=") for line in facts.splitlines()
                    if line.startswith("work="))
        self.assertFalse(self.work_path(work).exists())
        self.assertRegex((evidence / "status").read_text(), r"^[1-9][0-9]*\n$")

    def test_end_ledger_failure_after_start_skips_comparison_and_is_nonpass(self):
        output, evidence = self.run_lane("end-ledger-failure")
        self.assertNotEqual(output.returncode, 0)
        facts = self.facts(evidence)
        self.assertIn("input_ledger_start=", facts)
        self.assertIn("input_ledger_phase=failed-end", facts)
        self.assertNotIn("input_ledger_end=", facts)
        self.assertFalse((self.state / "input-compare-called").exists())
        self.assertFalse((self.state / "git-compare-called").exists())
        work = next(line.removeprefix("work=") for line in facts.splitlines()
                    if line.startswith("work="))
        self.assertFalse(self.work_path(work).exists())
        self.assertRegex((evidence / "status").read_text(), r"^[1-9][0-9]*\n$")

    def test_git_ledger_early_write_failure_is_not_masked(self):
        gate = self.gate.read_text()
        helper_start = gate.index("lane13_record_facts() {")
        helper_end = gate.index(
            "\n}\n\nlane13_record_file_fact()", helper_start
        ) + 3
        helper = gate[helper_start:helper_end]
        work = self.root / "git-ledger-write-failure"
        work.mkdir()
        probe = work / "probe.sh"
        probe.write_text(
            """#!/bin/sh
set +e
WORK=$1
EVIDENCE=$WORK
FACTS=$WORK/facts.log
BODY_STATUS=0
CLEANUP_STATUS=0
lane13_fact() { return 0; }
lane13_record_inputs() { return 0; }
git() {
    case "$*" in
        "rev-parse HEAD") command printf '%040d\\n' 1 ;;
        "rev-parse HEAD^{tree}") command printf '%040d\\n' 2 ;;
        "status --porcelain=v1") command printf ' M tracked\\n' ;;
        "diff --quiet"|"diff --cached --quiet") return 0 ;;
        *) return 1 ;;
    esac
}
printf() {
    case "$1" in
        'head=%s\\n'*)
            : > "$WORK/early-write-failure-injected"
            return 73
            ;;
    esac
    command printf "$@"
}
""" + helper + """
if lane13_record_facts start; then
    helper_status=0
else
    helper_status=$?
fi
: > "$WORK/cleanup-continued"
exit "$helper_status"
"""
        )
        output = subprocess.run(
            ["/bin/sh", str(probe), str(work)],
            text=True,
            capture_output=True,
            timeout=slack(5),
        )
        self.assertTrue((work / "early-write-failure-injected").is_file())
        self.assertTrue((work / "cleanup-continued").is_file())
        self.assertNotEqual(output.returncode, 0, output.stderr)

    def test_root_creation_signals_and_collisions_preserve_foreign_entries(self):
        output, evidence = self.run_lane("mkdir-signal")
        self.assertNotEqual(output.returncode, 0)
        self.assert_no_cargo_call()
        self.assertFalse((self.state / "checker.calls").exists())
        if evidence.exists():
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            status = (evidence / "status").read_text()
            self.assertRegex(status, r"^[1-9][0-9]*\n$")

        foreign = self.outside / "foreign-symlink-target"
        foreign.mkdir()
        sentinel = foreign / "sentinel"
        sentinel.write_bytes(b"foreign symlink target\n")
        sentinel.chmod(0o640)
        output, evidence = self.run_lane("mkdir-failure-symlink-signal", "collision-link")
        self.assertNotEqual(output.returncode, 0)
        self.assertTrue(evidence.is_symlink())
        self.assertEqual(evidence.resolve(), foreign)
        self.assertEqual(sentinel.read_bytes(), b"foreign symlink target\n")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
        self.assertEqual({entry.name for entry in foreign.iterdir()}, {"sentinel"})
        self.assert_no_collision_body()

        output, evidence = self.run_lane("mkdir-failure-directory", "collision-dir")
        self.assertNotEqual(output.returncode, 0)
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
        self.assertEqual({entry.name for entry in evidence.iterdir()}, {"sentinel-a", "sentinel-b"})
        self.assertEqual((evidence / "sentinel-a").read_bytes(), b"foreign-directory-sentinel-a\n")
        self.assertEqual((evidence / "sentinel-b").read_bytes(), b"foreign-directory-sentinel-b\n")
        self.assertEqual((evidence / "sentinel-a").stat().st_mode & 0o777, 0o640)
        self.assertEqual((evidence / "sentinel-b").stat().st_mode & 0o777, 0o600)
        self.assert_no_collision_body()

    def test_body_success_finalizes_after_cleanup(self):
        output, evidence = self.run_lane("body-success")
        self.assertEqual(
            output.returncode,
            0,
            f"outer={output.stderr}\nbody={(evidence / 'stderr.log').read_text()}\n"
            f"facts={self.facts(evidence)}\ncalls={self.calls()}",
        )
        self.assertEqual((evidence / "status").read_text(), "0\n")
        facts = self.facts(evidence)
        self.assertIn("input_ledger_phase=complete", facts)
        self.assertTrue((self.state / "git-compare-called").exists())
        work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
        expected = {
            f"generated_bpf_path={work}/product/release/build/p11scope-1/out/p11scope-ebpf",
            f"generated_bpf_size={EBPF_OBJECT.stat().st_size}",
            f"generated_bpf_sha256={hashlib.sha256(EBPF_OBJECT.read_bytes()).hexdigest()}",
            "generated_bpf_build_id=absent", "generated_bpf_elf_class=ELF64",
            "generated_bpf_elf_data=LSB", "generated_bpf_elf_type=ET_REL",
            "generated_bpf_elf_machine=EM_BPF",
        }
        generated = {line for line in facts.splitlines() if line.startswith("generated_bpf_")}
        self.assertEqual(generated, expected)
        for release_name, size, digest in RELEASES:
            copied = self.release_fixtures / release_name
            self.assertEqual(copied.stat().st_size, size)
            self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), digest)
            self.assertIn(f"release_pre_size={size}", facts)
            self.assertIn(f"release_pre_sha256={digest}", facts)
            self.assertIn(f"release_apply_success_{release_name}=1", facts)
            self.assertIn(f"release_deleted={release_name}", facts)
            self.assertIn(f"release_absent={release_name}", facts)
            self.assertIn("release_redirects=1", facts)
            self.assertIn(
                f"release_effective=https://release-assets.githubusercontent.com/{release_name}",
                facts,
            )
        expected_resources = {
            "serving-crds.yaml": [
                "customresourcedefinitions.apiextensions.k8s.io/fake",
                "namespace/knative-serving",
            ],
            "serving-core.yaml": [
                "deployment.apps/controller", "service/controller",
            ],
            "kourier.yaml": [
                "namespace/kourier-system", "service/kourier",
            ],
        }
        fact_lines = facts.splitlines()
        for release_name, resources in expected_resources.items():
            self.assertEqual(
                [line for line in fact_lines
                 if line.startswith(f"release_apply_{release_name}=")],
                [f"release_apply_{release_name}={resource}"
                 for resource in sorted(resources)],
            )
        self.assertFalse(any(line.startswith("release_apply=") for line in fact_lines))
        self.assertNotRegex(facts, r"input_ledger_(?:start|end)=.* path=.*\.lane13-")
        for scratch_name in (
            ".lane13-inputs", ".lane13-git-status", ".lane13-applied",
        ):
            self.assertNotIn(scratch_name, facts)
        self.assertEqual(
            (self.state / "release-applies").read_text().splitlines(),
            [name for name, _, _ in RELEASES],
        )
        self.assertEqual(
            (self.state / "release-deletion-observed").read_text().splitlines(),
            [name for name, _, _ in RELEASES],
        )
        calls = self.calls().splitlines()
        curl_calls = [line for line in calls if line.startswith("curl ")]
        self.assertEqual(curl_calls.count("curl --version"), 1)
        self.assertEqual(calls.count("kubectl version --client --output=yaml"), 1)
        downloads = [json.loads(line) for line in
                     (self.state / "curl-argv.jsonl").read_text().splitlines()]
        self.assertEqual(len(downloads), 3)
        for arguments, (release_name, _, _) in zip(downloads, RELEASES):
            owner = ("knative-extensions/net-kourier" if release_name == "kourier.yaml"
                     else "knative/serving")
            self.assertEqual(
                arguments,
                [
                    "--fail", "--silent", "--show-error", "--retry", "0",
                    "--connect-timeout", "30", "--max-time", "180",
                    "--max-filesize", "16777216", "--proto", "=https",
                    "--proto-redir", "=https", "--location", "--max-redirs", "1",
                    "--output", f"{work}/releases/{release_name}", "--write-out",
                    "%{url_effective}\\n%{num_redirects}",
                    f"https://github.com/{owner}/releases/download/"
                    f"knative-v1.23.0/{release_name}",
                ],
            )
        build_calls = [line for line in calls if line.startswith("docker build ")]
        self.assertEqual(len(build_calls), 1)
        self.assertIn(" --pull=false ", f" {build_calls[0]} ")
        release_apply_calls = [
            line for line in calls
            if line.startswith("kubectl apply -f ") and "/releases/" in line
        ]
        self.assertEqual(
            release_apply_calls,
            [f"kubectl apply -f {work}/releases/{name} -o name"
             for name, _, _ in RELEASES],
        )
        self.assertFalse(self.work_path(work).exists())
        for fact in ("cluster_absent=1", "workload_tag_absent=1",
                     "kubeconfig_absent=1", "work_absent=1"):
            self.assertIn(fact, facts)
        expected_evidence = {
            "stdout.log", "stderr.log", "facts.log", "status", "observed.json",
            "manifest-host.json", "profile.log", "portforward.log",
            "portforward.group.before.json", "portforward.group.after.json",
            "source.start.sha256", "source.end.sha256", "git.start", "git.end",
        }
        for phase in ("initial", "final"):
            for context in ("root", "bpf"):
                for suffix in ("command.json", "context.json", "status", "stdout.json", "stderr"):
                    expected_evidence.add(f"dependencies.{phase}.{context}.{suffix}")
            expected_evidence.add(f"dependencies.{phase}.ledger.sha256")
            expected_evidence.add(f"dependencies.{phase}.receipt.json")
        self.assertEqual({entry.name for entry in evidence.iterdir()}, expected_evidence)
        self.assertEqual((self.state / "checker.calls").read_text().splitlines(), ["checker"])

    def test_obsolete_kourier_owner_is_refused_before_fetch_or_facts(self):
        self.assertTrue((FIXTURES / "invoke-release-policy.sh").is_file())
        facts = self.root / "obsolete-owner.facts"
        facts.write_text("sentinel=fixed\n", encoding="utf-8")
        marker = self.root / "obsolete-owner.calls"
        result = subprocess.run(
            [
                sys.executable, "-I", str(FIXTURES / "invoke-release-policy.py"),
                "--driver", str(self.gate),
                "--url", (
                    "https://github.com/knative/net-kourier/releases/download/"
                    "knative-v1.23.0/kourier.yaml"
                ),
                "--name", "kourier.yaml", "--facts", str(facts),
                "--calls", str(marker),
            ],
            cwd=self.project, text=True, capture_output=True, timeout=slack(5),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(facts.read_text(encoding="utf-8"), "sentinel=fixed\n")
        self.assertFalse(marker.exists())
        canonical = subprocess.run(
            [
                sys.executable, "-I", str(FIXTURES / "invoke-release-policy.py"),
                "--driver", str(self.gate),
                "--url", (
                    "https://github.com/knative-extensions/net-kourier/releases/download/"
                    "knative-v1.23.0/kourier.yaml"
                ),
                "--name", "kourier.yaml", "--facts", str(facts),
                "--calls", str(marker),
            ],
            cwd=self.project, text=True, capture_output=True, timeout=slack(5),
        )
        self.assertNotEqual(canonical.returncode, 0)
        self.assertEqual(facts.read_text(encoding="utf-8"), "sentinel=fixed\n")
        self.assertEqual(marker.read_text(encoding="utf-8"), "curl\n")

    def test_preexisting_work_is_refused_before_resource_queries_or_build(self):
        output, evidence = self.run_lane("work-collision")
        self.assertNotEqual(output.returncode, 0)
        calls = self.calls().splitlines()
        self.assertFalse(any(line.startswith("docker image ls ") for line in calls), calls)
        self.assertFalse(any(line.startswith("docker build ") for line in calls), calls)
        self.assertFalse(any(line.startswith("kind get clusters") for line in calls), calls)
        self.assertFalse(any(line.startswith("kind create cluster") for line in calls), calls)
        collision = self.state / "work-collision-path"
        work = Path(collision.read_text(encoding="utf-8").strip())
        self.assertTrue((work / "foreign-sentinel").is_file())
        self.assertIn("lane-13 work path already exists", (evidence / "stderr.log").read_text())

    def test_unknown_final_body_group_snapshot_retains_custody_and_is_nonpass(self):
        output, evidence = self.run_lane("outer-final-snapshot-unknown")
        self.assertNotEqual(output.returncode, 0)
        self.assertEqual((evidence / "status").read_text(), "1\n")
        for name in (".lane13-body.pid", ".lane13-body-launch.log"):
            artifact = evidence / name
            self.assertTrue(artifact.is_file(), name)
            self.assertFalse(artifact.is_symlink(), name)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        record = json.loads((evidence / ".lane13-body.pid").read_text())
        self.assertGreater(record["pid"], 0)

    def test_release_expected_sha256_rejects_pre_apply_corruption(self):
        names = [name for name, _, _ in RELEASES]
        for bad_index, bad_name in enumerate(names):
            with self.subTest(release=bad_name):
                output, evidence = self.run_lane(
                    "pre-apply-release-corruption",
                    f"pre-apply-{bad_name}",
                    extra_env={"D2_CORRUPT_RELEASE": bad_name},
                )
                self.assertNotEqual(output.returncode, 0)
                self.assertEqual(
                    (self.state / "release-applies").read_text().splitlines()
                    if (self.state / "release-applies").exists() else [],
                    names[:bad_index],
                )
                self.assertIn(
                    f"Knative release SHA256 mismatch: {bad_name}",
                    (evidence / "stderr.log").read_text(),
                )
                facts = self.facts(evidence)
                self.assertNotIn(f"release_apply_success_{bad_name}=1", facts)
                for later_name in names[bad_index + 1:]:
                    self.assertNotIn(f"release_apply_success_{later_name}=1", facts)
                self.assertIn("cluster_absent=1", facts)
                self.assertIn("workload_tag_absent=1", facts)
                self.assertIn("kubeconfig_absent=1", facts)
                self.assertIn("work_absent=1", facts)
                self.assertRegex((evidence / "status").read_text(), r"^[1-9][0-9]*\n$")

    def test_release_same_size_mutation_during_apply_is_nonpass(self):
        names = [name for name, _, _ in RELEASES]
        for bad_index, bad_name in enumerate(names):
            with self.subTest(release=bad_name):
                output, evidence = self.run_lane(
                    "during-apply-release-corruption",
                    f"during-apply-{bad_name}",
                    extra_env={"D2_CORRUPT_RELEASE": bad_name},
                )
                self.assertNotEqual(output.returncode, 0)
                self.assertEqual(
                    (self.state / "release-applies").read_text().splitlines(),
                    names[:bad_index + 1],
                )
                facts = self.facts(evidence)
                self.assertNotIn(f"release_apply_success_{bad_name}=1", facts)
                self.assertNotIn(f"release_deleted={bad_name}", facts)
                self.assertNotIn(f"release_absent={bad_name}", facts)
                self.assertIn(
                    f"Knative release changed during apply: {bad_name}",
                    (evidence / "stderr.log").read_text(),
                )
                for later_name in names[bad_index + 1:]:
                    self.assertNotIn(f"release_apply_success_{later_name}=1", facts)
                self.assertIn("cluster_absent=1", facts)
                self.assertIn("workload_tag_absent=1", facts)
                self.assertIn("kubeconfig_absent=1", facts)
                self.assertIn("work_absent=1", facts)
                self.assertRegex((evidence / "status").read_text(), r"^[1-9][0-9]*\n$")

    def test_private_project_cleanup_ignores_malformed_work_facts(self):
        shared = ROOT / "target/matrix-knative"
        shared_before = self.tree_receipt(shared)
        sentinel = self.outside / "preserved"
        sentinel.write_bytes(b"outside-owned-sentinel\n")
        sentinel.chmod(0o640)
        output, evidence = self.run_lane("cleanup-cluster-failure", "retained-work")
        self.assertNotEqual(output.returncode, 0)
        facts = self.facts(evidence)
        work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
        self.assertTrue(self.work_path(work).is_dir())
        with (evidence / "facts.log").open("a") as stream:
            stream.write(f"work={self.outside}\n")
            stream.write("work=target/matrix-knative/../../foreign\n")
        self.cleanup_case()
        self.assertEqual(sentinel.read_bytes(), b"outside-owned-sentinel\n")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
        shared_after = self.tree_receipt(shared)
        self.assertEqual(shared_after, shared_before)

    def test_signals_finalize_and_cleanup(self):
        output, evidence = self.run_lane("signal-after-root")
        self.assertIn(output.returncode, (1, 143))
        self.assertEqual((evidence / "status").read_text(), f"{output.returncode}\n")
        facts = self.facts(evidence)
        self.assertIn("input_ledger_phase=unavailable-start", facts)
        self.assertIn("work_absent=1", facts)
        self.assertNotIn("input_ledger_start=", facts)
        work_parent = Path(self.env["P11SCOPE_MATRIX_TMPDIR"])
        self.assertFalse(work_parent.exists() and any(work_parent.iterdir()))

        self.clear_state()
        evidence = self.root / "terminal-signal"
        proc = self.start_owned(
            ["sh", str(self.gate)],
            self.env | {"D2_MODE": "terminal-signal",
                        "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
        )
        try:
            deadline = time.monotonic() + TERMINAL_READINESS_TIMEOUT_SECONDS
            while not (self.state / "terminal-signal-ready").exists() and time.monotonic() < deadline:
                self.assertIsNone(proc.poll(), "terminal boundary exited early")
                time.sleep(0.01)
            self.assertTrue((self.state / "terminal-signal-ready").exists())
            self.signal_owned_process(proc, signal.SIGTERM)
        finally:
            (self.state / "terminal-signal-go").write_text("go\n")
        stdout, stderr = self.finish_owned(proc, slack(8))
        self.assertNotEqual(proc.returncode, 0, f"{stdout}\n{stderr}")
        self.assertEqual((evidence / "status").read_text(), "1\n")
        facts = self.facts(evidence)
        for line in facts.splitlines():
            if line.startswith("work="):
                self.assertFalse(self.work_path(line.removeprefix("work=")).exists())

        self.clear_state()
        evidence = self.root / "outer-signal"
        proc = self.start_owned(
            ["sh", str(self.gate)],
            self.env | {"D2_MODE": "sleep-build",
                        "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
        )
        deadline = time.monotonic() + slack(5)
        while not (self.state / "sleep-build-ready").exists() and time.monotonic() < deadline:
            self.assertIsNone(proc.poll(), "outer signal body exited before WORK")
            time.sleep(0.025)
        self.assertTrue((self.state / "sleep-build-ready").exists())
        retained_body = self.retain_body_handle(evidence)
        self.assertTrue(self._pidfd_is_live(retained_body["pidfd"]))
        self.signal_owned_process(proc, signal.SIGTERM)
        self.finish_owned(proc, slack(5))
        self.assertTrue((evidence / "status").is_file())
        facts = self.facts(evidence)
        work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
        deadline = time.monotonic() + slack(5)
        while self.work_path(work).exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(self.work_path(work).exists())
        self.assertEqual(self.settle_recorded(), [])
        self.assertFalse(self._pidfd_is_live(retained_body["pidfd"]))

    def test_cleanup_waits_for_writer_after_its_session_leader_exits(self):
        self.cleanup_writer_case(refuse_cleanup=False)

    def test_cleanup_retains_evidence_if_session_writer_does_not_exit(self):
        self.cleanup_writer_case(refuse_cleanup=True)

    def test_cleanup_waits_for_worker_after_thread_group_leader_exits(self):
        self.cleanup_writer_case(refuse_cleanup=False, threaded_writer=True)

    def test_cleanup_rescans_child_forked_during_process_inventory(self):
        self.cleanup_writer_case(refuse_cleanup=False, relay_writer=True)

    def test_cleanup_retains_evidence_if_zombie_leader_has_live_worker(self):
        self.cleanup_writer_case(refuse_cleanup=True, threaded_writer=True)

    def test_cleanup_retains_evidence_for_child_forked_during_inventory(self):
        self.cleanup_writer_case(refuse_cleanup=True, relay_writer=True)

    def cleanup_writer_case(self, refuse_cleanup, threaded_writer=False, relay_writer=False):
        evidence = self.root / "late-writer"
        evidence.mkdir()
        read_fd, write_fd = os.pipe()
        descriptor = None
        descriptors = []
        relay_read, relay_write = os.pipe()
        timer = None
        real_cleanup = self.temp.cleanup
        try:
            code = """import os,sys,time
from pathlib import Path
root = Path(sys.argv[1])
control = int(sys.argv[2])
mode = sys.argv[3]
relay = int(sys.argv[4])
pid = os.fork()
if pid == 0:
    null = os.open(os.devnull, os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(null, target)
    os.close(null)
    def write_late():
        os.read(control, 1)
        (root / 'late.sha256').write_text('completed\\n')
        os._exit(0)
    (root / 'writer.pending').write_text(str(os.getpid()))
    (root / 'writer.pending').replace(root / 'writer.pid')
    if mode == 'threaded':
        import ctypes,threading
        threading.Thread(target=write_late).start()
        ctypes.CDLL(None).pthread_exit(None)
    elif mode == 'relay':
        os.read(relay, 1)
        if os.fork() != 0:
            os._exit(0)
        (root / 'writer-next.pending').write_text(str(os.getpid()))
        (root / 'writer-next.pending').replace(root / 'writer-next.pid')
        write_late()
    else:
        write_late()
os.close(control)
time.sleep(20)
"""
            mode = "threaded" if threaded_writer else "relay" if relay_writer else "single"
            parent = self.start_owned(
                [sys.executable, "-I", "-c", code, str(evidence), str(read_fd),
                 mode, str(relay_read)],
                self.env | {"P11SCOPE_LANE_EVIDENCE_DIR": str(evidence)},
                pass_fds=(read_fd, relay_read),
            )
            deadline = time.monotonic() + slack(5)
            while not (evidence / "writer.pid").exists() and time.monotonic() < deadline:
                self.assertIsNone(parent.poll())
                time.sleep(0.01)
            child = int((evidence / "writer.pid").read_text())
            descriptor = os.pidfd_open(child)
            descriptors.append(descriptor)
            self.assertEqual(self.read_process_identity(child)["sid"], parent.pid)
            self.assertTrue(self._pidfd_is_live(descriptor))
            if threaded_writer:
                while self.read_process_snapshot(child)["state"] != "Z" \
                        and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(self.read_process_snapshot(child)["state"], "Z")
                self.assertTrue(self._pidfd_is_live(descriptor))
            settled = self.settle_recorded
            read_snapshot = self.read_process_snapshot
            relay_started = False

            def snapshot_after_relay(pid):
                nonlocal descriptor, relay_started, timer
                if relay_writer and pid == child and not relay_started:
                    relay_started = True
                    os.write(relay_write, b"go")
                    ready = evidence / "writer-next.pid"
                    deadline = time.monotonic() + slack(5)
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    replacement = int(ready.read_text())
                    descriptor = os.pidfd_open(replacement)
                    descriptors.append(descriptor)
                    self.assertEqual(read_snapshot(replacement)["identity"]["sid"], parent.pid)
                    self.assertTrue(select.select([descriptors[0]], [], [], 5)[0])
                    self.assertTrue(self._pidfd_is_live(descriptor))
                    if not refuse_cleanup:
                        timer = threading.Timer(0.25, os.write, args=(write_fd, b"go"))
                        timer.start()
                return read_snapshot(pid)

            def settle_then_release_writer(*args, **kwargs):
                nonlocal timer
                result = settled(*args, **kwargs)
                launch = next(item for item in self.owned_launches.values()
                              if item["process"] is parent)
                self.assertFalse(self._pidfd_is_live(launch["pidfd"]))
                if not refuse_cleanup and not relay_writer:
                    timer = threading.Timer(0.25, os.write, args=(write_fd, b"go"))
                    timer.start()
                return result

            def delete_only_after_writer_exit():
                self.assertFalse(self._pidfd_is_live(descriptor),
                                 "evidence deletion raced an owned session writer")
                self.assertEqual((evidence / "late.sha256").read_text(), "completed\n")
                real_cleanup()

            with mock.patch.object(self, "settle_recorded", side_effect=settle_then_release_writer), \
                    mock.patch.object(self, "read_process_snapshot", side_effect=snapshot_after_relay), \
                    mock.patch.object(self.temp, "cleanup", side_effect=delete_only_after_writer_exit):
                if refuse_cleanup:
                    with mock.patch(__name__ + ".CLEANUP_SETTLE_SECONDS", 0), \
                            self.assertRaisesRegex(AssertionError, "owned session writers remained live"):
                        self.cleanup_case()
                    self.assertTrue(self.root.exists())
                    self.assertTrue(self._pidfd_is_live(descriptor))
                    self.assertFalse((evidence / "late.sha256").exists())
                else:
                    self.cleanup_case()
                    self.assertFalse(self.root.exists())
                if relay_writer:
                    self.assertTrue(relay_started)
        finally:
            os.write(relay_write, b"go")
            if timer is not None:
                timer.join(timeout=slack(2))
            else:
                os.write(write_fd, b"go")
            for handle in descriptors:
                self.close_controlled_handle(handle)
            os.close(read_fd)
            os.close(write_fd)
            os.close(relay_read)
            os.close(relay_write)
            real_cleanup()

    def test_retained_body_handle_settles_when_late_inventory_is_malformed(self):
        decoy = self.start_decoy()
        proc, evidence, pidfile, release, body = self.start_controlled_body(
            "retained-body-malformed-inventory", ignore_term=True
        )
        original_record = None
        try:
            retained_body = self.retain_body_handle(evidence)
            self.assertTrue(self._pidfd_is_live(retained_body["pidfd"]))
            original_record = pidfile.read_bytes()
            pidfile.write_bytes(b"{\n")

            release.write_text("exit\n")
            self.finish_owned(proc, slack(5))
            transitioned = self.read_process_snapshot(body["pid"])
            self.assertNotEqual(transitioned["identity"]["ppid"], body["ppid"])
            self.assertNotEqual(transitioned["state"], "Z")
            self.assertTrue(self._pidfd_is_live(retained_body["pidfd"]))
            diagnostics_before = len(self.settlement_diagnostics)
            failures = self.settle_recorded()
            try:
                json.loads("{\n")
            except json.JSONDecodeError as error:
                expected_failure = (
                    f"body identity inventory: malformed body identity in {pidfile}: {error}"
                )
            self.assertEqual(failures, [expected_failure])
            diagnostics = self.settlement_diagnostics[diagnostics_before:]
            self.assertEqual(len(diagnostics), 1, diagnostics)
            self.assertIn(f"record={body['record_id']}", diagnostics[0])
            for marker in ("expected=", "current=", "state=", "pinnedfd_ready=false"):
                self.assertIn(marker, diagnostics[0])
            self.assertFalse(self._pidfd_is_live(retained_body["pidfd"]))
            self.assertIsNone(decoy.poll(), "retained body settlement signaled the decoy")
            self.acknowledge_settlement_errors()
        finally:
            release.write_text("exit\n")
            if original_record is not None and pidfile.parent.exists():
                pidfile.write_bytes(original_record)
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def test_body_handle_admission_ignores_scheduler_state_only_transition(self):
        proc, evidence, _, release, body = self.start_controlled_body(
            "body-state-transition"
        )
        real_snapshot = self.read_process_snapshot
        body_reads = 0

        def transition_state(pid):
            nonlocal body_reads
            snapshot = real_snapshot(pid)
            if pid == body["pid"]:
                body_reads += 1
                if body_reads == 2:
                    snapshot = snapshot | {
                        "state": "R" if snapshot["state"] != "R" else "S"
                    }
            return snapshot

        try:
            with mock.patch.object(
                self, "read_process_snapshot", side_effect=transition_state
            ):
                retained = self.retain_body_handle(evidence)
            self.assertEqual(body_reads, 2)
            self.assertTrue(self._pidfd_is_live(retained["pidfd"]))
        finally:
            release.write_text("exit\n")
        self.finish_owned(proc, slack(5))
        self.assertEqual(self.settle_recorded(), [])

    def test_exit_before_real_term_keeps_published_descriptor_owned(self):
        proc, evidence, _, release, body = self.start_controlled_body(
            "exit-before-real-term"
        )
        other_evidence = self.root / "later-owned-settlement"
        other = self.start_owned(
            ["/bin/sleep", scaled_whole_seconds(20)],
            self.env | {"P11SCOPE_LANE_EVIDENCE_DIR": str(other_evidence)},
        )
        decoy = self.start_decoy()
        control = os.dup(self.controlled_bodies[evidence]["pidfd"])
        self.addCleanup(os.close, control)
        real_reread = self._reread_record
        real_sender = signal.pidfd_send_signal
        exited = False
        observed_esrch = []

        def exit_after_final_read(record):
            nonlocal exited
            if record["record_id"] == body["record_id"] and not exited:
                exited = True
                self.reap_controlled_body_after_final_read(
                    proc, control, body, real_sender
                )
            return real_reread(record)

        def observe_real_sender(descriptor, signal_number, siginfo=None, flags=0):
            try:
                return real_sender(descriptor, signal_number, siginfo, flags)
            except ProcessLookupError:
                observed_esrch.append((descriptor, signal_number))
                raise

        try:
            with mock.patch.object(self, "_reread_record", side_effect=exit_after_final_read), \
                    mock.patch("signal.pidfd_send_signal", side_effect=observe_real_sender):
                self.assertEqual(self.settle_recorded(), [])
            self.assertTrue(exited)
            self.assertTrue(observed_esrch, "real TERM sender did not report ESRCH")
            self.assertIsNotNone(other.poll(), "later owned process was not settled")
            self.assertIsNone(decoy.poll(), "exit-before-TERM settlement signaled decoy")
        finally:
            release.write_text("exit\n")
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def test_failed_exit_readiness_assertion_resumes_outer_and_reaps_child(self):
        proc, evidence, _, release, body = self.start_controlled_body(
            "failed-exit-readiness"
        )
        decoy = self.start_decoy()
        control = os.dup(self.controlled_bodies[evidence]["pidfd"])
        self.addCleanup(os.close, control)
        try:
            with mock.patch.object(
                self, "assertFalse", side_effect=AssertionError("injected readiness failure")
            ):
                with self.assertRaisesRegex(AssertionError, "injected readiness failure"):
                    self.reap_controlled_body_after_final_read(
                        proc, control, body, signal.pidfd_send_signal
                    )
            try:
                outer_stdout, outer_stderr = proc.communicate(timeout=slack(2))
            except subprocess.TimeoutExpired:
                self.fail("controlled outer remained stopped after readiness failure")
            self.assertEqual(proc.returncode, 0, outer_stderr)
            self.assertIn(f"controlled child settled {body['pid']}", outer_stdout)
            self.assert_process_absent(body["pid"], body["starttime"])
            self.assertEqual(self.settle_recorded(), [])
            self.assertIsNone(decoy.poll(), "readiness failure settlement signaled decoy")
        finally:
            release.write_text("exit\n")
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def test_exited_retained_body_ignores_late_numeric_observation(self):
        proc, evidence, _, release, body = self.start_controlled_body(
            "exited-retained-body"
        )
        decoy = self.start_decoy()
        retained = self.retain_body_handle(evidence)
        signal.pidfd_send_signal(retained["pidfd"], signal.SIGKILL, None, 0)
        deadline = time.monotonic() + slack(2)
        while self._pidfd_is_live(retained["pidfd"]) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(self._pidfd_is_live(retained["pidfd"]))
        release.write_text("exit\n")
        self.finish_owned(proc, slack(5))
        real_snapshot = self.read_process_snapshot
        real_open = os.pidfd_open
        real_send = signal.pidfd_send_signal
        for label in ("absent", "different-occupant"):
            observed = []
            reopened = []
            signaled = []

            def late_snapshot(pid):
                if pid == body["pid"]:
                    observed.append(pid)
                    if label == "absent":
                        raise FileNotFoundError(pid)
                    return real_snapshot(decoy.pid)
                return real_snapshot(pid)

            def tracked_open(pid):
                if pid == body["pid"]:
                    reopened.append(pid)
                return real_open(pid)

            def tracked_send(descriptor, signal_number, siginfo=None, flags=0):
                if descriptor == retained["pidfd"]:
                    signaled.append(signal_number)
                return real_send(descriptor, signal_number, siginfo, flags)

            with mock.patch.object(self, "read_process_snapshot", side_effect=late_snapshot), \
                    mock.patch("os.pidfd_open", side_effect=tracked_open), \
                    mock.patch("signal.pidfd_send_signal", side_effect=tracked_send):
                self.assertEqual(self.settle_recorded(), [])
            self.assertEqual(observed, [], label)
            self.assertEqual(reopened, [], label)
            self.assertEqual(signaled, [], label)
            self.assertIsNone(decoy.poll(), label)
        decoy.terminate()
        try:
            decoy.wait(timeout=slack(2))
        except subprocess.TimeoutExpired:
            decoy.kill()
            decoy.wait(timeout=slack(2))

    def test_retained_body_exit_during_late_observation_owns_settlement(self):
        decoy = self.start_decoy()
        for label in ("absent", "different-occupant"):
            proc, evidence, _, release, body = self.start_controlled_body(
                "exit-during-observation-" + label, ignore_term=True
            )
            retained = self.retain_body_handle(evidence)
            release.write_text("exit\n")
            self.finish_owned(proc, slack(3))
            self.assertTrue(self._pidfd_is_live(retained["pidfd"]))
            real_snapshot = self.read_process_snapshot
            observed = []

            def exit_during_snapshot(pid):
                if pid == body["pid"]:
                    self.assertTrue(self._pidfd_is_live(retained["pidfd"]))
                    observed.append(pid)
                    signal.pidfd_send_signal(retained["pidfd"], signal.SIGKILL, None, 0)
                    self.assertTrue(select.select([retained["pidfd"]], [], [], 2)[0])
                    if label == "absent":
                        raise FileNotFoundError(pid)
                    return real_snapshot(decoy.pid)
                return real_snapshot(pid)

            with mock.patch.object(self, "read_process_snapshot", side_effect=exit_during_snapshot), \
                    mock.patch("os.pidfd_open", side_effect=AssertionError("late reopen")):
                failures = self.settle_recorded()
            self.assertEqual(observed, [body["pid"]])
            self.assertFalse(self._pidfd_is_live(retained["pidfd"]))
            self.assertIsNone(decoy.poll(), label)
            self.assertEqual(failures, [], label)
            print(f"observation-window {label}: original exited; decoy live; failures={failures}")

    def test_retained_body_inspection_error_still_settles_original(self):
        decoy = self.start_decoy()
        proc, evidence, _, release, body = self.start_controlled_body(
            "live-inspection-error", ignore_term=True
        )
        retained = self.retain_body_handle(evidence)
        release.write_text("exit\n")
        self.finish_owned(proc, slack(3))
        self.assertTrue(self._pidfd_is_live(retained["pidfd"]))
        real_snapshot = self.read_process_snapshot
        inspected = []

        def inspection_error(pid):
            if pid == body["pid"]:
                inspected.append(pid)
                raise OSError("controlled proc inspection failure")
            return real_snapshot(pid)

        with mock.patch.object(self, "read_process_snapshot", side_effect=inspection_error), \
                mock.patch("os.pidfd_open", side_effect=AssertionError("late reopen")):
            failures = self.settle_recorded()
        self.assertEqual(inspected, [body["pid"]])
        self.assertFalse(self._pidfd_is_live(retained["pidfd"]),
                         "optional inspection skipped original-handle settlement")
        self.assertIsNone(decoy.poll())
        self.assertEqual(failures, [
            f"inspect {body['record_id']}: controlled proc inspection failure"
        ])
        self.acknowledge_settlement_errors()
        print(f"inspection-error: original exited; decoy live; failures={failures}")

    def test_conflicting_unaccepted_record_cannot_suppress_original_settlement(self):
        decoy = self.start_decoy()
        proc, evidence, _, release, body = self.start_controlled_body(
            "conflicting-inventory", ignore_term=True
        )
        retained = self.retain_body_handle(evidence)
        owner = next(owner for owner, launch in self.owned_launches.items()
                     if launch["process"] is proc)
        kind = "dispatch-kubectl"
        record_id = f"{owner}:{kind}:{body['pid']}:{body['starttime']}"
        conflict = {
            "version": 1, "record_id": record_id, "owner": owner,
            "evidence": str(evidence), "kind": kind,
            "pid": body["pid"], "starttime": body["starttime"],
            "ppid": body["ppid"], "pgid": body["pgid"] + 1,
            "sid": body["sid"], "exe": "/usr/bin/python3", "argv": body["argv"],
        }
        ledger = self.state / "fixture-pids"
        self.addCleanup(ledger.unlink, missing_ok=True)
        ledger.write_text(json.dumps(conflict) + "\n")
        self.assertEqual(self.fixture_records(), [conflict])
        release.write_text("exit\n")
        self.finish_owned(proc, slack(3))
        self.assertTrue(self._pidfd_is_live(retained["pidfd"]))
        failures = self.settle_recorded()
        self.assertFalse(self._pidfd_is_live(retained["pidfd"]),
                         "unaccepted duplicate suppressed original-handle settlement")
        self.assertEqual(len(failures), 1, failures)
        self.assertIn(f"identity mismatch before pin record={record_id}", failures[0])
        self.assertIsNone(decoy.poll())
        ledger.unlink()
        self.acknowledge_settlement_errors()
        print("conflicting-inventory: unaccepted record rejected; original exited; decoy live")

    def test_controlled_body_setup_failures_settle_original_before_return(self):
        decoy = self.start_decoy()
        for fault, expected in (
            ("before-ready", "controlled failure before readiness wait"),
            ("ready-timeout", "controlled body readiness timeout"),
            ("stat", "controlled body stat failure"),
            ("publication", "controlled body publication failure"),
        ):
            with self.subTest(fault=fault):
                label = "controlled-setup-" + fault
                started = time.monotonic()
                with self.assertRaisesRegex(ControlledBodySetupError, expected) as caught:
                    self.start_controlled_body(label, ignore_term=True, fault=fault)
                controlled = self.controlled_bodies[self.root / label]
                self.assertFalse(self._pidfd_is_live(controlled["pidfd"]),
                                 "outer returned without settling original child")
                self.assertIsNotNone(controlled["process"].returncode)
                self.assertIn("controlled outer exit=1", str(caught.exception))
                self.assertIn(f"controlled child settled {controlled['pid']}", str(caught.exception))
                self.assertNotIn("owned child did not settle", str(caught.exception))
                self.assertFalse((self.root / label / ".lane13-body.pid").exists())
                self.assertLess(time.monotonic() - started, slack(5))
                self.assertIsNone(decoy.poll())
                print(f"setup-{fault}: outer exit=1; original exited before return; decoy live")

    def test_assertion_failure_runs_registered_original_and_decoy_cleanup(self):
        # The normal TestCase stack runs even when the assertion below fails.
        # Independent copies protect the sensitivity run if registration regresses.
        owned = {}

        def fail_after_acquisition():
            with mock.patch.object(self, "addCleanup", side_effect=inner.addCleanup):
                decoy = self.start_decoy()
            original_add_cleanup(self.close_owned_child, decoy)
            owned["decoy"] = decoy
            with mock.patch.object(self, "addCleanup", side_effect=inner.addCleanup):
                proc, evidence, _, _, _ = self.start_controlled_body("assertion-cleanup")
            original_fd = self.controlled_bodies[evidence]["pidfd"]
            rescue = os.dup(original_fd)
            original_add_cleanup(self.close_controlled_handle, rescue)
            owned["rescue"] = rescue
            owned["outer"] = proc
            raise AssertionError("controlled assertion after original acquisition")

        original_add_cleanup = self.addCleanup
        inner = unittest.FunctionTestCase(fail_after_acquisition)
        result = unittest.TestResult()
        inner.run(result)
        self.assertEqual(len(result.failures), 1, result.failures)
        self.assertIn("controlled assertion after original acquisition", result.failures[0][1])
        self.assertEqual(result.errors, [])
        self.assertIsNotNone(owned["decoy"].poll(), "registered decoy cleanup was skipped")
        self.assertFalse(self._pidfd_is_live(owned["rescue"]), "registered original cleanup was skipped")
        self.finish_owned(owned["outer"], slack(3))
        print("assertion-failure: expected failure retained; original and decoy settled by registered cleanup")

    def test_forced_holds_are_bounded_settled_and_preserve_decoy(self):
        decoy = self.start_decoy()
        try:
            # The 1 s budget starts at each hold marker. The readiness hold is
            # the dispatch's 4 s D2_HOLD_SECONDS sleep, so the timeout fires
            # inside it whatever setup took; the communication hold lasts until
            # settlement releases it.
            for label, mode, extra, marker in (
                ("terminal-readiness-failure", "terminal-readiness-failure", {},
                 "terminal-readiness-hold"),
                ("terminal-communication-timeout", "terminal-communication-timeout", {},
                 "terminal-signal-ready"),
            ):
                with self.subTest(mode=label):
                    output, _ = self.run_lane(
                        mode, name=label, timeout=1, extra_env=extra, hold_marker=marker
                    )
                    self.assertNotEqual(output.returncode, 0, output.stderr)
                    self.assertEqual(output.returncode, 124, output.stderr)
                    self.assertIn("native fixture communication timeout", output.stderr)
                    # Boundedness of the held phase and its settlement; setup
                    # before the marker is a separate SLACK wait.
                    self.assertLess(time.monotonic() - self.budget_started, slack(10))
                    if label == "terminal-readiness-failure":
                        self.assertTrue((self.state / "terminal-readiness-hold").exists())
                        self.assertFalse((self.state / "terminal-signal-ready").exists())
                    elif label == "terminal-communication-timeout":
                        self.assertTrue((self.state / "terminal-signal-ready").exists())
                    self.assertEqual(self.settle_recorded(), [])
                    self.assertIsNone(decoy.poll())
        finally:
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def observe_missing_terminal_readiness(self, launched, proc, evidence):
        # The controlled failure starts only after dispatch has recorded its
        # identity and entered the hold. Scheduling and fsync before that phase
        # belong to setup, not to the 200 ms missing-readiness observation.
        held = self.state / "terminal-readiness-hold"
        setup_deadline = launched + TERMINAL_READINESS_TIMEOUT_SECONDS
        while not held.exists() and time.monotonic() < setup_deadline:
            self.assertIsNone(proc.poll(), "terminal boundary exited before controlled hold")
            time.sleep(0.01)
        setup_diagnostic = None if held.exists() else self.terminal_readiness_diagnostic(
            launched, proc, evidence
        )
        self.assertTrue(held.exists(), setup_diagnostic)

        ready = self.state / "terminal-signal-ready"
        deadline = time.monotonic() + 0.2
        while not ready.exists() and time.monotonic() < deadline:
            self.assertIsNone(proc.poll(), "terminal boundary exited before controlled timeout")
            time.sleep(0.01)
        diagnostic = None if ready.exists() else self.terminal_readiness_diagnostic(
            launched, proc, evidence
        )
        self.assertTrue(ready.exists(), diagnostic)

    def test_missing_terminal_readiness_observation_waits_for_delayed_setup(self):
        # Model 350 ms of fixture setup without a wall-clock race. The actual
        # marker and diagnostic formatter remain real; only scheduling is
        # controlled. Starting the 200 ms observation at launch would inspect
        # the fixture before it reaches the intentionally held phase.
        clock = [0.0]
        evidence = self.root / "delayed-readiness-diagnostic"

        class LiveProcess:
            pid = os.getpid()

            @staticmethod
            def poll():
                return None

        def advance(seconds):
            clock[0] = round(clock[0] + seconds, 6)
            if clock[0] >= 0.35:
                (self.state / "terminal-readiness-hold").touch()

        inner = unittest.FunctionTestCase(
            lambda: self.observe_missing_terminal_readiness(0.0, LiveProcess(), evidence)
        )
        result = unittest.TestResult()
        with mock.patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(time, "sleep", side_effect=advance):
            inner.run(result)
        self.assertEqual(len(result.failures), 1, result.failures)
        self.assertEqual(result.errors, [])
        self.assertIn("phase_markers=terminal-readiness-hold", result.failures[0][1])
        self.assertEqual(clock[0], 0.55, "200 ms observation follows 350 ms of setup")
        self.assertFalse((self.state / "terminal-signal-ready").exists())

    def test_missing_terminal_readiness_reports_bounded_diagnostics(self):
        evidence = self.root / "controlled-readiness-diagnostic"
        proc = self.start_owned(
            ["sh", str(self.gate)],
            self.env | {
                "D2_MODE": "terminal-readiness-failure",
                "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence),
            },
        )
        launched = time.monotonic()

        inner = unittest.FunctionTestCase(
            lambda: self.observe_missing_terminal_readiness(launched, proc, evidence)
        )
        result = unittest.TestResult()
        inner.run(result)
        self.assertEqual(len(result.failures), 1, result.failures)
        self.assertEqual(result.errors, [])
        failure = result.failures[0][1]
        for expected in (
            "elapsed_after_launch=", "outer_process=", "fixture_call_tail=",
            "body_diagnostics=", "phase_markers=terminal-readiness-hold",
        ):
            self.assertIn(expected, failure)

        calls = self.state / "calls"
        calls.unlink()
        try:
            missing_calls = self.terminal_readiness_diagnostic(launched, proc, evidence)
        except OSError as error:
            self.fail(f"missing calls ledger masked readiness diagnostic: {error}")
        self.assertIn('fixture_call_tail=["absent"]', missing_calls)

        calls.mkdir()
        try:
            unreadable_calls = self.terminal_readiness_diagnostic(launched, proc, evidence)
        except OSError as error:
            self.fail(f"unreadable calls ledger masked readiness diagnostic: {error}")
        self.assertIn("fixture_call_tail=", unreadable_calls)
        self.assertIn("unavailable:", unreadable_calls)
        calls.rmdir()

        oversized = b"oversized:" + (b"\0" * 20000)
        calls.write_bytes(oversized)
        diagnostic_evidence = self.root / "oversized-diagnostic-inputs"
        diagnostic_evidence.mkdir()
        for name in (".lane13-body.pid", "stdout.log", "stderr.log", "facts.log"):
            (diagnostic_evidence / name).write_bytes(oversized)
        bounded = self.terminal_readiness_diagnostic(
            launched, proc, diagnostic_evidence
        )
        self.assertLessEqual(len(bounded.encode("utf-8")), 8192)
        for expected in (
            "elapsed_after_launch=", "outer_process=", "fixture_call_tail=",
            "body_diagnostics=", "phase_markers=", "byte_tail_truncated=",
            "field_truncated=1", "diagnostic_truncated=1",
        ):
            self.assertIn(expected, bounded)
        self.assertFalse((self.state / "terminal-signal-ready").exists())
        self.assertEqual(self.settle_recorded(), [])

    def test_cleanup_rejects_between_read_and_pin_identity_change(self):
        decoy = self.start_decoy()
        proc, control, target = self.start_recorded_hold("identity-change")
        original_fd = self.owned_launches[target["owner"]]["pidfd"]
        ledger = self.state / "fixture-pids"
        original = ledger.read_bytes()
        try:
            decoy_identity = self.read_process_identity(decoy.pid)

            def replace_identity(record):
                if record["record_id"] != target["record_id"]:
                    return
                replacement = target | decoy_identity | {
                    "pid": decoy.pid,
                    "argv": list(decoy.args),
                }
                ledger.write_text(json.dumps(replacement, separators=(",", ":")) + "\n")

            self.before_pidfd_open = replace_identity
            # This direct child has two valid authorities: its fixture record
            # and start_owned's retained launch. Keep the authentication map,
            # but defer independent launch settlement for this one assertion;
            # otherwise that valid route kills the original even when the
            # poisoned fixture record is correctly rejected.
            failures = self.settle_recorded(defer_owned_process=proc)
            self.assertTrue(self._pidfd_is_live(original_fd),
                            "identity-race rejection signaled the original")
            self.assertIsNone(decoy.poll(), "identity-race rejection signaled the decoy")
            self.assertEqual(len(failures), 1, failures)
            self.assertTrue(
                any("identity record changed before pin" in failure for failure in failures),
                failures,
            )
            self.assertIsNone(decoy.poll(), "identity-race rejection signaled the decoy")
            ledger.write_bytes(original)
            self.before_pidfd_open = None
            self.acknowledge_settlement_errors()
            self.assertEqual(self.settle_recorded(), [])
            proc.communicate(timeout=slack(2))
            self.assertFalse(self._pidfd_is_live(original_fd))
            self.assert_process_absent(target["pid"], target["starttime"])
            self.assertIsNone(decoy.poll())

            unknown = target | {"owner": "unknown-owned-launch"}
            unknown["record_id"] = (
                f"{unknown['owner']}:{unknown['kind']}:{unknown['pid']}:{unknown['starttime']}"
            )
            mismatched = target | {"record_id": "mismatched-record-id"}
            for label, payload, expected in (
                ("malformed", b"{\n", "malformed fixture identity"),
                ("unknown", (json.dumps(unknown) + "\n").encode(),
                 "unknown fixture launch authority"),
                ("mismatched", (json.dumps(mismatched) + "\n").encode(),
                 "mismatched fixture record id"),
            ):
                with self.subTest(invalid=label):
                    ledger.write_bytes(payload)
                    rejected = self.settle_recorded()
                    self.assertEqual(len(rejected), 1, rejected)
                    self.assertTrue(any(expected in item for item in rejected), rejected)
                    self.assertIsNone(decoy.poll())
            ledger.write_bytes(original)
            self.acknowledge_settlement_errors()
        finally:
            self.before_pidfd_open = None
            ledger.write_bytes(original)
            # Retained exact custody covers failed assertions too. Reap the
            # direct child before cleanup_case can remove its filesystem.
            if self._pidfd_is_live(original_fd):
                try:
                    signal.pidfd_send_signal(original_fd, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
            proc.communicate(timeout=slack(2))
            control.close()
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))
        self.assertFalse(self._pidfd_is_live(original_fd), "writer still live at deletion")
        self.assertIsNotNone(proc.returncode, "original direct child was not reaped")
        self.assertIsNotNone(decoy.returncode, "decoy direct child was not reaped")
        self.cleanup_case()
        self.assertFalse(self.root.exists())

    def test_actual_port_forward_timeout_is_nonpass_and_settled(self):
        decoy = self.start_decoy()
        evidence = self.root / "actual-port-forward-hold"
        proc = self.start_owned(
            ["sh", str(self.gate)],
            self.env | {
                "D2_MODE": "body-success",
                "D2_PORT_FORWARD_HOLD": "1",
                "D2_PORT_FORWARD_SECONDS": scaled_whole_seconds(15),
                "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence),
            },
        )
        try:
            ready = self.state / "portforward-ready"
            deadline = time.monotonic() + slack(12)
            while not ready.exists() and time.monotonic() < deadline:
                self.assertIsNone(proc.poll(), "production caller exited before native readiness")
                time.sleep(0.01)
            self.assertTrue(ready.exists(), self.calls())
            native = json.loads(ready.read_text())
            self.assertIn(native, self.fixture_records())
            self.assertEqual(native["kind"], "native-port-forward")
            self.assertEqual(native["pid"], native["pgid"])
            self.assertEqual(native["pid"], native["sid"])
            self.assertEqual(self.read_process_identity(native["pid"]), {
                key: native[key] for key in ("starttime", "ppid", "pgid", "sid")
            })
            body = json.loads((evidence / ".lane13-body.pid").read_text())

            with self.assertRaisesRegex(
                OwnedCommunicationTimeout, "native fixture communication timeout"
            ) as caught:
                self.finish_owned(proc, 0.05)
            self.assertEqual(caught.exception.result.returncode, 124)
            self.assertNotEqual(int((evidence / "status").read_text()), 0)
            self.assert_process_absent(native["pid"], native["starttime"])
            self.assert_process_absent(body["pid"], body["starttime"])
            self.assertEqual(self.settle_recorded(), [])
            self.assertIsNone(decoy.poll())
        finally:
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def test_finish_owned_allows_outer_to_finalize_after_descendant_settlement(self):
        decoy = self.start_decoy()
        evidence = self.root / "delayed-outer-finalization"
        outer = """
import os
from pathlib import Path
import subprocess
import time

evidence = Path(os.environ["P11SCOPE_LANE_EVIDENCE_DIR"])
evidence.mkdir(mode=0o700)
status = evidence / "status"
status.touch(mode=0o600)
child = subprocess.Popen(
    ["kubectl", "port-forward", "-n", "kourier-system",
     "svc/kourier-internal", "127.0.0.1:80"],
    executable=os.environ["D2_PORT_FORWARD_HELPER"],
    start_new_session=True,
)
child.wait()
time.sleep(1.2)
status.write_text("1\\n", encoding="utf-8")
raise SystemExit(1)
"""
        proc = self.start_owned(
            [sys.executable, "-c", outer],
            self.env | {
                "D2_PORT_FORWARD_HOLD": "1",
                "D2_PORT_FORWARD_SECONDS": scaled_whole_seconds(15),
                "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence),
            },
        )
        try:
            ready = self.state / "portforward-ready"
            deadline = time.monotonic() + slack(5)
            while not ready.exists() and time.monotonic() < deadline:
                self.assertIsNone(proc.poll(), "delayed outer exited before native readiness")
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "native descendant did not publish readiness")
            native = json.loads(ready.read_text())

            # The bound under test is "outer finalizes after descendant
            # settlement", not "in under 2 s": the outer sleeps 1.2 s after
            # the child exits, so the follow-up slice gets headroom. The
            # 0.05 s budget above stays — it is the property under test.
            with self.assertRaisesRegex(
                OwnedCommunicationTimeout, "native fixture communication timeout"
            ) as caught:
                self.finish_owned(proc, 0.05, finalize_timeout=slack(10))
            self.assertEqual(caught.exception.result.returncode, 124)
            self.assertEqual((evidence / "status").read_text(), "1\n")
            self.assert_process_absent(native["pid"], native["starttime"])
            self.assertEqual(self.settle_recorded(), [])
            self.assertIsNone(decoy.poll())
        finally:
            decoy.terminate()
            try:
                decoy.wait(timeout=slack(2))
            except subprocess.TimeoutExpired:
                decoy.kill()
                decoy.wait(timeout=slack(2))

    def test_timeout_and_settlement_errors_remain_observable(self):
        evidence = self.root / "normal-timeout-rescue"
        proc = self.start_owned(
            ["sh", str(self.gate)],
            self.env | {
                "D2_MODE": "terminal-signal",
                "P11SCOPE_LANE_EVIDENCE_DIR": str(evidence),
            },
        )
        launched = time.monotonic()
        deadline = launched + TERMINAL_READINESS_TIMEOUT_SECONDS
        while not (self.state / "terminal-signal-ready").exists() and time.monotonic() < deadline:
            self.assertIsNone(proc.poll(), "terminal boundary exited before controlled timeout")
            time.sleep(0.01)
        ready = self.state / "terminal-signal-ready"
        diagnostic = None if ready.exists() else self.terminal_readiness_diagnostic(
            launched, proc, evidence
        )
        self.assertTrue(ready.exists(), diagnostic)
        self.signal_owned_process(proc, signal.SIGTERM)
        with self.assertRaisesRegex(
            OwnedCommunicationTimeout, "native fixture communication timeout"
        ):
            self.finish_owned(proc, 0.05)
        self.assertIsNotNone(proc.returncode)
        self.assertEqual(self.settle_recorded(), [])

        sleeper_evidence = self.root / "settlement-error"
        sleeper = self.start_owned(
            ["/bin/sleep", scaled_whole_seconds(20)],
            self.env | {"P11SCOPE_LANE_EVIDENCE_DIR": str(sleeper_evidence)},
        )
        real_sender = signal.pidfd_send_signal
        failed_once = False

        def fail_once(descriptor, signal_number, siginfo=None, flags=0):
            nonlocal failed_once
            if not failed_once:
                failed_once = True
                raise OSError("controlled settlement failure")
            return real_sender(descriptor, signal_number, siginfo, flags)

        with mock.patch("signal.pidfd_send_signal", side_effect=fail_once):
            failures = self.settle_recorded()
        self.assertEqual(len(failures), 1, failures)
        self.assertTrue(any("controlled settlement failure" in item for item in failures))
        sleeper.communicate(timeout=slack(2))
        sticky = tuple(self.settlement_errors)
        self.clear_state()
        self.assertEqual(self.settle_recorded(), [])
        self.assertEqual(tuple(self.settlement_errors), sticky)
        self.acknowledge_settlement_errors()

    def test_query_failures_preserve_unknown_absence(self):
        for mode, fact in (
            ("cleanup-image-query-failure", "workload_tag_absent=0"),
            ("cleanup-cluster-query-failure", "cluster_absent=0"),
            ("cleanup-node-query-failure", "cluster_absent=0"),
        ):
            with self.subTest(mode=mode):
                output, evidence = self.run_lane(mode)
                self.assertNotEqual(output.returncode, 0)
                self.assertEqual((evidence / "status").read_text(), "1\n")
                facts = self.facts(evidence)
                self.assertIn(fact, facts)
                self.assertNotIn(fact.replace("=0", "=1"), facts)

    def test_partial_creation_cleanup_and_replacement_refusal(self):
        for mode, cleanup_marker, absence in (
            ("partial-image-creation", "image-cleaned", "workload_tag_absent=1"),
            ("partial-cluster-creation", "cluster-delete-called", "cluster_absent=1"),
        ):
            with self.subTest(mode=mode):
                output, evidence = self.run_lane(mode)
                self.assertNotEqual(output.returncode, 0)
                self.assertTrue((self.state / cleanup_marker).is_file())
                facts = self.facts(evidence)
                self.assertIn(absence, facts)
                work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
                self.assertFalse(self.work_path(work).exists())
        output, evidence = self.run_lane("cluster-replacement")
        self.assertNotEqual(output.returncode, 0)
        self.assertFalse((self.state / "cluster-delete-called").exists())
        facts = self.facts(evidence)
        self.assertIn("cluster_absent=0", facts)
        self.assertIn("work_absent=0", facts)
        work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
        self.assertTrue(self.work_path(work).is_dir())

    def test_cleanup_failure_retains_diagnostics_and_continues(self):
        output, evidence = self.run_lane("cleanup-cluster-failure", "cleanup-failure")
        self.assertNotEqual(output.returncode, 0)
        self.assertIn("build product", (evidence / "stdout.log").read_text())
        self.assertIn(
            "controlled cluster cleanup failure", (evidence / "stderr.log").read_text()
        )
        facts = self.facts(evidence)
        work = next(line.removeprefix("work=") for line in facts.splitlines() if line.startswith("work="))
        self.assertTrue(self.work_path(work).is_dir())
        for marker in (
            "input_ledger_start=", "input_ledger_end=", "image_cluster_node_repo_digests=",
            "image_cluster_node_diff_ids=", "copied_provider_size=",
            "manifest_selected_provider_sha256=", "capture_provider_build_id=deadbeef",
            "cluster_absent=0", "workload_tag_absent=1", "kubeconfig_absent=1",
            "work_absent=0", "cleanup_status=",
        ):
            self.assertIn(marker, facts)
        self.assertEqual((evidence / "status").read_text(), "1\n")
        self.assertTrue((self.state / "cluster-delete-called").exists())
        self.assertTrue((self.state / "cluster").exists())
        self.assertTrue((self.state / "image-cleaned").exists())
        for name in ("observed.json", "manifest-host.json", "profile.log", "portforward.log",
                     "portforward.group.before.json", "portforward.group.after.json"):
            self.assertTrue((evidence / name).is_file())
        self.assertFalse((evidence / "foreign-unrelated.tmp").exists())
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
        for entry in evidence.iterdir():
            self.assertEqual(entry.stat().st_mode & 0o777, 0o600)

    def test_setup_copy_and_image_query_failures_are_nonpass(self):
        for mode in ("copy-failure", "setup-failure", "image-query-failure"):
            with self.subTest(mode=mode):
                output, evidence = self.run_lane(mode)
                self.assertNotEqual(output.returncode, 0)
                self.assertEqual((evidence / "status").read_text(), "1\n")
                if mode == "copy-failure":
                    self.assertTrue((self.state / "image-cleaned").exists())

    def test_mutation_is_refused_with_both_ledgers(self):
        output, evidence = self.run_lane("mutate-head")
        self.assertNotEqual(output.returncode, 0)
        facts = self.facts(evidence)
        for marker in (
            "git_head_start=", "git_head_end=", "git_tree_start=", "git_tree_end=",
            "git_status_end=", "input_ledger_start=", "input_ledger_end=",
        ):
            self.assertIn(marker, facts)
        self.assertIn("input_ledger_phase=complete", facts)


def main():
    global EBPF_OBJECT
    parser = argparse.ArgumentParser()
    parser.add_argument("--ebpf-object", required=True, type=Path)
    args, tests = parser.parse_known_args()
    EBPF_OBJECT = args.ebpf_object.resolve()
    if not args.ebpf_object.is_absolute() or not EBPF_OBJECT.is_file():
        parser.error("--ebpf-object must name an absolute regular file")
    runner_probe = os.environ.get("P11SCOPE_LANE13_RUNNER_PROBE")
    if runner_probe == "empty":
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite())
    elif runner_probe == "skip":
        def skip_probe():
            raise unittest.SkipTest("native runner skip probe")
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.TestSuite([unittest.FunctionTestCase(skip_probe)])
        )
    else:
        argv = [
            sys.argv[0],
            *(tests or ["Lane13InputLedgerTests", "Lane13EvidenceTests"]),
        ]
        result = unittest.main(argv=argv, exit=False, verbosity=2).result
    if result.testsRun == 0 or result.skipped or not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
