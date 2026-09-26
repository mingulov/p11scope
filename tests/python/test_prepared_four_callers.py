#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native tests for prepared-dependency integration in four receipt callers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
SNAPSHOT = REPOSITORY / "scripts/prepared-dependency-snapshot.sh"
MERGER = REPOSITORY / "scripts/merge-checksum-ledgers.py"
FIXTURES = REPOSITORY / "tests/fixtures/prepared-four-callers"
CALLERS = (
    REPOSITORY / "scripts/verify-induced-gaps.sh",
    REPOSITORY / "scripts/matrix/verify-oracle.sh",
    REPOSITORY / "scripts/matrix/verify-shared-layer.sh",
    REPOSITORY / "scripts/matrix/verify-fork-scope.sh",
)
CHILD_CALLERS = (CALLERS[0], CALLERS[2], CALLERS[3])
EvidenceFixture = __import__("runpy").run_path(
    str(REPOSITORY / "tests/python/test_prepared_dependency_evidence.py")
)["EvidenceFixture"]


def logical_commands(path: Path) -> list[str]:
    commands = []
    pending = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending.append(line)
        if not line.rstrip().endswith("\\"):
            commands.append("\n".join(pending))
            pending = []
    if pending:
        commands.append("\n".join(pending))
    return commands


def source_section(path: Path, start: str, end: str) -> str:
    source = path.read_text(encoding="utf-8")
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


class FinalizerFixture:
    def __init__(self, temporary: Path, caller: Path):
        self.base = temporary
        self.base.chmod(0o700)
        self.prepared = EvidenceFixture(temporary)
        self.root = self.prepared.root
        self.caller = caller
        self.oracle = caller == CALLERS[1]
        relative_caller = caller.relative_to(REPOSITORY)
        inputs = [
            "scripts/lib.sh", "scripts/prepared-dependency-evidence.py",
            "scripts/prepared-dependency-snapshot.sh", "scripts/merge-checksum-ledgers.py",
            "scripts/check-capture-evidence.py", relative_caller.as_posix(),
        ]
        if self.oracle:
            inputs += [
                "scripts/check-subset-oracle.py", "scripts/matrix/oracle-workload.sh",
                "scripts/matrix/oracle-cgroup-cleanup.py",
                "tests/fixtures/oracle-lifecycle/scenarios.sh",
                "tests/fixtures/oracle-lifecycle/sudo",
            ]
        if caller == CALLERS[0]:
            # The sourced receipt_finalize section shells out to this oracle.
            inputs += ["scripts/lane-induced-gaps-oracle-5.py"]
        for relative in inputs:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY / relative, destination)
        ignored = self.prepared.base.output.relative_to(self.root).as_posix()
        (self.root / ".gitignore").write_text(
            (REPOSITORY / ".gitignore").read_text(encoding="utf-8") + ignored + "/\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "fixture"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        self.tools = self.prepared.tools
        shutil.copy2(FIXTURES / "fixture_common.py", self.tools / "fixture_common.py")
        for name in ("stable cargo", "bpf cargo"):
            shutil.copy2(FIXTURES / "build-cargo.py", self.tools / name)
            (self.tools / name).chmod(0o755)
        self.python = temporary / "selected python with spaces"
        shutil.copy2(FIXTURES / "python-wrapper.py", self.python)
        self.python.chmod(0o755)
        self.receipt = temporary / "receipt"
        self.receipt.mkdir(mode=0o700)
        self.artifacts = self.receipt / "artifacts"
        self.work = self.receipt / "work"
        self.artifacts.mkdir(mode=0o700)
        self.work.mkdir(mode=0o700)
        for name in ("facts.log", "stdout.log", "stderr.log"):
            (self.receipt / name).write_text("", encoding="utf-8")
        (self.artifacts / "capture.json").write_text("capture\n", encoding="utf-8")
        (self.artifacts / "checker.log").write_text("checker\n", encoding="utf-8")
        labels = {CALLERS[0]: "induced", CALLERS[1]: "oracle",
                  CALLERS[2]: "shared", CALLERS[3]: "fork"}
        self.prefix = self.artifacts / f"{labels[caller]}.prepared"
        self.cleanup = temporary / "cleanup.marker"
        self.events = temporary / "events.jsonl"
        self.config_path = temporary / "config.json"
        self.config = {
            "events": str(self.events), "prefix": str(self.prefix),
            "driver_status": str(self.receipt / "status"),
            "cleanup_marker": str(self.cleanup),
            "root_metadata": str(self.prepared.root_metadata),
            "bpf_metadata": str(self.prepared.bpf_metadata),
        }
        self.write_config()
        self.environment = os.environ.copy()
        self.environment.update(P11SCOPE_FOUR_CALLERS_FIXTURE=str(self.config_path))
        self._capture_initial()
        stem = self.artifacts / f"{labels[caller]}.source.initial"
        snapshot = subprocess.run([
            "sh", str(FIXTURES / "snapshot-launcher.sh"),
            str(self.python), str(stem), str(Path(str(self.prefix) + ".initial.ledger.sha256")),
        ], cwd=self.root, env=self.environment, text=False, stdout=subprocess.PIPE,
           stderr=subprocess.PIPE)
        if snapshot.returncode:
            raise AssertionError(snapshot.stderr.decode())
        (self.artifacts / "source.start.tsv").write_bytes(snapshot.stdout)
        self.functions = temporary / "actual-finalizer-functions.sh"
        if not self.oracle:
            self.functions.write_text(
                source_section(caller, "receipt_snapshot() {", "receipt_fact()")
                + source_section(caller, "receipt_finalize() {", "receipt_receipt_run()"),
                encoding="utf-8",
            )

    def write_config(self):
        self.config_path.write_text(__import__("json").dumps(self.config), encoding="utf-8")

    def _capture_initial(self):
        result = subprocess.run([
            str(self.python), "-I", str(self.root / "scripts/prepared-dependency-evidence.py"),
            "capture", "--prefix", str(self.prefix),
            "--stable-cargo", str(self.tools / "stable cargo"),
            "--stable-rustc", str(self.tools / "stable rustc"),
            "--bpf-cargo", str(self.tools / "bpf cargo"),
            "--bpf-rustc", str(self.tools / "bpf rustc"),
        ], cwd=self.root, env=self.environment if hasattr(self, "environment") else {
            **os.environ, "P11SCOPE_FOUR_CALLERS_FIXTURE": str(self.config_path)
        }, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise AssertionError(result.stderr)

    @staticmethod
    def identity(path: Path) -> str:
        metadata = path.stat()
        return f"{metadata.st_dev}:{metadata.st_ino}"

    def run(self, scenario: str):
        initial_status = 23 if scenario == "prior-nonzero" or (
            scenario == "cleanup-failure" and not self.oracle
        ) else 77 if "77" in scenario else 0
        admitted = 0 if scenario == "unadmitted-77" else 1
        cleanup_status = 1 if scenario == "cleanup-failure" else 0
        environment = self.environment.copy()
        if scenario == "generated-mutation":
            target = self.prepared.base.output / "src/lib.rs"
            target.write_text(target.read_text() + "mutation\n")
        elif scenario == "tool-mutation":
            target = self.tools / "stable rustc"
            target.write_bytes(target.read_bytes() + b"mutation\n")
        elif scenario == "input-mutation":
            (self.root / ".gitignore").write_text("changed\n")
        elif scenario == "query-failure":
            self.config["root_status"] = 41
            self.write_config()
        elif scenario == "config-redirect":
            redirected = self.base / "redirected-root.json"
            value = __import__("json").loads(self.prepared.root_metadata.read_text())
            value["packages"][1]["source"] = "registry+https://example.invalid/index"
            value["packages"][1]["manifest_path"] = "/registry/demo/Cargo.toml"
            redirected.write_text(__import__("json").dumps(value))
            trigger = self.root / ".cargo/config.toml"
            trigger.parent.mkdir()
            trigger.write_text("[source.fixture]\n")
            self.config.update(config_trigger=str(trigger), redirect_root_metadata=str(redirected))
            self.write_config()
        elif scenario == "producer-failure":
            controlled = self.base / "controlled"
            controlled.mkdir()
            (controlled / "sort").symlink_to(FIXTURES / "tool-dispatch.sh")
            environment["PATH"] = f"{controlled}:/usr/bin:/bin"
            environment["P11SCOPE_FAIL_TOOL"] = "sort"
        elif scenario == "merge-failure":
            environment["P11SCOPE_CORRUPT_FINAL_LEDGER"] = "1"
            environment["P11SCOPE_DUPLICATE_TRACKED"] = str(self.root / ".gitignore")
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=self.root, text=True).strip()
        caller_relative = self.caller.relative_to(REPOSITORY)
        variables = {
            "RECEIPT_ROOT": str(self.receipt), "RECEIPT_FACTS": str(self.receipt / "facts.log"),
            "RECEIPT_ROOT_ID": self.identity(self.receipt),
            "RECEIPT_ARTIFACTS_ID": self.identity(self.artifacts),
            "RECEIPT_WORK_ID": self.identity(self.work), "RECEIPT_HEAD": head, "RECEIPT_TREE": tree,
            "RECEIPT_DRIVER_HASH": hashlib.sha256((self.root / caller_relative).read_bytes()).hexdigest(),
            "RECEIPT_CHECKER_HASH": hashlib.sha256((self.root / "scripts/check-capture-evidence.py").read_bytes()).hexdigest(),
            "RECEIPT_PREPARED_ADMITTED": str(admitted), "RECEIPT_PREPARED_PREFIX": str(self.prefix),
            "P11SCOPE_PREPARED_PYTHON": str(self.python),
            "P11SCOPE_FINALIZER_FUNCTIONS": str(self.functions),
            "P11SCOPE_FINALIZER_SOURCE": str(self.root / caller_relative),
            "P11SCOPE_FINALIZER_ORACLE": "1" if self.oracle else "0",
            "P11SCOPE_FINALIZER_INITIAL_STATUS": str(initial_status),
            "P11SCOPE_FINALIZER_CLEANUP_STATUS": str(cleanup_status),
            "P11SCOPE_FINALIZER_CLEANUP_MARKER": str(self.cleanup),
        }
        if self.oracle:
            oracle_inputs = {
                "RECEIPT_SUBSET_HASH": "scripts/check-subset-oracle.py",
                "RECEIPT_WORKLOAD_HASH": "scripts/matrix/oracle-workload.sh",
                "RECEIPT_CGROUP_HELPER_HASH": "scripts/matrix/oracle-cgroup-cleanup.py",
                "RECEIPT_LIFECYCLE_FIXTURE_HASH": "tests/fixtures/oracle-lifecycle/scenarios.sh",
                "RECEIPT_SUDO_FIXTURE_HASH": "tests/fixtures/oracle-lifecycle/sudo",
            }
            for variable, relative in oracle_inputs.items():
                variables[variable] = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
            variables.update(
                ORACLE_WORKLOAD=str(self.root / "scripts/matrix/oracle-workload.sh"),
                ORACLE_CGROUP_HELPER=str(self.root / "scripts/matrix/oracle-cgroup-cleanup.py"),
                ORACLE_LIFECYCLE_FIXTURE=str(self.root / "tests/fixtures/oracle-lifecycle/scenarios.sh"),
                ORACLE_SUDO_FIXTURE=str(self.root / "tests/fixtures/oracle-lifecycle/sudo"),
                RECEIPT_SIBLING_BASELINE="0", ORACLE_BODY_COMPLETE="0",
            )
        environment.update(variables)
        return subprocess.run(
            ["sh", str(FIXTURES / "finalizer-harness.sh")], cwd=self.root,
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


class SnapshotFixture:
    def __init__(self, temporary: Path):
        self.root = temporary / "repository with spaces"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy2(SNAPSHOT, self.root / "scripts" / SNAPSHOT.name)
        shutil.copy2(MERGER, self.root / "scripts" / MERGER.name)
        (self.root / "tracked file.txt").write_text("tracked\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "scripts", "tracked file.txt"], cwd=self.root, check=True)
        self.generated = self.root / "generated source.rs"
        self.generated.write_text("generated\n", encoding="utf-8")
        self.prepared = temporary / "prepared ledger with spaces.sha256"
        digest = hashlib.sha256(self.generated.read_bytes()).hexdigest()
        self.prepared.write_text(f"{digest}  generated source.rs\n", encoding="utf-8")
        self.stem = temporary / "artifacts with spaces" / "source.start"
        self.stem.parent.mkdir()

    def run(self, *, prepared: Path | None = None, environment: dict[str, str] | None = None):
        command = [
            "sh", str(FIXTURES / "snapshot-launcher.sh"),
            sys.executable, str(self.stem), str(prepared or self.prepared),
        ]
        return subprocess.run(command, cwd=self.root, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class PreparedFourCallersTests(unittest.TestCase):
    def test_each_actual_finalizer_propagates_controls_mutations_and_failures(self):
        scenarios = (
            "success", "prior-nonzero", "cleanup-failure",
            "generated-mutation", "tool-mutation", "input-mutation",
            "query-failure", "config-redirect", "producer-failure", "merge-failure",
            "unadmitted-77", "admitted-77",
        )
        for caller in CALLERS:
          for scenario in scenarios:
            with self.subTest(caller=caller.name, scenario=scenario), tempfile.TemporaryDirectory(
                dir=REPOSITORY / ".superpowers"
            ) as raw:
                fixture = FinalizerFixture(Path(raw), caller)
                result = fixture.run(scenario)
                if scenario == "success":
                    expected = 0
                elif scenario == "prior-nonzero":
                    expected = 23
                elif scenario == "cleanup-failure" and caller != CALLERS[1]:
                    expected = 23
                elif scenario in ("unadmitted-77", "admitted-77"):
                    expected = 77
                else:
                    expected = 1
                diagnostic = result.stderr
                for name in ("facts.log", "status"):
                    path = fixture.receipt / name
                    if path.is_file():
                        diagnostic += f"\n{name}:\n" + path.read_text()
                self.assertEqual(result.returncode, expected, diagnostic)
                status_path = fixture.receipt / "status"
                self.assertTrue(status_path.is_file(), diagnostic)
                self.assertEqual(status_path.read_text(), f"{expected}\n")
                calls = [] if not fixture.events.exists() else [
                    __import__("json").loads(row) for row in fixture.events.read_text().splitlines()
                ]
                final = [call for call in calls
                         if call["kind"] == "metadata" and call["phase"] == "final"]
                if scenario in ("unadmitted-77", "admitted-77"):
                    self.assertEqual(final, [])
                for call in final:
                    self.assertTrue(call["cleanup_ready"])
                    self.assertFalse(call["status_present"])
                if scenario in ("success", "prior-nonzero", "cleanup-failure",
                                "input-mutation", "config-redirect",
                                "producer-failure", "merge-failure") and not (
                                    scenario == "config-redirect" and caller == CALLERS[1]
                                ):
                    self.assertEqual([call["context"] for call in final], ["root", "bpf"])
                if scenario in ("success", "prior-nonzero", "cleanup-failure"):
                    self.assertEqual(
                        (fixture.artifacts / "source.start.tsv").read_bytes(),
                        (fixture.artifacts / "source.end.tsv").read_bytes(),
                    )

    def test_each_actual_parent_rejects_every_failed_admission_before_resources(self):
        scenarios = (
            "missing-tree", "tampered-tree", "stale-generation",
            "root-query", "bpf-query", "snapshot-producer", "duplicate-merge",
        )
        for caller in CALLERS:
          for scenario in scenarios:
            with self.subTest(caller=caller.name, scenario=scenario), tempfile.TemporaryDirectory(
                dir=REPOSITORY / ".superpowers"
            ) as raw:
                base = Path(raw)
                base.chmod(0o700)
                prepared = EvidenceFixture(base)
                root = prepared.root
                common = (
                    "scripts/lib.sh", "scripts/prepared-dependency-tools.sh",
                    "scripts/prepared-dependency-snapshot.sh",
                    "scripts/merge-checksum-ledgers.py",
                    "scripts/check-capture-evidence.py",
                )
                relative_caller = caller.relative_to(REPOSITORY).as_posix()
                extra = ()
                if caller == CALLERS[0]:
                    # The sourced receipt_finalize section shells out to this oracle.
                    extra = ("scripts/lane-induced-gaps-oracle-5.py",)
                if caller == CALLERS[1]:
                    extra = (
                        "scripts/check-subset-oracle.py", "scripts/matrix/oracle-workload.sh",
                        "scripts/matrix/oracle-cgroup-cleanup.py",
                        "tests/fixtures/oracle-lifecycle/scenarios.sh",
                        "tests/fixtures/oracle-lifecycle/sudo",
                    )
                for relative in (*common, relative_caller, *extra):
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(REPOSITORY / relative, destination)
                ignored = prepared.base.output.relative_to(root).as_posix()
                (root / ".gitignore").write_text(
                    (REPOSITORY / ".gitignore").read_text(encoding="utf-8") + ignored + "/\n",
                    encoding="utf-8",
                )
                generated = prepared.base.output / "src/lib.rs"
                if scenario == "missing-tree":
                    generated.unlink()
                elif scenario == "tampered-tree":
                    generated.write_text("tampered generated tree\n", encoding="utf-8")
                elif scenario == "stale-generation":
                    receipt = prepared.base.output / prepared.base.preparer.RECEIPT_NAME
                    value = __import__("json").loads(receipt.read_text())
                    value["revision"] += 1
                    receipt.write_text(__import__("json").dumps(value), encoding="utf-8")
                subprocess.run(["git", "init", "-q"], cwd=root, check=True)
                subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
                subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
                subprocess.run(["git", "add", "."], cwd=root, check=True)
                if scenario == "duplicate-merge":
                    subprocess.run(["git", "add", "-f", str(generated)], cwd=root, check=True)
                subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
                fixture_bin = base / "fixture bin"
                fixture_bin.mkdir()
                for name in ("fixture_common.py", "fake-rustup.py", "fake-sudo.py"):
                    shutil.copy2(FIXTURES / name, fixture_bin / name)
                for source, target in (("fake-rustup.py", "rustup"), ("fake-sudo.py", "sudo")):
                    shutil.copy2(fixture_bin / source, fixture_bin / target)
                    (fixture_bin / target).chmod(0o755)
                for name in ("docker", "gcc", "bpftool", "systemd-run", "systemctl", "capsh"):
                    (fixture_bin / name).symlink_to("/bin/true")
                if scenario == "snapshot-producer":
                    (fixture_bin / "sort").symlink_to(FIXTURES / "tool-dispatch.sh")
                shutil.copy2(FIXTURES / "fixture_common.py", prepared.tools / "fixture_common.py")
                for name in ("stable cargo", "bpf cargo"):
                    shutil.copy2(FIXTURES / "build-cargo.py", prepared.tools / name)
                    (prepared.tools / name).chmod(0o755)
                private = base / "private evidence"
                private.mkdir(mode=0o700)
                evidence = private / "receipt"
                labels = {CALLERS[0]: "induced", CALLERS[1]: "oracle",
                          CALLERS[2]: "shared", CALLERS[3]: "fork"}
                prefix = evidence / f"artifacts/{labels[caller]}.prepared"
                events = base / "events.jsonl"
                config = base / "config.json"
                fixture_config = {
                    "events": str(events), "prefix": str(prefix),
                    "driver_status": str(evidence / "status"), "sudo_status": 73,
                    "root_metadata": str(prepared.root_metadata),
                    "bpf_metadata": str(prepared.bpf_metadata),
                    "tools": {
                        "1.88:cargo": str(prepared.tools / "stable cargo"),
                        "1.88:rustc": str(prepared.tools / "stable rustc"),
                        "nightly-2026-05-20:cargo": str(prepared.tools / "bpf cargo"),
                        "nightly-2026-05-20:rustc": str(prepared.tools / "bpf rustc"),
                    },
                }
                if scenario == "root-query":
                    fixture_config["root_status"] = 31
                elif scenario == "bpf-query":
                    fixture_config["bpf_status"] = 32
                config.write_text(__import__("json").dumps(fixture_config), encoding="utf-8")
                environment = os.environ.copy()
                environment.update(
                    PATH=f"{fixture_bin}:/usr/bin:/bin",
                    P11SCOPE_FOUR_CALLERS_FIXTURE=str(config),
                    P11SCOPE_FAKE_CARGO_CONFIG=str(prepared.config_path),
                )
                if caller == CALLERS[0]:
                    module = base / "module.so"
                    module.write_bytes(b"fixture")
                    environment["P11SCOPE_PKCS11_MODULE"] = str(module)
                if caller == CALLERS[1]:
                    sibling = base / "sibling"
                    sibling.mkdir()
                    environment["PKCS11_CHECK_DIR"] = str(sibling)
                if scenario == "snapshot-producer":
                    environment["P11SCOPE_FAIL_TOOL"] = "sort"
                result = subprocess.run(
                    ["sh", str(root / relative_caller), str(evidence)], cwd=root,
                    env=environment, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=15,
                )
                diagnostic = result.stdout + result.stderr
                for receipt_name in ("stdout.log", "stderr.log", "facts.log", "status"):
                    receipt_path = evidence / receipt_name
                    if receipt_path.is_file():
                        diagnostic += f"\n{receipt_name}:\n" + receipt_path.read_text()
                expected_status = 1 if caller == CALLERS[1] else 77
                self.assertEqual(result.returncode, expected_status, diagnostic)
                calls = [] if not events.exists() else [
                    __import__("json").loads(row) for row in events.read_text().splitlines()
                ]
                initial = [call for call in calls
                           if call["kind"] == "metadata" and call["phase"] == "initial"]
                expected_contexts = {
                    "root-query": ["root"], "bpf-query": ["root", "bpf"],
                }.get(scenario, ["root", "bpf"])
                self.assertEqual([call["context"] for call in initial], expected_contexts)
                self.assertFalse(any(call["kind"] == "sudo" for call in calls))
                self.assertFalse(any(call["kind"] == "build" for call in calls))
                start = evidence / "artifacts/source.start.tsv"
                self.assertFalse(start.is_file() and start.stat().st_size > 0)
                self.assertEqual((evidence / "status").read_text(), f"{expected_status}\n")
                self.assertFalse(any(call.get("phase") == "final" for call in calls))

    def test_actual_shared_parent_hands_exact_selected_pair_to_child_build(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY / ".superpowers") as raw:
            base = Path(raw)
            base.chmod(0o700)
            prepared = EvidenceFixture(base)
            root = prepared.root
            for relative in (
                "scripts/lib.sh", "scripts/cleanup-traps.sh",
                "scripts/prepared-dependency-tools.sh",
                "scripts/prepared-dependency-snapshot.sh",
                "scripts/merge-checksum-ledgers.py",
                "scripts/matrix/matrix-lib.sh",
                "scripts/matrix/verify-shared-layer.sh",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPOSITORY / relative, destination)
            prepared_relative = prepared.base.output.relative_to(root).as_posix()
            (root / ".gitignore").write_text(
                (REPOSITORY / ".gitignore").read_text(encoding="utf-8")
                + prepared_relative + "/\n", encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            fixture_bin = base / "fixture bin"
            fixture_bin.mkdir()
            for name in ("fixture_common.py", "fake-rustup.py", "fake-sudo.py"):
                shutil.copy2(FIXTURES / name, fixture_bin / name)
            for source, target in (("fake-rustup.py", "rustup"), ("fake-sudo.py", "sudo")):
                shutil.copy2(fixture_bin / source, fixture_bin / target)
                (fixture_bin / target).chmod(0o755)
            (fixture_bin / "docker").symlink_to("/bin/true")
            shutil.copy2(FIXTURES / "fixture_common.py", prepared.tools / "fixture_common.py")
            for name in ("stable cargo", "bpf cargo"):
                shutil.copy2(FIXTURES / "build-cargo.py", prepared.tools / name)
                (prepared.tools / name).chmod(0o755)
            private = base / "private evidence"
            private.mkdir(mode=0o700)
            evidence = private / "shared receipt"
            prefix = evidence / "artifacts/shared.prepared"
            events = base / "events.jsonl"
            config = base / "config.json"
            config.write_text(__import__("json").dumps({
                "events": str(events), "prefix": str(prefix),
                "driver_status": str(evidence / "status"),
                "root_metadata": str(prepared.root_metadata),
                "bpf_metadata": str(prepared.bpf_metadata),
                "sudo_status": 0,
                "tools": {
                    "1.88:cargo": str(prepared.tools / "stable cargo"),
                    "1.88:rustc": str(prepared.tools / "stable rustc"),
                    "nightly-2026-05-20:cargo": str(prepared.tools / "bpf cargo"),
                    "nightly-2026-05-20:rustc": str(prepared.tools / "bpf rustc"),
                },
            }), encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                PATH=f"{fixture_bin}:/usr/bin:/bin",
                P11SCOPE_FOUR_CALLERS_FIXTURE=str(config),
                P11SCOPE_FAKE_CARGO_CONFIG=str(prepared.config_path),
            )
            result = subprocess.run(
                ["sh", str(root / "scripts/matrix/verify-shared-layer.sh"), str(evidence)],
                cwd=root, env=environment, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)
            receipt_stderr = evidence / "stderr.log"
            diagnostic = result.stdout + "\n" + result.stderr
            if receipt_stderr.is_file():
                diagnostic += "\nreceipt stderr:\n" + receipt_stderr.read_text()
            facts = evidence / "facts.log"
            if facts.is_file():
                diagnostic += "\nfacts:\n" + facts.read_text()
            status_file = evidence / "status"
            if status_file.is_file():
                diagnostic += "\nstatus:\n" + status_file.read_text()
            self.assertTrue(events.is_file(), diagnostic)
            calls = [__import__("json").loads(row) for row in events.read_text().splitlines()]
            build = [call for call in calls if call["kind"] == "build"]
            self.assertEqual(len(build), 1)
            selections = [call for call in calls if call["kind"] == "rustup"]
            self.assertEqual(len(selections), 4)
            self.assertTrue(all(calls.index(call) < calls.index(build[0])
                                for call in selections))
            self.assertEqual(build[0]["executable"], str((prepared.tools / "stable cargo").resolve()))
            self.assertEqual(build[0]["rustc"], str((prepared.tools / "stable rustc").resolve()))
            self.assertEqual(build[0]["bpf_cargo"], str((prepared.tools / "bpf cargo").resolve()))
            self.assertEqual(build[0]["bpf_rustc"], str((prepared.tools / "bpf rustc").resolve()))
            self.assertEqual(build[0]["argv"], [
                "build", "--locked", "--offline", "--release", "--workspace",
                "--target-dir", str(evidence / "work/product"),
            ])
            self.assertTrue(Path(str(prefix) + ".initial.ledger.sha256").is_file())
            self.assertTrue(build[0]["initial_ready"])
            self.assertLess(
                max(index for index, call in enumerate(calls)
                    if call["kind"] == "metadata" and call["phase"] == "initial"),
                calls.index(build[0]),
            )
            final_metadata = [call for call in calls
                              if call["kind"] == "metadata" and call["phase"] == "final"]
            self.assertEqual([call["context"] for call in final_metadata], ["root", "bpf"])
            self.assertLess(calls.index(build[0]), min(calls.index(call) for call in final_metadata))
            self.assertEqual(
                (evidence / "artifacts/source.start.tsv").read_bytes(),
                (evidence / "artifacts/source.end.tsv").read_bytes(),
            )
            self.assertFalse(build[0]["status_present"])

    def test_snapshot_merges_tracked_and_generated_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = SnapshotFixture(Path(raw))
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = result.stdout.splitlines()
            self.assertEqual([row[66:] for row in rows], [
                "generated source.rs", "scripts/merge-checksum-ledgers.py",
                "scripts/prepared-dependency-snapshot.sh", "tracked file.txt",
            ])
            self.assertTrue(Path(str(fixture.stem) + ".tracked.paths.z").is_file())
            self.assertTrue(Path(str(fixture.stem) + ".tracked.ledger.sha256").is_file())

    def test_snapshot_rejects_bad_arity_duplicate_and_each_producer_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            fixture = SnapshotFixture(base)
            bad = subprocess.run(
                ["sh", str(FIXTURES / "snapshot-launcher.sh")],
                cwd=fixture.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("usage", bad.stderr)
            duplicate = base / "duplicate.sha256"
            digest = hashlib.sha256((fixture.root / "tracked file.txt").read_bytes()).hexdigest()
            duplicate.write_text(f"{digest}  tracked file.txt\n", encoding="utf-8")
            refused = fixture.run(prepared=duplicate)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, "")
            self.assertIn("duplicate path", refused.stderr)
            dispatch = FIXTURES / "tool-dispatch.sh"
            tools = base / "controlled tools"
            tools.mkdir()
            for name in ("git", "sort", "xargs", "sha256sum"):
                (tools / name).symlink_to(dispatch)
            for failed in ("git", "sort", "xargs"):
                environment = os.environ.copy()
                environment["PATH"] = f"{tools}:/usr/bin:/bin"
                environment["P11SCOPE_FAIL_TOOL"] = failed
                result = fixture.run(environment=environment)
                self.assertNotEqual(result.returncode, 0, failed)
                self.assertIn(f"{failed} fixture refusal", result.stderr)

    def test_sourcing_snapshot_defines_only_function_and_preserves_shell_state(self):
        with tempfile.TemporaryDirectory(prefix="snapshot source state ") as scratch:
            result = subprocess.run(
                ["sh", str(REPOSITORY / "tests/fixtures/source-state.sh"), str(SNAPSHOT),
                 "p11scope_prepared_snapshot", scratch],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_executes_every_selected_build_variant_and_timeout_path(self):
        expected = {
            CALLERS[0]: [
                ("default-build", None, None, None, None),
                ("ring-build", "1", None, None, None),
                ("state-build", None, "1", None, None),
                ("freeze-build", None, None, "unsafe-unvalidated-metadata", None),
            ],
            CALLERS[1]: [("product", None, None, None,
                          ["--signal=TERM", "--kill-after=10s", "900s"])],
            CALLERS[2]: [("product", None, None, None,
                          ["--signal=TERM", "--kill-after=5s", "600s"])],
            CALLERS[3]: [("product", None, None, None, None)],
        }
        for caller, cases in expected.items():
            commands = [command for command in logical_commands(caller)
                        if '"$P11SCOPE_PREPARED_STABLE_CARGO" build' in command]
            self.assertEqual(len(commands), len(cases))
            for index, (command, case) in enumerate(zip(commands, cases)):
                with self.subTest(caller=caller.name, index=index), tempfile.TemporaryDirectory() as raw:
                    base = Path(raw)
                    tools = base / "tools with spaces"
                    tools.mkdir()
                    selected_cargo = tools / "selected cargo"
                    selected_rustc = tools / "selected rustc"
                    shutil.copy2(FIXTURES / "build-cargo.py", selected_cargo)
                    shutil.copy2(FIXTURES / "fixture_common.py", tools / "fixture_common.py")
                    selected_cargo.chmod(0o755)
                    selected_rustc.write_text("fixture rustc\n")
                    selected_rustc.chmod(0o755)
                    selected_bpf_cargo = tools / "selected bpf cargo"
                    selected_bpf_rustc = tools / "selected bpf rustc"
                    selected_bpf_cargo.write_text("fixture bpf cargo\n")
                    selected_bpf_rustc.write_text("fixture bpf rustc\n")
                    selected_bpf_cargo.chmod(0o755)
                    selected_bpf_rustc.chmod(0o755)
                    fixture_bin = base / "bin"
                    fixture_bin.mkdir()
                    shutil.copy2(FIXTURES / "fake-timeout.py", fixture_bin / "timeout")
                    shutil.copy2(FIXTURES / "fixture_common.py", fixture_bin / "fixture_common.py")
                    (fixture_bin / "timeout").chmod(0o755)
                    for name in ("cargo", "rustc"):
                        (fixture_bin / name).symlink_to(FIXTURES / "tripwire.sh")
                    events = base / "events.jsonl"
                    config = base / "config.json"
                    config.write_text(__import__("json").dumps({
                        "events": str(events), "prefix": str(base / "prepared"),
                        "driver_status": str(base / "status"),
                    }), encoding="utf-8")
                    work = base / "work"
                    work.mkdir()
                    product = work / "product"
                    environment = os.environ.copy()
                    environment.update(
                        PATH=f"{fixture_bin}:/usr/bin:/bin",
                        P11SCOPE_FOUR_CALLERS_FIXTURE=str(config),
                        WORK=str(work), PRODUCT=str(product),
                    )
                    command_file = base / "build-command.sh"
                    command_file.write_text(command, encoding="utf-8")
                    result = subprocess.run(
                        ["sh", str(FIXTURES / "unexported-build-launcher.sh"),
                         str(command_file), str(selected_cargo), str(selected_rustc),
                         str(selected_bpf_cargo), str(selected_bpf_rustc)],
                        cwd=REPOSITORY, env=environment,
                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    self.assertEqual(result.returncode, 83, result.stderr)
                    calls = [__import__("json").loads(row) for row in events.read_text().splitlines()]
                    build = next(call for call in calls if call["kind"] == "build")
                    target, ring, state, feature, timeout_prefix = case
                    expected_argv = ["build", "--locked", "--offline", "--release",
                                     "--workspace"]
                    if feature is not None:
                        expected_argv.extend(["--features", feature])
                    expected_argv.extend(["--target-dir", str(work / target)])
                    self.assertEqual(build["rustc"], str(selected_rustc))
                    self.assertEqual(build["bpf_cargo"], str(selected_bpf_cargo))
                    self.assertEqual(build["bpf_rustc"], str(selected_bpf_rustc))
                    self.assertEqual(build["small_ring"], ring)
                    self.assertEqual(build["small_state"], state)
                    self.assertEqual(build["argv"], expected_argv)
                    timeouts = [call for call in calls if call["kind"] == "timeout"]
                    if timeout_prefix is None:
                        self.assertEqual(timeouts, [])
                    else:
                        self.assertEqual(len(timeouts), 1)
                        self.assertEqual(
                            timeouts[0]["argv"],
                            timeout_prefix + [str(selected_cargo)] + expected_argv,
                        )

    def test_executes_each_exact_parent_child_handoff_block(self):
        for caller in CHILD_CALLERS:
            commands = [command for command in logical_commands(caller)
                        if command.lstrip().startswith("P11SCOPE_RECEIPT_BODY=1")]
            self.assertEqual(len(commands), 1)
            with self.subTest(caller=caller.name), tempfile.TemporaryDirectory() as raw:
                base = Path(raw)
                (base / "work").mkdir()
                record = base / "handoff.txt"
                cargo = base / "selected cargo with spaces"
                rustc = base / "selected rustc with spaces"
                bpf_cargo = base / "selected bpf cargo with spaces"
                bpf_rustc = base / "selected bpf rustc with spaces"
                command_file = base / "command.sh"
                command_file.write_text(commands[0], encoding="utf-8")
                environment = os.environ.copy()
                for name in (
                    "P11SCOPE_PREPARED_PYTHON",
                    "P11SCOPE_PREPARED_RUSTUP",
                    "P11SCOPE_PREPARED_STABLE_CARGO",
                    "P11SCOPE_PREPARED_STABLE_RUSTC",
                    "P11SCOPE_PREPARED_BPF_CARGO",
                    "P11SCOPE_PREPARED_BPF_RUSTC",
                ):
                    environment.pop(name, None)
                environment.update(
                    RECEIPT_ROOT=str(base),
                    P11SCOPE_HANDOFF_RECORD=str(record),
                )
                result = subprocess.run(
                    ["sh", str(FIXTURES / "unexported-handoff-launcher.sh"),
                     str(command_file), str(FIXTURES / "handoff-recorder.sh"),
                     str(cargo), str(rustc), str(bpf_cargo), str(bpf_rustc)],
                    cwd=REPOSITORY, env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = record.read_text().splitlines()
                self.assertEqual(rows[:4], [f"cargo={cargo}", f"rustc={rustc}",
                                           f"bpf_cargo={bpf_cargo}",
                                           f"bpf_rustc={bpf_rustc}"])
                self.assertEqual(rows[4:], [
                    "name=P11SCOPE_PREPARED_BPF_CARGO",
                    "name=P11SCOPE_PREPARED_BPF_RUSTC",
                    "name=P11SCOPE_PREPARED_STABLE_CARGO",
                    "name=P11SCOPE_PREPARED_STABLE_RUSTC",
                ])

    def test_direct_child_missing_handoff_refuses_before_resources(self):
        for caller in CHILD_CALLERS:
            for mask in range(15):
                with self.subTest(caller=caller.name, mask=mask):
                    environment = os.environ.copy()
                    environment["P11SCOPE_RECEIPT_BODY"] = "1"
                    values = ("/stable/cargo", "/stable/rustc", "/bpf/cargo", "/bpf/rustc")
                    for index, name in enumerate((
                        "P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
                        "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC",
                    )):
                        environment.pop(name, None)
                        if mask & (1 << index):
                            environment[name] = values[index]
                    result = subprocess.run(
                        ["sh", str(caller)], cwd=REPOSITORY, env=environment,
                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("prepared stable/BPF Cargo/rustc handoff required", result.stderr)
                    self.assertNotIn("passwordless sudo", result.stderr)

    def test_oracle_source_only_remains_side_effect_free_without_selection(self):
        environment = os.environ.copy()
        environment["P11SCOPE_ORACLE_SOURCE_ONLY"] = "1"
        result = subprocess.run(
            ["sh", str(CALLERS[1])], cwd=REPOSITORY, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
