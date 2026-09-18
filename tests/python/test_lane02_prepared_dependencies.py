#!/usr/bin/env python3
"""Native integration tests for Lane02 prepared-dependency receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
FIXTURES = REPOSITORY / "tests/fixtures/lane02-prepared-dependencies"
EvidenceFixture = __import__("runpy").run_path(
    str(REPOSITORY / "tests/python/test_prepared_dependency_evidence.py")
)["EvidenceFixture"]


class Lane02Fixture:
    def __init__(self, temporary: Path):
        self.prepared = EvidenceFixture(temporary)
        self.root = self.prepared.root
        copied = (
            "scripts/verify-receipt-lane02.sh", "scripts/lib.sh", "scripts/cleanup-traps.sh",
            "scripts/check-capture-evidence.py", "scripts/lane02-inputs.py",
            "scripts/prepared-dependency-tools.sh", "scripts/prepared-dependency-snapshot.sh",
            "scripts/product-build.sh", "scripts/merge-checksum-ledgers.py",
            "scripts/check-prepared-dependencies.py", "scripts/prepare-dependencies.py",
            "spike/harness.c", "spike/expected.txt",
            # The lane's and lib's extracted oracle fragments are runtime files
            # of the copied lane: the fixture runs its main flow.
            "scripts/lane-receipt-lane02-oracle-1.py", "scripts/lane-receipt-lane02-oracle-2.py",
            "scripts/lane-receipt-lane02-oracle-3.py", "scripts/lane-receipt-lane02-oracle-4.py",
            "scripts/lane-receipt-lane02-oracle-5.py", "scripts/lane-receipt-lane02-oracle-6.py",
            "scripts/lane-receipt-lane02-oracle-7.py", "scripts/lane-receipt-lane02-oracle-8.py",
            "scripts/lane-receipt-lane02-oracle-9.py", "scripts/lane-receipt-lane02-oracle-10.py",
            "scripts/lane-receipt-lane02-oracle-11.py", "scripts/lane-receipt-lane02-oracle-12.py",
            "scripts/lane-lib-oracle-1.py", "scripts/lane-lib-oracle-2.py",
            "scripts/lane-lib-oracle-3.py", "scripts/lane-lib-oracle-4.py",
            "scripts/lane-lib-oracle-5.py", "scripts/lane-lib-oracle-6.py",
        )
        for relative in copied:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY / relative, destination)
        self.module = temporary / "fixture module.so"
        self.module.write_bytes(b"controlled module\n")
        driver = self.root / "scripts/verify-receipt-lane02.sh"
        source = driver.read_text(encoding="utf-8")
        source = source.replace(
            "MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            f"MODULE={shlex.quote(str(self.module))}",
            1,
        )
        if os.environ.get("P11SCOPE_LANE02_MUTANT") == "late-build-cleanup":
            cleanup = (
                '    if [ -n "${ROOT-}" ] && [ -d "$ROOT/build" ]; then\n'
                '        find "$ROOT/build" -depth -delete || cleanup_status=1\n'
                '    fi\n'
            )
            if source.count(cleanup) != 1:
                raise AssertionError("late-cleanup mutant could not locate cleanup block")
            source = source.replace(cleanup, "", 1)
            terminal = '    if [ "$FINALIZED" -eq 0 ] && [ -n "${FACTS-}" ]'
            source = source.replace(terminal, cleanup + terminal, 1)
        elif os.environ.get("P11SCOPE_LANE02_MUTANT") == "ignore-terminal-refusal":
            checked = "            validate_terminal_tree || cleanup_status=1"
            if source.count(checked) != 1:
                raise AssertionError("terminal-refusal mutant could not locate checked call")
            source = source.replace(checked, "            validate_terminal_tree || :", 1)
        driver.write_text(source, encoding="utf-8")

        ignore = self.prepared.base.output.relative_to(self.root).as_posix()
        (self.root / ".gitignore").write_text(f"{ignore}/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "fixture"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.invalid"],
            cwd=self.root, check=True,
        )
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.root, check=True)

        self.bin = temporary / "controlled path"
        self.bin.mkdir()
        for target, fixture in (
            ("rustup", "fake-rustup.py"), ("sudo", "fake-sudo.py"),
            ("softhsm2-util", "fake-softhsm.py"), ("readelf", "fake-readelf.py"),
        ):
            shutil.copy2(FIXTURES / fixture, self.bin / target)
            (self.bin / target).chmod(0o755)
        for name, fixture in (
            ("stable cargo", "fake-cargo.py"), ("bpf cargo", "fake-cargo.py"),
            ("stable rustc", "fake-rustc.py"), ("bpf rustc", "fake-rustc.py"),
        ):
            shutil.copy2(FIXTURES / fixture, self.prepared.tools / name)
            (self.prepared.tools / name).chmod(0o755)

        self.evidence_parent = temporary / "private evidence parent"
        self.evidence_parent.mkdir(mode=0o700)
        self.evidence = self.evidence_parent / "lane02 receipt"
        self.events = temporary / "events.jsonl"
        self.config_path = temporary / "lane02 fixture.json"
        self.config = {
            "events": str(self.events),
            "initial_receipt": str(self.evidence / "prepared/lane02.initial.receipt.json"),
            "root_metadata": str(self.prepared.root_metadata),
            "bpf_metadata": str(self.prepared.bpf_metadata),
            "stable_cargo": str((self.prepared.tools / "stable cargo").resolve()),
            "stable_rustc": str((self.prepared.tools / "stable rustc").resolve()),
            "bpf_cargo": str((self.prepared.tools / "bpf cargo").resolve()),
            "bpf_rustc": str((self.prepared.tools / "bpf rustc").resolve()),
            "build_root": str(self.evidence / "build"),
            "built_responder": str(FIXTURES / "built-p11scope.sh"),
            "build_status": 83,
        }
        self.write_config()
        self.home = temporary / "empty home"
        self.home.mkdir()

    def write_config(self) -> None:
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        for name in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
            "RUSTC_WRAPPER", "CC", "CFLAGS", "SOFTHSM2_CONF",
        ):
            environment.pop(name, None)
        environment.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.home),
            "P11SCOPE_LANE02_FIXTURE": str(self.config_path),
        })
        return environment

    def run(self):
        return subprocess.run(
            ["sh", str(self.root / "scripts/verify-receipt-lane02.sh"), str(self.evidence)],
            cwd=self.root.parent, env=self.environment(), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def prepare_completed_body(self) -> tuple[Path, Path]:
        self.evidence.mkdir(mode=0o700)
        prepared = self.evidence / "prepared"
        prepared.mkdir(mode=0o700)
        prefix = prepared / "lane02"
        capture = subprocess.run([
            sys.executable, "-I", str(self.root / "scripts/prepared-dependency-evidence.py"),
            "capture", "--prefix", str(prefix),
            "--stable-cargo", self.config["stable_cargo"],
            "--stable-rustc", self.config["stable_rustc"],
            "--bpf-cargo", self.config["bpf_cargo"],
            "--bpf-rustc", self.config["bpf_rustc"],
        ], cwd=self.root, env=self.environment(), text=True,
           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if capture.returncode:
            raise AssertionError(capture.stderr)
        snapshot = subprocess.run([
            "sh", str(FIXTURES / "snapshot.sh"), sys.executable,
            str(prepared / "source.initial"), str(Path(f"{prefix}.initial.ledger.sha256")),
        ], cwd=self.root, env=self.environment(), stdout=subprocess.PIPE,
           stderr=subprocess.PIPE)
        if snapshot.returncode:
            raise AssertionError(snapshot.stderr.decode())
        (prepared / "source.start.tsv").write_bytes(snapshot.stdout)
        for path in prepared.iterdir():
            if path.is_file():
                path.chmod(0o600)

        for directory in (self.evidence / "bin", self.evidence / "rows", self.evidence / "tokens"):
            directory.mkdir(mode=0o700)
        for relative in (
            "facts.log", "cargo-configs.tsv", "softhsm2.conf", "bin/p11scope",
            "bin/harness", "bin/harness-initial",
        ):
            path = self.evidence / relative
            path.write_text("fixture\n", encoding="utf-8")
            path.chmod(0o600)
        for row in (
            "01-initial-set-never", "02-initial-set-auto", "03-initial-set-always",
            "04-dlopen-never", "05-dlopen-auto", "06-dlopen-always",
        ):
            directory = self.evidence / "rows" / row
            directory.mkdir(mode=0o700)
            for name in ("observer.log", "checker.log"):
                path = directory / name
                path.write_text("fixture\n", encoding="utf-8")
                path.chmod(0o600)
        (self.evidence / "build/private").mkdir(parents=True)
        (self.evidence / "build/private/output").write_text("owned build\n")

        driver = (self.root / "scripts/verify-receipt-lane02.sh").read_text()
        functions = self.root.parent / "lane02 finalizer functions.sh"
        functions.write_text(
            driver[driver.index("validate_terminal_tree() {"):driver.index("cargo_config_line() {")]
            + driver[driver.index("cleanup() {"):driver.index(". scripts/cleanup-traps.sh")],
            encoding="utf-8",
        )
        return functions, prefix

    def run_completed_finalizer(self, *, cleanup_failure: bool = False,
                                foreign_terminal_file: bool = False):
        functions, prefix = self.prepare_completed_body()
        if foreign_terminal_file:
            foreign = self.evidence / "foreign-review.txt"
            foreign.write_text("foreign retained artifact\n", encoding="utf-8")
            foreign.chmod(0o600)
        finalizer_events = self.root.parent / "finalizer events"
        environment = self.environment()
        environment["P11SCOPE_LANE02_FINALIZER_EVENTS"] = str(finalizer_events)
        environment["P11SCOPE_LANE02_CLEANUP_FAIL"] = "1" if cleanup_failure else "0"
        result = subprocess.run([
            "sh", str(FIXTURES / "finalizer.sh"), str(functions), str(self.evidence),
            sys.executable, str(prefix),
        ], cwd=self.root, env=environment, text=True,
           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result, finalizer_events

    def recorded_events(self) -> list[dict]:
        if not self.events.exists():
            return []
        return [json.loads(line) for line in self.events.read_text().splitlines()]


class Lane02PreparedDependenciesTests(unittest.TestCase):
    def fixture(self, label: str) -> Lane02Fixture:
        path = Path(self.temporary.name) / label
        path.mkdir()
        return Lane02Fixture(path)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temporary.cleanup()

    def test_driver_orders_admission_build_cleanup_and_terminal_acceptance(self):
        source = (REPOSITORY / "scripts/verify-receipt-lane02.sh").read_text()
        capture = source.index("scripts/prepared-dependency-evidence.py capture")
        first_sudo = source.index('sudo -n true || { echo "passwordless sudo required"')
        build = source.index("p11scope_product_build prepared --release --workspace")
        self.assertLess(capture, first_sudo)
        self.assertLess(first_sudo, build)
        cleanup = source[source.index("cleanup() {"):source.index(". scripts/cleanup-traps.sh")]
        self.assertLess(cleanup.index("terminate_owned_harness"), cleanup.index(" recheck "))
        self.assertLess(cleanup.index("prepared_snapshot final"),
                        cleanup.index("validate_terminal_tree"))

    def test_admission_build_and_cleanup_recheck_use_one_selected_tool_set(self):
        fixture = self.fixture("ordinary failure after build")
        result = fixture.run()
        self.assertEqual(result.returncode, 1, result.stderr)
        events = fixture.recorded_events()
        self.assertEqual([event["key"] for event in events if event["kind"] == "select"], [
            "stable_cargo", "stable_rustc", "bpf_cargo", "bpf_rustc",
        ])
        metadata = [event for event in events if event["kind"] == "metadata"]
        self.assertEqual([(event["phase"], event["context"]) for event in metadata], [
            ("initial", "root"), ("initial", "bpf"),
            ("final", "root"), ("final", "bpf"),
        ])
        sudo_index = next(i for i, event in enumerate(events) if event["kind"] == "sudo")
        build_index = next(i for i, event in enumerate(events) if event["kind"] == "build")
        self.assertLess(max(i for i, event in enumerate(events)
                            if event["kind"] == "metadata" and event["phase"] == "initial"),
                        sudo_index)
        self.assertLess(sudo_index, build_index)
        self.assertTrue(all(not event["build_exists"] for event in metadata
                            if event["phase"] == "final"))
        build = events[build_index]
        self.assertEqual(build["argv"], [
            "build", "--locked", "--offline", "--release", "--workspace",
            "--target-dir", str(fixture.evidence / "build"),
        ])
        self.assertEqual(build["rustc"], fixture.config["stable_rustc"])
        self.assertEqual(build["bpf_cargo"], fixture.config["bpf_cargo"])
        self.assertEqual(build["bpf_rustc"], fixture.config["bpf_rustc"])
        self.assertFalse((fixture.evidence / "build").exists())
        self.assertTrue((fixture.evidence / "prepared/lane02.final.receipt.json").is_file())
        self.assertEqual(
            (fixture.evidence / "prepared/source.start.tsv").read_bytes(),
            (fixture.evidence / "prepared/source.end.tsv").read_bytes(),
        )
        facts = (fixture.evidence / "facts.log").read_text()
        self.assertIn("prepared_final_ledger\tlane02.final.ledger.sha256 ", facts)
        self.assertIn("terminal_status\t1\n", facts)

    def test_selected_stable_tool_diagnostic_failure_refuses_before_sudo_and_build(self):
        for tool in ("cargo", "rustc"):
            with self.subTest(tool=tool):
                fixture = self.fixture(f"selected {tool} diagnostic")
                fixture.config[f"{tool}_version_status"] = 39
                fixture.write_config()
                result = fixture.run()
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn(f"controlled selected {tool} version failure", result.stderr)
                kinds = [event["kind"] for event in fixture.recorded_events()]
                self.assertNotIn("sudo", kinds)
                self.assertNotIn("build", kinds)

    def test_completed_body_accepts_terminal_tree_after_cleanup_and_final_queries(self):
        fixture = self.fixture("completed body")
        result, finalizer_events = fixture.run_completed_finalizer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(finalizer_events.read_text(), "cleanup\n")
        final = [event for event in fixture.recorded_events()
                 if event["kind"] == "metadata" and event["phase"] == "final"]
        self.assertEqual([event["context"] for event in final], ["root", "bpf"])
        self.assertTrue(all(not event["build_exists"] for event in final))
        self.assertFalse((fixture.evidence / "build").exists())
        self.assertTrue((fixture.evidence / "prepared/source.end.tsv").is_file())
        self.assertIn("terminal_status\t0\n", (fixture.evidence / "facts.log").read_text())

    def test_completed_body_rejects_foreign_terminal_artifact(self):
        fixture = self.fixture("foreign completed terminal")
        result, _finalizer_events = fixture.run_completed_finalizer(
            foreign_terminal_file=True
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("foreign terminal file: foreign-review.txt", result.stderr)
        final = [event for event in fixture.recorded_events()
                 if event["kind"] == "metadata" and event["phase"] == "final"]
        self.assertEqual([event["context"] for event in final], ["root", "bpf"])
        self.assertTrue((fixture.evidence / "prepared/source.end.tsv").is_file())
        self.assertIn("terminal_status\t1\n", (fixture.evidence / "facts.log").read_text())

    def test_cleanup_failure_remains_nonzero_but_final_queries_still_run(self):
        fixture = self.fixture("cleanup failure")
        result, finalizer_events = fixture.run_completed_finalizer(cleanup_failure=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(finalizer_events.read_text(), "cleanup\n")
        final = [event for event in fixture.recorded_events()
                 if event["kind"] == "metadata" and event["phase"] == "final"]
        self.assertEqual([event["context"] for event in final], ["root", "bpf"])
        self.assertTrue(all(not event["build_exists"] for event in final))

    def test_failed_initial_admission_has_no_sudo_build_or_resource_and_records_unavailable(self):
        for label, setting in (
            ("query", {"initial_root_status": 41}),
            ("mutation", {"initial_root_mutation": "Cargo.lock"}),
        ):
            with self.subTest(label=label):
                fixture = self.fixture(f"initial {label}")
                if label == "mutation":
                    setting = {"initial_root_mutation": str(fixture.root / "Cargo.lock")}
                fixture.config.update(setting)
                fixture.write_config()
                result = fixture.run()
                self.assertEqual(result.returncode, 77, result.stderr)
                kinds = [event["kind"] for event in fixture.recorded_events()]
                self.assertNotIn("sudo", kinds)
                self.assertNotIn("build", kinds)
                self.assertFalse((fixture.evidence / "build").exists())
                self.assertFalse((fixture.evidence / "bin").exists())
                self.assertFalse((fixture.evidence / "rows").exists())
                self.assertFalse((fixture.evidence / "tokens").exists())
                self.assertIn(
                    "prepared_final_ledger\tUNAVAILABLE\n",
                    (fixture.evidence / "facts.log").read_text(),
                )

    def test_final_mutation_and_query_failure_refuse_after_owned_cleanup(self):
        for context in ("root", "bpf"):
            for label in ("mutation", "query"):
              with self.subTest(context=context, label=label):
                fixture = self.fixture(f"final {context} {label}")
                setting = f"final_{context}_{'mutation' if label == 'mutation' else 'status'}"
                fixture.config[setting] = (
                    str(fixture.root / "Cargo.lock") if label == "mutation" else 42
                )
                fixture.write_config()
                result = fixture.run()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((fixture.evidence / "build").exists())
                events = fixture.recorded_events()
                self.assertEqual(sum(event["kind"] == "build" for event in events), 1)
                self.assertEqual(sum(event["kind"] == "sudo" for event in events), 1)
                self.assertFalse(
                    (fixture.evidence / "prepared/lane02.final.ledger.sha256").exists()
                )
                self.assertIn(
                    "prepared_final_ledger\tUNAVAILABLE\n",
                    (fixture.evidence / "facts.log").read_text(),
                )
                self.assertIn(
                    "terminal_status\t1\n",
                    (fixture.evidence / "facts.log").read_text(),
                )


if __name__ == "__main__":
    unittest.main()
