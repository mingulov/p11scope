#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual-CLI prepared dependency tests for the ABI routing driver."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/prepared-abi-driver"
EvidenceFixture = runpy.run_path(
    str(ROOT / "tests/python/test_prepared_dependency_evidence.py")
)["EvidenceFixture"]


class AbiDriverFixture:
    def __init__(self, base: Path):
        self.base = base
        self.base.chmod(0o700)
        self.prepared = EvidenceFixture(base)
        self.root = self.prepared.root
        self._copy_repository_inputs()

        self.bin = base / "fixture bin"
        self.bin.mkdir(mode=0o700)
        for name in (
            "fixture_common.py",
            "fake-rustup.py",
            "fake-sudo.py",
            "fake-compiler.py",
        ):
            shutil.copy2(FIXTURES / name, self.bin / name)
        shutil.copy2(
            FIXTURES / "fixture_common.py",
            self.prepared.tools / "fixture_common.py",
        )
        shutil.copy2(self.bin / "fake-rustup.py", self.bin / "rustup")
        shutil.copy2(self.bin / "fake-sudo.py", self.bin / "sudo")
        shutil.copy2(self.bin / "fake-compiler.py", self.bin / "gcc")
        for path in (self.bin / "rustup", self.bin / "sudo", self.bin / "gcc"):
            path.chmod(0o755)

        for name in ("stable cargo", "bpf cargo"):
            shutil.copy2(FIXTURES / "fake-cargo.py", self.prepared.tools / name)
            (self.prepared.tools / name).chmod(0o755)
        shutil.copy2(
            FIXTURES / "version-rustc.py",
            self.prepared.tools / "stable rustc",
        )
        (self.prepared.tools / "stable rustc").chmod(0o755)
        alias = self.prepared.tools / "stable cargo link"
        alias.symlink_to(self.prepared.tools / "stable cargo")

        self.private = base / "private evidence parent"
        self.private.mkdir(mode=0o700)
        self.evidence = self.private / "abi evidence"
        self.prefix = self.evidence / "abi.prepared"
        self.events_path = base / "events.jsonl"
        self.config_path = base / "driver-config.json"
        self.config = {
            "events": str(self.events_path),
            "prefix": str(self.prefix),
            "driver_status": str(self.evidence / "driver.status"),
            "root_metadata": str(self.prepared.root_metadata),
            "bpf_metadata": str(self.prepared.bpf_metadata),
            "ordinary_source": str(self.root / "src/consumed source with spaces.rs"),
            "prepared_source": str(self.prepared.base.output / "src/lib.rs"),
            "recipe": str(self.root / "third-party/sources.json"),
            "tools": {
                "1.88:cargo": str(alias),
                "1.88:rustc": str(self.prepared.tools / "stable rustc"),
                "nightly-2026-05-20:cargo": str(self.prepared.tools / "bpf cargo"),
                "nightly-2026-05-20:rustc": str(self.prepared.tools / "bpf rustc"),
            },
        }

    def _copy_repository_inputs(self):
        for relative in (
            "build.rs",
            "examples/abi-routing.rs",
            "scripts/lib.sh",
            "scripts/recorded-process-exec.py",
            "scripts/prepared-dependency-tools.sh",
            "scripts/prepared-dependency-evidence.py",
            "scripts/check-prepared-dependencies.py",
            "scripts/prepare-dependencies.py",
            "scripts/merge-checksum-ledgers.py",
            "scripts/matrix/verify-abi-routing.sh",
            "scripts/matrix/ia32-compat-harness.c",
            "tests/fixtures/abi-routing/fail-ack.py",
            "tests/shell/test_abi_routing_driver.sh",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        shutil.copy2(
            FIXTURES / "finalize-cleanup-failure.sh",
            self.root / "tests/shell/finalize-cleanup-failure.sh",
        )
        for relative in (
            "src",
            "crates/ebpf/src",
            "crates/ebpf-common/src",
            "crates/manifest/src",
        ):
            destination = self.root / relative
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(ROOT / relative, destination)
        shutil.copy2(
            FIXTURES / "consumed source with spaces.rs",
            self.root / "src/consumed source with spaces.rs",
        )

    def run(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        environment = self.environment()
        return subprocess.run(
            [
                "/bin/sh",
                str(self.root / "scripts/matrix/verify-abi-routing.sh"),
                str(self.evidence),
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
        )

    def environment(self):
        environment = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_TARGET_DIR",
                "CARGO_BUILD_TARGET",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "RUSTUP_TOOLCHAIN",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "CC",
                "CFLAGS",
                "P11SCOPE_SMALL_RING",
                "P11SCOPE_SMALL_STATE_MAPS",
                "P11SCOPE_SMALL_DISCOVERY_RING",
            }
        }
        environment.update(
            PATH=str(self.bin) + ":/usr/bin:/bin",
            P11SCOPE_ABI_FIXTURE=str(self.config_path),
        )
        return environment

    def run_cleanup_failure(self):
        evidence = self.private / "cleanup failure evidence"
        self.prefix = evidence / "abi.prepared"
        self.config["prefix"] = str(self.prefix)
        self.config["driver_status"] = str(evidence / "driver.status")
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        return subprocess.run(
            [
                "/bin/sh",
                str(self.root / "tests/shell/finalize-cleanup-failure.sh"),
                str(self.root),
                str(evidence),
                "/usr/bin/python3",
                str(self.prepared.tools / "stable cargo"),
                str(self.prepared.tools / "stable rustc"),
                str(self.prepared.tools / "bpf cargo"),
                str(self.prepared.tools / "bpf rustc"),
            ],
            cwd=self.root,
            env=self.environment(),
            text=True,
            capture_output=True,
            timeout=15,
        )

    def events(self):
        if not self.events_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.events_path.read_text(encoding="utf-8").splitlines()
        ]

    def ledger(self, phase):
        rows = (self.evidence / f"source-{phase}.sha256").read_text(
            encoding="utf-8"
        )
        return {row[66:]: row[:64] for row in rows.splitlines()}


class PreparedAbiDriverTests(unittest.TestCase):
    def setUp(self):
        superpowers = ROOT / ".superpowers"
        superpowers.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="prepared-abi-driver-", dir=superpowers
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def fixture(self, name="case"):
        path = self.base / name
        path.mkdir(mode=0o700)
        return AbiDriverFixture(path)

    def test_actual_cli_admission_brackets_sudo_and_terminal_publication(self):
        fixture = self.fixture()
        result = fixture.run()

        self.assertEqual(result.returncode, 1)
        events = fixture.events()
        self.assertEqual(
            [(event["phase"], event["context"]) for event in events if event["kind"] == "metadata"],
            [
                ("initial", "root"),
                ("initial", "bpf"),
                ("final", "root"),
                ("final", "bpf"),
            ],
        )
        sudo_index = next(index for index, event in enumerate(events) if event["kind"] == "sudo")
        metadata_indexes = [index for index, event in enumerate(events) if event["kind"] == "metadata"]
        self.assertLess(metadata_indexes[1], sudo_index)
        self.assertLess(sudo_index, metadata_indexes[2])
        sudo = events[sudo_index]
        self.assertTrue(sudo["initial_ready"])
        self.assertFalse(sudo["final_ready"])
        self.assertFalse(sudo["driver_status_present"])
        self.assertEqual(
            result.stdout.count("RESULT=NONPASS"),
            1,
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertEqual(
            (fixture.evidence / "driver.status").read_text(encoding="utf-8").splitlines()[0],
            "result=NONPASS",
        )
        self.assertEqual(
            (fixture.evidence / "driver-cleanup.status").read_text(encoding="utf-8"),
            "cleanup_status=0\n",
        )
        self.assertIn(
            "exit_status=1\n",
            (fixture.evidence / "driver.status").read_text(encoding="utf-8"),
        )

    def test_actual_cli_uses_exact_selected_tools_and_merged_source_inputs(self):
        fixture = self.fixture()
        fixture.run()

        rustup = [event for event in fixture.events() if event["kind"] == "rustup"]
        self.assertEqual(
            [event["argv"] for event in rustup],
            [
                ["which", "--toolchain", "1.88", "cargo"],
                ["which", "--toolchain", "1.88", "rustc"],
                ["which", "--toolchain", "nightly-2026-05-20", "cargo"],
                ["which", "--toolchain", "nightly-2026-05-20", "rustc"],
            ],
        )
        self.assertEqual({event["auto_install"] for event in rustup}, {"0"})
        metadata = [event for event in fixture.events() if event["kind"] == "metadata"]
        self.assertEqual(metadata[0]["executable"], str((fixture.prepared.tools / "stable cargo").resolve()))
        self.assertEqual(metadata[0]["rustc"], str((fixture.prepared.tools / "stable rustc").resolve()))
        self.assertEqual(metadata[1]["executable"], str((fixture.prepared.tools / "bpf cargo").resolve()))
        self.assertEqual(metadata[1]["rustc"], str((fixture.prepared.tools / "bpf rustc").resolve()))
        initial = fixture.ledger("initial")
        final = fixture.ledger("final")
        self.assertEqual(initial, final)
        self.assertIn("src/consumed source with spaces.rs", initial)
        self.assertIn("third-party/sources.json", initial)
        self.assertIn("third-party/patches/demo-1.0.0/ordered.patch", initial)
        self.assertIn("third-party/src/demo-1.0.0-p1/src/lib.rs", initial)
        self.assertNotIn("third-party/aya", "\n".join(initial))

    def test_actual_builds_forward_all_selected_tools_with_unexported_parent_variables(self):
        fixture = self.fixture("build paths with spaces")
        source = (fixture.root / "scripts/matrix/verify-abi-routing.sh").read_text()
        start = '    P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \\\n'
        end = "    DEFAULT_BIN="
        self.assertEqual(source.count(start), 2)
        command = fixture.base / "abi-build-commands.sh"
        command.write_text(source[source.index(start):source.index(end)])
        cargo = fixture.base / "selected stable cargo"
        shutil.copy2(FIXTURES / "build-probe.py", cargo)
        cargo.chmod(0o700)
        tools = [cargo]
        for name in ("selected stable rustc", "selected bpf cargo", "selected bpf rustc"):
            path = fixture.base / name
            path.write_text("fixture tool\n")
            path.chmod(0o700)
            tools.append(path)
        launcher = FIXTURES / "build-launcher.sh.in"

        def run(omitted):
            record = fixture.base / "abi-builds.jsonl"
            record.unlink(missing_ok=True)
            result = subprocess.run(
                ["/bin/sh", str(launcher), str(command), str(record),
                 *(str(path) for path in tools), omitted],
                cwd=fixture.root, env=fixture.environment(), text=True,
                capture_output=True, timeout=15,
            )
            return result, record

        result, record = run("none")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in record.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["target"] for row in rows], [
            str(command.parent / "default target"),
            str(command.parent / "diagnostic target"),
        ])
        self.assertEqual(rows[0]["argv"], ["build", "--locked", "--offline",
                                                   "--example", "abi-routing",
                                                   "--no-default-features"])
        self.assertEqual(rows[1]["argv"], rows[0]["argv"] +
                         ["--features", "unsafe-unvalidated-metadata"])
        for row in rows:
            self.assertEqual(row["cargo"], str(cargo.resolve()))
            self.assertEqual(row["rustc"], str(tools[1]))
            self.assertEqual(row["bpf_cargo"], str(tools[2]))
            self.assertEqual(row["bpf_rustc"], str(tools[3]))

        for omitted in ("P11SCOPE_PREPARED_STABLE_CARGO",
                        "P11SCOPE_PREPARED_STABLE_RUSTC",
                        "P11SCOPE_PREPARED_BPF_CARGO",
                        "P11SCOPE_PREPARED_BPF_RUSTC"):
            with self.subTest(omitted=omitted):
                result, record = run(omitted)
                self.assertNotEqual(result.returncode, 0, omitted)
                self.assertFalse(record.exists(), omitted)

    def test_actual_cli_quotes_spaced_version_tools_before_compiler(self):
        fixture = self.fixture()
        fixture.config["sudo_status"] = 0
        result = fixture.run()

        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=native64_fixture_build_failed", result.stdout)
        events = fixture.events()
        versions = [
            event for event in events
            if event["kind"] in ("cargo_version", "rustc_version")
        ]
        self.assertEqual(
            [(event["kind"], event["argv"]) for event in versions],
            [("cargo_version", ["--version"]), ("rustc_version", ["--version"])],
        )
        self.assertEqual(
            versions[0]["executable"],
            str((fixture.prepared.tools / "stable cargo").resolve()),
        )
        self.assertEqual(
            versions[0]["rustc"],
            str((fixture.prepared.tools / "stable rustc").resolve()),
        )
        self.assertEqual(
            versions[1]["executable"],
            str((fixture.prepared.tools / "stable rustc").resolve()),
        )
        kinds = [event["kind"] for event in events]
        self.assertLess(kinds.index("cargo_version"), kinds.index("compiler_version"))
        self.assertLess(kinds.index("rustc_version"), kinds.index("compiler_version"))
        self.assertLess(kinds.index("compiler_version"), kinds.index("compiler_refusal"))
        environment = (fixture.evidence / "environment.status").read_text(encoding="utf-8")
        self.assertIn("cargo_version=cargo 1.88.0 (fixture)\n", environment)
        self.assertIn("rustc_version=rustc 1.88.0 (fixture)\n", environment)

    def test_actual_cli_version_failures_stop_before_compiler(self):
        cases = (
            ("cargo_version_status", "stable_cargo_version_failed", "cargo_version"),
            ("rustc_version_status", "stable_rustc_version_failed", "rustc_version"),
        )
        for status_key, reason, final_kind in cases:
            with self.subTest(status_key=status_key):
                fixture = self.fixture(status_key)
                fixture.config["sudo_status"] = 0
                fixture.config[status_key] = 31
                result = fixture.run()

                self.assertEqual(result.returncode, 1)
                self.assertIn(f"reason={reason}", result.stdout)
                kinds = [event["kind"] for event in fixture.events()]
                self.assertIn(final_kind, kinds)
                self.assertFalse(any(kind.startswith("compiler") for kind in kinds))
                self.assertFalse((fixture.evidence / "environment.status").exists())

    def test_actual_cli_prepared_refusals_precede_sudo(self):
        cases = ("prepared_source", "missing_prepared_source", "root", "bpf")
        for name in cases:
            with self.subTest(name=name):
                fixture = self.fixture(name)
                if name == "prepared_source":
                    Path(fixture.config[name]).write_text("tampered\n", encoding="utf-8")
                elif name == "missing_prepared_source":
                    Path(fixture.config["prepared_source"]).unlink()
                else:
                    fixture.config[name + "_status"] = 23
                result = fixture.run()
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("NONPASS", result.stderr)
                self.assertFalse(any(event["kind"] == "sudo" for event in fixture.events()))
                self.assertFalse((fixture.evidence / "abi.prepared.final.receipt.json").exists())

    def test_actual_cli_final_mutation_remains_nonpass(self):
        fixture = self.fixture()
        fixture.config["mutation"] = "ordinary_source"
        result = fixture.run()

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("RESULT=NONPASS"), 1)
        self.assertNotEqual(fixture.ledger("initial"), fixture.ledger("final"))
        self.assertEqual(
            (fixture.evidence / "driver.status").read_text(encoding="utf-8").splitlines()[0],
            "result=NONPASS",
        )

    def test_function_only_finalizer_retains_cleanup_failure_after_recheck(self):
        fixture = self.fixture()
        result = fixture.run_cleanup_failure()

        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stdout.count("RESULT=NONPASS"),
            1,
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertFalse(any(event["kind"] == "sudo" for event in fixture.events()))
        self.assertEqual(
            [(event["phase"], event["context"]) for event in fixture.events()],
            [
                ("initial", "root"),
                ("initial", "bpf"),
                ("final", "root"),
                ("final", "bpf"),
            ],
        )
        self.assertTrue(Path(str(fixture.prefix) + ".final.receipt.json").is_file())
        status = (fixture.prefix.parent / "driver.status").read_text(encoding="utf-8")
        self.assertIn("result=NONPASS\n", status)
        self.assertIn("exit_status=1\n", status)
        self.assertEqual(
            (fixture.prefix.parent / "driver-cleanup.status").read_text(encoding="utf-8"),
            "cleanup_status=1\n",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
