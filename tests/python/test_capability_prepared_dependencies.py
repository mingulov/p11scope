#!/usr/bin/env python3
"""Native prepared-dependency tests for the capability-tier receipt owner."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "tests/fixtures/capability-prepared-dependencies"
EvidenceFixture = runpy.run_path(str(ROOT / "tests/python/test_prepared_dependency_evidence.py"))["EvidenceFixture"]


class CapabilityFixture:
    def __init__(self, base: Path):
        self.base = base
        self.evidence = EvidenceFixture(base / "source")
        self.repo = self.evidence.root
        for relative in (
            "scripts/verify-capability-tier.sh", "scripts/prepared-dependency-tools.sh",
            "scripts/prepared-dependency-snapshot.sh", "scripts/product-build.sh",
            "scripts/merge-checksum-ledgers.py",
        ):
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.tools = base / "selected tools with spaces"
        self.tools.mkdir()
        for name, fixture in (("stable cargo", "cargo.py"), ("bpf cargo", "cargo.py"),
                              ("stable rustc", "noop.sh"), ("bpf rustc", "noop.sh")):
            shutil.copy2(NATIVE / fixture, self.tools / name)
            (self.tools / name).chmod(0o755)
        self.fakebin = base / "path tools"
        self.fakebin.mkdir()
        (self.fakebin / "python3").symlink_to(sys.executable)
        for name, fixture in (("rustup", "rustup.py"), ("sudo", "sudo.py"),
                              ("capsh", "noop.sh"), ("gcc", "gcc.py"),
                              ("grep", "grep.py"), ("cat", "cat.py"),
                              ("sha256sum", "sha256sum.py")):
            shutil.copy2(NATIVE / fixture, self.fakebin / name)
            (self.fakebin / name).chmod(0o755)
        shutil.copy2(NATIVE / "target.sh", self.fakebin / "target.sh")
        self.events = base / "events.jsonl"
        self.sudo_marker = base / "sudo.marker"
        self.config_path = base / "config.json"
        self.config = {
            "events": str(self.events), "sudo_marker": str(self.sudo_marker),
            "fixture_root": str(base),
            "root_metadata": str(self.evidence.root_metadata),
            "bpf_metadata": str(self.evidence.bpf_metadata),
            "tools": {
                "1.88:cargo": str(self.tools / "stable cargo"),
                "1.88:rustc": str(self.tools / "stable rustc"),
                "nightly-2026-05-20:cargo": str(self.tools / "bpf cargo"),
                "nightly-2026-05-20:rustc": str(self.tools / "bpf rustc"),
            },
        }
        self.write_config()
        (self.repo / ".gitignore").write_text("third-party/src/\ntarget/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                        "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "fixture"], cwd=self.repo, check=True)
        self.environment = os.environ.copy()
        self.environment.update({
            "PATH": str(self.fakebin) + ":/usr/bin:/bin",
            "TMPDIR": str(base),
            "P11SCOPE_CAPABILITY_FIXTURE": str(self.config_path),
            "P11SCOPE_FAKE_CARGO_CONFIG": str(self.evidence.config_path),
        })
        self.module = base / "libsofthsm2.so"
        self.module.write_bytes(b"fixture module\n")
        self.environment["P11SCOPE_PKCS11_MODULE"] = str(self.module)
        binary = self.repo / "target/release/p11scope"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"fixture binary\n")

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def run(self):
        return subprocess.run(["/bin/sh", "scripts/verify-capability-tier.sh"], cwd=self.repo,
                              env=self.environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    def calls(self):
        if not self.events.exists():
            return []
        return [json.loads(row) for row in self.events.read_text().splitlines()]

    def work(self):
        values = list(self.base.glob("p11scope-verify-*/target/capability-tier"))
        if len(values) != 1:
            raise AssertionError(values)
        return values[0]


class CapabilityPreparedDependenciesTests(unittest.TestCase):
    def fixture(self, name):
        temporary = tempfile.TemporaryDirectory(prefix="capability-prepared-")
        self.addCleanup(temporary.cleanup)
        return CapabilityFixture(Path(temporary.name) / name)

    def test_actual_entry_admits_and_builds_with_all_four_selected_tools_before_sudo(self):
        fixture = self.fixture("success paths with spaces")
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("UNRUN: passwordless sudo unavailable", result.stdout)
        calls = fixture.calls()
        self.assertEqual(len(calls), 5)
        build = calls[2]
        self.assertEqual(build["argv"], ["build", "--locked", "--offline", "--release", "--workspace"])
        self.assertEqual(build["cargo"], str((fixture.tools / "stable cargo").resolve()))
        self.assertEqual(build["rustc"], str(fixture.tools / "stable rustc"))
        self.assertEqual(build["bpf_cargo"], str(fixture.tools / "bpf cargo"))
        self.assertEqual(build["bpf_rustc"], str(fixture.tools / "bpf rustc"))
        self.assertTrue(fixture.sudo_marker.is_file())

    def test_stale_initial_prepared_tree_refuses_before_build_and_sudo(self):
        fixture = self.fixture("stale")
        target = fixture.evidence.base.output / "src/lib.rs"
        target.write_bytes(target.read_bytes() + b"stale\n")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.sudo_marker.exists())
        self.assertFalse(any(call["argv"] and call["argv"][0] == "build" for call in fixture.calls()))

    def test_final_mutation_and_query_failure_are_nonpass_after_cleanup(self):
        for scenario in ("mutation", "query"):
            with self.subTest(scenario=scenario):
                fixture = self.fixture(scenario)
                if scenario == "mutation":
                    fixture.config["mutation_path"] = str(fixture.evidence.base.output / "src/lib.rs")
                else:
                    fixture.config["final_query_status"] = 19
                fixture.write_config()
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(fixture.sudo_marker.is_file())
                self.assertIn("refusal", result.stderr)

    def test_earlier_build_failure_is_preserved_and_never_reaches_sudo(self):
        fixture = self.fixture("prior failure")
        fixture.config["build_status"] = 83
        fixture.write_config()
        result = fixture.run()
        self.assertEqual(result.returncode, 83, result.stderr)
        self.assertFalse(fixture.sudo_marker.exists())
        self.assertEqual(len(fixture.calls()), 5)

    def test_metadata_binds_initial_and_final_receipts_and_snapshots(self):
        fixture = self.fixture("metadata")
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = fixture.work()
        metadata = (work / "metadata.txt").read_text()
        for key in ("prepared_initial_receipt_sha256=", "prepared_final_receipt_sha256=",
                    "prepared_initial_snapshot_sha256=", "prepared_final_snapshot_sha256="):
            self.assertEqual(metadata.count(key), 1, metadata)
        self.assertEqual((work / "source.start.tsv").read_bytes(), (work / "source.end.tsv").read_bytes())
        values = dict(line.split("=", 1) for line in metadata.splitlines() if "=" in line)
        for key, path in (
            ("prepared_initial_receipt_sha256", work / "dependencies.initial.receipt.json"),
            ("prepared_final_receipt_sha256", work / "dependencies.final.receipt.json"),
            ("prepared_initial_snapshot_sha256", work / "source.start.tsv"),
            ("prepared_final_snapshot_sha256", work / "source.end.tsv"),
        ):
            self.assertEqual(values[key], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_checksum_failure_is_nonpass_and_never_publishes_that_phase_bindings(self):
        for failure in ("initial-receipt", "initial-snapshot", "final-receipt", "final-snapshot"):
            with self.subTest(failure=failure):
                fixture = self.fixture("hash " + failure)
                fixture.config["hash_failure"] = failure
                fixture.write_config()
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                metadata_path = fixture.work() / "metadata.txt"
                metadata = metadata_path.read_text() if metadata_path.exists() else ""
                phase = failure.split("-", 1)[0]
                self.assertNotIn(f"prepared_{phase}_receipt_sha256=", metadata)
                self.assertNotIn(f"prepared_{phase}_snapshot_sha256=", metadata)
                if phase == "initial":
                    self.assertFalse(fixture.sudo_marker.exists())
                else:
                    self.assertTrue(fixture.sudo_marker.is_file())

    def test_final_checksum_failure_does_not_replace_an_earlier_status(self):
        fixture = self.fixture("hash after prior failure")
        fixture.config.update(build_status=83, hash_failure="final-receipt")
        fixture.write_config()
        result = fixture.run()
        self.assertEqual(result.returncode, 83, result.stderr)
        metadata_path = fixture.work() / "metadata.txt"
        metadata = metadata_path.read_text() if metadata_path.exists() else ""
        self.assertNotIn("prepared_final_receipt_sha256=", metadata)
        self.assertNotIn("prepared_final_snapshot_sha256=", metadata)

    def test_initial_and_final_metadata_output_failures_are_nonpass(self):
        for phase in ("initial", "final"):
            with self.subTest(phase=phase):
                fixture = self.fixture(phase + " publication failure")
                fixture.config[phase + "_publication_failure"] = True
                fixture.write_config()
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual((fixture.work() / "metadata.txt").is_dir(), True)
                self.assertEqual(fixture.sudo_marker.exists(), phase == "final")

    def test_digest_output_failure_is_not_masked_by_scratch_cleanup(self):
        fixture = self.fixture("digest output failure")
        source = (fixture.repo / "scripts/verify-capability-tier.sh").read_text()
        start = "dependency_digest() {\n"
        end = "record_metadata() {\n"
        self.assertEqual(source.count(start), 1)
        self.assertEqual(source.count(end), 1)
        definitions = fixture.base / "digest-definition.sh"
        definitions.write_text(source[source.index(start):source.index(end)])
        result = subprocess.run([
            "/bin/sh", str(NATIVE / "digest-launcher.sh"), str(definitions),
            str(fixture.module), "/dev/full",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_final_publication_failure_does_not_replace_an_earlier_status(self):
        fixture = self.fixture("publication after prior failure")
        fixture.config.update(build_status=83, final_publication_failure_after_build=True)
        fixture.write_config()
        result = fixture.run()
        self.assertEqual(result.returncode, 83, result.stderr)
        self.assertTrue((fixture.work() / "metadata.txt").is_dir())
        self.assertFalse(fixture.sudo_marker.exists())

    def test_full_actual_rows_stop_targets_before_fresh_final_queries(self):
        fixture = self.fixture("full finalization")
        fixture.config["full_runtime"] = True
        fixture.write_config()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("capability-tier: finite assessed doctor rows", result.stdout)
        calls = fixture.calls()
        self.assertEqual(len(calls), 5)
        self.assertEqual([call["targets_stopped"] for call in calls[3:]], [True, True])
        metadata = (fixture.work() / "metadata.txt").read_text()
        self.assertIn("prepared_final_receipt_sha256=", metadata)


if __name__ == "__main__":
    unittest.main(verbosity=2)
