#!/usr/bin/env python3
"""Actual live-freeze shell/checker tests with controlled external tools."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/live-freeze-prepared-dependencies"
EvidenceFixture = runpy.run_path(
    str(ROOT / "tests/python/test_prepared_dependency_evidence.py")
)["EvidenceFixture"]


class LiveFreezePreparedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="live freeze ")
        base = Path(self.temporary.name)
        self.prepared = EvidenceFixture(base)
        self.root = self.prepared.root
        for relative in (
            "scripts/verify-live-discovery-preflight.sh", "scripts/check-live-discovery-evidence.py",
            "scripts/lib.sh", "scripts/cleanup-traps.sh", "scripts/prepared-dependency-tools.sh",
            "scripts/prepared-dependency-snapshot.sh", "scripts/product-build.sh",
            "scripts/merge-checksum-ledgers.py", "crates/ebpf/src/main.rs",
            "scripts/check-bpf-map-defs.py",
            "crates/ebpf-common/src/lib.rs", "src/discovery/engine.rs",
            "src/discovery/loader.rs", "docs/privacy/allowlist-v1.md",
            "tests/fixtures/live-discovery-provider.c", "tests/fixtures/live-discovery-driver.c",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        shutil.copy2(FIXTURES / "object-inventory.py",
                     self.root / "scripts/check-live-discovery-object.py")
        self.bin = base / "bin with spaces"
        self.bin.mkdir()
        for name in ("rustup", "gcc", "ld", "ldd", "sudo", "cargo", "rustc"):
            shutil.copy2(FIXTURES / "tool.py", self.bin / name)
            (self.bin / name).chmod(0o755)
        for name in ("stable cargo", "bpf cargo"):
            shutil.copy2(FIXTURES / "tool.py", self.prepared.tools / name)
            (self.prepared.tools / name).chmod(0o755)
        self.private = base / "private frozen root"
        self.config_path = base / "freeze config.json"
        self.events_path = base / "freeze events.jsonl"
        self.config = {
            "private": str(self.private), "events": str(self.events_path),
            "metadata_tool": str(ROOT / "tests/fixtures/prepared-dependency-evidence/fake-cargo.py"),
            "object_checker": str(ROOT / "scripts/check-live-discovery-object.py"),
            "libc": str(Path("/lib/x86_64-linux-gnu/libc.so.6").resolve()),
            "tools": {f"{chain}:{kind}": str(self.prepared.tools / f"{prefix} {kind}")
                      for chain, prefix in (("1.88", "stable"), ("nightly-2026-05-20", "bpf"))
                      for kind in ("cargo", "rustc")},
        }
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "scripts", "src", "crates",
                        "docs", "tests", "Cargo.toml", "Cargo.lock", "third-party/sources.json",
                        "third-party/patches"], check=True)

    def tearDown(self):
        self.temporary.cleanup()

    def environment(self):
        self.config_path.write_text(json.dumps(self.config))
        environment = os.environ.copy()
        environment.update(PATH=str(self.bin) + ":/usr/bin:/bin",
                           P11SCOPE_LIVE_FREEZE_FIXTURE=str(self.config_path),
                           P11SCOPE_FAKE_CARGO_CONFIG=str(self.prepared.config_path))
        return environment

    def invoke(self, *args):
        return subprocess.run(["/bin/sh", str(self.root / "scripts/verify-live-discovery-preflight.sh"),
                               *args], cwd=self.root, env=self.environment(), capture_output=True,
                              text=True, timeout=30)

    def checker(self, *args):
        return subprocess.run([sys.executable, str(self.root / "scripts/check-live-discovery-evidence.py"),
                               *args], cwd=self.root, env=self.environment(), capture_output=True,
                              text=True, timeout=30)

    def freeze(self):
        return self.invoke("--freeze", str(self.private))

    def events(self):
        return ([json.loads(line) for line in self.events_path.read_text().splitlines()]
                if self.events_path.exists() else [])

    def assert_failed_unpublished(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.private / "execution-manifest.json").exists())
        self.assertFalse((self.private / "campaign/state.json").exists())
        self.assertNotIn("sudo", [event["tool"] for event in self.events()])

    def test_freeze_binds_selected_tools_and_both_receipts_before_publication(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads((self.private / "execution-manifest.json").read_text())
        self.assertEqual(manifest["schema"], "p11scope-live-discovery-execution/v2")
        state = json.loads((self.private / "campaign/state.json").read_text())
        self.assertEqual(state["state"], "frozen")
        self.assertEqual(state["manifest_sha256"], hashlib.sha256(
            (self.private / "execution-manifest.json").read_bytes()).hexdigest())
        dependencies = manifest["prepared_dependencies"]
        self.assertIn("initial.receipt.json", dependencies["artifacts"])
        self.assertIn("final.receipt.json", dependencies["artifacts"])
        self.assertEqual(dependencies["snapshots"]["initial"]["sha256"],
                         dependencies["snapshots"]["final"]["sha256"])
        events = self.events()
        builds = [event for event in events if event["argv"][0] == "build"]
        self.assertEqual(len(builds), 1)
        build = builds[0]
        self.assertEqual(build["argv"], ["build", "--locked", "--offline", "--release",
                                        "--workspace", "--target-dir", str(self.private / "build")])
        self.assertEqual(build["rustc"], str(self.prepared.tools / "stable rustc"))
        self.assertEqual(build["bpf_cargo"], str(self.prepared.tools / "bpf cargo"))
        self.assertEqual(build["bpf_rustc"], str(self.prepared.tools / "bpf rustc"))
        self.assertTrue(all(event["private_ready"] for event in events))
        self.assertTrue(build["initial_ready"])
        self.assertTrue(all(not event["published"] for event in events))
        calls = self.prepared.invocations()
        self.assertEqual([row["context"] for row in calls], ["root", "bpf", "root", "bpf"])

    def test_partial_metadata_failure_precedes_build_and_publication(self):
        self.prepared.config.update(bpf_status=19, bpf_stdout="partial query", bpf_stderr="failed query")
        self.prepared.write_config()
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertIn("status 19", result.stderr)
        self.assertNotIn("build", [event["argv"][0] for event in self.events()])
        evidence = self.private / "dependencies/prepared.initial.bpf.stdout.json"
        self.assertEqual(evidence.read_text(), "partial query")

    def test_changed_prepared_input_refuses_publication(self):
        self.config["mutate"] = str(self.prepared.base.output / "src/lib.rs")
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertIn("prepared", result.stderr)

    def test_partial_final_query_refuses_manifest_and_retains_raw_failure(self):
        self.config["final_bpf_status"] = 23
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertIn("status 23", result.stderr)
        self.assertTrue((self.private / "dependencies/prepared.initial.receipt.json").is_file())
        self.assertFalse((self.private / "dependencies/prepared.final.receipt.json").exists())
        self.assertEqual((self.private / "dependencies/prepared.final.bpf.stdout.json").read_text(),
                         "partial final query")

    def test_changed_tracked_input_refuses_publication(self):
        self.config["mutate"] = str(self.root / "src/discovery/loader.rs")
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertTrue((self.private / "dependencies/prepared.final.receipt.json").is_file())
        self.assertIn("differ", result.stdout)

    def test_changed_selected_tool_refuses_publication(self):
        self.config["mutate"] = str(self.prepared.tools / "stable rustc")
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertIn("selected tool identity changed", result.stderr)

    def test_build_failure_retains_initial_receipt_without_final_manifest(self):
        self.config["build_status"] = 17
        result = self.freeze()
        self.assert_failed_unpublished(result)
        self.assertEqual(result.returncode, 17)
        self.assertTrue((self.private / "dependencies/prepared.initial.receipt.json").is_file())

    def test_run_refuses_dependency_mutation_and_legacy_schema_before_sudo(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = self.private / "execution-manifest.json"
        manifest = json.loads(path.read_text())
        queries = len(self.prepared.invocations())
        for change in ("path", "schema", "receipt"):
            with self.subTest(change=change):
                mutated = json.loads(json.dumps(manifest))
                if change == "schema":
                    mutated["schema"] = "p11scope-live-discovery-execution/v1"
                elif change == "path":
                    mutated["prepared_dependencies"]["artifacts"]["initial.receipt.json"]["path"] = "/tmp/foreign"
                else:
                    receipt = self.private / "dependencies/prepared.final.receipt.json"
                    receipt.write_bytes(receipt.read_bytes() + b" ")
                path.write_text(json.dumps(mutated))
                result = self.invoke("--run", str(self.private), "fixture-kernel")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("sudo", [event["tool"] for event in self.events()])
                self.assertEqual(len(self.prepared.invocations()), queries)

    def test_normal_manifest_creation_requires_prepared_receipts(self):
        created = self.checker("--create-root", "--private-root", str(self.private))
        self.assertEqual(created.returncode, 0, created.stderr)
        result = self.checker("--write-manifest", "--private-root", str(self.private))
        self.assert_failed_unpublished(result)
        self.assertIn("initial receipt", result.stderr)

    def test_copied_root_with_intact_foreign_root_refuses_before_sudo(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        harness = self.private / "frozen/preflight-harness"
        shutil.copyfile("/bin/true", harness)
        harness.chmod(0o700)
        copied = Path(self.temporary.name) / "copied private root"
        shutil.copytree(self.private, copied)
        self.config["private"] = str(copied)
        queries = len(self.prepared.invocations())
        for missing_dependencies in (False, True):
            with self.subTest(missing_dependencies=missing_dependencies):
                if missing_dependencies:
                    shutil.rmtree(copied / "dependencies")
                result = self.invoke("--run", str(copied), "fixture-kernel")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requested execution manifest path", result.stderr)
                self.assertNotIn("sudo", [event["tool"] for event in self.events()])
                self.assertEqual(len(self.prepared.invocations()), queries)
                original = self.checker("--manifest", str(self.private / "execution-manifest.json"),
                                        "--require-prepared-dependencies")
                self.assertEqual(original.returncode, 0, original.stderr)

    def test_state_publication_failure_leaves_no_admissible_manifest(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.private / "execution-manifest.json"
        manifest.unlink()
        state = self.private / "campaign/state.json"
        state.unlink()
        state.mkdir()
        queries = len(self.prepared.invocations())
        result = self.checker("--write-manifest", "--private-root", str(self.private))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("state.json", result.stderr)
        self.assertFalse(manifest.exists())
        admission = self.checker("--manifest", str(manifest), "--require-prepared-dependencies")
        self.assertNotEqual(admission.returncode, 0)
        self.assertEqual(len(self.prepared.invocations()), queries)
        self.assertNotIn("sudo", [event["tool"] for event in self.events()])

    def test_repeated_publication_preserves_existing_manifest_and_state(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = [self.private / "execution-manifest.json", self.private / "campaign/state.json"]
        before = [path.read_bytes() for path in paths]
        result = self.checker("--write-manifest", "--private-root", str(self.private))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_coherent_historical_manifest_is_readonly_and_cannot_run(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.private / "execution-manifest.json"
        manifest = json.loads(path.read_text())
        manifest["schema"] = "p11scope-live-discovery-execution/v1"
        del manifest["prepared_dependencies"]
        manifest["validators"] = {name: digest for name, digest in manifest["validators"].items()
                                  if name in ("scripts/check-live-discovery-evidence.py",
                                              "scripts/check-live-discovery-object.py",
                                              "scripts/verify-live-discovery-preflight.sh")}
        path.write_text(json.dumps(manifest))
        result = self.checker("--manifest", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        harness = self.private / "frozen/preflight-harness"
        shutil.copyfile("/bin/true", harness)
        harness.chmod(0o700)
        queries = len(self.prepared.invocations())
        result = self.invoke("--run", str(self.private), "fixture-kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("historical v1 cannot run", result.stderr)
        self.assertEqual(len(self.prepared.invocations()), queries)
        self.assertNotIn("sudo", [event["tool"] for event in self.events()])

    def test_run_missing_final_receipt_and_symlink_receipt_refuse_before_sudo(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self.private / "dependencies/prepared.final.receipt.json"
        content = receipt.read_bytes()
        receipt.unlink()
        result = self.invoke("--run", str(self.private), "fixture-kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("final receipt", result.stderr)
        foreign = Path(self.temporary.name) / "copied receipt.json"
        foreign.write_bytes(content)
        receipt.symlink_to(foreign)
        result = self.invoke("--run", str(self.private), "fixture-kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)
        self.assertNotIn("sudo", [event["tool"] for event in self.events()])

    def test_valid_run_without_harness_stays_unrun_without_metadata_or_sudo(self):
        result = self.freeze()
        self.assertEqual(result.returncode, 0, result.stderr)
        queries = len(self.prepared.invocations())
        result = self.invoke("--run", str(self.private), "fixture-kernel")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UNRUN: no frozen preflight harness", result.stderr)
        self.assertEqual(len(self.prepared.invocations()), queries)
        self.assertNotIn("sudo", [event["tool"] for event in self.events()])

    def test_existing_frozen_path_mutations_still_refuse(self):
        result = self.invoke("--self-test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("input mutations rejected: OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
