#!/usr/bin/env python3
"""Native behavior tests for the finite offline dependency payload helper."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from types import SimpleNamespace


REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / "scripts/offline-dependencies.py"
PREPARER = REPOSITORY / "scripts/prepare-dependencies.py"
CHECKER = REPOSITORY / "scripts/check-prepared-dependencies.py"
FIXTURES = REPOSITORY / "tests/fixtures/offline-dependencies"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class OfflineFixture:
    def __init__(self, temporary: Path):
        self.root = temporary / "source root with spaces"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "third-party/patches/demo-1.0.0").mkdir(parents=True)
        (self.root / "crates/ebpf").mkdir(parents=True)
        for source in (HELPER, PREPARER, CHECKER):
            shutil.copy2(source, self.root / "scripts" / source.name)
        self.preparer = load_module(self.root / "scripts/prepare-dependencies.py", "fixture_preparer")

        (self.root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
        (self.root / "crates/ebpf/Cargo.toml").write_text(
            "[package]\nname = 'fixture-ebpf'\nversion = '0.1.0'\n", encoding="utf-8"
        )
        self.patch = self.root / "third-party/patches/demo-1.0.0/value.patch"
        self.patch.write_text(
            "diff --git a/value.txt b/value.txt\nindex df967b9..b8f3990 100644\n"
            "--- a/value.txt\n+++ b/value.txt\n@@ -1 +1 @@\n-base\n+final\n",
            encoding="utf-8",
        )
        self.archive_dir = temporary / "original archives"
        self.archive_dir.mkdir()
        self.archive = self.archive_dir / "demo-1.0.0.crate"
        self._archive(self.archive)
        expected = temporary / "expected"
        expected.mkdir(mode=0o755)
        (expected / "Cargo.toml").write_text(
            "[package]\nname = 'demo'\nversion = '1.0.0'\n", encoding="utf-8"
        )
        (expected / "value.txt").write_text("final\n", encoding="utf-8")
        for path in expected.iterdir():
            path.chmod(0o644)
        record = {
            "name": "demo", "version": "1.0.0", "revision": 1,
            "archive_sha256": digest(self.archive.read_bytes()),
            "patches": ["third-party/patches/demo-1.0.0/value.patch"],
            "expected_tree_sha256": self.preparer.compute_tree_digest(expected),
            "applies_to": ["Cargo.toml"],
        }
        self.sources = self.root / "third-party/sources.json"
        self.sources.write_text(json.dumps({
            "schema_version": 1,
            "workspace_manifests": ["Cargo.toml", "crates/ebpf/Cargo.toml"],
            "packages": [record],
        }, indent=2) + "\n", encoding="utf-8")
        self.export_manifest = self.root / ".p11scope-source-export.json"
        self.export_manifest.write_text(json.dumps({
            "schema_version": 1, "revision": "1" * 40,
            "source_entries": [], "archives": [],
        }) + "\n", encoding="utf-8")

        self.shared_url = "https://example.invalid/shared-dependency"
        self.shared_revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPOSITORY, check=True,
            stdout=subprocess.PIPE, text=True,
        ).stdout.strip()
        shared_source = f"git+{self.shared_url}?rev={self.shared_revision}#{self.shared_revision}"
        (self.root / "Cargo.lock").write_text(self._lock(shared_source, root=True), encoding="utf-8")
        (self.root / "crates/ebpf/Cargo.lock").write_text(
            self._lock(shared_source, root=False), encoding="utf-8"
        )

        self.sysroot = temporary / "nightly sysroot with spaces"
        rust = self.sysroot / "lib/rustlib/src/rust"
        (rust / "library/sysroot").mkdir(parents=True)
        (rust / "library/core/src").mkdir(parents=True)
        (rust / "library/sysroot/Cargo.toml").write_text(
            "[package]\nname = 'sysroot'\nversion = '0.0.0'\n", encoding="utf-8"
        )
        (rust / "library/Cargo.lock").write_text(self._sysroot_lock(), encoding="utf-8")
        (rust / "library/core/src/lib.rs").write_text("pub struct Core;\n", encoding="utf-8")
        for directory, _, files in os.walk(rust):
            Path(directory).chmod(0o775)
            for name in files:
                (Path(directory) / name).chmod(0o644)

        self.shared = temporary / "shared source"
        self.shared.mkdir()
        subprocess.run(
            ["git", "bundle", "create", str(self.shared / "source.bundle"), "HEAD"],
            cwd=REPOSITORY, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        (self.shared / "LICENSE-MIT").write_text("fixture MIT license\n", encoding="utf-8")
        (self.shared / "LICENSE-APACHE").write_text("fixture Apache license\n", encoding="utf-8")

        self.vendor_template = temporary / "Cargo vendor result"
        self.vendor_template.mkdir()
        self._vendor_package("registry-1.2.3", "registry", "1.2.3", "registry payload\n", "a" * 64)
        self._vendor_package("shared-0.1.0", "shared", "0.1.0", "shared payload\n", None)
        self._vendor_package("sysdep-0.0.1", "sysdep", "0.0.1", "sysroot payload\n", "b" * 64)

        self.tools = temporary / "selected tools with spaces"
        self.tools.mkdir()
        for name, source in (
            ("stable cargo", "fake-cargo.py"), ("bpf cargo", "fake-cargo.py"),
            ("stable rustc", "fake-rustc.py"), ("bpf rustc", "fake-rustc.py"),
            ("nightly rustc", "fake-rustc.py"),
        ):
            target = self.tools / name
            shutil.copy2(FIXTURES / source, target)
            target.chmod(0o755)
        self.log = temporary / "cargo invocations.jsonl"
        self._metadata_files()
        (self.tools / "fixture.json").write_text(json.dumps({
            "log": str(self.log), "source_root": str(self.root),
            "root_metadata": str(self.tools / "root-metadata.json"),
            "bpf_metadata": str(self.tools / "bpf-metadata.json"),
            "vendor_template": str(self.vendor_template), "sysroot": str(self.sysroot),
        }), encoding="utf-8")
        self.output = temporary / "payload location with spaces"
        self.candidate = temporary / "candidate recipe.json"
        self.prefix = temporary / "evidence with spaces" / "offline dependencies"
        self.prefix.parent.mkdir()

    @staticmethod
    def _archive(path: Path):
        with tarfile.open(path, "w:gz") as archive:
            for relative, content in {
                "Cargo.toml": b"[package]\nname = 'demo'\nversion = '1.0.0'\n",
                "value.txt": b"base\n",
            }.items():
                info = tarfile.TarInfo(f"demo-1.0.0/{relative}")
                info.mode = 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))

    def _lock(self, shared_source: str, *, root: bool) -> str:
        local = "fixture-root" if root else "fixture-ebpf"
        registry = "\n[[package]]\nname = 'registry'\nversion = '1.2.3'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\nchecksum = '" + "a" * 64 + "'\n" if root else ""
        return (
            "version = 4\n\n[[package]]\nname = '" + local + "'\nversion = '0.1.0'\n"
            + registry
            + "\n[[package]]\nname = 'shared'\nversion = '0.1.0'\nsource = '"
            + shared_source + "'\n"
        )

    @staticmethod
    def _sysroot_lock() -> str:
        return (
            "version = 4\n\n[[package]]\nname = 'sysdep'\nversion = '0.0.1'\n"
            "source = 'registry+https://github.com/rust-lang/crates.io-index'\nchecksum = '"
            + "b" * 64 + "'\n"
        )

    def _vendor_package(self, directory: str, name: str, version: str, body: str,
                        package_digest: str | None):
        root = self.vendor_template / directory
        root.mkdir()
        manifest = f"[package]\nname = '{name}'\nversion = '{version}'\n"
        (root / "Cargo.toml").write_text(manifest, encoding="utf-8")
        (root / "src.rs").write_text(body, encoding="utf-8")
        checksums = {
            "files": {
                "Cargo.toml": digest(manifest.encode()),
                "src.rs": digest(body.encode()),
            },
            "package": package_digest,
        }
        (root / ".cargo-checksum.json").write_text(
            json.dumps(checksums, sort_keys=True) + "\n", encoding="utf-8"
        )
        for path in root.iterdir():
            path.chmod(0o644)

    def _metadata_files(self):
        def package(identifier, name, version, manifest, source=None):
            return {"id": identifier, "name": name, "version": version,
                    "manifest_path": manifest, "source": source,
                    "dependencies": [], "features": {}}
        root_id = "path+file://fixture#fixture-root@0.1.0"
        demo_id = "path+file://fixture/demo#demo@1.0.0"
        root_metadata = {
            "version": 1, "workspace_root": "@SOURCE_ROOT@",
            "packages": [
                package(root_id, "fixture-root", "0.1.0", "@SOURCE_ROOT@/Cargo.toml"),
                package(demo_id, "demo", "1.0.0", "@SOURCE_ROOT@/third-party/src/demo-1.0.0-p1/Cargo.toml"),
            ],
            "workspace_members": [root_id],
            "resolve": {"root": root_id, "nodes": [
                {"id": root_id, "dependencies": [demo_id], "deps": [
                    {"name": "demo", "pkg": demo_id, "dep_kinds": [{"kind": None, "target": None}]}
                ], "features": []},
                {"id": demo_id, "dependencies": [], "deps": [], "features": []},
            ]},
        }
        bpf_id = "path+file://fixture/ebpf#fixture-ebpf@0.1.0"
        bpf_metadata = {
            "version": 1, "workspace_root": "@SOURCE_ROOT@/crates/ebpf",
            "packages": [package(bpf_id, "fixture-ebpf", "0.1.0", "@SOURCE_ROOT@/crates/ebpf/Cargo.toml")],
            "workspace_members": [bpf_id],
            "resolve": {"root": bpf_id, "nodes": [
                {"id": bpf_id, "dependencies": [], "deps": [], "features": []}
            ]},
        }
        (self.tools / "root-metadata.json").write_text(json.dumps(root_metadata), encoding="utf-8")
        (self.tools / "bpf-metadata.json").write_text(json.dumps(bpf_metadata), encoding="utf-8")

    def run(self, phase: str, *, payload: Path | None = None, prefix: Path | None = None,
            environment: dict[str, str] | None = None):
        command = [sys.executable, "-I", str(self.root / "scripts/offline-dependencies.py"), phase]
        if phase == "assemble":
            command += [
                "--output", str(self.output), "--candidate-recipe", str(self.candidate),
                "--archive-dir", str(self.archive_dir), "--shared-source", str(self.shared),
                "--prefix", str(prefix or self.prefix),
                "--stable-cargo", str(self.tools / "stable cargo"),
                "--stable-rustc", str(self.tools / "stable rustc"),
                "--bpf-cargo", str(self.tools / "bpf cargo"),
                "--bpf-rustc", str(self.tools / "bpf rustc"),
            ]
        else:
            command += [
                "--payload", str(payload or self.output),
                "--nightly-rustc", str(self.tools / "nightly rustc"),
                "--prefix", str(prefix or self.prefix),
            ]
        return subprocess.run(command, cwd=self.root.parent, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assemble(self):
        result = self.run("assemble")
        self.testcase.assertEqual(result.returncode, 0, result.stderr)
        return result

    def approve(self):
        shutil.copy2(self.candidate, self.root / "third-party/offline-dependencies.json")

    def update_tool_configuration(self, **values):
        path = self.tools / "fixture.json"
        configuration = json.loads(path.read_text(encoding="utf-8"))
        configuration.update(values)
        path.write_text(json.dumps(configuration), encoding="utf-8")


class OfflineDependenciesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = OfflineFixture(Path(self.temporary.name))
        self.fixture.testcase = self

    def tearDown(self):
        self.temporary.cleanup()

    def assert_refused(self, result, *needles):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_assemble_runs_fixed_offline_resolver_and_produces_complete_payload(self):
        self.fixture.assemble()
        calls = [json.loads(line) for line in self.fixture.log.read_text().splitlines()]
        self.assertEqual([call["program"] for call in calls],
                         ["stable cargo", "bpf cargo", "bpf cargo", "stable cargo", "bpf cargo"])
        self.assertTrue(all(call["cargo_net_offline"] == "true" for call in calls))
        self.assertEqual([call["rustc"] for call in calls], [
            str(self.fixture.tools / "stable rustc"),
            str(self.fixture.tools / "bpf rustc"),
            str(self.fixture.tools / "bpf rustc"),
            str(self.fixture.tools / "stable rustc"),
            str(self.fixture.tools / "bpf rustc"),
        ])
        self.assertEqual(calls[0]["argv"], [
            "metadata", "--locked", "--offline", "--all-features", "--format-version", "1",
            "--manifest-path", str(self.fixture.root / "Cargo.toml"),
        ])
        self.assertEqual(calls[1]["argv"], [
            "metadata", "--locked", "--offline", "--all-features", "--format-version", "1",
            "--manifest-path", str(self.fixture.root / "crates/ebpf/Cargo.toml"),
        ])
        vendor = calls[2]["argv"]
        self.assertEqual(vendor[:4], ["vendor", "--locked", "--offline", "--versioned-dirs"])
        self.assertEqual(vendor.count("--sync"), 2)
        self.assertEqual(Path(vendor[-1]).name, "vendor")
        self.assertEqual((self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt").read_text(), "final\n")
        self.assertEqual(set(path.name for path in (self.fixture.output / "archives").iterdir()),
                         {"demo-1.0.0.crate"})
        self.assertTrue((self.fixture.output / "provenance/shared/source.bundle").is_file())
        self.assertTrue((self.fixture.output / "provenance/nightly/sysroot-Cargo.toml").is_file())
        recipe = json.loads(self.fixture.candidate.read_text())
        self.assertEqual(set(recipe), {"schema_version", "workspaces", "preparation", "nightly",
                                      "shared_git", "payload_tree_sha256"})
        self.assertNotIn("HEAD", self.fixture.candidate.read_text())
        self.assertNotIn(str(self.fixture.root), self.fixture.candidate.read_text())
        for suffix in ("command.json", "tools.json", "inputs.json", "outcome.json"):
            self.assertTrue(Path(f"{self.fixture.prefix}.assemble.{suffix}").is_file())

    def test_assemble_refuses_unrecognized_cargo_checksum_schema(self):
        mutations = (
            ("altered comment", {"$comment": "altered"}),
            ("extra key", {"unexpected": True}),
        )
        for index, (label, mutation) in enumerate(mutations):
            with self.subTest(label=label):
                temporary = Path(self.temporary.name) / f"checksum schema {index}"
                temporary.mkdir()
                fixture = OfflineFixture(temporary)
                fixture.testcase = self
                fixture.update_tool_configuration(vendor_checksum_mutation=mutation)

                result = fixture.run("assemble")

                self.assert_refused(result, "malformed Cargo vendor checksum")
                self.assertFalse(fixture.candidate.exists())
                self.assertFalse(fixture.output.exists())
                self.assertFalse(Path(f"{fixture.prefix}.assemble.outcome.json").exists())

    def test_verify_refuses_unrecognized_cargo_checksum_schema_before_receipt(self):
        self.fixture.assemble()
        self.fixture.approve()
        mutations = (
            ("altered comment", {"$comment": "altered"}),
            ("extra key", {"unexpected": True}),
        )
        for index, (label, mutation) in enumerate(mutations):
            with self.subTest(label=label):
                payload = Path(self.temporary.name) / f"checksum verify {index}"
                shutil.copytree(self.fixture.output, payload)
                checksum_path = payload / "vendor/shared-0.1.0/.cargo-checksum.json"
                checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
                checksum.update(mutation)
                checksum_path.write_text(json.dumps(checksum) + "\n", encoding="utf-8")
                prefix = self.fixture.prefix.parent / f"checksum verify evidence {index}"

                result = self.fixture.run("verify", payload=payload, prefix=prefix)

                self.assert_refused(result, "malformed Cargo vendor checksum")
                self.assertFalse(Path(f"{prefix}.verify.outcome.json").exists())
                self.assertFalse(Path(f"{prefix}.verify.receipt.json").exists())

    def test_bundle_advertisement_requires_self_contained_commit_closure(self):
        pack = b"PACK" + struct.pack(">II", 2, 0)
        pack += hashlib.sha1(pack).digest()
        header = f"# v2 git bundle\n{self.fixture.shared_revision} refs/heads/fixture\n\n".encode()
        (self.fixture.shared / "source.bundle").write_bytes(header + pack)
        result = self.fixture.run("assemble")
        self.assert_refused(result, "advertised revision is not a self-contained commit")
        self.assertFalse(self.fixture.candidate.exists())

    def test_bundle_validation_cannot_borrow_ambient_git_objects(self):
        valid_bundle = self.fixture.shared / "source.bundle"
        external = Path(self.temporary.name) / "ambient object store"
        (external / "objects").mkdir(parents=True)
        (external / "refs").mkdir()
        (external / "HEAD").write_text("ref: refs/heads/unused\n", encoding="ascii")
        clean = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        clean.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        imported = subprocess.run(
            ["git", f"--git-dir={external}", "bundle", "unbundle", str(valid_bundle)],
            env=clean, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        poisoned = os.environ.copy()
        poisoned.update({
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(external / "objects"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.warnAmbiguousRefs",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_NO_REPLACE_OBJECTS": "0",
        })

        valid_result = self.fixture.run("assemble", environment=poisoned)
        self.assertEqual(valid_result.returncode, 0, valid_result.stderr)
        self.fixture.approve()
        valid_verify_prefix = self.fixture.prefix.parent / "valid poisoned verify"
        valid_verify = self.fixture.run(
            "verify", prefix=valid_verify_prefix, environment=poisoned
        )
        self.assertEqual(valid_verify.returncode, 0, valid_verify.stderr)

        pack = b"PACK" + struct.pack(">II", 2, 0)
        pack += hashlib.sha1(pack).digest()
        header = f"# v2 git bundle\n{self.fixture.shared_revision} refs/heads/fixture\n\n".encode()
        empty_bundle = header + pack

        assemble_temporary = Path(self.temporary.name) / "empty bundle assembly"
        assemble_temporary.mkdir()
        invalid_assemble = OfflineFixture(assemble_temporary)
        invalid_assemble.testcase = self
        (invalid_assemble.shared / "source.bundle").write_bytes(empty_bundle)
        assemble_result = invalid_assemble.run("assemble", environment=poisoned)

        verify_temporary = Path(self.temporary.name) / "empty bundle verification"
        verify_temporary.mkdir()
        invalid_verify = OfflineFixture(verify_temporary)
        invalid_verify.testcase = self
        invalid_verify.assemble()
        payload_bundle = invalid_verify.output / "provenance/shared/source.bundle"
        payload_bundle.write_bytes(empty_bundle)
        provenance_path = invalid_verify.output / "provenance/shared/packages.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["source"]["bundle_sha256"] = digest(empty_bundle)
        provenance_path.write_text(
            json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        recipe = json.loads(invalid_verify.candidate.read_text(encoding="utf-8"))
        module = load_module(
            invalid_verify.root / "scripts/offline-dependencies.py", "invalid_helper"
        )
        recipe["payload_tree_sha256"] = module.tree_content_digest(invalid_verify.output)
        (invalid_verify.root / "third-party/offline-dependencies.json").write_text(
            json.dumps(recipe, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        verify_result = invalid_verify.run("verify", environment=poisoned)

        with self.subTest(phase="assemble"):
            self.assert_refused(
                assemble_result, "advertised revision is not a self-contained commit"
            )
            self.assertFalse(invalid_assemble.candidate.exists())
            self.assertFalse(invalid_assemble.output.exists())
            self.assertFalse(Path(f"{invalid_assemble.prefix}.assemble.outcome.json").exists())
        with self.subTest(phase="verify"):
            self.assert_refused(
                verify_result, "advertised revision is not a self-contained commit"
            )
            self.assertFalse(Path(f"{invalid_verify.prefix}.verify.outcome.json").exists())
            self.assertFalse(Path(f"{invalid_verify.prefix}.verify.receipt.json").exists())

    def test_final_metadata_preserves_all_three_frozen_lock_inputs(self):
        targets = (
            ("root", "Cargo.lock"),
            ("bpf", "crates/ebpf/Cargo.lock"),
            ("sysroot", "nightly sysroot with spaces/lib/rustlib/src/rust/library/Cargo.lock"),
        )
        for index, (label, relative) in enumerate(targets):
            with self.subTest(label=label):
                temporary = Path(self.temporary.name) / f"lock case {index}"
                temporary.mkdir()
                fixture = OfflineFixture(temporary)
                fixture.testcase = self
                target = temporary / relative if label == "sysroot" else fixture.root / relative
                fixture.update_tool_configuration(cargo_mutation={
                    "call": 5, "path": str(target), "append": "\n# final metadata mutation\n",
                })
                result = fixture.run("assemble")
                self.assert_refused(result, "changed during assembly")
                self.assertFalse(fixture.candidate.exists())
                self.assertFalse(Path(f"{fixture.prefix}.assemble.outcome.json").exists())

    def test_final_nightly_query_precedes_approved_payload_comparison(self):
        self.fixture.assemble()
        self.fixture.approve()
        self.fixture.update_tool_configuration(rustc_payload_mutation={
            "program": "nightly rustc", "call": 2, "payload": str(self.fixture.output),
            "append": "changed during final nightly query\n",
        })
        result = self.fixture.run("verify")
        self.assert_refused(result, "payload tree digest mismatch")
        self.assertFalse(Path(f"{self.fixture.prefix}.verify.receipt.json").exists())

    def test_verify_uses_only_fixed_recipe_and_detects_coherent_payload_tamper(self):
        self.fixture.assemble()
        self.assert_refused(self.fixture.run("verify"), "fixed recipe")
        self.fixture.approve()
        shutil.rmtree(self.fixture.root / "third-party/src")
        self.assertEqual(self.fixture.run("verify").returncode, 0)
        self.assertEqual(
            (self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt").read_text(),
            "final\n",
        )
        package = self.fixture.output / "vendor/shared-0.1.0"
        manifest = package / "Cargo.toml"
        manifest.write_text(manifest.read_text() + "description = 'tampered'\n", encoding="utf-8")
        checksum_path = package / ".cargo-checksum.json"
        checksum = json.loads(checksum_path.read_text())
        checksum["files"]["Cargo.toml"] = digest(manifest.read_bytes())
        checksum_path.write_text(json.dumps(checksum, sort_keys=True) + "\n", encoding="utf-8")
        provenance_path = self.fixture.output / "provenance/shared/packages.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["packages"][0]["manifest_sha256"] = digest(manifest.read_bytes())
        provenance_path.write_text(json.dumps(provenance, sort_keys=True) + "\n", encoding="utf-8")
        self.assert_refused(self.fixture.run("verify"), "payload tree digest mismatch")

    def test_verify_binds_inputs_but_ignores_unrelated_project_source_identity(self):
        self.fixture.assemble()
        self.fixture.approve()
        (self.fixture.root / "unrelated-source.txt").write_text("new project HEAD content\n", encoding="utf-8")
        result = self.fixture.run("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(Path(f"{self.fixture.prefix}.verify.receipt.json").read_text())
        self.assertEqual(receipt["project_source"]["revision"], "1" * 40)
        export = json.loads(self.fixture.export_manifest.read_text())
        export["revision"] = "2" * 40
        self.fixture.export_manifest.write_text(json.dumps(export) + "\n", encoding="utf-8")
        second_prefix = self.fixture.prefix.parent / "after source-only revision"
        second = self.fixture.run("verify", prefix=second_prefix)
        self.assertEqual(second.returncode, 0, second.stderr)
        second_receipt = json.loads(Path(f"{second_prefix}.verify.receipt.json").read_text())
        self.assertEqual(second_receipt["project_source"]["revision"], "2" * 40)
        self.assertEqual(receipt["payload_tree_sha256"], second_receipt["payload_tree_sha256"])
        for label, path in (
            ("package recipe", self.fixture.patch),
            ("sources manifest", self.fixture.sources),
            ("workspace lock", self.fixture.root / "Cargo.lock"),
            ("nightly source", self.fixture.sysroot / "lib/rustlib/src/rust/library/core/src/lib.rs"),
        ):
            original = path.read_bytes()
            path.write_bytes(original + b"tamper\n")
            result = self.fixture.run("verify")
            self.assert_refused(result, label)
            path.write_bytes(original)

    def test_recipe_schema_and_shared_revision_are_closed(self):
        self.fixture.assemble()
        self.fixture.approve()
        recipe_path = self.fixture.root / "third-party/offline-dependencies.json"
        original = recipe_path.read_text()
        duplicate = original.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        recipe_path.write_text(duplicate, encoding="utf-8")
        self.assert_refused(self.fixture.run("verify"), "duplicate JSON key")
        recipe_path.write_text(original, encoding="utf-8")
        checksum = self.fixture.output / "vendor/shared-0.1.0/.cargo-checksum.json"
        checksum_original = checksum.read_text()
        checksum.write_text(checksum_original.replace('"files":', '"files":{},"files":'), encoding="utf-8")
        self.assert_refused(self.fixture.run("verify"), "duplicate JSON key")
        checksum.write_text(checksum_original, encoding="utf-8")
        recipe = json.loads(original)
        recipe["preparation"]["package_recipes"]["extra-9.9.9-p1"] = "0" * 64
        recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
        self.assert_refused(self.fixture.run("verify"), "package recipe entries")
        recipe = json.loads(original)
        recipe["shared_git"]["revision"] = "0" * 40
        recipe_path.write_text(json.dumps(recipe), encoding="utf-8")
        self.assert_refused(self.fixture.run("verify"), "shared Git revision")

    def test_structure_paths_links_and_delivery_modes_are_refused(self):
        self.fixture.assemble()
        self.fixture.approve()
        pristine = Path(self.temporary.name) / "pristine"
        shutil.copytree(self.fixture.output, pristine)
        mutations = (
            ("missing license", lambda p: (p / "provenance/shared/LICENSE-MIT").unlink(), "missing payload entry"),
            ("missing archive", lambda p: (p / "archives/demo-1.0.0.crate").unlink(), "archive set mismatch"),
            ("extra entry", lambda p: ((p / "extra").write_text("extra"), (p / "extra").chmod(0o644)),
             "unexpected payload entry"),
            ("unsafe link", lambda p: (p / "vendor/link").symlink_to("shared-0.1.0"), "unsafe symbolic link"),
            ("unsafe mode", lambda p: (p / "vendor/shared-0.1.0/src.rs").chmod(0o600), "unsafe delivery mode"),
            ("unsafe root mode", lambda p: p.chmod(0o700), "unsafe delivery mode"),
        )
        for index, (label, mutate, needle) in enumerate(mutations):
            with self.subTest(label=label):
                payload = Path(self.temporary.name) / f"mutated {index}"
                shutil.copytree(pristine, payload)
                mutate(payload)
                self.assert_refused(self.fixture.run("verify", payload=payload), needle)

    def test_payload_identity_and_finite_config_survive_relocation_with_spaces(self):
        self.fixture.assemble()
        self.fixture.approve()
        relocated = Path(self.temporary.name) / "another location with spaces" / "payload"
        relocated.parent.mkdir()
        shutil.copytree(self.fixture.output, relocated)
        result = self.fixture.run("verify", payload=relocated)
        self.assertEqual(result.returncode, 0, result.stderr)
        module = load_module(self.root_helper, "offline_dependency_config")
        shared = {"url": self.fixture.shared_url, "revision": self.fixture.shared_revision}
        absolute = module.replacement_config(relocated, shared)
        relative = module.replacement_config(relocated, shared, vendor_path="deps/vendor")
        self.assertIn(str(relocated / "vendor").encode(), absolute)
        self.assertIn(b'directory = "deps/vendor"', relative)
        self.assertEqual(absolute.count(b"replace-with"), 2)
        parsed = tomllib.loads(relative.decode("utf-8"))
        self.assertEqual(parsed["source"]["vendored-sources"]["directory"], "deps/vendor")
        self.assertTrue(parsed["net"]["offline"])
        with self.assertRaises(module.OfflineDependencyError):
            module.replacement_config(relocated, shared, vendor_path="../vendor")

    def test_git_free_v2_source_identity_is_accepted_by_real_verify_and_returns_receipt(self):
        self.fixture.assemble()
        self.fixture.approve()
        association = {
            "payload_path": "third-party/offline",
            "recipe_path": "third-party/offline-dependencies.json",
            "recipe_sha256": digest(
                (self.fixture.root / "third-party/offline-dependencies.json").read_bytes()
            ),
            "payload_tree_sha256": json.loads(self.fixture.candidate.read_text())[
                "payload_tree_sha256"
            ],
            "config_path": ".cargo/config.toml",
            "config_sha256": "2" * 64,
        }
        self.fixture.export_manifest.write_text(json.dumps({
            "schema_version": 2, "revision": "1" * 40,
            "source_entries": [], "archives": [],
            "offline_dependencies": association,
        }) + "\n", encoding="utf-8")
        module = load_module(self.root_helper, "offline_dependency_v2_receipt")
        options = SimpleNamespace(
            payload=self.fixture.output,
            nightly_rustc=self.fixture.tools / "nightly rustc",
            prefix=self.fixture.prefix.parent / "v2 direct receipt",
        )

        receipt = module.verify(self.fixture.root, options, self.fixture.preparer)

        self.assertEqual(receipt["project_source"]["kind"], "source-export")
        self.assertEqual(receipt["project_source"]["revision"], "1" * 40)
        self.assertEqual(receipt["payload_tree_sha256"], association["payload_tree_sha256"])

    def test_v2_source_identity_refuses_open_or_malformed_association_and_unknown_schema(self):
        self.fixture.assemble()
        self.fixture.approve()
        valid = {
            "schema_version": 2, "revision": "1" * 40,
            "source_entries": [], "archives": [],
            "offline_dependencies": {
                "payload_path": "third-party/offline",
                "recipe_path": "third-party/offline-dependencies.json",
                "recipe_sha256": "0" * 64,
                "payload_tree_sha256": "1" * 64,
                "config_path": ".cargo/config.toml",
                "config_sha256": "2" * 64,
            },
        }
        mutations = []
        missing = json.loads(json.dumps(valid))
        del missing["offline_dependencies"]["config_sha256"]
        mutations.append(("missing", missing))
        additional = json.loads(json.dumps(valid))
        additional["offline_dependencies"]["extra"] = "value"
        mutations.append(("additional", additional))
        wrong_type = json.loads(json.dumps(valid))
        wrong_type["offline_dependencies"]["payload_path"] = 7
        mutations.append(("wrong type", wrong_type))
        unknown = json.loads(json.dumps(valid))
        unknown["schema_version"] = 3
        mutations.append(("unknown schema", unknown))

        module = load_module(self.root_helper, "offline_dependency_v2_refusals")
        for label, manifest in mutations:
            with self.subTest(label=label):
                self.fixture.export_manifest.write_text(json.dumps(manifest) + "\n")
                with self.assertRaisesRegex(
                    module.OfflineDependencyError, "source export manifest"
                ):
                    module._project_source_identity(self.fixture.root)

    def test_real_verify_rejects_non_integer_export_and_recipe_schema_versions(self):
        self.fixture.assemble()
        self.fixture.approve()
        v1 = {
            "schema_version": 1, "revision": "1" * 40,
            "source_entries": [], "archives": [],
        }
        association = {
            "payload_path": "third-party/offline",
            "recipe_path": "third-party/offline-dependencies.json",
            "recipe_sha256": "0" * 64,
            "payload_tree_sha256": json.loads(self.fixture.candidate.read_text())[
                "payload_tree_sha256"
            ],
            "config_path": ".cargo/config.toml",
            "config_sha256": "2" * 64,
        }
        exports = []
        boolean_v1 = dict(v1)
        boolean_v1["schema_version"] = True
        exports.append(("boolean v1", boolean_v1))
        float_v2 = dict(v1)
        float_v2.update({"schema_version": 2.0, "offline_dependencies": association})
        exports.append(("float v2", float_v2))
        string_v1 = dict(v1)
        string_v1["schema_version"] = "1"
        exports.append(("string v1", string_v1))
        for index, (label, manifest) in enumerate(exports):
            with self.subTest(label=label):
                self.fixture.export_manifest.write_text(json.dumps(manifest) + "\n")
                result = self.fixture.run(
                    "verify", prefix=self.fixture.prefix.parent / f"numeric export {index}"
                )
                self.assert_refused(result, "source export manifest")

        self.fixture.export_manifest.write_text(json.dumps(v1) + "\n")
        recipe_path = self.fixture.root / "third-party/offline-dependencies.json"
        recipe = json.loads(recipe_path.read_text())
        recipe["schema_version"] = True
        recipe_path.write_text(json.dumps(recipe) + "\n")
        result = self.fixture.run(
            "verify", prefix=self.fixture.prefix.parent / "numeric recipe"
        )
        self.assert_refused(result, "fixed recipe")

    @property
    def root_helper(self):
        return self.fixture.root / "scripts/offline-dependencies.py"


if __name__ == "__main__":
    unittest.main()
