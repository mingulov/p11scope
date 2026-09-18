#!/usr/bin/env python3
"""Behavior tests for the finite dependency source preparer."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest


SOURCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "prepare-dependencies.py"

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


def load_module(path: Path):
    return load_path(path, "prepare_dependencies")


class Fixture:
    def __init__(self, temporary: Path):
        self.root = temporary / "source"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "third-party" / "patches").mkdir(parents=True)
        shutil.copy2(SOURCE_SCRIPT, self.root / "scripts" / SOURCE_SCRIPT.name)
        (self.root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        self.archive_dir = temporary / "archives"
        self.archive_dir.mkdir()
        self.packages = []
        self.module = load_module(self.root / "scripts" / SOURCE_SCRIPT.name)

    def archive(self, name="demo", version="1.0.0", files=None, members=None):
        if files is None:
            files = {"Cargo.toml": b"[package]\nname = \"demo\"\n", "value.txt": b"base\n"}
        path = self.archive_dir / f"{name}-{version}.crate"
        with tarfile.open(path, "w:gz") as archive:
            if members is not None:
                for info, content in members:
                    archive.addfile(info, io.BytesIO(content) if content is not None else None)
            else:
                for relative, content in files.items():
                    info = tarfile.TarInfo(f"{name}-{version}/{relative}")
                    info.size = len(content)
                    info.mode = 0o755 if relative.endswith(".sh") else 0o644
                    archive.addfile(info, io.BytesIO(content))
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def patch(self, name, version, filename, text):
        directory = self.root / "third-party" / "patches" / f"{name}-{version}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_text(text, encoding="utf-8")
        return f"third-party/patches/{name}-{version}/{filename}"

    def record(self, name="demo", version="1.0.0", revision=1, files=None, patches=()):
        archive, digest = self.archive(name, version, files)
        expected = self.expected_tree(name, version, files or {
            "Cargo.toml": b"[package]\nname = \"demo\"\n", "value.txt": b"base\n"
        }, patches)
        record = {
            "name": name,
            "version": version,
            "revision": revision,
            "archive_sha256": digest,
            "patches": list(patches),
            "expected_tree_sha256": expected,
            "applies_to": ["Cargo.toml"],
        }
        self.packages.append(record)
        return record

    def expected_tree(self, name, version, files, patches):
        stage = self.root.parent / f"expected-{name}-{version}-{len(self.packages)}"
        stage.mkdir()
        stage.chmod(0o755)
        for relative, content in files.items():
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            parent = target.parent
            while parent.is_relative_to(stage):
                parent.chmod(0o755)
                if parent == stage:
                    break
                parent = parent.parent
            target.write_bytes(content)
            target.chmod(0o755 if relative.endswith(".sh") else 0o644)
        for patch in patches:
            result = subprocess.run(
                ["git", "apply", "--", str(self.root / patch)],
                cwd=stage, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            if result.returncode:
                raise AssertionError(result.stderr)
        self.module.normalize_tree_modes(stage)
        digest = self.module.compute_tree_digest(stage)
        shutil.rmtree(stage)
        return digest

    def write_manifest(self):
        data = {"schema_version": 1, "workspace_manifests": ["Cargo.toml"], "packages": self.packages}
        (self.root / "third-party" / "sources.json").write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )

    def run(self, *arguments, cwd=None, env=None):
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts" / SOURCE_SCRIPT.name), *arguments],
            cwd=cwd or self.root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )


PATCH_ONE = """diff --git a/value.txt b/value.txt
index df967b9..223b783 100644
--- a/value.txt
+++ b/value.txt
@@ -1 +1 @@
-base
+middle
"""
PATCH_TWO = """diff --git a/value.txt b/value.txt
index 223b783..b8f3990 100644
--- a/value.txt
+++ b/value.txt
@@ -1 +1 @@
-middle
+final
"""


class PrepareDependenciesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def prepare_demo(self, patches=(), revision=1):
        self.fixture.record(patches=patches, revision=revision)
        self.fixture.write_manifest()
        return self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))

    def test_fresh_offline_reconstruction_applies_ordered_series(self):
        first = self.fixture.patch("demo", "1.0.0", "01.patch", PATCH_ONE)
        second = self.fixture.patch("demo", "1.0.0", "02.patch", PATCH_TWO)
        result = self.prepare_demo((first, second))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.fixture.root / "third-party/src/demo-1.0.0-p1"
        self.assertEqual((output / "value.txt").read_bytes(), b"final\n")
        receipt = json.loads((output / ".p11scope-prepared.json").read_text())
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["package"], "demo")
        self.assertEqual(self.fixture.run("--check").returncode, 0)

    def test_ordered_series_applies_inside_actual_checkout_and_ignores_inherited_git_context(self):
        checkout_temporary = tempfile.TemporaryDirectory(dir=SOURCE_SCRIPT.parents[1])
        self.addCleanup(checkout_temporary.cleanup)
        fixture = Fixture(Path(checkout_temporary.name))
        first = fixture.patch("demo", "1.0.0", "01.patch", PATCH_ONE)
        second = fixture.patch("demo", "1.0.0", "02.patch", PATCH_TWO)
        record = fixture.record(patches=(first, second))
        record["expected_tree_sha256"] = fixture.expected_tree(
            "demo", "1.0.0",
            {"Cargo.toml": b"[package]\nname = \"demo\"\n", "value.txt": b"final\n"},
            (),
        )
        fixture.write_manifest()

        inherited_repository = Path(self.temporary.name) / "inherited-repository"
        inherited_repository.mkdir()
        init = subprocess.run(
            ["git", "init", "--quiet"], cwd=inherited_repository,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(init.returncode, 0, init.stderr)
        environment = os.environ.copy()
        environment["GIT_DIR"] = str(inherited_repository / ".git")
        environment["GIT_WORK_TREE"] = str(inherited_repository)
        environment["GIT_CONFIG_COUNT"] = "1"
        environment["GIT_CONFIG_KEY_0"] = "apply.whitespace"
        environment["GIT_CONFIG_VALUE_0"] = "error-all"

        result = fixture.run(
            "--offline", "--archive-dir", str(fixture.archive_dir), env=environment
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = fixture.root / "third-party/src/demo-1.0.0-p1"
        self.assertEqual((output / "value.txt").read_bytes(), b"final\n")
        self.assertFalse((output / ".git").exists())

    def test_another_package_version_is_added_only_through_manifest_data(self):
        self.fixture.record("demo", "1.0.0")
        self.fixture.record("other", "2.1.0", files={"Cargo.toml": b"other\n", "run.sh": b"#!/bin/sh\n"})
        self.fixture.write_manifest()
        result = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertEqual(result.returncode, 0, result.stderr)
        executable = self.fixture.root / "third-party/src/other-2.1.0-p1/run.sh"
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)

    def test_offline_missing_and_corrupt_archives_are_named_refusals(self):
        record = self.fixture.record()
        self.fixture.write_manifest()
        archive = self.fixture.archive_dir / "demo-1.0.0.crate"
        archive.unlink()
        missing = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("offline archive is missing", missing.stderr)
        archive.write_bytes(b"corrupt")
        corrupt = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertNotEqual(corrupt.returncode, 0)
        self.assertIn(record["archive_sha256"], corrupt.stderr)

    def test_partial_patch_failure_preserves_preexisting_output(self):
        bad = self.fixture.patch("other", "1.0.0", "bad.patch", PATCH_TWO)
        self.fixture.record("demo", "1.0.0")
        _other_archive, other_digest = self.fixture.archive("other", "1.0.0")
        self.fixture.packages.append({"name": "other", "version": "1.0.0", "revision": 1,
            "archive_sha256": other_digest, "patches": [bad], "expected_tree_sha256": "0" * 64,
            "applies_to": ["Cargo.toml"]})
        self.fixture.write_manifest()
        result = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("patch failed", result.stderr)
        output = self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt"
        before = output.read_bytes()
        self.assertEqual(output.read_bytes(), before)
        self.assertFalse((self.fixture.root / "third-party/src/other-1.0.0-p1").exists())
        self.fixture.packages[1]["patches"] = []
        self.fixture.packages[1]["expected_tree_sha256"] = self.fixture.expected_tree(
            "other", "1.0.0", {"Cargo.toml": b"[package]\nname = \"demo\"\n", "value.txt": b"base\n"}, ()
        )
        self.fixture.write_manifest()
        recovered = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(output.read_bytes(), before)

    def test_changed_same_revision_recipe_is_refused_without_mutation(self):
        self.assertEqual(self.prepare_demo().returncode, 0)
        output = self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt"
        original_mtime = output.stat().st_mtime_ns
        self.fixture.packages[0]["applies_to"] = ["Cargo.toml", "alternate/Cargo.toml"]
        self.fixture.write_manifest()
        result = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recipe identity mismatch", result.stderr)
        self.assertEqual(output.stat().st_mtime_ns, original_mtime)

    def test_reuse_verifies_bytes_and_is_idempotent(self):
        self.assertEqual(self.prepare_demo().returncode, 0)
        output = self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt"
        mtime = output.stat().st_mtime_ns
        self.assertEqual(self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir)).returncode, 0)
        self.assertEqual(output.stat().st_mtime_ns, mtime)
        output.write_bytes(b"tampered\n")
        result = self.fixture.run("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tree digest mismatch", result.stderr)

    def test_reuse_rejects_mode_tampering(self):
        self.assertEqual(self.prepare_demo().returncode, 0)
        output = self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt"
        output.chmod(0o755)
        result = self.fixture.run("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tree digest mismatch", result.stderr)

    def test_two_preparers_publish_one_valid_tree(self):
        self.fixture.record()
        self.fixture.write_manifest()
        command = [sys.executable, "-I", str(self.fixture.root / "scripts" / SOURCE_SCRIPT.name),
                   "--offline", "--archive-dir", str(self.fixture.archive_dir)]
        first = subprocess.Popen(command, cwd=self.fixture.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen(command, cwd=self.fixture.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        first_out, first_err = first.communicate(timeout=20)
        second_out, second_err = second.communicate(timeout=20)
        self.assertEqual((first.returncode, second.returncode), (0, 0), first_err + second_err + first_out + second_out)
        self.assertEqual(self.fixture.run("--check").returncode, 0)

    def test_new_revision_retains_old_tree(self):
        self.assertEqual(self.prepare_demo(revision=1).returncode, 0)
        self.fixture.packages = []
        self.fixture.record(revision=2)
        self.fixture.write_manifest()
        self.assertEqual(self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir)).returncode, 0)
        self.assertTrue((self.fixture.root / "third-party/src/demo-1.0.0-p1").is_dir())
        self.assertTrue((self.fixture.root / "third-party/src/demo-1.0.0-p2").is_dir())

    def test_interrupted_stage_is_never_accepted(self):
        stage = self.fixture.root / "third-party/.prepare-dependencies-stage-interrupted"
        stage.mkdir()
        (stage / "value.txt").write_text("poison", encoding="utf-8")
        result = self.prepare_demo()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.fixture.root / "third-party/src/demo-1.0.0-p1/value.txt").read_bytes(), b"base\n")

    def test_archive_rejects_unsafe_members_duplicates_and_links(self):
        cases = []
        traversal = tarfile.TarInfo("demo-1.0.0/../escape"); traversal.size = 1
        cases.append(("traversal", [(traversal, b"x")]))
        absolute = tarfile.TarInfo("/absolute"); absolute.size = 1
        cases.append(("absolute", [(absolute, b"x")]))
        duplicate_a = tarfile.TarInfo("demo-1.0.0/a"); duplicate_a.size = 1
        duplicate_b = tarfile.TarInfo("demo-1.0.0/a"); duplicate_b.size = 1
        cases.append(("duplicate", [(duplicate_a, b"x"), (duplicate_b, b"y")]))
        symlink = tarfile.TarInfo("demo-1.0.0/link"); symlink.type = tarfile.SYMTYPE; symlink.linkname = "a"
        cases.append(("link", [(symlink, None)]))
        git_config = tarfile.TarInfo("demo-1.0.0/.git/config"); git_config.size = 3
        cases.append(("Git metadata", [(git_config, b"bad")]))
        for label, members in cases:
            with self.subTest(label=label):
                local = Path(self.temporary.name) / label
                local.mkdir()
                fixture = Fixture(local)
                archive, digest = fixture.archive(members=members)
                fixture.packages.append({"name": "demo", "version": "1.0.0", "revision": 1,
                    "archive_sha256": digest, "patches": [], "expected_tree_sha256": "0" * 64,
                    "applies_to": ["Cargo.toml"]})
                fixture.write_manifest()
                result = fixture.run("--offline", "--archive-dir", str(fixture.archive_dir))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe archive", result.stderr)
                if label == "Git metadata":
                    self.assertIn("Git metadata", result.stderr)

    def test_archive_supports_explicit_directories_but_rejects_writable_modes(self):
        root = tarfile.TarInfo("demo-1.0.0"); root.type = tarfile.DIRTYPE; root.mode = 0o755
        nested = tarfile.TarInfo("demo-1.0.0/bin"); nested.type = tarfile.DIRTYPE; nested.mode = 0o755
        executable = tarfile.TarInfo("demo-1.0.0/bin/run"); executable.size = 2; executable.mode = 0o755
        archive, _digest = self.fixture.archive(members=[(root, None), (nested, None), (executable, b"x\n")])
        destination = Path(self.temporary.name) / "directories"
        self.fixture.module.extract_archive(archive, destination, "demo", "1.0.0")
        self.assertEqual(stat.S_IMODE((destination / "bin").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((destination / "bin/run").stat().st_mode), 0o755)

        writable = tarfile.TarInfo("demo-1.0.0/writable"); writable.type = tarfile.DIRTYPE; writable.mode = 0o775
        unsafe, _digest = self.fixture.archive(members=[(writable, None)])
        with self.assertRaisesRegex(self.fixture.module.PreparationError, "unsafe archive directory mode"):
            self.fixture.module.extract_archive(unsafe, Path(self.temporary.name) / "writable", "demo", "1.0.0")

    def test_reserved_receipt_and_general_limits_are_enforced(self):
        for relative in (".p11scope-prepared.json",):
            archive, digest = self.fixture.archive(files={relative: b"forged"})
            self.fixture.packages = [{"name": "demo", "version": "1.0.0", "revision": 1,
                "archive_sha256": digest, "patches": [], "expected_tree_sha256": "0" * 64,
                "applies_to": ["Cargo.toml"]}]
            self.fixture.write_manifest()
            result = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reserved receipt", result.stderr)

    def test_entry_and_expanded_byte_limits_accept_boundary_and_reject_excess(self):
        module = self.fixture.module
        module.MAX_ARCHIVE_ENTRIES = 2
        exact_members = []
        for name in ("a", "b"):
            info = tarfile.TarInfo(f"demo-1.0.0/{name}"); info.size = 1; info.mode = 0o644
            exact_members.append((info, b"x"))
        exact, _digest = self.fixture.archive(members=exact_members)
        destination = Path(self.temporary.name) / "exact"
        module.MAX_EXPANDED_BYTES = 2
        module.extract_archive(exact, destination, "demo", "1.0.0")
        self.assertEqual(sorted(path.name for path in destination.iterdir()), ["a", "b"])

        third = tarfile.TarInfo("demo-1.0.0/c"); third.size = 1; third.mode = 0o644
        excess_entries, _digest = self.fixture.archive(members=exact_members + [(third, b"x")])
        with self.assertRaisesRegex(module.PreparationError, "entry limit"):
            module.extract_archive(excess_entries, Path(self.temporary.name) / "too-many", "demo", "1.0.0")

        module.MAX_ARCHIVE_ENTRIES = 3
        with self.assertRaisesRegex(module.PreparationError, "expanded-byte limit"):
            module.extract_archive(excess_entries, Path(self.temporary.name) / "too-large", "demo", "1.0.0")

    def test_patch_cannot_supply_reserved_receipt(self):
        patch = self.fixture.patch("demo", "1.0.0", "receipt.patch", """diff --git a/.p11scope-prepared.json b/.p11scope-prepared.json
new file mode 100644
--- /dev/null
+++ b/.p11scope-prepared.json
@@ -0,0 +1 @@
+forged
""")
        files = {"Cargo.toml": b"[package]\nname = \"demo\"\n", "value.txt": b"base\n"}
        _archive, digest = self.fixture.archive(files=files)
        self.fixture.packages.append({"name": "demo", "version": "1.0.0", "revision": 1,
            "archive_sha256": digest, "patches": [patch], "expected_tree_sha256": "0" * 64,
            "applies_to": ["Cargo.toml"]})
        self.fixture.write_manifest()
        result = self.fixture.run("--offline", "--archive-dir", str(self.fixture.archive_dir))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("patch supplied reserved receipt", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
