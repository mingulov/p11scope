#!/usr/bin/env python3
"""Native source-export tests with isolated synthetic Git repositories."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "scripts/export-source.py"
PREPARER = ROOT / "scripts/prepare-dependencies.py"
EXPORT_MANIFEST = ".p11scope-source-export.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


PREPARE = load_module(PREPARER, "export_test_preparer")


class ExportFixture:
    def __init__(self, base: Path):
        self.base = base
        self.root = base / "source"
        self.archives = base / "originals"
        self.outputs = base / "outputs"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "third-party/patches").mkdir(parents=True)
        self.archives.mkdir(parents=True)
        self.outputs.mkdir(parents=True)
        shutil.copy2(EXPORTER, self.root / "scripts/export-source.py")
        shutil.copy2(PREPARER, self.root / "scripts/prepare-dependencies.py")
        (self.root / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        (self.root / "README.md").write_text("committed source\n")
        (self.root / ".gitignore").write_text("ignored.out\nthird-party/archives/\nthird-party/src/\n")
        self.packages = []
        self.git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.git_env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(base.resolve()),
        })

    def package(self, name: str, version: str, value: bytes):
        filename = f"{name}-{version}.crate"
        archive = self.archives / filename
        prefix = f"{name}-{version}"
        with tarfile.open(archive, "w:gz") as output:
            directory = tarfile.TarInfo(prefix)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            output.addfile(directory)
            files = {
                "Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode(),
                "value.txt": value,
            }
            for relative, content in files.items():
                member = tarfile.TarInfo(f"{prefix}/{relative}")
                member.mode = 0o644
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
        tree = self.base / f"tree-{name}-{version}"
        tree.mkdir(mode=0o755)
        for relative, content in files.items():
            path = tree / relative
            path.write_bytes(content)
            path.chmod(0o644)
        self.packages.append({
            "name": name,
            "version": version,
            "revision": 1,
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "patches": [],
            "expected_tree_sha256": PREPARE.compute_tree_digest(tree),
            "applies_to": ["Cargo.toml"],
        })

    def commit(self, force=()):
        manifest = {
            "schema_version": 1,
            "workspace_manifests": ["Cargo.toml"],
            "packages": self.packages,
        }
        (self.root / "third-party/sources.json").write_text(json.dumps(manifest, indent=2) + "\n")
        commands = [
            ["git", "init", "--quiet", "--template="],
            ["git", "add", "--all"],
        ]
        if force:
            commands.append(["git", "add", "--force", "--", *force])
        commands.append(
            ["git", "-c", "user.name=Source Export Test", "-c", "user.email=test.invalid",
             "commit", "--quiet", "-m", "fixture"]
        )
        for command in commands:
            result = subprocess.run(command, cwd=self.root, env=self.git_env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                raise AssertionError(f"fixture Git command failed: {command}: {result.stderr}")

    def run(self, output: Path, *arguments: str):
        return subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts/export-source.py"),
             "--output", str(output), *arguments],
            cwd=self.base, env=self.git_env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def offline(self, output: Path):
        return self.run(output, "--offline", "--archive-dir", str(self.archives))


class ExportSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope-source-export-")
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, name="case"):
        fixture = ExportFixture(self.base / name)
        fixture.package("demo", "1.0.0", b"demo value\n")
        return fixture

    def assert_refused(self, result, *needles):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_clean_export_is_deterministic_and_prepares_from_fresh_offline_extraction(self):
        fixture = self.fixture()
        fixture.package("other", "2.1.0", b"other value\n")
        (fixture.root / "AGENTS.md").write_text("repository instructions\n")
        (fixture.root / "CLAUDE.md").symlink_to("AGENTS.md")
        (fixture.root / "docs").mkdir()
        (fixture.root / "docs/GUIDE.md").symlink_to("../AGENTS.md")
        (fixture.root / "NORMALIZED.md").symlink_to("docs/../README.md")
        fixture.commit()
        (fixture.root / "ignored.out").write_text("generated\n")
        default_archives = fixture.root / "third-party/archives"
        default_archives.mkdir()
        for archive in fixture.archives.iterdir():
            shutil.copy2(archive, default_archives / archive.name)
        first = fixture.outputs / "first.tar.gz"
        second = fixture.outputs / "second.tar.gz"

        one = fixture.offline(first)
        two = fixture.run(second, "--offline")
        self.assertEqual(one.returncode, 0, one.stderr)
        self.assertEqual(two.returncode, 0, two.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        extracted = self.base / "extracted"
        with tarfile.open(first, "r:gz") as archive:
            names = archive.getnames()
            archive.extractall(extracted, filter="data")
        ordinary = self.base / "ordinary"
        with tarfile.open(second, "r:gz") as archive:
            archive.extractall(ordinary)
        self.assertFalse(any("/.git/" in f"/{name}/" for name in names))
        self.assertFalse(any(name.endswith("/ignored.out") for name in names))
        self.assertFalse(any("/third-party/src/" in f"/{name}/" for name in names))
        roots = {name.split("/", 1)[0] for name in names}
        self.assertEqual(roots, {"pkcs11-scope-source"})
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=fixture.root, env=fixture.git_env,
            text=True, check=True, stdout=subprocess.PIPE,
        ).stdout.strip()
        shutil.rmtree(fixture.root)
        shutil.rmtree(fixture.archives)
        source = extracted / "pkcs11-scope-source"
        self.assertEqual((source / "README.md").read_text(), "committed source\n")
        self.assertTrue((source / "CLAUDE.md").is_symlink())
        self.assertEqual(os.readlink(source / "CLAUDE.md"), "AGENTS.md")
        self.assertEqual((source / "CLAUDE.md").read_text(), "repository instructions\n")
        self.assertTrue((source / "docs/GUIDE.md").is_symlink())
        self.assertEqual(os.readlink(source / "docs/GUIDE.md"), "../AGENTS.md")
        self.assertEqual((source / "docs/GUIDE.md").read_text(), "repository instructions\n")
        ordinary_source = ordinary / "pkcs11-scope-source"
        self.assertEqual(os.readlink(ordinary_source / "NORMALIZED.md"),
                         "docs/../README.md")
        self.assertEqual((ordinary_source / "NORMALIZED.md").read_text(), "committed source\n")
        export_manifest = json.loads((source / EXPORT_MANIFEST).read_text())
        self.assertEqual(export_manifest["revision"], revision)
        readme_entry = next(item for item in export_manifest["source_entries"]
                            if item["path"] == "README.md")
        self.assertEqual(readme_entry, {
            "path": "README.md", "kind": "file", "mode": "0644", "size": 17,
            "sha256": hashlib.sha256(b"committed source\n").hexdigest(),
        })
        link_entry = next(item for item in export_manifest["source_entries"]
                          if item["path"] == "CLAUDE.md")
        self.assertEqual(link_entry, {
            "path": "CLAUDE.md", "kind": "symlink", "mode": "120000",
            "target": "AGENTS.md", "size": 9,
            "sha256": hashlib.sha256(b"AGENTS.md").hexdigest(),
        })
        self.assertEqual(
            [item["path"] for item in export_manifest["archives"]],
            ["third-party/archives/demo-1.0.0.crate",
             "third-party/archives/other-2.1.0.crate"],
        )
        self.assertTrue(all((source / item["path"]).is_file()
                            for item in export_manifest["archives"]))
        self.assertTrue(all(
            hashlib.sha256((source / item["path"]).read_bytes()).hexdigest() == item["sha256"]
            for item in export_manifest["archives"]
        ))

        unrelated = self.base / "unrelated"
        unrelated.mkdir()
        prepare = subprocess.run(
            [sys.executable, "-I", str(source / "scripts/prepare-dependencies.py"),
             "--offline", "--archive-dir", str(source / "third-party/archives")],
            cwd=unrelated, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        check = subprocess.run(
            [sys.executable, "-I", str(source / "scripts/prepare-dependencies.py"), "--check"],
            cwd=unrelated, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_dirty_tracked_index_and_visible_untracked_inputs_are_refused(self):
        for label in ("tracked", "index", "untracked"):
            with self.subTest(label=label):
                fixture = self.fixture(label)
                fixture.commit()
                if label == "tracked":
                    (fixture.root / "README.md").write_text("dirty\n")
                elif label == "index":
                    (fixture.root / "staged.txt").write_text("staged\n")
                    subprocess.run(["git", "add", "staged.txt"], cwd=fixture.root,
                                   env=fixture.git_env, check=True)
                else:
                    (fixture.root / "visible.txt").write_text("visible\n")
                output = fixture.outputs / f"{label}.tar.gz"
                result = fixture.offline(output)
                self.assert_refused(result, "source repository is not clean")
                self.assertFalse(output.exists())

    def test_missing_and_corrupt_offline_originals_are_named_refusals(self):
        for label in ("missing", "corrupt"):
            with self.subTest(label=label):
                fixture = self.fixture(label)
                fixture.commit()
                archive = fixture.archives / "demo-1.0.0.crate"
                if label == "missing":
                    archive.unlink()
                else:
                    archive.write_bytes(b"corrupt")
                output = fixture.outputs / f"{label}.tar.gz"
                result = fixture.offline(output)
                self.assert_refused(result, "demo-1.0.0.crate")
                self.assertFalse(output.exists())

    def test_preexisting_output_and_foreign_temporary_are_preserved_on_failure(self):
        fixture = self.fixture()
        fixture.commit()
        output = fixture.outputs / "existing.tar.gz"
        output.write_bytes(b"foreign output")
        collision = fixture.outputs / ".existing.tar.gz.foreign"
        collision.write_text("foreign temporary")
        result = fixture.offline(output)
        self.assert_refused(result, "output already exists")
        self.assertEqual(output.read_bytes(), b"foreign output")
        self.assertEqual(collision.read_text(), "foreign temporary")

        absent = fixture.outputs / "absent.tar.gz"
        (fixture.archives / "demo-1.0.0.crate").unlink()
        failed = fixture.offline(absent)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(absent.exists())
        self.assertEqual(sorted(path.name for path in fixture.outputs.iterdir()),
                         [".existing.tar.gz.foreign", "existing.tar.gz"])

    def test_relative_output_and_reserved_manifest_collision_are_refused(self):
        fixture = self.fixture()
        fixture.commit()
        relative = fixture.run(Path("relative.tar.gz"), "--offline", "--archive-dir",
                               str(fixture.archives))
        self.assert_refused(relative, "absolute")

        colliding = self.fixture("collision")
        (colliding.root / EXPORT_MANIFEST).write_text("reserved\n")
        colliding.commit()
        output = colliding.outputs / "collision.tar.gz"
        result = colliding.offline(output)
        self.assert_refused(result, "reserved export manifest")
        self.assertFalse(output.exists())

    def test_duplicate_embedded_archive_destination_is_refused(self):
        fixture = self.fixture()
        duplicate = dict(fixture.packages[0])
        duplicate["revision"] = 2
        fixture.packages.append(duplicate)
        fixture.commit()
        output = fixture.outputs / "ambiguous.tar.gz"

        result = fixture.offline(output)
        self.assert_refused(result, "duplicate embedded archive destination")
        self.assertFalse(output.exists())

    def test_uncommitted_info_export_subst_cannot_change_committed_blob(self):
        fixture = self.fixture()
        (fixture.root / "README.md").write_text("revision=$Format:%H$\n")
        fixture.commit()
        info = fixture.root / ".git/info"
        info.mkdir(exist_ok=True)
        (info / "attributes").write_text("README.md export-subst\n")
        output = fixture.outputs / "subst.tar.gz"

        result = fixture.offline(output)
        self.assert_refused(result, "Git archive differs from committed blob", "README.md")
        self.assertFalse(output.exists())

    def test_generated_destination_prefix_conflicts_are_refused(self):
        cases = ("reserved-directory", "archive-as-directory", "archives-as-file")
        for label in cases:
            with self.subTest(label=label):
                fixture = self.fixture(label)
                force = []
                if label == "reserved-directory":
                    collision = fixture.root / EXPORT_MANIFEST / "tracked.txt"
                elif label == "archive-as-directory":
                    collision = fixture.root / "third-party/archives/demo-1.0.0.crate/tracked.txt"
                    force.append("third-party/archives/demo-1.0.0.crate/tracked.txt")
                else:
                    collision = fixture.root / "third-party/archives"
                collision.parent.mkdir(parents=True, exist_ok=True)
                collision.write_text("tracked collision\n")
                fixture.commit(force)
                output = fixture.outputs / f"{label}.tar.gz"

                result = fixture.offline(output)
                self.assert_refused(result, "generated destination conflicts with committed source")
                self.assertFalse(output.exists())

    def test_symlinks_must_target_a_direct_contained_regular_file(self):
        cases = {
            "absolute": ("LINK", "/outside", {}),
            "escaping": ("LINK", "../outside", {}),
            "dangling": ("LINK", "missing", {}),
            "chain": ("LINK", "SECOND", {"SECOND": "README.md"}),
            "directory": ("LINK", "docs", {"docs/file.txt": None}),
            "backslash": ("LINK", "dir\\file", {"dir/file": None}),
            "control": ("LINK", "bad\ntarget", {}),
            "missing-intermediate": ("LINK", "missing/../README.md", {}),
            "regular-intermediate": ("LINK", "README.md/../README.md", {}),
        }
        for label, (link_name, target, extra) in cases.items():
            with self.subTest(label=label):
                fixture = self.fixture(label)
                for relative, link_target in extra.items():
                    path = fixture.root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if link_target is None:
                        path.write_text("target\n")
                    else:
                        path.symlink_to(link_target)
                (fixture.root / link_name).symlink_to(target)
                fixture.commit()
                output = fixture.outputs / f"{label}.tar.gz"

                result = fixture.offline(output)
                self.assert_refused(result, "unsafe committed symlink", link_name)
                self.assertFalse(output.exists())

    def test_required_export_inputs_must_be_committed_regular_files(self):
        fixture = self.fixture()
        (fixture.root / "Cargo.toml").unlink()
        (fixture.root / "Cargo.toml").symlink_to("README.md")
        fixture.commit()
        output = fixture.outputs / "required-link.tar.gz"

        result = fixture.offline(output)
        self.assert_refused(result, "required export input is not a committed regular file",
                            "Cargo.toml")
        self.assertFalse(output.exists())


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExportSourceTests)
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)
