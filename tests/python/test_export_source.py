#!/usr/bin/env python3
"""Native source-export tests with isolated synthetic Git repositories."""

from __future__ import annotations

import builtins
import hashlib
import inspect
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
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path

EXPORTER = ROOT / "scripts/export-source.py"
LOADER = ROOT / "scripts/_loader.py"
PREPARER = ROOT / "scripts/prepare-dependencies.py"
EXPORT_MANIFEST = ".p11scope-source-export.json"
OFFLINE_TESTS = ROOT / "tests/python/test_offline_dependencies.py"
EXPORT_FIXTURES = ROOT / "tests/fixtures/export-source"


def extract_archive(archive: Path, destination: Path) -> subprocess.CompletedProcess[str]:
    destination.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        ["tar", "--same-permissions", "--no-same-owner", "-xzf", str(archive),
         "-C", str(destination)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def load_module(path: Path, name: str):
    return load_path(path, name)


PREPARE = load_module(PREPARER, "export_test_preparer")
OFFLINE_TEST_MODULE = load_module(OFFLINE_TESTS, "export_test_offline_fixture")
EXPORT = load_module(EXPORTER, "export_test_exporter")


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
        shutil.copy2(LOADER, self.root / "scripts/_loader.py")
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
        tree.chmod(0o755)
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

    def test_offline_helper_missing_parser_is_named_export_refusal(self):
        root = self.base / "loader"
        (root / "scripts").mkdir(parents=True)
        shutil.copy2(OFFLINE_TEST_MODULE.HELPER, root / "scripts/offline-dependencies.py")
        original_import = builtins.__import__

        def missing_parser(name, *args, **kwargs):
            if name in {"tomllib", "tomli"}:
                raise ModuleNotFoundError("missing parser", name=name)
            return original_import(name, *args, **kwargs)

        with mock.patch.object(builtins, "__import__", missing_parser):
            with self.assertRaisesRegex(EXPORT.ExportError, "cannot load offline dependency helper"):
                EXPORT._load_offline_helper(root)

    def test_cli_converts_offline_helper_import_failure_to_refusal(self):
        with mock.patch.object(
            EXPORT, "run", side_effect=EXPORT.ExportError(
                "cannot load offline dependency helper: Python TOML parser unavailable"
            )
        ):
            with mock.patch.object(EXPORT, "print") as output:
                self.assertEqual(EXPORT.main(["--output", str(self.base / "output")]), 1)
        output.assert_called_once()
        self.assertIn("export-source: refusal:", output.call_args.args[0])

    def full_fixture(self, name="full"):
        base = self.base / name
        fixture = OFFLINE_TEST_MODULE.OfflineFixture(base)
        fixture.testcase = self
        shutil.copy2(EXPORTER, fixture.root / "scripts/export-source.py")
        fixture.assemble()
        fixture.approve()
        shutil.rmtree(fixture.root / "third-party/src")
        (fixture.root / "third-party/.prepare-dependencies.lock").unlink(missing_ok=True)
        fixture.export_manifest.unlink()
        (fixture.root / ".gitignore").write_text(
            "third-party/src/\nthird-party/archives/\nthird-party/.prepare-dependencies.lock\n",
            encoding="utf-8"
        )
        commands = (
            ["git", "init", "--quiet", "--template="],
            ["git", "add", "--all"],
            ["git", "-c", "user.name=Full Export Test", "-c",
             "user.email=test.invalid", "commit", "--quiet", "-m", "fixture"],
        )
        git_environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        git_environment.update({
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        })
        for command in commands:
            result = subprocess.run(command, cwd=fixture.root, env=git_environment,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr)
        return fixture

    @staticmethod
    def full_export(fixture, output: Path, *, environment=None, extra=()):
        return subprocess.run([
            sys.executable, "-I", str(fixture.root / "scripts/export-source.py"),
            "--output", str(output), "--offline-payload", str(fixture.output),
            "--nightly-rustc", str(fixture.tools / "nightly rustc"), *extra,
        ], cwd=fixture.root.parent, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def validate_full(self, source: Path, cargo_home: Path, *, environment=None,
                      prepared=None):
        clean = {key: value for key, value in os.environ.items()
                 if not key.startswith(("CARGO_", "RUST", "P11SCOPE_"))
                 and key not in ("CC", "CFLAGS")}
        if environment:
            clean.update(environment)
        command = [
            sys.executable, "-I", str(source / "scripts/export-source.py"),
            "--verify-extracted", str(source), "--cargo-home", str(cargo_home),
        ]
        if prepared is not None:
            command += ["--prepared", prepared]
        return subprocess.run(command, cwd=self.base, env=clean, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

    def extracted_full(self, fixture, name: str):
        archive = fixture.root.parent / f"{name}.tar.gz"
        result = self.full_export(fixture, archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        extracted = self.base / f"{name} extraction"
        extracted.mkdir()
        unpacked = extract_archive(archive, extracted)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
        return extracted / "pkcs11-scope-source"

    @staticmethod
    def update_source_row(source: Path, relative: str):
        manifest_path = source / EXPORT_MANIFEST
        manifest = json.loads(manifest_path.read_text())
        content = (source / relative).read_bytes()
        row = next(item for item in manifest["source_entries"] if item["path"] == relative)
        row["size"] = len(content)
        row["sha256"] = hashlib.sha256(content).hexdigest()
        manifest_path.write_text(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ) + "\n")

    @staticmethod
    def add_symlink_row(source: Path, relative: str, target: str):
        (source / relative).symlink_to(target)
        encoded = target.encode()
        manifest_path = source / EXPORT_MANIFEST
        manifest = json.loads(manifest_path.read_text())
        manifest["source_entries"].append({
            "path": relative, "kind": "symlink", "mode": "120000",
            "target": target, "size": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })
        manifest["source_entries"].sort(key=lambda item: item["path"].encode())
        manifest_path.write_text(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ) + "\n")

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
        unpacked = extract_archive(first, extracted)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
        ordinary = self.base / "ordinary"
        unpacked = extract_archive(second, ordinary)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
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

    def test_full_export_is_deterministic_relocatable_and_has_closed_v2_schema(self):
        fixture = self.full_fixture()
        first = fixture.root.parent / "full first.tar.gz"
        second = fixture.root.parent / "full second.tar.gz"
        one = self.full_export(fixture, first)
        two = self.full_export(fixture, second)
        self.assertEqual(one.returncode, 0, one.stderr)
        self.assertEqual(two.returncode, 0, two.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        extracted = self.base / "relocated export with spaces"
        with tarfile.open(first, "r:gz") as archive:
            self.assertEqual(
                archive.getmember("pkcs11-scope-source/third-party/offline").mode,
                0o755,
            )
        extracted.mkdir()
        unpacked = extract_archive(first, extracted)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
        source = extracted / "pkcs11-scope-source"
        manifest = json.loads((source / EXPORT_MANIFEST).read_text())
        self.assertEqual(set(manifest), {
            "schema_version", "revision", "source_entries", "archives",
            "offline_dependencies",
        })
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(set(manifest["offline_dependencies"]), {
            "payload_path", "recipe_path", "recipe_sha256", "payload_tree_sha256",
            "config_path", "config_sha256",
        })
        self.assertTrue(all(
            entry["path"].startswith("third-party/offline/archives/")
            for entry in manifest["archives"]
        ))
        self.assertFalse(any(
            entry["path"].startswith("third-party/offline/")
            or entry["path"] == ".cargo/config.toml"
            for entry in manifest["source_entries"]
        ))
        cargo_home = self.base / "fresh cargo home"
        cargo_home.mkdir(mode=0o700)
        verified = self.validate_full(source, cargo_home)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_full_mode_pairs_inputs_and_refuses_overrides_collisions_and_mutations(self):
        basic = self.fixture("paired")
        basic.commit()
        output = basic.outputs / "paired.tar.gz"
        for arguments in (
            ("--offline-payload", str(basic.archives)),
            ("--nightly-rustc", sys.executable),
        ):
            with self.subTest(arguments=arguments):
                result = basic.run(output, *arguments)
                self.assert_refused(result, "must be supplied together")
                self.assertFalse(output.exists())

        fixture = self.full_fixture("refusals")
        override = fixture.root.parent / "override.tar.gz"
        result = self.full_export(
            fixture, override, extra=("--archive-dir", str(fixture.archive_dir))
        )
        self.assert_refused(result, "archive-dir", "full")
        self.assertFalse(override.exists())

        collision = fixture.root / "third-party/offline/collision"
        collision.parent.mkdir(parents=True)
        collision.write_text("collision\n")
        subprocess.run(["git", "add", "--force", str(collision)], cwd=fixture.root,
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run([
            "git", "-c", "user.name=Full Export Test", "-c", "user.email=test.invalid",
            "commit", "--quiet", "-m", "collision",
        ], cwd=fixture.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        collided = fixture.root.parent / "collision.tar.gz"
        result = self.full_export(fixture, collided)
        self.assert_refused(result, "generated destination conflicts")
        self.assertFalse(collided.exists())

    def test_full_export_detects_private_streaming_mutation_and_cleans_without_publication(self):
        fixture = self.full_fixture("stream-mutation")
        nightly = fixture.tools / "nightly rustc"
        shutil.copy2(EXPORT_FIXTURES / "mutating-rustc.py", nightly)
        nightly.chmod(0o755)
        configuration_path = fixture.tools / "fixture.json"
        configuration = json.loads(configuration_path.read_text())
        configuration.update({
            "export_parent": str(fixture.root.parent),
            "export_mutation_call": 5,
        })
        configuration_path.write_text(json.dumps(configuration), encoding="utf-8")
        output = fixture.root.parent / "stream-mutated.tar.gz"

        result = self.full_export(fixture, output)

        self.assert_refused(result, "payload tree digest mismatch")
        self.assertFalse(output.exists())
        self.assertEqual(
            list(fixture.root.parent.glob(".stream-mutated.tar.gz.export-*")), []
        )

    def test_full_export_binds_every_streamed_payload_read_to_retained_inventory(self):
        cases = (
            ("content", "vendor/shared-0.1.0/src.rs", "read"),
            ("archive", "archives/demo-1.0.0.crate", "read"),
            ("mode", "vendor/shared-0.1.0/src.rs", "mode"),
        )
        for index, (label, relative, mutation) in enumerate(cases):
            with self.subTest(label=label):
                fixture = self.full_fixture(f"stream-custody-{index}")
                module = load_module(
                    fixture.root / "scripts/export-source.py", f"stream_custody_{index}"
                )
                output = fixture.root.parent / f"custody-{index}.tar.gz"
                original_read = Path.read_bytes
                original_lstat = Path.lstat

                def transient_read(path):
                    content = original_read(path)
                    if ("private-payload" in path.parts
                            and path.as_posix().endswith(relative)):
                        return content + b"transient mutation"
                    return content

                def transient_lstat(path):
                    metadata = original_lstat(path)
                    completed = list(fixture.root.parent.glob(
                        f".{output.name}.export-*/completed.tar.gz"
                    ))
                    if (completed and "private-payload" in path.parts
                            and path.as_posix().endswith(relative)
                            and any(frame.function == "_build_archive"
                                    for frame in inspect.stack())):
                        values = list(metadata)
                        values[0] = (metadata.st_mode & ~0o777) | 0o600
                        return os.stat_result(values)
                    return metadata

                patcher = (mock.patch.object(Path, "read_bytes", transient_read)
                           if mutation == "read" else
                           mock.patch.object(Path, "lstat", transient_lstat))
                with patcher, self.assertRaisesRegex(module.ExportError, "payload.*(digest|mode)"):
                    module.run(
                        fixture.root, output, offline=False, archive_dir=None,
                        offline_payload=fixture.output,
                        nightly_rustc=fixture.tools / "nightly rustc",
                    )
                self.assertFalse(output.exists())
                self.assertEqual(
                    list(fixture.root.parent.glob(f".{output.name}.export-*")), []
                )

    def test_full_producer_refuses_root_and_nested_competing_cargo_configs(self):
        paths = (
            ".cargo/config",
            "crates/.cargo/config",
            "crates/.cargo/config.toml",
            "crates/ebpf/.cargo/config",
            "crates/ebpf/.cargo/config.toml",
        )
        for index, relative in enumerate(paths):
            with self.subTest(relative=relative):
                fixture = self.full_fixture(f"producer-config-{index}")
                path = fixture.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[net]\noffline = false\n")
                subprocess.run(["git", "add", relative], cwd=fixture.root, check=True)
                subprocess.run([
                    "git", "-c", "user.name=Full Export Test", "-c",
                    "user.email=test.invalid", "commit", "--quiet", "-m", "config",
                ], cwd=fixture.root, check=True)
                output = fixture.root.parent / f"config-{index}.tar.gz"

                result = self.full_export(fixture, output)

                self.assert_refused(result, "competing Cargo configuration", relative)
                self.assertFalse(output.exists())

    def test_full_producer_refuses_directory_at_delivered_cargo_config_before_work(self):
        fixture = self.full_fixture("producer-config-directory")
        relative = "crates/.cargo/config.toml/unexpected"
        path = fixture.root / relative
        path.parent.mkdir(parents=True)
        path.write_text("committed descendant\n")
        subprocess.run(["git", "add", relative], cwd=fixture.root, check=True)
        subprocess.run([
            "git", "-c", "user.name=Full Export Test", "-c",
            "user.email=test.invalid", "commit", "--quiet", "-m", "config directory",
        ], cwd=fixture.root, check=True)
        module = load_module(
            fixture.root / "scripts/export-source.py", "producer_config_directory"
        )
        output = fixture.root.parent / "config-directory.tar.gz"
        original_run = subprocess.run

        def refuse_compiler(command, *args, **kwargs):
            if command and Path(command[0]) == fixture.tools / "nightly rustc":
                raise AssertionError("compiler invocation reached")
            return original_run(command, *args, **kwargs)

        with (
            mock.patch.object(
                module.tempfile, "mkdtemp",
                side_effect=AssertionError("staging reached"),
            ),
            mock.patch.object(
                module, "_verify_payload",
                side_effect=AssertionError("payload verification reached"),
            ),
            mock.patch.object(module.subprocess, "run", refuse_compiler),
        ):
            with self.assertRaisesRegex(
                module.ExportError, "generated destination conflicts.*config.toml"
            ):
                module.run(
                    fixture.root,
                    output,
                    offline=False,
                    archive_dir=None,
                    offline_payload=fixture.output,
                    nightly_rustc=fixture.tools / "nightly rustc",
                )

        self.assertFalse(output.exists())
        self.assertEqual(
            list(fixture.root.parent.glob(f".{output.name}.export-*")), []
        )

    def test_committed_source_second_read_is_bound_to_git_blob_and_cleans(self):
        fixture = self.fixture("source-stream-custody")
        fixture.commit()
        module = load_module(
            fixture.root / "scripts/export-source.py", "source_stream_custody"
        )
        output = fixture.outputs / "source-mutated.tar.gz"
        original_extractfile = tarfile.TarFile.extractfile
        read_count = 0

        def transient_extractfile(archive, member):
            nonlocal read_count
            stream = original_extractfile(archive, member)
            if member.name == "README.md":
                read_count += 1
                if read_count == 2:
                    with stream:
                        content = stream.read()
                    return io.BytesIO(content + b"transient mutation")
            return stream

        with mock.patch.object(
            tarfile.TarFile, "extractfile", transient_extractfile
        ):
            with self.assertRaisesRegex(
                module.ExportError,
                "Git archive changed during committed source emission",
            ):
                module.run(
                    fixture.root,
                    output,
                    offline=True,
                    archive_dir=fixture.archives,
                )

        self.assertEqual(read_count, 2)
        self.assertFalse(output.exists())
        self.assertEqual(list(fixture.outputs.glob(f".{output.name}.export-*")), [])

    def test_extracted_validator_refuses_mutated_source_payload_config_and_extra_entries(self):
        fixture = self.full_fixture("validator-mutations")
        archive = fixture.root.parent / "validator.tar.gz"
        result = self.full_export(fixture, archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        pristine = self.base / "validator pristine"
        pristine.mkdir()
        unpacked = extract_archive(archive, pristine)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
        pristine_source = pristine / "pkcs11-scope-source"
        cargo_home = self.base / "validator cargo home"
        cargo_home.mkdir(mode=0o700)
        mutations = (
            ("source", lambda root: (root / "Cargo.toml").write_text("changed\n"),
             "source export entry digest mismatch"),
            ("payload", lambda root: (root / "third-party/offline/vendor/shared-0.1.0/src.rs")
             .write_text("changed\n"), "payload"),
            ("config", lambda root: (root / ".cargo/config.toml").write_text("[net]\n"),
             "configuration custody"),
            ("extra payload", lambda root: (root / "third-party/offline/extra").write_text("x"),
             "payload"),
            ("payload link", lambda root: (root / "third-party/offline/link")
             .symlink_to("vendor"), "symbolic link"),
            ("payload mode", lambda root: (root / "third-party/offline/vendor")
             .chmod(0o700), "unsafe delivery mode"),
        )
        for index, (label, mutate, needle) in enumerate(mutations):
            with self.subTest(label=label):
                case = self.base / f"validator mutation {index}"
                shutil.copytree(pristine_source, case, symlinks=True)
                mutate(case)
                refused = self.validate_full(case, cargo_home)
                self.assert_refused(refused, needle)

    def test_extracted_validator_refuses_competing_configs_and_build_environment(self):
        fixture = self.full_fixture("validator-custody")
        archive = fixture.root.parent / "custody.tar.gz"
        result = self.full_export(fixture, archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        extracted = self.base / "custody extraction"
        extracted.mkdir()
        unpacked = extract_archive(archive, extracted)
        self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
        source = extracted / "pkcs11-scope-source"
        cargo_home = self.base / "custody cargo home"
        cargo_home.mkdir(mode=0o700)

        config_cases = (
            source / ".cargo/config",
            source / "crates/ebpf/.cargo/config.toml",
            source.parent / ".cargo/config.toml",
            cargo_home / "config.toml",
        )
        for path in config_cases:
            with self.subTest(config=str(path)):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[net]\noffline = false\n")
                refused = self.validate_full(source, cargo_home)
                self.assert_refused(refused, "competing Cargo configuration")
                path.unlink()

        variables = (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS", "CARGO_SOURCE_CRATES_IO_REPLACE_WITH",
            "CARGO_BUILD_JOBS", "RUSTC", "RUSTC_WRAPPER", "RUSTDOCFLAGS",
            "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "CC",
            "CFLAGS", "P11SCOPE_PRODUCT_BUILD_MODE", "P11SCOPE_PREPARED_STABLE_CARGO",
            "P11SCOPE_PREPARED_BPF_RUSTC", "P11SCOPE_PREPARED_PYTHON",
            "P11SCOPE_SMALL_RING", "P11SCOPE_SMALL_STATE_MAPS", "P11SCOPE_SMALL_MAPS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "CC_X86_64_UNKNOWN_LINUX_GNU",
            "CFLAGS_x86_64_unknown_linux_gnu", "HOST_CC", "TARGET_CC", "HOST_CFLAGS",
            "TARGET_CFLAGS",
        )
        for variable in variables:
            with self.subTest(variable=variable):
                refused = self.validate_full(source, cargo_home, environment={variable: "set"})
                self.assert_refused(refused, "refusing inherited build environment", variable)

    def test_extracted_validator_revalidates_contained_direct_source_symlinks(self):
        fixture = self.full_fixture("source-symlinks")
        pristine = self.extracted_full(fixture, "source-symlink-pristine")
        cargo_home = self.base / "source symlink cargo home"
        cargo_home.mkdir(mode=0o700)
        valid = self.base / "valid source symlink"
        shutil.copytree(pristine, valid, symlinks=True)
        self.add_symlink_row(valid, "VALID-LINK", "Cargo.toml")
        accepted = self.validate_full(valid, cargo_home)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        cases = (
            ("absolute", "/etc/passwd", None),
            ("escape", "../outside", None),
            ("dangling", "missing", None),
            ("chain", "SECOND-LINK", "Cargo.toml"),
            ("directory", "crates", None),
        )
        for index, (label, target, chained_target) in enumerate(cases):
            with self.subTest(label=label):
                case = self.base / f"source symlink {index}"
                shutil.copytree(pristine, case, symlinks=True)
                if chained_target is not None:
                    self.add_symlink_row(case, "SECOND-LINK", chained_target)
                self.add_symlink_row(case, "BAD-LINK", target)
                refused = self.validate_full(case, cargo_home)
                self.assert_refused(refused, "unsafe", "symlink")

    def test_extracted_validator_rejects_non_integer_schema_and_size(self):
        fixture = self.full_fixture("json-numbers")
        pristine = self.extracted_full(fixture, "json-number-pristine")
        cargo_home = self.base / "json number cargo home"
        cargo_home.mkdir(mode=0o700)
        schema = self.base / "float schema"
        shutil.copytree(pristine, schema, symlinks=True)
        manifest_path = schema / EXPORT_MANIFEST
        manifest = json.loads(manifest_path.read_text())
        manifest["schema_version"] = 2.0
        manifest_path.write_text(json.dumps(manifest) + "\n")
        size = self.base / "boolean size"
        shutil.copytree(pristine, size, symlinks=True)
        (size / "one-byte").write_bytes(b"x")
        (size / "one-byte").chmod(0o644)
        manifest_path = size / EXPORT_MANIFEST
        manifest = json.loads(manifest_path.read_text())
        manifest["source_entries"].append({
            "path": "one-byte", "kind": "file", "mode": "0644", "size": True,
            "sha256": hashlib.sha256(b"x").hexdigest(),
        })
        manifest_path.write_text(json.dumps(manifest) + "\n")
        for case in (schema, size):
            with self.subTest(case=case.name):
                refused = self.validate_full(case, cargo_home)
                self.assert_refused(refused, "source export")

    def test_extracted_validator_binds_fixed_recipe_workspace_and_preparation_inputs(self):
        fixture = self.full_fixture("fixed-inputs")
        pristine = self.extracted_full(fixture, "fixed-input-pristine")
        cargo_home = self.base / "fixed input cargo home"
        cargo_home.mkdir(mode=0o700)
        cases = (
            ("root manifest", "Cargo.toml", "workspace lock or manifest"),
            ("root lock", "Cargo.lock", "workspace lock or manifest"),
            ("bpf manifest", "crates/ebpf/Cargo.toml", "workspace lock or manifest"),
            ("bpf lock", "crates/ebpf/Cargo.lock", "workspace lock or manifest"),
            ("sources", "third-party/sources.json", "sources manifest"),
            ("patch", "third-party/patches/demo-1.0.0/value.patch", "package recipe"),
        )
        for index, (label, relative, needle) in enumerate(cases):
            with self.subTest(label=label):
                case = self.base / f"fixed input {index}"
                shutil.copytree(pristine, case, symlinks=True)
                target = case / relative
                target.write_bytes(target.read_bytes() + b"\n")
                self.update_source_row(case, relative)
                refused = self.validate_full(case, cargo_home)
                self.assert_refused(refused, needle)

    def test_extracted_validator_prepared_modes_preserve_verified_outputs_and_lock(self):
        fixture = self.full_fixture("prepared-modes")
        source = self.extracted_full(fixture, "prepared-modes")
        cargo_home = self.base / "prepared modes cargo home"
        cargo_home.mkdir(mode=0o700)

        absent_allow = self.validate_full(source, cargo_home, prepared="allow")
        self.assertEqual(absent_allow.returncode, 0, absent_allow.stderr)
        absent_require = self.validate_full(source, cargo_home, prepared="require")
        self.assert_refused(absent_require, "required prepared output is missing")
        prepared_root = source / "third-party/src"
        prepared_root.mkdir(mode=0o755)
        prepared_root.chmod(0o755)
        empty_forbid = self.validate_full(source, cargo_home)
        self.assert_refused(empty_forbid, "prepared output is forbidden")
        prepared_root.rmdir()
        lock = source / "third-party/.prepare-dependencies.lock"
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        lock_only = self.validate_full(source, cargo_home, prepared="allow")
        self.assertEqual(lock_only.returncode, 0, lock_only.stderr)
        lock_only_require = self.validate_full(source, cargo_home, prepared="require")
        self.assert_refused(lock_only_require, "required prepared output is missing")
        lock.unlink()

        prepare = subprocess.run([
            sys.executable, "-I", str(source / "scripts/prepare-dependencies.py"),
            "--offline", "--archive-dir", str(source / "third-party/offline/archives"),
        ], cwd=source, text=True, capture_output=True)
        self.assertEqual(prepare.returncode, 0, prepare.stderr)
        package = source / "third-party/src/demo-1.0.0-p1/value.txt"
        lock = source / "third-party/.prepare-dependencies.lock"
        lock.unlink()
        missing_lock_allow = self.validate_full(source, cargo_home, prepared="allow")
        self.assert_refused(missing_lock_allow, "third-party/.prepare-dependencies.lock")
        missing_lock = self.validate_full(source, cargo_home, prepared="require")
        self.assert_refused(missing_lock, "third-party/.prepare-dependencies.lock")
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        before = (package.read_bytes(), package.stat().st_mode, package.stat().st_mtime_ns,
                  lock.stat().st_ino, lock.stat().st_mode, lock.stat().st_mtime_ns)

        default = self.validate_full(source, cargo_home)
        self.assert_refused(default, "prepared output is forbidden")
        for mode in ("allow", "require"):
            result = self.validate_full(source, cargo_home, prepared=mode)
            self.assertEqual(result.returncode, 0, result.stderr)
        after = (package.read_bytes(), package.stat().st_mode, package.stat().st_mtime_ns,
                 lock.stat().st_ino, lock.stat().st_mode, lock.stat().st_mtime_ns)
        self.assertEqual(after, before)

    def test_extracted_validator_refuses_and_preserves_unknown_or_corrupt_prepared_state(self):
        fixture = self.full_fixture("prepared-refusals")
        source = self.extracted_full(fixture, "prepared-refusals")
        cargo_home = self.base / "prepared refusal cargo home"
        cargo_home.mkdir(mode=0o700)
        prepare = subprocess.run([
            sys.executable, "-I", str(source / "scripts/prepare-dependencies.py"),
            "--offline", "--archive-dir", str(source / "third-party/offline/archives"),
        ], cwd=source, text=True, capture_output=True)
        self.assertEqual(prepare.returncode, 0, prepare.stderr)

        unknown = source / "third-party/src/unknown-sibling"
        unknown.mkdir()
        sentinel = unknown / "sentinel"
        sentinel.write_text("preserve\n", encoding="utf-8")
        refused = self.validate_full(source, cargo_home, prepared="allow")
        self.assert_refused(refused, "unexpected prepared output")
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve\n")
        shutil.rmtree(unknown)

        package = source / "third-party/src/demo-1.0.0-p1/value.txt"
        package.write_text("corrupt\n", encoding="utf-8")
        refused = self.validate_full(source, cargo_home, prepared="require")
        self.assert_refused(refused, "tree digest mismatch")
        self.assertEqual(package.read_text(encoding="utf-8"), "corrupt\n")

    def test_prepared_cli_option_is_closed_and_verify_extracted_only(self):
        fixture = self.full_fixture("prepared-cli")
        source = self.extracted_full(fixture, "prepared-cli")
        cargo_home = self.base / "prepared cli cargo home"
        cargo_home.mkdir(mode=0o700)
        invalid = self.validate_full(source, cargo_home, prepared="unknown")
        self.assertNotEqual(invalid.returncode, 0)
        output = self.base / "invalid prepared export.tar.gz"
        mixed = subprocess.run([
            sys.executable, "-I", str(fixture.root / "scripts/export-source.py"),
            "--output", str(output), "--prepared", "allow",
        ], cwd=self.base, text=True, capture_output=True)
        self.assert_refused(mixed, "only accepted with verify-extracted")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExportSourceTests)
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)
