#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native wrapper tests with real preparation and a synthetic Cargo executable."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREPARER_TESTS = runpy.run_path(str(ROOT / "tests/python/test_prepare_dependencies.py"))
FIXTURES = ROOT / "tests/fixtures/cargo-wrapper"


class CargoWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope cargo wrapper ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fixture = PREPARER_TESTS["Fixture"](self.base)
        self.root = self.fixture.root
        self.wrapper = self.root / "scripts/cargo.sh"
        shutil.copy2(ROOT / "scripts/cargo.sh", self.wrapper)
        patch = self.fixture.patch("demo", "1.0.0", "value.patch", PREPARER_TESTS["PATCH_ONE"])
        self.fixture.record(patches=[patch])
        self.fixture.write_manifest()
        self.archives = self.root / "third-party/archives"
        shutil.copytree(self.fixture.archive_dir, self.archives)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        shutil.copy2(FIXTURES / "fake-cargo.py", self.bin / "cargo")
        self.unrelated = self.base / "unrelated working directory"
        self.unrelated.mkdir()
        self.environment = dict(os.environ)
        self.environment["PATH"] = str(self.bin) + os.pathsep + os.environ["PATH"]
        self.cargo_environment = {
            "CARGO_HOME": str(self.base / "caller cargo home"),
            "RUSTUP_HOME": str(self.base / "caller rustup home"),
            "CARGO_TARGET_DIR": str(self.base / "caller target"),
            "RUSTUP_TOOLCHAIN": "caller-toolchain",
            "RUSTFLAGS": "--cfg caller_setting",
            "CARGO_NET_OFFLINE": "false",
        }
        self.environment.update(self.cargo_environment)
        self.config = {"environment_keys": ["PATH", *self.cargo_environment]}
        self.write_config()

    def write_config(self):
        (self.base / "cargo-config.json").write_text(json.dumps(self.config), encoding="utf-8")

    def invoke(self, *arguments):
        return subprocess.run([str(self.wrapper), *arguments], cwd=self.unrelated,
                              env=self.environment, text=True, capture_output=True)

    def cargo_record(self):
        self.assertTrue((self.base / "cargo-executed").is_file(), "fake Cargo did not execute")
        return json.loads((self.base / "cargo.json").read_text(encoding="utf-8"))

    def guard_downloads(self):
        preparer = self.root / "scripts/prepare-dependencies.py"
        preparer.rename(preparer.with_name("actual-prepare-dependencies.py"))
        shutil.copy2(FIXTURES / "guarded-preparer.py", preparer)

    def preparation_record(self):
        path = self.base / "preparation.json"
        self.assertTrue(path.is_file(), "preparer did not execute")
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["cwd"], str(self.root))
        self.assertEqual(record["isolated"], 1)
        return record

    def clear_markers(self):
        for name in ("cargo-executed", "cargo.json", "preparation.json", "downloader-executed"):
            (self.base / name).unlink(missing_ok=True)

    def test_preparation_precedes_cargo_and_preserves_arguments_and_environment(self):
        arguments = ("+1.88", "build", "--locked", "--manifest-path", "folder with spaces/Cargo.toml",
                     "--", "argument with spaces", "", "*", "--offline", "--frozen")
        result = self.invoke(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.cargo_record()
        self.assertEqual(record["cwd"], str(self.root))
        self.assertEqual(record["argv"], list(arguments))
        self.assertEqual(record["prepared_value"], "middle\n")
        self.assertTrue(record["prepared_receipt"])
        self.assertEqual(record["environment"], {key: self.environment[key] for key in self.config["environment_keys"]})

    def test_preparation_refusal_stops_before_cargo(self):
        (self.archives / "demo-1.0.0.crate").write_bytes(b"corrupt pinned archive")
        result = self.invoke("+1.88", "build", "--locked")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive digest mismatch", result.stderr)
        self.assertFalse((self.base / "cargo-executed").exists())

    def test_offline_and_frozen_missing_archives_never_reach_downloader(self):
        self.guard_downloads()
        shutil.rmtree(self.archives)
        for arguments in (("--offline", "build"), ("+1.88", "build", "--frozen"),
                          ("+1.88", "--frozen", "--offline", "build")):
            with self.subTest(arguments=arguments):
                self.clear_markers()
                result = self.invoke(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("offline archive is missing", result.stderr)
                self.assertEqual(self.preparation_record()["argv"], ["--offline"])
                self.assertFalse((self.base / "downloader-executed").exists())
                self.assertFalse((self.base / "cargo-executed").exists())

    def test_literal_delimiter_preserves_application_flags(self):
        self.guard_downloads()
        arguments = ("+1.88", "run", "--", "--offline", "--frozen", "two words")
        result = self.invoke(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.preparation_record()["argv"], [])
        self.assertEqual(self.cargo_record()["argv"], list(arguments))
        self.assertEqual(self.cargo_record()["prepared_value"], "middle\n")

    def test_application_offline_flag_does_not_suppress_preparer_acquisition(self):
        self.guard_downloads()
        shutil.rmtree(self.archives)
        result = self.invoke("run", "--", "--offline")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.preparation_record()["argv"], [])
        self.assertIn("fixture downloader blocked", result.stderr)
        self.assertTrue((self.base / "downloader-executed").is_file())
        self.assertFalse((self.base / "cargo-executed").exists())

    def test_cargo_exit_status_and_streams_are_preserved(self):
        self.config.update(status=37, stdout="fake Cargo stdout\n", stderr="fake Cargo stderr\n")
        self.write_config()
        result = self.invoke("+1.88", "check", "--locked")
        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, self.config["stdout"])
        self.assertEqual(result.stderr, self.config["stderr"])
        self.assertEqual(self.cargo_record()["prepared_value"], "middle\n")

    def test_no_arguments_and_help_do_not_inject_a_toolchain(self):
        for arguments in ((), ("--help",)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                record = self.cargo_record()
                self.assertEqual(record["argv"], list(arguments))
                self.assertEqual(record["prepared_value"], "middle\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
