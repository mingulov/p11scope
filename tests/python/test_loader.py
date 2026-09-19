#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native tests for the single importlib driver (scripts/_loader.py)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
import _loader


class LoaderTests(unittest.TestCase):
    def test_load_sibling_loads_by_filename(self):
        module = _loader.load_sibling("_loader.py")
        self.assertTrue(callable(module.load_sibling))
        self.assertTrue(callable(module.load_path))
        self.assertEqual(module.__name__, "_loader")

    def test_load_path_executes_fixture_without_bytecode(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-loader-") as directory:
            fixture = Path(directory) / "fixture_module.py"
            fixture.write_text("VALUE = 40 + 2\n", encoding="utf-8")
            module = _loader.load_path(fixture, "loader_fixture")
            self.assertEqual(module.VALUE, 42)
            self.assertEqual(module.__name__, "loader_fixture")
            self.assertEqual(list(Path(directory).iterdir()), [fixture])

    def test_each_load_returns_a_fresh_module(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-loader-") as directory:
            fixture = Path(directory) / "fresh.py"
            fixture.write_text("VALUE = 1\n", encoding="utf-8")
            first = _loader.load_path(fixture, "loader_fresh_probe")
            second = _loader.load_path(fixture, "loader_fresh_probe")
        self.assertIsNot(first, second)
        self.assertNotIn("loader_fresh_probe", sys.modules)

    def test_import_disables_bytecode_writes(self):
        # Consumers run from integrity-checked trees (a fixture export
        # refuses a dirty repo); importing _loader must never litter
        # scripts/ with __pycache__, including its own bytecode.
        self.assertTrue(sys.dont_write_bytecode)

    def test_missing_sibling_raises_file_not_found_naming_file(self):
        with self.assertRaises(FileNotFoundError) as raised:
            _loader.load_sibling("no-such-helper.py")
        self.assertIn("no-such-helper.py", str(raised.exception))

    def test_missing_path_raises_file_not_found_naming_file(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-loader-") as directory:
            missing = Path(directory) / "absent.py"
            with self.assertRaises(FileNotFoundError) as raised:
                _loader.load_path(missing)
            self.assertIn("absent.py", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
