#!/usr/bin/env python3
"""Native tests for the shared ordinary/prepared product build launcher."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/product-build.sh"
FIXTURES = ROOT / "tests/fixtures/product-build"
PREPARED_NAMES = (
    "P11SCOPE_PREPARED_STABLE_CARGO",
    "P11SCOPE_PREPARED_STABLE_RUSTC",
    "P11SCOPE_PREPARED_BPF_CARGO",
    "P11SCOPE_PREPARED_BPF_RUSTC",
)


class ProductBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope product build ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.record = self.base / "record.json"
        self.environment = os.environ.copy()
        for name in (*PREPARED_NAMES, "RUSTC"):
            self.environment.pop(name, None)
        self.environment["P11SCOPE_PRODUCT_BUILD_RECORD"] = str(self.record)

    def make_tool(self, directory, name, fixture="record-cargo.py"):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        shutil.copy2(FIXTURES / fixture, path)
        path.chmod(0o755)
        return path

    def prepared_tools(self):
        directory = self.base / "selected tools with spaces"
        return (
            self.make_tool(directory, "stable cargo"),
            self.make_tool(directory, "stable rustc", "unused-tool.sh"),
            self.make_tool(directory, "bpf cargo", "unused-tool.sh"),
            self.make_tool(directory, "bpf rustc", "unused-tool.sh"),
        )

    def invoke(self, mode, tools, *arguments, cwd=None, environment=None):
        return subprocess.run(
            ["sh", str(FIXTURES / "unexported-launcher.sh"), str(HELPER), mode,
             *(str(tool) for tool in tools), *arguments],
            cwd=cwd or ROOT, env=environment or self.environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def read_record(self):
        return json.loads(self.record.read_text(encoding="utf-8"))

    def test_ordinary_uses_existing_wrapper_with_pinned_locked_arguments(self):
        root = self.base / "ordinary root"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/cargo.sh", scripts / "cargo.sh")
        shutil.copy2(FIXTURES / "record-preparer.py", scripts / "prepare-dependencies.py")
        bin_dir = self.base / "ordinary bin"
        self.make_tool(bin_dir, "cargo")
        environment = self.environment.copy()
        environment["PATH"] = f"{bin_dir}:/usr/bin:/bin"
        arguments = ("--release", "--workspace", "--features", "two words", "--target-dir",
                     str(self.base / "target with spaces"))

        result = self.invoke("ordinary", ("", "", "", ""), *arguments,
                             cwd=root, environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.read_record()
        self.assertEqual(record["argv"], ["+1.88", "build", "--locked", *arguments])
        self.assertEqual(record["cwd"], str(root))
        self.assertEqual(record["environment"], {})
        preparation = json.loads((self.base / "preparation.json").read_text())
        self.assertEqual(preparation, {"argv": [], "cwd": str(root), "isolated": 1})

    def test_prepared_uses_exact_selected_context_and_preserves_variants(self):
        tools = self.prepared_tools()
        tripwires = self.base / "path tripwires"
        for name in ("cargo", "rustup", "python3", "prepare-dependencies.py"):
            self.make_tool(tripwires, name, "unused-tool.sh")
        environment = self.environment.copy()
        environment["PATH"] = f"{tripwires}:/usr/bin:/bin"
        arguments = ("--release", "--workspace", "--features",
                     "unsafe-unvalidated-metadata", "--target-dir",
                     str(self.base / "prepared target with spaces"))

        result = self.invoke("prepared", tools, *arguments, environment=environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.read_record()
        self.assertEqual(record["argv"], ["build", "--locked", "--offline", *arguments])
        self.assertEqual(record["environment"], {
            "RUSTC": str(tools[1]),
            "P11SCOPE_PREPARED_BPF_CARGO": str(tools[2]),
            "P11SCOPE_PREPARED_BPF_RUSTC": str(tools[3]),
        })
        self.assertFalse((self.base / "unused-tool-invoked").exists())

    def test_prepared_refuses_every_missing_or_partial_context_before_build(self):
        tools = self.prepared_tools()
        for mask in range(15):
            with self.subTest(mask=mask):
                self.record.unlink(missing_ok=True)
                selected = tuple(tool if mask & (1 << index) else ""
                                 for index, tool in enumerate(tools))
                result = self.invoke("prepared", selected, "--release")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("complete prepared product-build context required", result.stderr)
                self.assertFalse(self.record.exists())

    def test_prepared_refuses_nonabsolute_nonregular_and_nonexecutable_tools(self):
        tools = list(self.prepared_tools())
        invalid = self.base / "not executable"
        invalid.write_text("fixture\n", encoding="utf-8")
        directory = self.base / "directory tool"
        directory.mkdir()
        cases = ("relative/tool", invalid, directory)
        for index in range(4):
            for value in cases:
                with self.subTest(index=index, value=value):
                    self.record.unlink(missing_ok=True)
                    selected = tools.copy()
                    selected[index] = value
                    result = self.invoke("prepared", selected)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("absolute executable prepared product-build tool required",
                                  result.stderr)
                    self.assertFalse(self.record.exists())

    def test_selected_cargo_failure_status_and_streams_are_preserved(self):
        tools = self.prepared_tools()
        environment = self.environment.copy()
        environment.update(P11SCOPE_PRODUCT_BUILD_STATUS="37",
                           P11SCOPE_PRODUCT_BUILD_STDOUT="selected stdout\n",
                           P11SCOPE_PRODUCT_BUILD_STDERR="selected stderr\n")
        result = self.invoke("prepared", tools, "--release", environment=environment)
        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, "selected stdout\n")
        self.assertEqual(result.stderr, "selected stderr\n")

        root = self.base / "ordinary failure root"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/cargo.sh", scripts / "cargo.sh")
        shutil.copy2(FIXTURES / "record-preparer.py", scripts / "prepare-dependencies.py")
        bin_dir = self.base / "ordinary failure bin"
        self.make_tool(bin_dir, "cargo")
        environment["PATH"] = f"{bin_dir}:/usr/bin:/bin"
        self.record.unlink()
        result = self.invoke("ordinary", ("", "", "", ""), "--release",
                             cwd=root, environment=environment)
        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, "selected stdout\n")
        self.assertEqual(result.stderr, "selected stderr\n")
        self.assertEqual(self.read_record()["argv"],
                         ["+1.88", "build", "--locked", "--release"])

    def test_invalid_mode_and_source_time_have_no_side_effects(self):
        invalid = self.invoke("unknown", ("", "", "", ""))
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("usage: p11scope_product_build ordinary|prepared", invalid.stderr)
        self.assertFalse(self.record.exists())
        result = subprocess.run(
            ["sh", str(ROOT / "tests/fixtures/source-state.sh"), str(HELPER),
             "p11scope_product_build", str(self.base)],
            cwd=self.base, env=self.environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
