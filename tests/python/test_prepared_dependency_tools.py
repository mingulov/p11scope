#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LIBRARY = ROOT / "scripts" / "prepared-dependency-tools.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "prepared-dependency-tools"
OUTPUT_KEYS = (
    "python",
    "rustup",
    "stable_cargo",
    "stable_rustc",
    "bpf_cargo",
    "bpf_rustc",
)


def parse_output(stdout: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in stdout.splitlines())


class PreparedDependencyToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="p11scope tools ")
        self.work = Path(self.tempdir.name)
        self.bin_dir = self.work / "selected tools"
        self.bin_dir.mkdir()
        self.log = self.work / "rustup calls.log"

        self.actual = {}
        for name in (
            "python actual",
            "rustup actual",
            "stable cargo actual",
            "stable rustc actual",
            "bpf cargo actual",
            "bpf rustc actual",
        ):
            destination = self.bin_dir / name
            source = FIXTURES / ("fake-rustup.sh" if name == "rustup actual" else "tool.sh")
            shutil.copy2(source, destination)
            destination.chmod(0o755)
            self.actual[name] = destination

        self.links = {}
        for name, target in self.actual.items():
            link = self.bin_dir / name.replace(" actual", " link")
            link.symlink_to(target.name)
            self.links[name] = link

        self.env = os.environ.copy()
        self.env.update(
            {
                "P11SCOPE_FIXTURE_LOG": str(self.log),
                "P11SCOPE_FIXTURE_STABLE_CARGO": str(self.links["stable cargo actual"]),
                "P11SCOPE_FIXTURE_STABLE_RUSTC": str(self.links["stable rustc actual"]),
                "P11SCOPE_FIXTURE_BPF_CARGO": str(self.links["bpf cargo actual"]),
                "P11SCOPE_FIXTURE_BPF_RUSTC": str(self.links["bpf rustc actual"]),
                "RUSTUP_AUTO_INSTALL": "caller-value",
            }
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_select(
        self,
        *arguments: Path,
        env: dict[str, str] | None = None,
        shell_options: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/sh",
                *shell_options,
                str(FIXTURES / "select.sh"),
                str(LIBRARY),
                str(FIXTURES / "child-env.sh"),
                *(str(argument) for argument in arguments),
            ],
            cwd=self.work,
            env=self.env if env is None else env,
            text=True,
            capture_output=True,
            check=False,
        )

    def rustup_calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()

    def assert_outputs_cleared(self, result: subprocess.CompletedProcess[str]) -> None:
        values = parse_output(result.stdout)
        self.assertEqual(values["state"], "same")
        self.assertEqual(values["auto_install"], values["before_auto_install"])
        for key in OUTPUT_KEYS:
            self.assertEqual(values[key], "unset", key)
        self.assertEqual(values["exported"], "")

    def test_refuses_allexport_without_queries_or_exported_results(self) -> None:
        result = self.run_select(
            self.links["python actual"],
            self.links["rustup actual"],
            shell_options=("-a",),
        )

        values = parse_output(result.stdout)
        self.assertNotEqual(values["status"], "0")
        self.assertIn(
            "p11scope_prepared_tools_select: allexport shell option is unsupported",
            result.stderr,
        )
        self.assertEqual(self.rustup_calls(), [])
        self.assert_outputs_cleared(result)

    def test_selects_canonical_executables_with_fixed_queries_and_no_exports(self) -> None:
        result = self.run_select(
            self.links["python actual"], self.links["rustup actual"]
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        values = parse_output(result.stdout)
        self.assertEqual(values["state"], "same")
        self.assertEqual(values["auto_install"], "caller-value")
        self.assertEqual(values["before_auto_install"], "caller-value")
        self.assertEqual(values["status"], "0")
        self.assertEqual(values["python"], str(self.actual["python actual"]))
        self.assertEqual(values["rustup"], str(self.actual["rustup actual"]))
        self.assertEqual(values["stable_cargo"], str(self.actual["stable cargo actual"]))
        self.assertEqual(values["stable_rustc"], str(self.actual["stable rustc actual"]))
        self.assertEqual(values["bpf_cargo"], str(self.actual["bpf cargo actual"]))
        self.assertEqual(values["bpf_rustc"], str(self.actual["bpf rustc actual"]))
        self.assertEqual(values["exported"], "")
        self.assertEqual(
            self.rustup_calls(),
            [
                "0\t4\twhich\t--toolchain\t1.88\tcargo",
                "0\t4\twhich\t--toolchain\t1.88\trustc",
                "0\t4\twhich\t--toolchain\tnightly-2026-05-20\tcargo",
                "0\t4\twhich\t--toolchain\tnightly-2026-05-20\trustc",
            ],
        )

    def test_rejects_invalid_arity_before_running_rustup_and_clears_outputs(self) -> None:
        cases = (
            (),
            (self.links["python actual"],),
            (
                self.links["python actual"],
                self.links["rustup actual"],
                self.links["stable cargo actual"],
            ),
        )
        for arguments in cases:
            with self.subTest(argument_count=len(arguments)):
                self.log.unlink(missing_ok=True)
                result = self.run_select(*arguments)
                self.assertEqual(result.returncode, 0)
                self.assertNotEqual(parse_output(result.stdout)["status"], "0")
                self.assertIn(
                    "p11scope_prepared_tools_select: expected "
                    "PYTHON_PATH RUSTUP_PATH",
                    result.stderr,
                )
                self.assertEqual(self.rustup_calls(), [])
                self.assert_outputs_cleared(result)

    def test_rejects_absent_or_nonexecutable_inputs_before_queries(self) -> None:
        missing = self.work / "missing"
        directory = self.work / "executable directory"
        directory.mkdir()
        nonexecutable = self.actual["python actual"]
        nonexecutable.chmod(0o644)
        cases = (
            (missing, self.links["rustup actual"], "python"),
            (directory, self.links["rustup actual"], "python"),
            (nonexecutable, self.links["rustup actual"], "python"),
            (self.actual["stable cargo actual"], missing, "rustup"),
            (self.actual["stable cargo actual"], nonexecutable, "rustup"),
        )
        for python, rustup, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic, python=python, rustup=rustup):
                self.log.unlink(missing_ok=True)
                result = self.run_select(python, rustup)
                self.assertNotEqual(parse_output(result.stdout)["status"], "0")
                self.assertIn(f"p11scope_prepared_tools_select: invalid {diagnostic} executable", result.stderr)
                self.assertEqual(self.rustup_calls(), [])
                self.assert_outputs_cleared(result)

    def test_rejects_executable_directory_returned_by_rustup(self) -> None:
        directory = self.work / "returned directory"
        directory.mkdir()
        env = self.env.copy()
        env["P11SCOPE_FIXTURE_STABLE_CARGO"] = str(directory)

        result = self.run_select(
            self.links["python actual"], self.links["rustup actual"], env=env
        )

        self.assertNotEqual(parse_output(result.stdout)["status"], "0")
        self.assertIn(
            "p11scope_prepared_tools_select: invalid stable cargo executable",
            result.stderr,
        )
        self.assertEqual(len(self.rustup_calls()), 1)
        self.assert_outputs_cleared(result)

    def test_rejects_each_absent_returned_tool_and_stops_at_first_failure(self) -> None:
        keys = (
            "P11SCOPE_FIXTURE_STABLE_CARGO",
            "P11SCOPE_FIXTURE_STABLE_RUSTC",
            "P11SCOPE_FIXTURE_BPF_CARGO",
            "P11SCOPE_FIXTURE_BPF_RUSTC",
        )
        labels = ("stable cargo", "stable rustc", "BPF cargo", "BPF rustc")
        for index, (key, label) in enumerate(zip(keys, labels), start=1):
            with self.subTest(tool=label):
                self.log.unlink(missing_ok=True)
                env = self.env.copy()
                env[key] = str(self.work / "absent returned tool")
                result = self.run_select(
                    self.links["python actual"], self.links["rustup actual"], env=env
                )
                self.assertNotEqual(parse_output(result.stdout)["status"], "0")
                self.assertIn(
                    f"p11scope_prepared_tools_select: invalid {label} executable",
                    result.stderr,
                )
                self.assertEqual(len(self.rustup_calls()), index)
                self.assert_outputs_cleared(result)

    def test_rejects_nonexecutable_returned_tool(self) -> None:
        self.actual["stable rustc actual"].chmod(0o644)
        result = self.run_select(
            self.links["python actual"], self.links["rustup actual"]
        )

        self.assertNotEqual(parse_output(result.stdout)["status"], "0")
        self.assertIn("p11scope_prepared_tools_select: invalid stable rustc executable", result.stderr)
        self.assertEqual(len(self.rustup_calls()), 2)
        self.assert_outputs_cleared(result)

    def test_rustup_query_failure_stops_later_queries_and_clears_outputs(self) -> None:
        env = self.env.copy()
        env["P11SCOPE_FIXTURE_FAIL_QUERY"] = "1.88:rustc"
        result = self.run_select(
            self.links["python actual"], self.links["rustup actual"], env=env
        )

        self.assertNotEqual(parse_output(result.stdout)["status"], "0")
        self.assertIn("p11scope_prepared_tools_select: rustup failed to select stable rustc", result.stderr)
        self.assertEqual(len(self.rustup_calls()), 2)
        self.assert_outputs_cleared(result)

    def test_sourcing_only_defines_functions_and_preserves_shell_state(self) -> None:
        env = self.env.copy()
        empty_path = self.work / "empty path"
        empty_path.mkdir()
        env["PATH"] = str(empty_path)
        result = subprocess.run(
            ["/bin/sh", str(FIXTURES / "source-only.sh"), str(LIBRARY)],
            cwd=self.work,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            parse_output(result.stdout),
            {"state": "same", "python": "source-sentinel"},
        )
        self.assertEqual(self.rustup_calls(), [])


if __name__ == "__main__":
    unittest.main()
