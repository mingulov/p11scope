#!/usr/bin/env python3
"""Native ordinary/prepared build tests for attach and canary callers."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/dual-build-callers"
CHILDREN = (ROOT / "scripts/verify-attach-e2e.sh", ROOT / "scripts/verify-canaries.sh")
PREPARED = ("P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
            "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC")


def logical_commands(path):
    commands, pending = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending.append(line)
        if not line.rstrip().endswith("\\"):
            commands.append("\n".join(pending)); pending = []
    return commands


class DualBuildCallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p11scope dual callers ")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "checkout with spaces"
        (self.repo / "scripts").mkdir(parents=True)
        for source in CHILDREN:
            shutil.copy2(source, self.repo / "scripts" / source.name)
        for name in ("product-build.sh", "cargo.sh", "lib.sh", "cleanup-traps.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        shutil.copy2(FIXTURES / "record-preparer.py", self.repo / "scripts/prepare-dependencies.py")
        self.bin = self.base / "PATH tripwires"
        self.bin.mkdir()
        shutil.copy2(FIXTURES / "dispatch.py", self.bin / "dispatch.py")
        (self.bin / "dispatch.py").chmod(0o755)
        for name in ("cargo", "gcc", "softhsm2-util", "bpftool", "sudo", "rustup"):
            (self.bin / name).symlink_to("dispatch.py")
        self.tools = self.base / "selected tools with spaces"
        self.tools.mkdir()
        self.stable_cargo = self.tools / "stable cargo"
        shutil.copy2(FIXTURES / "dispatch.py", self.stable_cargo)
        self.stable_cargo.chmod(0o755)
        self.selected = (self.stable_cargo,
                         self.make_inert("stable rustc"), self.make_inert("bpf cargo"),
                         self.make_inert("bpf rustc"))
        self.events = self.base / "events.jsonl"
        self.config = self.base / "config.json"
        self.module = self.base / "module.so"
        self.module.write_bytes(b"fixture")
        self.work = self.base / "private work"
        self.environment = os.environ.copy()
        for name in (*PREPARED, "P11SCOPE_PRODUCT_BUILD_MODE"):
            self.environment.pop(name, None)
        self.environment.update(PATH=f"{self.bin}:/usr/bin:/bin",
                                P11SCOPE_DUAL_BUILD_CONFIG=str(self.config),
                                P11SCOPE_PKCS11_MODULE=str(self.module),
                                P11SCOPE_TASK4_WORK=str(self.work))

    def make_inert(self, name):
        path = self.tools / name
        shutil.copy2(FIXTURES / "unused-tool.sh", path)
        path.chmod(0o755)
        return path

    def configure(self, statuses):
        self.config.write_text(json.dumps({"events": str(self.events),
                                           "cargo_statuses": statuses}), encoding="utf-8")

    def rows(self):
        return [json.loads(row) for row in self.events.read_text().splitlines()]

    def run_child(self, child, bits=64, prepared=False):
        self.events.unlink(missing_ok=True)
        environment = self.environment.copy()
        environment["P11SCOPE_CANARY_TARGET_BITS"] = str(bits)
        if prepared:
            environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prepared"
            environment.update({name: str(value) for name, value in zip(PREPARED, self.selected)})
        return subprocess.run(["sh", str(self.repo / "scripts" / child.name)], cwd=self.base,
                              env=environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10)

    def expected(self, child, bits, prepared):
        prefix = ["build", "--locked", "--offline"] if prepared else ["+1.88", "build", "--locked"]
        if child.name == "verify-attach-e2e.sh":
            return [prefix + ["--release", "--workspace", "--target-dir", str(self.work / "build")]]
        rows = [
            prefix + ["--release", "--workspace", "--target-dir", str(self.work / "default-build")],
            prefix + ["--release", "--workspace", "--features", "unsafe-unvalidated-metadata",
                      "--target-dir", str(self.work / "feature-build")],
        ]
        if bits == 32:
            rows.append(prefix + ["--release", "-p", "p11scope-discover", "--target",
                                   "i686-unknown-linux-gnu", "--target-dir",
                                   str(self.work / "helper-build")])
        return rows

    def assert_builds(self, child, bits, prepared):
        expected = self.expected(child, bits, prepared)
        self.configure([0] * (len(expected) - 1) + [83])
        result = self.run_child(child, bits, prepared)
        self.assertEqual(result.returncode, 83, result.stderr)
        rows = self.rows()
        builds = [row for row in rows if row["kind"] == "cargo"]
        self.assertEqual([row["argv"] for row in builds], expected)
        resources = {"sudo", "gcc", "bpftool", "softhsm2-util", "rustup"}
        self.assertFalse(resources & {row["kind"] for row in rows})
        if prepared:
            for row in builds:
                self.assertEqual(row["executable"], str(self.stable_cargo.resolve()))
                self.assertEqual(row["rustc"], str(self.selected[1]))
                self.assertEqual(row["bpf_cargo"], str(self.selected[2]))
                self.assertEqual(row["bpf_rustc"], str(self.selected[3]))
            self.assertFalse(any(row["kind"] == "prepare" for row in rows))
        else:
            preparations = [row for row in rows if row["kind"] == "prepare"]
            self.assertEqual(len(preparations), len(builds))
            self.assertTrue(all(row["isolated"] == 1 and row["argv"] == []
                                for row in preparations))

    def test_canary_product_builds_precede_task_storage_helper(self):
        commands = [command.lstrip() for command in logical_commands(CHILDREN[1])]
        product_builds = [index for index, command in enumerate(commands)
                          if command.startswith("p11scope_product_build ")]
        helper_builds = [index for index, command in enumerate(commands)
                         if command.startswith("scripts/build-task-storage-reader.sh ")]
        self.assertEqual(len(product_builds), 3)
        self.assertEqual(len(helper_builds), 1)
        self.assertLess(max(product_builds), helper_builds[0])

    def test_standalone_defaults_to_ordinary_for_all_variants(self):
        self.assert_builds(CHILDREN[0], 64, False)
        self.assert_builds(CHILDREN[1], 64, False)
        self.assert_builds(CHILDREN[1], 32, False)

    def test_prepared_mode_uses_exact_tools_without_preparation_or_reselection(self):
        self.assert_builds(CHILDREN[0], 64, True)
        self.assert_builds(CHILDREN[1], 64, True)
        self.assert_builds(CHILDREN[1], 32, True)

    def test_every_partial_prepared_context_refuses_before_build_and_resources(self):
        self.configure([83])
        for child in CHILDREN:
            for mask in range(15):
                with self.subTest(child=child.name, mask=mask):
                    self.events.unlink(missing_ok=True)
                    environment = self.environment.copy()
                    environment["P11SCOPE_PRODUCT_BUILD_MODE"] = "prepared"
                    for index, (name, value) in enumerate(zip(PREPARED, self.selected)):
                        if mask & (1 << index):
                            environment[name] = str(value)
                    result = subprocess.run(
                        ["sh", str(self.repo / "scripts" / child.name)], cwd=self.base,
                        env=environment, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("complete prepared product-build context required", result.stderr)
                    self.assertFalse(self.events.exists())

    def test_release_handoffs_unexported_selected_context_to_actual_children(self):
        release = ROOT / "scripts/build-release.sh"
        commands = [command for command in logical_commands(release)
                    if command.startswith("P11SCOPE_PRODUCT_BUILD_MODE=prepared")]
        self.assertEqual(len(commands), 2)
        for command, child, bits in zip(commands, CHILDREN[::-1], (64, 64)):
            with self.subTest(child=child.name):
                self.events.unlink(missing_ok=True)
                expected = self.expected(child, bits, True)
                self.configure([0] * (len(expected) - 1) + [83])
                command_file = self.base / f"{child.name}.command"
                command_file.write_text(command, encoding="utf-8")
                result = subprocess.run(
                    ["sh", str(FIXTURES / "release-handoff-launcher.sh"),
                     str(command_file), *(str(value) for value in self.selected)],
                    cwd=self.repo, env=self.environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 83, result.stderr)
                builds = [row for row in self.rows() if row["kind"] == "cargo"]
                self.assertEqual([row["argv"] for row in builds], expected)
                self.assertTrue(all(row["executable"] == str(self.stable_cargo.resolve())
                                    and row["rustc"] == str(self.selected[1])
                                    and row["bpf_cargo"] == str(self.selected[2])
                                    and row["bpf_rustc"] == str(self.selected[3]) for row in builds))

    def compiler_free_tripwires(self):
        """The PATH tripwires a delegated `--self-test` may never reach.

        The validator suites compile their own fixtures, so a real compiler is
        part of the self-test and `gcc` is deliberately left resolvable; cargo,
        the privilege escalator and the hardware tools are not, and
        `dispatch.py` records any attempt to run one.
        """
        directory = self.base / "PATH tripwires without a compiler"
        directory.mkdir()
        shutil.copy2(FIXTURES / "dispatch.py", directory / "dispatch.py")
        (directory / "dispatch.py").chmod(0o755)
        for name in ("cargo", "softhsm2-util", "bpftool", "sudo", "rustup"):
            (directory / name).symlink_to("dispatch.py")
        return directory

    def test_self_test_fast_paths_remain_before_build_setup(self):
        # The claim is that `--self-test` returns before `product-build.sh` runs
        # two `--release --workspace` builds. This file's own PATH tripwires are
        # the check, not a clock: a self-test that reached build setup, sudo or
        # a hardware tool leaves a recorded event behind, which is caught even
        # when the stand-in returns instantly. The delegated validator suites
        # grew with the canary matrix (60 evidence + 11 workload cases per
        # width, each compiling fixtures and spawning subprocesses), so a
        # budget under their cost on a slower supported guest had made this a
        # timing tripwire rather than a build-setup check; the timeout below is
        # only a hang guard, far above any observed self-test cost.
        self.configure([0, 0, 0])
        environment = dict(self.environment,
                           PATH=f"{self.compiler_free_tripwires()}:/usr/bin:/bin")
        for child in CHILDREN:
            with self.subTest(child=child.name):
                self.events.unlink(missing_ok=True)
                result = subprocess.run(["sh", str(child), "--self-test"], cwd=ROOT,
                                        env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=900)
                # The substantive check first: a recorded event names exactly
                # which tool a fallen-through self-test reached.
                self.assertFalse(
                    self.events.exists(),
                    f"{child.name} --self-test reached build setup or a resource tool: "
                    f"{self.rows() if self.events.exists() else ''}")
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
