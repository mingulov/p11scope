#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native tests for ordinary product builds in five shell callers."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/ordinary-build-callers"
CALLERS = (
    ROOT / "scripts/matrix/verify-kind-pod.sh",
    ROOT / "scripts/matrix/verify-docker.sh",
    ROOT / "scripts/matrix/verify-proxy-stack.sh",
    ROOT / "scripts/verify-inspect-doctor.sh",
    ROOT / "scripts/bench-overhead.sh",
)


def logical_commands(path):
    commands = []
    pending = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending.append(line)
        if not line.rstrip().endswith("\\"):
            commands.append("\n".join(pending))
            pending = []
    return commands


class OrdinaryBuildCallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p11scope ordinary callers ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "checkout with spaces"
        (self.root / "scripts/matrix").mkdir(parents=True)
        for relative in ("scripts/cargo.sh", "scripts/lib.sh", "scripts/cleanup-traps.sh",
                         "scripts/matrix/matrix-lib.sh"):
            destination = self.root / relative
            shutil.copy2(ROOT / relative, destination)
        shutil.copy2(FIXTURES / "record-preparer.py",
                     self.root / "scripts/prepare-dependencies.py")
        for caller in CALLERS:
            relative = caller.relative_to(ROOT)
            shutil.copy2(caller, self.root / relative)
        self.bin = self.base / "controlled tools"
        self.bin.mkdir()
        shutil.copy2(FIXTURES / "dispatch.py", self.bin / "dispatch.py")
        (self.bin / "dispatch.py").chmod(0o755)
        for name in ("cargo", "timeout", "sudo", "docker", "kind", "kubectl",
                     "gcc", "softhsm2-util"):
            (self.bin / name).symlink_to("dispatch.py")
        self.events = self.base / "events.jsonl"
        self.config = self.base / "config.json"
        self.environment = os.environ.copy()
        self.environment.update(
            PATH=f"{self.bin}:/usr/bin:/bin",
            P11SCOPE_ORDINARY_CALLERS_CONFIG=str(self.config),
        )
        self.write_config()

    def write_config(self, **values):
        self.config.write_text(json.dumps({"events": str(self.events), **values}),
                               encoding="utf-8")

    def rows(self):
        if not self.events.exists():
            return []
        return [json.loads(line) for line in self.events.read_text().splitlines()]

    def build_command(self, caller):
        matches = [command for command in logical_commands(caller)
                   if "scripts/cargo.sh +1.88 build --locked" in command]
        self.assertEqual(len(matches), 1, caller.name)
        return matches[0]

    def expected_cargo(self, caller):
        if caller.name in ("verify-kind-pod.sh", "verify-docker.sh"):
            return ["+1.88", "build", "--locked", "--release", "--workspace",
                    "--target-dir", "target/matrix-product"]
        if caller.name == "verify-proxy-stack.sh":
            return ["+1.88", "build", "--locked", "--release", "--workspace",
                    "--target-dir", "target/test-work/build"]
        if caller.name == "verify-inspect-doctor.sh":
            return ["+1.88", "build", "--locked", "--release", "--target-dir",
                    "target/test-work/build"]
        return ["+1.88", "build", "--locked", "--release", "--workspace"]

    def test_each_real_build_command_preserves_exact_arguments_and_timeout(self):
        for caller in CALLERS:
            with self.subTest(caller=caller.name):
                self.events.unlink(missing_ok=True)
                result = subprocess.run(
                    ["sh", "-c", self.build_command(caller)], cwd=self.root,
                    env={**self.environment, "WORK": "target/test-work",
                         "PRODUCT": "target/matrix-product"},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, 83, result.stderr)
                rows = self.rows()
                self.assertEqual([row["kind"] for row in rows],
                                 (["timeout"] if caller.name in
                                  ("verify-kind-pod.sh", "verify-docker.sh") else [])
                                 + ["prepare", "cargo"])
                self.assertEqual(rows[-1]["argv"], self.expected_cargo(caller))
                preparation = next(row for row in rows if row["kind"] == "prepare")
                self.assertEqual(preparation["argv"], [])
                self.assertEqual(preparation["isolated"], 1)
                if rows[0]["kind"] == "timeout":
                    self.assertEqual(rows[0]["argv"], [
                        "--signal=TERM", "--kill-after=5s", "600s",
                        "scripts/cargo.sh", *self.expected_cargo(caller),
                    ])

    def test_preparation_failure_stops_before_cargo_and_resource_tools(self):
        self.write_config(prepare_status=41)
        for caller in CALLERS:
            with self.subTest(caller=caller.name):
                self.events.unlink(missing_ok=True)
                result = subprocess.run(
                    ["sh", "-c", self.build_command(caller)], cwd=self.root,
                    env={**self.environment, "WORK": "target/test-work",
                         "PRODUCT": "target/matrix-product"},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(result.returncode, 41, result.stderr)
                kinds = [row["kind"] for row in self.rows()]
                self.assertIn("prepare", kinds)
                self.assertNotIn("cargo", kinds)
                self.assertFalse(set(kinds) & {"sudo", "docker", "kind", "kubectl", "gcc"})

    def test_actual_privileged_entries_build_before_resource_acquisition(self):
        cases = (
            (CALLERS[0], {}),
            (CALLERS[1], {}),
            (CALLERS[3], {"P11SCOPE_PKCS11_MODULE": str(self.base / "module.so")}),
        )
        (self.base / "module.so").write_bytes(b"fixture")
        for prepare_status, expected_status in ((0, 83), (41, 41)):
            self.write_config(prepare_status=prepare_status)
            for caller, additions in cases:
                with self.subTest(caller=caller.name, prepare_status=prepare_status):
                    self.events.unlink(missing_ok=True)
                    relative = caller.relative_to(ROOT)
                    result = subprocess.run(
                        ["sh", str(self.root / relative)], cwd=self.base,
                        env={**self.environment, **additions}, text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                    )
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    kinds = [row["kind"] for row in self.rows()]
                    self.assertIn("prepare", kinds)
                    self.assertEqual("cargo" in kinds, prepare_status == 0)
                    self.assertFalse(set(kinds) &
                                     {"sudo", "docker", "kind", "kubectl", "gcc"})

    def test_build_precedes_privilege_and_container_commands_in_every_source(self):
        for caller in CALLERS:
            source = caller.read_text(encoding="utf-8")
            build = source.index("scripts/cargo.sh +1.88 build --locked")
            for marker in ("sudo -n true", "docker build", "kind create cluster"):
                if marker in source:
                    self.assertLess(build, source.index(marker), (caller.name, marker))

    def test_inspect_self_test_fast_path_is_unchanged(self):
        result = subprocess.run(
            ["sh", str(CALLERS[3]), "--self-test"], cwd=ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verify-inspect-doctor self-test: OK", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
